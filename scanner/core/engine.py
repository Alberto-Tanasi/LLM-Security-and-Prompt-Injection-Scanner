"""
scanner.core.engine
======================

The orchestration engine: given a ``ScanConfig`` and a list of
``Payload`` objects, runs each payload against the target model and
yields a ``TestResult`` as soon as it's ready.

This is implemented as a **generator** (``run_iter``) rather than a
function that returns a list, specifically so that:

* The GUI can drive it from a background thread and push each result
  onto a queue as it arrives (real-time progress, per README's "Live
  Scan" tab), instead of blocking until all 25 payloads finish.
* The CLI can iterate over it directly and print progress line-by-line.
* Tests can exhaust it into a list when they just want the final set.

Neither front-end duplicates the actual scanning logic -- both are
thin wrappers around this one generator, which is the main payoff of
splitting "core" from "gui"/"cli" in the first place.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional

from ..adapters.base import BaseLLMAdapter
from ..adapters.mock_adapter import MockAdapter
from ..analysis.analyzer import ResponseAnalyzer
from .models import Payload, ScanConfig, TestResult


@dataclass
class EngineEvent:
    """Wraps a single yielded item from run_iter so callers can distinguish
    a completed test result from lifecycle/status events (useful for the
    GUI's live log, which shows more than just pass/fail rows)."""

    kind: str  # "result" | "status" | "error"
    result: Optional[TestResult] = None
    message: str = ""
    index: int = 0
    total: int = 0


class ScanEngine:
    """Runs a full scan against a target adapter, one payload at a time."""

    def __init__(self, adapter: BaseLLMAdapter, config: ScanConfig, analyzer: Optional[ResponseAnalyzer] = None):
        self.adapter = adapter
        self.config = config
        self.analyzer = analyzer or ResponseAnalyzer()

    def run_iter(
        self,
        payloads: List[Payload],
        stop_flag: Optional[threading.Event] = None,
        pause_flag: Optional[threading.Event] = None,
    ) -> Iterator[EngineEvent]:
        """Yield an ``EngineEvent`` for each lifecycle step and each completed test.

        ``stop_flag``: if set, the generator stops (raises StopIteration)
        before starting the next payload -- lets the GUI's Cancel button
        interrupt a run cleanly between requests rather than mid-request.

        ``pause_flag``: if set, the generator blocks (polling every
        200ms) before starting the next payload -- lets the GUI's
        Pause button hold the scan without losing any state.
        """
        total = len(payloads)
        # MockAdapter needs to know the payload list up front so it can
        # match canned responses by exact prompt text.
        if isinstance(self.adapter, MockAdapter):
            self.adapter.register_payloads(payloads)

        yield EngineEvent(kind="status", message=f"Starting scan: {total} payload(s) queued.", total=total)

        for index, payload in enumerate(payloads, start=1):
            if stop_flag is not None and stop_flag.is_set():
                yield EngineEvent(kind="status", message="Scan cancelled by user.", index=index - 1, total=total)
                return

            while pause_flag is not None and pause_flag.is_set():
                if stop_flag is not None and stop_flag.is_set():
                    yield EngineEvent(kind="status", message="Scan cancelled by user.", index=index - 1, total=total)
                    return
                time.sleep(0.2)

            yield EngineEvent(
                kind="status",
                message=f"Testing {payload.id} ({payload.technique})...",
                index=index,
                total=total,
            )

            response = self.adapter.generate(
                prompt=payload.render(),
                system_prompt=self.config.target_system_prompt or None,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.request_timeout,
            )

            result = self.analyzer.analyze(payload, response, self.config.canary_tokens)
            yield EngineEvent(kind="result", result=result, index=index, total=total)

            if self.config.delay_between_requests > 0 and index < total:
                time.sleep(self.config.delay_between_requests)

        yield EngineEvent(kind="status", message="Scan complete.", index=total, total=total)

    def run(
        self,
        payloads: List[Payload],
        on_event: Optional[Callable[[EngineEvent], None]] = None,
    ) -> List[TestResult]:
        """Convenience non-generator wrapper: runs to completion and returns all results.

        ``on_event``, if given, is called synchronously for every event
        (useful for a simple CLI progress printer that doesn't need
        threading). For the GUI's threaded flow, use ``run_iter``
        directly instead -- see gui/scan_controller.py.
        """
        results: List[TestResult] = []
        for event in self.run_iter(payloads):
            if on_event:
                on_event(event)
            if event.kind == "result" and event.result is not None:
                results.append(event.result)
        return results
