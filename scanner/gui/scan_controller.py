"""
scanner.gui.scan_controller
==============================

Bridges the generator-based ``ScanEngine`` (see core/engine.py) onto
tkinter's single-threaded event loop.

Ollama/API calls are blocking HTTP requests, and tkinter's mainloop
must never block or the whole window freezes (no repaint, no button
clicks, nothing). The standard, correct fix is: run the engine on a
background thread, have that thread push events onto a thread-safe
``queue.Queue``, and have the GUI thread drain the queue on a timer via
``root.after(...)``. That's exactly what this class does -- it is the
only place in the GUI codebase that touches ``threading`` directly, so
every panel can just register plain callback functions and stay
oblivious to the concurrency.
"""
from __future__ import annotations

import queue
import threading
from typing import Callable, List, Optional

from ..adapters.base import BaseLLMAdapter
from ..analysis.analyzer import ResponseAnalyzer
from ..core.engine import EngineEvent, ScanEngine
from ..core.models import Payload, ScanConfig, TestResult


class ScanController:
    """Owns the background thread + queue for one running (or completed) scan."""

    def __init__(self, root, poll_interval_ms: int = 80):
        self._root = root
        self._poll_interval_ms = poll_interval_ms
        self._queue: "queue.Queue[EngineEvent]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._pause_flag = threading.Event()
        self._results: List[TestResult] = []
        self._polling = False

        # Callbacks the owning panel/app registers.
        self.on_status: Optional[Callable[[EngineEvent], None]] = None
        self.on_result: Optional[Callable[[TestResult], None]] = None
        self.on_complete: Optional[Callable[[List[TestResult]], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def results(self) -> List[TestResult]:
        return list(self._results)

    def start(self, adapter: BaseLLMAdapter, config: ScanConfig, payloads: List[Payload]) -> None:
        if self.is_running:
            raise RuntimeError("A scan is already running.")

        self._results = []
        self._stop_flag.clear()
        self._pause_flag.clear()
        # Drain any stale events from a previous run.
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

        engine = ScanEngine(adapter, config, ResponseAnalyzer())

        def _worker():
            try:
                for event in engine.run_iter(payloads, stop_flag=self._stop_flag, pause_flag=self._pause_flag):
                    self._queue.put(event)
            except Exception as exc:  # noqa: BLE001 - surface any adapter/engine bug to the GUI, don't crash silently
                self._queue.put(EngineEvent(kind="error", message=str(exc)))

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        if not self._polling:
            self._polling = True
            self._root.after(self._poll_interval_ms, self._poll)

    def pause(self) -> None:
        self._pause_flag.set()

    def resume(self) -> None:
        self._pause_flag.clear()

    def cancel(self) -> None:
        self._stop_flag.set()
        self._pause_flag.clear()  # don't leave it stuck paused mid-cancel

    def _poll(self) -> None:
        try:
            while True:
                event = self._queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass

        if self.is_running or not self._queue.empty():
            self._root.after(self._poll_interval_ms, self._poll)
        else:
            self._polling = False

    def _handle_event(self, event: EngineEvent) -> None:
        if event.kind == "error":
            if self.on_error:
                self.on_error(event.message)
            return
        if event.kind == "status":
            if self.on_status:
                self.on_status(event)
            if "Scan complete" in event.message or "cancelled" in event.message:
                if self.on_complete:
                    self.on_complete(list(self._results))
            return
        if event.kind == "result" and event.result is not None:
            self._results.append(event.result)
            if self.on_result:
                self.on_result(event.result)
