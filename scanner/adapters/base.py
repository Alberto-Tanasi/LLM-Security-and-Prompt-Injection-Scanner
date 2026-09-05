"""
scanner.adapters.base
=======================

Abstract interface every LLM backend adapter must implement. Keeping
this contract narrow (connect, list models, generate) is what lets the
scan engine, GUI, and CLI treat "a local Ollama model" and "a hosted
OpenAI-compatible API" identically.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from ..core.models import LLMResponse


class AdapterConnectionError(Exception):
    """Raised when a connectivity check fails in a way callers should surface clearly."""


class BaseLLMAdapter(ABC):
    """Common interface for all target-model backends."""

    #: Human-readable backend name, shown in the GUI and reports.
    name: str = "base"

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """Attempt to reach the backend.

        Returns
        -------
        (success, message):
            ``success`` is True if the backend is reachable and usable.
            ``message`` is a short human-readable status suitable for
            display directly in the GUI's connection indicator.
        """
        raise NotImplementedError

    @abstractmethod
    def list_models(self) -> List[str]:
        """Return the list of model names/ids available on this backend.

        Should return an empty list (not raise) if the backend is
        unreachable -- callers are expected to call ``test_connection``
        first and handle connectivity errors there.
        """
        raise NotImplementedError

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
        timeout: int = 60,
    ) -> LLMResponse:
        """Send ``prompt`` (with optional ``system_prompt``) and return the response.

        Implementations must never raise on ordinary failure modes
        (connection refused, timeout, HTTP error, malformed JSON) --
        those are caught internally and returned as an ``LLMResponse``
        with ``error`` set, so the scan engine can keep going through
        the remaining payloads instead of crashing the whole run.
        """
        raise NotImplementedError

    def describe_target(self, model: str) -> str:
        """Short string used in report headers, e.g. 'Ollama @ llama3.2'."""
        return f"{self.name} @ {model}"
