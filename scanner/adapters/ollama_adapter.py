"""
scanner.adapters.ollama_adapter
==================================

Adapter for a locally-running Ollama instance (https://ollama.com).

This is the primary backend for the scanner: everything stays on
``localhost`` (or whatever LAN host you point it at) -- no data ever
leaves the machine running Ollama, and there is nothing to log on a
third-party server. This is why the project defaults to Ollama for a
first-time, "safe to experiment freely" red-teaming target.

Endpoints used (see https://docs.ollama.com/api):
    GET  {host}/api/tags       -> list locally-available models
    POST {host}/api/generate   -> single-turn completion, with an
                                   optional top-level "system" field
                                   used to set the system prompt for
                                   that one request.

We use ``/api/generate`` with ``"stream": false`` rather than
``/api/chat`` because every payload in this scanner is a single-turn
test (no multi-turn memory needed), which keeps the adapter -- and the
job of reasoning about "what exactly did we send" during analysis --
much simpler.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..core.models import LLMResponse
from .base import BaseLLMAdapter


class OllamaAdapter(BaseLLMAdapter):
    name = "Ollama"

    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.2", **_ignored):
        self.host = host.rstrip("/")
        self.model = model
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_connection(self) -> Tuple[bool, str]:
        try:
            resp = self._session.get(f"{self.host}/api/tags", timeout=5)
        except requests.exceptions.ConnectionError:
            return False, (
                f"Could not connect to Ollama at {self.host}. "
                "Is 'ollama serve' running?"
            )
        except requests.exceptions.Timeout:
            return False, f"Connection to {self.host} timed out."
        except requests.exceptions.RequestException as exc:
            return False, f"Connection error: {exc}"

        if resp.status_code != 200:
            return False, f"Ollama responded with HTTP {resp.status_code}."

        try:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
        except ValueError:
            return False, "Connected, but the response wasn't valid JSON."

        if not models:
            return True, (
                "Connected to Ollama, but no models are pulled yet. "
                "Run 'ollama pull llama3.2' (or any model) first."
            )
        if self.model not in models:
            return True, (
                f"Connected to Ollama. Note: '{self.model}' is not in the pulled "
                f"model list ({', '.join(models[:5])}{'...' if len(models) > 5 else ''})."
            )
        return True, f"Connected to Ollama. {len(models)} model(s) available."

    def list_models(self) -> List[str]:
        try:
            resp = self._session.get(f"{self.host}/api/tags", timeout=5)
            resp.raise_for_status()
            return [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]
        except (requests.exceptions.RequestException, ValueError):
            return []

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 512,
        timeout: int = 60,
    ) -> LLMResponse:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        start = time.monotonic()
        try:
            resp = self._session.post(
                f"{self.host}/api/generate", json=payload, timeout=timeout
            )
        except requests.exceptions.ConnectionError:
            return LLMResponse.error_response(
                self.model,
                f"Connection refused at {self.host}. Is Ollama running?",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except requests.exceptions.Timeout:
            return LLMResponse.error_response(
                self.model,
                f"Request timed out after {timeout}s. The model may be slow to "
                "load, or 'num_predict'/prompt length may be too large.",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except requests.exceptions.RequestException as exc:
            return LLMResponse.error_response(
                self.model, f"Request error: {exc}",
                latency_ms=(time.monotonic() - start) * 1000,
            )

        latency_ms = (time.monotonic() - start) * 1000

        if resp.status_code == 404:
            return LLMResponse.error_response(
                self.model,
                f"Model '{self.model}' not found on this Ollama instance. "
                f"Run 'ollama pull {self.model}' first.",
                latency_ms=latency_ms,
            )
        if resp.status_code != 200:
            return LLMResponse.error_response(
                self.model, f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}",
                latency_ms=latency_ms,
            )

        try:
            data = resp.json()
        except ValueError:
            return LLMResponse.error_response(
                self.model, "Ollama returned a non-JSON response.", latency_ms=latency_ms
            )

        text = data.get("response", "")
        prompt_tokens = data.get("prompt_eval_count")
        completion_tokens = data.get("eval_count")

        return LLMResponse(
            text=text,
            model=self.model,
            latency_ms=latency_ms,
            raw=data,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def describe_target(self, model: str) -> str:
        return f"Ollama (local) @ {model} [{self.host}]"
