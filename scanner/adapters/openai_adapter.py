"""
scanner.adapters.openai_adapter
==================================

Adapter for the OpenAI Chat Completions API *and* anything that speaks
the same wire format -- which in practice includes Azure OpenAI, most
self-hosted inference servers (vLLM, LM Studio, text-generation-webui),
and Ollama's own OpenAI-compatibility layer at ``/v1/chat/completions``.

This exists mainly to demonstrate that the framework's adapter
interface generalizes beyond Ollama (see ``BaseLLMAdapter``); the GUI
ships with Ollama selected by default per the project's initial scope
("start local, nothing leaves the machine"), but pointing this at a
hosted API only requires filling in a host + API key.

Note: unlike the Ollama adapter, requests made with this adapter leave
the local machine if ``host`` points at a remote API. The GUI displays
a reminder about this whenever "OpenAI-compatible" is selected as the
backend -- see gui/panels/config_panel.py.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..core.models import LLMResponse
from .base import BaseLLMAdapter


class OpenAICompatibleAdapter(BaseLLMAdapter):
    name = "OpenAI-compatible"

    def __init__(
        self,
        host: str = "https://api.openai.com",
        model: str = "gpt-4o-mini",
        api_key: str = "",
        **_ignored,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.api_key = api_key
        self._session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_connection(self) -> Tuple[bool, str]:
        if not self.api_key:
            return False, "No API key configured. Set one in the Configuration tab."
        try:
            resp = self._session.get(
                f"{self.host}/v1/models", headers=self._headers(), timeout=8
            )
        except requests.exceptions.ConnectionError:
            return False, f"Could not connect to {self.host}."
        except requests.exceptions.Timeout:
            return False, f"Connection to {self.host} timed out."
        except requests.exceptions.RequestException as exc:
            return False, f"Connection error: {exc}"

        if resp.status_code == 401:
            return False, "Authentication failed - check your API key."
        if resp.status_code != 200:
            return False, f"API responded with HTTP {resp.status_code}."
        return True, f"Connected to {self.host}."

    def list_models(self) -> List[str]:
        try:
            resp = self._session.get(
                f"{self.host}/v1/models", headers=self._headers(), timeout=8
            )
            resp.raise_for_status()
            return [m.get("id", "") for m in resp.json().get("data", []) if m.get("id")]
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
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        start = time.monotonic()
        try:
            resp = self._session.post(
                f"{self.host}/v1/chat/completions",
                json=body,
                headers=self._headers(),
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError:
            return LLMResponse.error_response(
                self.model, f"Connection refused at {self.host}.",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except requests.exceptions.Timeout:
            return LLMResponse.error_response(
                self.model, f"Request timed out after {timeout}s.",
                latency_ms=(time.monotonic() - start) * 1000,
            )
        except requests.exceptions.RequestException as exc:
            return LLMResponse.error_response(
                self.model, f"Request error: {exc}",
                latency_ms=(time.monotonic() - start) * 1000,
            )

        latency_ms = (time.monotonic() - start) * 1000

        if resp.status_code == 401:
            return LLMResponse.error_response(
                self.model, "Authentication failed - check your API key.", latency_ms=latency_ms
            )
        if resp.status_code == 429:
            return LLMResponse.error_response(
                self.model, "Rate limited (HTTP 429). Slow down the request rate.",
                latency_ms=latency_ms,
            )
        if resp.status_code != 200:
            return LLMResponse.error_response(
                self.model, f"API returned HTTP {resp.status_code}: {resp.text[:200]}",
                latency_ms=latency_ms,
            )

        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError):
            return LLMResponse.error_response(
                self.model, "Could not parse the API response.", latency_ms=latency_ms
            )

        usage = data.get("usage", {})
        return LLMResponse(
            text=text or "",
            model=self.model,
            latency_ms=latency_ms,
            raw=data,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )

    def describe_target(self, model: str) -> str:
        return f"OpenAI-compatible API @ {model} [{self.host}]"
