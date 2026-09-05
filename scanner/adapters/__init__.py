"""
LLM backend adapters.

Every adapter implements ``BaseLLMAdapter`` and returns a normalized
``scanner.core.models.LLMResponse``, which is what lets the rest of the
framework (payload engine, analyzer, GUI, CLI) stay completely
backend-agnostic. Add a new backend by subclassing ``BaseLLMAdapter``
and registering it in ``get_adapter``.
"""
from .base import BaseLLMAdapter
from .ollama_adapter import OllamaAdapter
from .openai_adapter import OpenAICompatibleAdapter
from .mock_adapter import MockAdapter


def get_adapter(backend: str, **kwargs) -> BaseLLMAdapter:
    """Factory function used by both the GUI and CLI to build the right adapter.

    Parameters
    ----------
    backend:
        One of ``"ollama"``, ``"openai"``, or ``"mock"``.
    **kwargs:
        Forwarded to the adapter's constructor (host, model, api_key, ...).
    """
    backend = backend.lower().strip()
    if backend == "ollama":
        return OllamaAdapter(**kwargs)
    if backend in ("openai", "openai-compatible", "openai_compatible"):
        return OpenAICompatibleAdapter(**kwargs)
    if backend in ("mock", "demo"):
        return MockAdapter(**kwargs)
    raise ValueError(
        f"Unknown backend '{backend}'. Expected one of: ollama, openai, mock."
    )


__all__ = [
    "BaseLLMAdapter",
    "OllamaAdapter",
    "OpenAICompatibleAdapter",
    "MockAdapter",
    "get_adapter",
]
