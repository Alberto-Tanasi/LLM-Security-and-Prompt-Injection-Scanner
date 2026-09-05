"""
Tests for scanner.adapters.ollama_adapter.

Every test here mocks ``requests.Session.get``/``.post`` directly, so
none of them need a live Ollama server running, any network access, or
any API key (Ollama doesn't use one anyway -- it's a local server).
This is deliberate: it lets the adapter's request-building and
response-parsing logic be verified in CI, in this sandbox, or on any
machine, regardless of whether Ollama happens to be installed there.

See README.md > "Testing Without an API Key or Local LLM" for the
broader picture of how the whole project was validated this way.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from scanner.adapters.ollama_adapter import OllamaAdapter


def _fake_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


class TestConnection:
    def test_successful_connection_with_models(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        fake = _fake_response(200, {"models": [{"name": "llama3.2"}, {"name": "mistral"}]})
        with patch.object(adapter._session, "get", return_value=fake) as mock_get:
            ok, message = adapter.test_connection()
        assert ok is True
        assert "2 model(s)" in message
        mock_get.assert_called_once()
        assert "/api/tags" in mock_get.call_args[0][0]

    def test_connection_refused(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        with patch.object(adapter._session, "get", side_effect=requests.exceptions.ConnectionError()):
            ok, message = adapter.test_connection()
        assert ok is False
        assert "ollama serve" in message.lower()

    def test_connection_timeout(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        with patch.object(adapter._session, "get", side_effect=requests.exceptions.Timeout()):
            ok, message = adapter.test_connection()
        assert ok is False
        assert "timed out" in message.lower()

    def test_connected_but_no_models_pulled(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        fake = _fake_response(200, {"models": []})
        with patch.object(adapter._session, "get", return_value=fake):
            ok, message = adapter.test_connection()
        assert ok is True
        assert "ollama pull" in message.lower()

    def test_connected_but_requested_model_not_pulled(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="phi3")
        fake = _fake_response(200, {"models": [{"name": "llama3.2"}]})
        with patch.object(adapter._session, "get", return_value=fake):
            ok, message = adapter.test_connection()
        assert ok is True
        assert "phi3" in message
        assert "not in the pulled model list" in message

    def test_non_200_status(self):
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        fake = _fake_response(500)
        with patch.object(adapter._session, "get", return_value=fake):
            ok, message = adapter.test_connection()
        assert ok is False
        assert "500" in message


class TestListModels:
    def test_returns_model_names(self):
        adapter = OllamaAdapter()
        fake = _fake_response(200, {"models": [{"name": "llama3.2"}, {"name": "gemma3"}]})
        with patch.object(adapter._session, "get", return_value=fake):
            models = adapter.list_models()
        assert models == ["llama3.2", "gemma3"]

    def test_returns_empty_list_on_error_rather_than_raising(self):
        adapter = OllamaAdapter()
        with patch.object(adapter._session, "get", side_effect=requests.exceptions.ConnectionError()):
            models = adapter.list_models()
        assert models == []


class TestGenerate:
    def test_request_body_is_built_correctly(self):
        """Verifies the exact wire format sent to Ollama's /api/generate."""
        adapter = OllamaAdapter(host="http://localhost:11434", model="llama3.2")
        fake = _fake_response(200, {"response": "Hello!", "prompt_eval_count": 5, "eval_count": 2})
        with patch.object(adapter._session, "post", return_value=fake) as mock_post:
            adapter.generate(
                prompt="Hi there", system_prompt="You are a helpful bot.",
                temperature=0.55, max_tokens=256, timeout=30,
            )
        mock_post.assert_called_once()
        url, kwargs = mock_post.call_args[0][0], mock_post.call_args[1]
        assert url == "http://localhost:11434/api/generate"
        body = kwargs["json"]
        assert body["model"] == "llama3.2"
        assert body["prompt"] == "Hi there"
        assert body["system"] == "You are a helpful bot."
        assert body["stream"] is False
        assert body["options"]["temperature"] == 0.55
        assert body["options"]["num_predict"] == 256
        assert kwargs["timeout"] == 30

    def test_system_prompt_omitted_when_none(self):
        adapter = OllamaAdapter()
        fake = _fake_response(200, {"response": "hi"})
        with patch.object(adapter._session, "post", return_value=fake) as mock_post:
            adapter.generate(prompt="Hi", system_prompt=None)
        body = mock_post.call_args[1]["json"]
        assert "system" not in body

    def test_successful_generation_returns_parsed_response(self):
        adapter = OllamaAdapter(model="llama3.2")
        fake = _fake_response(200, {"response": "The answer is 42.", "prompt_eval_count": 10, "eval_count": 6})
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="What is the answer?")
        assert result.success is True
        assert result.text == "The answer is 42."
        assert result.prompt_tokens == 10
        assert result.completion_tokens == 6
        assert result.latency_ms >= 0

    def test_connection_refused_returns_error_response_not_exception(self):
        adapter = OllamaAdapter()
        with patch.object(adapter._session, "post", side_effect=requests.exceptions.ConnectionError()):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "ollama" in result.error.lower() or "connection" in result.error.lower()

    def test_timeout_returns_error_response(self):
        adapter = OllamaAdapter()
        with patch.object(adapter._session, "post", side_effect=requests.exceptions.Timeout()):
            result = adapter.generate(prompt="test", timeout=15)
        assert result.success is False
        assert "15s" in result.error

    def test_model_not_found_404(self):
        adapter = OllamaAdapter(model="nonexistent-model")
        fake = _fake_response(404)
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "nonexistent-model" in result.error
        assert "pull" in result.error.lower()

    def test_non_200_status_returns_error(self):
        adapter = OllamaAdapter()
        fake = _fake_response(500, text="internal server error")
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "500" in result.error

    def test_malformed_json_response_returns_error(self):
        adapter = OllamaAdapter()
        fake = _fake_response(200, json_data=None)  # .json() will raise ValueError
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "non-json" in result.error.lower()

    def test_never_raises_on_any_failure_mode(self):
        """The engine depends on generate() never raising -- a raised
        exception mid-scan would kill the whole run instead of just
        marking one test as failed."""
        adapter = OllamaAdapter()
        failure_modes = [
            requests.exceptions.ConnectionError(),
            requests.exceptions.Timeout(),
            requests.exceptions.RequestException("generic failure"),
        ]
        for exc in failure_modes:
            with patch.object(adapter._session, "post", side_effect=exc):
                result = adapter.generate(prompt="test")  # should not raise
            assert result.success is False


class TestDescribeTarget:
    def test_includes_host_and_model(self):
        adapter = OllamaAdapter(host="http://localhost:11434")
        description = adapter.describe_target("llama3.2")
        assert "llama3.2" in description
        assert "11434" in description
        assert "local" in description.lower()
