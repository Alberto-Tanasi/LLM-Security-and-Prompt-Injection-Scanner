"""
Tests for scanner.adapters.openai_adapter.

Same approach as test_ollama_adapter.py: HTTP calls are mocked, so
these tests run without a real OpenAI API key or any network access.
A fake key string is used purely to exercise the "Authorization
header gets set" code path -- it is never sent anywhere.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from scanner.adapters.openai_adapter import OpenAICompatibleAdapter

_FAKE_KEY = "sk-not-a-real-key-used-only-to-test-header-construction"


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
    def test_no_api_key_fails_fast_without_any_request(self):
        adapter = OpenAICompatibleAdapter(api_key="")
        with patch.object(adapter._session, "get") as mock_get:
            ok, message = adapter.test_connection()
        assert ok is False
        assert "no api key" in message.lower()
        mock_get.assert_not_called()

    def test_successful_connection(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        fake = _fake_response(200, {"data": [{"id": "gpt-4o-mini"}]})
        with patch.object(adapter._session, "get", return_value=fake) as mock_get:
            ok, message = adapter.test_connection()
        assert ok is True
        headers = mock_get.call_args[1]["headers"]
        assert headers["Authorization"] == f"Bearer {_FAKE_KEY}"

    def test_401_reports_auth_failure(self):
        adapter = OpenAICompatibleAdapter(api_key="bad-key")
        fake = _fake_response(401)
        with patch.object(adapter._session, "get", return_value=fake):
            ok, message = adapter.test_connection()
        assert ok is False
        assert "auth" in message.lower()

    def test_connection_error_handled_gracefully(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        with patch.object(adapter._session, "get", side_effect=requests.exceptions.ConnectionError()):
            ok, message = adapter.test_connection()
        assert ok is False


class TestGenerate:
    def test_request_body_matches_openai_chat_format(self):
        adapter = OpenAICompatibleAdapter(model="gpt-4o-mini", api_key=_FAKE_KEY)
        fake = _fake_response(200, {
            "choices": [{"message": {"content": "Hi there!"}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4},
        })
        with patch.object(adapter._session, "post", return_value=fake) as mock_post:
            adapter.generate(prompt="Hello", system_prompt="Be nice.", temperature=0.3, max_tokens=100)

        url = mock_post.call_args[0][0]
        kwargs = mock_post.call_args[1]
        assert url.endswith("/v1/chat/completions")
        body = kwargs["json"]
        assert body["messages"] == [
            {"role": "system", "content": "Be nice."},
            {"role": "user", "content": "Hello"},
        ]
        assert body["temperature"] == 0.3
        assert body["max_tokens"] == 100
        assert kwargs["headers"]["Authorization"] == f"Bearer {_FAKE_KEY}"

    def test_omits_system_message_when_none_given(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        fake = _fake_response(200, {"choices": [{"message": {"content": "hi"}}]})
        with patch.object(adapter._session, "post", return_value=fake) as mock_post:
            adapter.generate(prompt="Hello", system_prompt=None)
        body = mock_post.call_args[1]["json"]
        assert body["messages"] == [{"role": "user", "content": "Hello"}]

    def test_successful_response_parsed_correctly(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        fake = _fake_response(200, {
            "choices": [{"message": {"content": "42 is the answer."}}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 5},
        })
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is True
        assert result.text == "42 is the answer."
        assert result.prompt_tokens == 8
        assert result.completion_tokens == 5

    def test_401_returns_error_response(self):
        adapter = OpenAICompatibleAdapter(api_key="invalid")
        fake = _fake_response(401)
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "auth" in result.error.lower()

    def test_429_rate_limit_returns_error_response(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        fake = _fake_response(429)
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False
        assert "rate limited" in result.error.lower()

    def test_malformed_response_body_handled(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        fake = _fake_response(200, {"unexpected": "shape"})
        with patch.object(adapter._session, "post", return_value=fake):
            result = adapter.generate(prompt="test")
        assert result.success is False

    def test_never_raises_on_connection_error(self):
        adapter = OpenAICompatibleAdapter(api_key=_FAKE_KEY)
        with patch.object(adapter._session, "post", side_effect=requests.exceptions.ConnectionError()):
            result = adapter.generate(prompt="test")  # should not raise
        assert result.success is False
