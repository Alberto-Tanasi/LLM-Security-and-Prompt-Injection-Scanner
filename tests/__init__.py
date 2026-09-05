"""
Test suite for the LLM Security & Prompt Injection Scanner.

None of these tests require a live Ollama instance, an OpenAI API key,
or any network access at all -- HTTP calls are mocked with
unittest.mock, and the analyzer/engine tests run against the built-in
MockAdapter's canned responses. See README.md > "Testing Without an
API Key or Local LLM" for the full explanation of how this works and
why it was designed this way.

Run with: pytest -v (from the project root)
"""
