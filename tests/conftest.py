"""
tests.conftest
================

Shared fixtures. Kept deliberately small: most tests build their own
tiny, purpose-specific objects (a two-line ``Payload``, a one-line
``LLMResponse``) rather than routing everything through generic
fixtures, since that keeps each test's setup visible in the test
itself rather than hidden in a fixture file you have to go cross-
reference. The fixtures here are only for the handful of things that
are genuinely shared and non-trivial to construct.
"""
from __future__ import annotations

import pytest

from scanner.core.models import DEFAULT_CANARY_TOKENS, ScanConfig
from scanner.payloads.loader import load_payloads


@pytest.fixture(scope="session")
def all_payloads():
    """The real, shipped payload library (data/payloads.json), loaded once per test session."""
    return load_payloads()


@pytest.fixture
def default_canaries():
    return list(DEFAULT_CANARY_TOKENS)


@pytest.fixture
def mock_scan_config():
    return ScanConfig(backend="mock", model="demo-model", delay_between_requests=0.0)
