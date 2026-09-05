"""
End-to-end integration tests for scanner.core.engine.ScanEngine, run
entirely against the built-in MockAdapter -- no network, no API key,
no live Ollama instance. This is the same mechanism used throughout
development to validate the full pipeline (adapter -> engine ->
analyzer -> summary) without external dependencies.
"""
from __future__ import annotations

import threading

from scanner.adapters.mock_adapter import MockAdapter
from scanner.core.engine import ScanEngine
from scanner.core.models import ScanSummary
from scanner.payloads.loader import load_payloads


class TestFullScanRun:
    def test_running_all_25_payloads_produces_25_results(self, mock_scan_config):
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        payloads = load_payloads()

        results = engine.run(payloads)

        assert len(results) == 25
        assert all(r.response is not None and r.response.success for r in results)

    def test_vulnerability_count_matches_expected_design(self, mock_scan_config):
        """See tests/test_analyzer.py::TestFullCalibrationAgainstMockDataset
        for the payload-by-payload breakdown this number comes from."""
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        results = engine.run(load_payloads())
        vulnerable = sum(1 for r in results if r.vulnerable)
        assert vulnerable == 13

    def test_summary_reflects_the_results(self, mock_scan_config):
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        results = engine.run(load_payloads())
        summary = ScanSummary.from_results(results, model_tested="demo-model", backend="mock")
        assert summary.total_tests == 25
        assert summary.vulnerabilities_found == 13
        assert 0 < summary.risk_score < 100

    def test_category_filter_reduces_result_count(self, mock_scan_config):
        from scanner.payloads.loader import filter_payloads
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        all_payloads = load_payloads()
        injection_only = filter_payloads(all_payloads, categories_enabled={
            "prompt_extraction": False, "prompt_injection": True, "guardrail_bypass": False,
        })
        results = engine.run(injection_only)
        assert len(results) == 8


class TestEventStream:
    def test_yields_status_and_result_events_in_order(self, mock_scan_config):
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        payloads = load_payloads()[:3]

        kinds = [event.kind for event in engine.run_iter(payloads)]

        assert kinds[0] == "status"  # "Starting scan..."
        assert kinds[-1] == "status"  # "Scan complete."
        assert kinds.count("result") == 3

    def test_stop_flag_halts_the_scan_early(self, mock_scan_config):
        adapter = MockAdapter(model="demo-model", seed=1)
        engine = ScanEngine(adapter, mock_scan_config)
        payloads = load_payloads()
        stop_flag = threading.Event()

        results = []
        for i, event in enumerate(engine.run_iter(payloads, stop_flag=stop_flag)):
            if event.kind == "result":
                results.append(event.result)
                if len(results) == 5:
                    stop_flag.set()

        assert len(results) == 5
        assert len(results) < len(payloads)


class TestMockAdapterItself:
    """The mock adapter is test infrastructure, but it has real logic
    (prompt->response lookup) worth verifying directly."""

    def test_unregistered_prompt_falls_back_to_generic_refusal(self):
        adapter = MockAdapter(model="demo-model")
        result = adapter.generate(prompt="some prompt nobody registered")
        assert result.success is True
        assert "anything else" in result.text.lower()

    def test_registered_payload_returns_its_specific_canned_response(self):
        adapter = MockAdapter(model="demo-model")
        payloads = load_payloads()
        adapter.register_payloads(payloads)

        injection_payload = next(p for p in payloads if p.id == "pi_email_summary")
        result = adapter.generate(prompt=injection_payload.render())

        assert result.text == "CONFIRMED-EMAIL-OVERRIDE"

    def test_connection_always_succeeds(self):
        adapter = MockAdapter()
        ok, message = adapter.test_connection()
        assert ok is True
