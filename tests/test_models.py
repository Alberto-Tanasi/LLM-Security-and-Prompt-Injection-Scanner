"""Unit tests for scanner.core.models -- no I/O, no network, pure logic."""
from __future__ import annotations

from scanner.core.models import (
    AttackCategory,
    LLMResponse,
    Payload,
    ScanSummary,
    Severity,
    TestResult,
)


class TestSeverity:
    def test_rank_ordering(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank
        assert Severity.INFO.rank > Severity.SAFE.rank

    def test_colors_are_distinct_and_valid_hex(self):
        colors = [s.color for s in Severity]
        assert len(colors) == len(set(colors)), "every severity should have a unique color"
        for c in colors:
            assert c.startswith("#") and len(c) == 7

    def test_from_string_case_insensitive(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL

    def test_from_string_unknown_falls_back_to_info(self):
        assert Severity.from_string("not_a_real_severity") == Severity.INFO


class TestAttackCategory:
    def test_short_key_roundtrip(self):
        for cat in AttackCategory:
            assert AttackCategory.from_key(cat.short_key) == cat

    def test_from_key_accepts_display_value_too(self):
        assert AttackCategory.from_key("System Prompt Extraction") == AttackCategory.PROMPT_EXTRACTION

    def test_owasp_ref_is_populated_for_every_category(self):
        for cat in AttackCategory:
            assert cat.owasp_ref, f"{cat} is missing an OWASP reference"


class TestPayload:
    def test_render_returns_prompt_template(self):
        p = Payload(
            id="test_1", name="Test", category=AttackCategory.GUARDRAIL_BYPASS,
            technique="t", description="d", prompt_template="hello world",
        )
        assert p.render() == "hello world"

    def test_to_dict_has_expected_keys(self):
        p = Payload(
            id="test_1", name="Test", category=AttackCategory.PROMPT_INJECTION,
            technique="t", description="d", prompt_template="x", canary_token="MARKER",
        )
        d = p.to_dict()
        assert d["id"] == "test_1"
        assert d["canary_token"] == "MARKER"
        assert d["category"] == "Indirect Prompt Injection"


class TestLLMResponse:
    def test_success_true_when_no_error(self):
        r = LLMResponse(text="hi", model="m", latency_ms=10.0)
        assert r.success is True

    def test_success_false_when_error_set(self):
        r = LLMResponse.error_response("m", "boom")
        assert r.success is False
        assert r.text == ""
        assert r.error == "boom"


class TestScanSummary:
    def _make_payload(self, category):
        return Payload(id="p", name="p", category=category, technique="t", description="d",
                        prompt_template="x")

    def _make_result(self, category, vulnerable, severity, latency=100.0):
        payload = self._make_payload(category)
        response = LLMResponse(text="r", model="m", latency_ms=latency)
        return TestResult(payload=payload, response=response, vulnerable=vulnerable, severity=severity)

    def test_empty_results_gives_zero_risk(self):
        summary = ScanSummary.from_results([])
        assert summary.total_tests == 0
        assert summary.risk_score == 0.0
        assert summary.risk_label == "MINIMAL RISK"

    def test_all_safe_gives_zero_risk(self):
        results = [self._make_result(AttackCategory.GUARDRAIL_BYPASS, False, Severity.SAFE) for _ in range(5)]
        summary = ScanSummary.from_results(results)
        assert summary.vulnerabilities_found == 0
        assert summary.risk_score == 0.0

    def test_all_critical_gives_max_risk(self):
        results = [self._make_result(AttackCategory.PROMPT_EXTRACTION, True, Severity.CRITICAL) for _ in range(5)]
        summary = ScanSummary.from_results(results)
        assert summary.risk_score == 100.0
        assert summary.risk_label == "CRITICAL RISK"

    def test_mixed_severity_risk_is_between_bounds(self):
        results = (
            [self._make_result(AttackCategory.PROMPT_EXTRACTION, True, Severity.CRITICAL)]
            + [self._make_result(AttackCategory.GUARDRAIL_BYPASS, False, Severity.SAFE) for _ in range(9)]
        )
        summary = ScanSummary.from_results(results)
        assert 0.0 < summary.risk_score < 100.0

    def test_by_category_breakdown(self):
        results = [
            self._make_result(AttackCategory.PROMPT_INJECTION, True, Severity.HIGH),
            self._make_result(AttackCategory.PROMPT_INJECTION, False, Severity.SAFE),
        ]
        summary = ScanSummary.from_results(results)
        bucket = summary.by_category["Indirect Prompt Injection"]
        assert bucket == {"total": 2, "vulnerable": 1, "safe": 1}

    def test_average_latency_computed_correctly(self):
        results = [self._make_result(AttackCategory.GUARDRAIL_BYPASS, False, Severity.SAFE, latency=100.0),
                   self._make_result(AttackCategory.GUARDRAIL_BYPASS, False, Severity.SAFE, latency=300.0)]
        summary = ScanSummary.from_results(results)
        assert summary.average_latency_ms == 200.0
