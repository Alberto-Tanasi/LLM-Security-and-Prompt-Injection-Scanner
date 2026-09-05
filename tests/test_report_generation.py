"""Tests for scanner.reporting -- both the JSON and HTML report generators."""
from __future__ import annotations

import json

from scanner.core.models import AttackCategory, LLMResponse, Payload, ScanConfig, ScanSummary, Severity, TestResult
from scanner.reporting.html_report import generate_html_report
from scanner.reporting.json_report import generate_json_report


def _make_result(vulnerable=True, severity=Severity.CRITICAL, response_text="leaked data",
                  category=AttackCategory.PROMPT_EXTRACTION):
    payload = Payload(id="p1", name="Test Payload", category=category, technique="Direct Elicitation",
                       description="desc", prompt_template="prompt text", owasp_ref="LLM08:2026")
    response = LLMResponse(text=response_text, model="test-model", latency_ms=250.0)
    return TestResult(payload=payload, response=response, vulnerable=vulnerable, confidence=85.0,
                       severity=severity, matched_patterns=["canary: 'test'"],
                       analysis_notes="Test analysis notes.", remediation="Test remediation advice.")


class TestJSONReport:
    def test_report_is_valid_json_serializable(self):
        results = [_make_result()]
        summary = ScanSummary.from_results(results, model_tested="llama3.2", backend="ollama")
        config = ScanConfig()
        report = generate_json_report(results, summary, config)
        # Should not raise -- this is the actual round-trip a downstream tool would do.
        serialized = json.dumps(report)
        reparsed = json.loads(serialized)
        assert reparsed["schema_version"] == 1

    def test_report_contains_target_and_summary(self):
        results = [_make_result()]
        summary = ScanSummary.from_results(results, model_tested="llama3.2", backend="ollama")
        config = ScanConfig(model="llama3.2", host="http://localhost:11434")
        report = generate_json_report(results, summary, config)
        assert report["target"]["model"] == "llama3.2"
        assert report["summary"]["total_tests"] == 1
        assert len(report["results"]) == 1

    def test_mock_backend_does_not_leak_host_field(self):
        config = ScanConfig(backend="mock")
        report = generate_json_report([], ScanSummary.from_results([]), config)
        assert report["target"]["host"] == "n/a (demo mode)"


class TestHTMLReport:
    def test_report_is_well_formed_html(self):
        results = [_make_result()]
        summary = ScanSummary.from_results(results, model_tested="llama3.2", backend="ollama")
        html = generate_html_report(results, summary, ScanConfig())
        assert html.strip().startswith("<!DOCTYPE html>")
        assert html.count("<details") == html.count("</details>")
        assert "</html>" in html

    def test_critical_and_high_findings_expanded_by_default(self):
        results = [_make_result(severity=Severity.CRITICAL), _make_result(severity=Severity.LOW, vulnerable=False)]
        summary = ScanSummary.from_results(results)
        html = generate_html_report(results, summary, ScanConfig())
        # Critical should have the `open` attribute, Low should not.
        assert '<details class="result-card sev-critical" open>' in html
        assert '<details class="result-card sev-low">' in html

    def test_response_text_is_html_escaped_to_prevent_xss(self):
        """Security-critical: a model response containing script-like content
        must never execute when the report is opened in a browser. This is
        exactly the kind of untrusted-downstream-content discipline the
        scanner's own injection payloads are testing the *target* model for.

        The correct property to check is "no LIVE, browser-parseable tag
        exists in the output" -- i.e. no unescaped '<script' or '<img '.
        html.escape() neutralizes tags by escaping angle brackets, which
        means substrings like 'onerror=alert' can still appear *as inert
        text* (e.g. inside '&lt;img ... &gt;') without that constituting a
        vulnerability; asserting their total absence would be checking the
        wrong thing entirely.
        """
        malicious_text = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
        results = [_make_result(response_text=malicious_text)]
        summary = ScanSummary.from_results(results)
        html = generate_html_report(results, summary, ScanConfig())

        # No live, browser-parseable tag should exist anywhere in the output.
        assert "<script>" not in html
        assert "<script " not in html
        assert "<img " not in html
        assert "<img>" not in html

        # The escaped form should be present instead (rendered as inert,
        # visible text rather than a live element).
        assert "&lt;script&gt;" in html
        assert "&lt;img" in html

    def test_empty_results_does_not_crash(self):
        summary = ScanSummary.from_results([])
        html = generate_html_report([], summary, ScanConfig())
        assert "<!DOCTYPE html>" in html

    def test_severity_bar_chart_omits_zero_count_severities(self):
        results = [_make_result(severity=Severity.CRITICAL)]
        summary = ScanSummary.from_results(results)
        html = generate_html_report(results, summary, ScanConfig())
        # LOW had zero occurrences and should not appear as a bar row label.
        assert 'class="bar-label">LOW<' not in html
        assert 'class="bar-label">CRITICAL<' in html

    def test_owasp_reference_appears_in_output(self):
        results = [_make_result()]
        summary = ScanSummary.from_results(results)
        html = generate_html_report(results, summary, ScanConfig())
        assert "LLM08:2026" in html
