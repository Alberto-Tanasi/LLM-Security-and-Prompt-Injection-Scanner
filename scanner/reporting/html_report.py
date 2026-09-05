"""
scanner.reporting.html_report
================================

Generates a single, self-contained HTML file (inline CSS, no CDN or
JS framework dependency) suitable for opening directly in a browser,
attaching to an email, or dropping into a portfolio.

Security note, since this is a *security* tool: response text
returned by the target model is untrusted input as far as this report
is concerned -- a successful prompt-injection payload could easily
contain HTML/script content. Every piece of dynamic text is passed
through ``html.escape()`` before being embedded, so a vulnerable
response can't turn into a stored-XSS payload against whoever opens
the report next. This is exactly the kind of "treat model output as
untrusted downstream" discipline the injection payloads in this
scanner are testing the *target* model's application layer for --
this report generator holds itself to the same standard.
"""
from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Union

from ..core.models import ScanConfig, ScanSummary, Severity, TestResult

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.SAFE]


def _esc(text: str) -> str:
    return html_lib.escape(str(text), quote=True)


def _severity_badge(sev: Severity) -> str:
    return (
        f'<span class="badge" style="background:{sev.color}22;color:{sev.color};'
        f'border:1px solid {sev.color}66;">{_esc(sev.value)}</span>'
    )


def _bar_chart_rows(summary: ScanSummary) -> str:
    max_count = max(summary.by_severity.values(), default=1)
    rows = []
    for sev in _SEVERITY_ORDER:
        count = summary.by_severity.get(sev.value, 0)
        if count == 0:
            continue
        pct = int(round((count / max_count) * 100)) if max_count else 0
        rows.append(f"""
        <div class="bar-row">
          <span class="bar-label">{_esc(sev.value)}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{sev.color};"></div>
          </div>
          <span class="bar-count">{count}</span>
        </div>""")
    return "".join(rows)


def _category_rows(summary: ScanSummary) -> str:
    rows = []
    for cat, stats in summary.by_category.items():
        total = stats.get("total", 0)
        vuln = stats.get("vulnerable", 0)
        pct = int(round((vuln / total) * 100)) if total else 0
        rows.append(f"""
        <tr>
          <td>{_esc(cat)}</td>
          <td>{total}</td>
          <td class="{'vuln-cell' if vuln else ''}">{vuln}</td>
          <td>{total - vuln}</td>
          <td>{pct}%</td>
        </tr>""")
    return "".join(rows)


def _result_card(result: TestResult) -> str:
    sev = result.severity
    payload = result.payload
    open_attr = " open" if sev in (Severity.CRITICAL, Severity.HIGH) else ""
    matched = ", ".join(_esc(m) for m in result.matched_patterns) or "&mdash;"
    remediation_block = (
        f'<div class="remediation"><strong>Remediation:</strong> {_esc(result.remediation)}</div>'
        if result.remediation else ""
    )
    error_block = (
        f'<div class="error-note">Request error: {_esc(result.response.error)}</div>'
        if result.response and result.response.error else ""
    )
    latency = f"{result.response.latency_ms:.0f} ms" if result.response else "n/a"

    return f"""
    <details class="result-card sev-{sev.value.lower()}"{open_attr}>
      <summary>
        {_severity_badge(sev)}
        <span class="result-title">{_esc(payload.name if payload else 'Unknown')}</span>
        <span class="result-meta">{_esc(payload.technique if payload else '')} &middot; confidence {result.confidence:.0f}% &middot; {latency}</span>
      </summary>
      <div class="result-body">
        <p class="description">{_esc(payload.description if payload else '')}</p>
        <div class="io-grid">
          <div>
            <h4>Prompt Sent</h4>
            <pre>{_esc(result.prompt_sent)}</pre>
          </div>
          <div>
            <h4>Model Response</h4>
            <pre>{_esc(result.response_text) or '<em>(empty response)</em>'}</pre>
          </div>
        </div>
        {error_block}
        <div class="analysis">
          <h4>Analysis</h4>
          <p>{_esc(result.analysis_notes)}</p>
          <p><strong>Matched signals:</strong> {matched}</p>
          <p><strong>OWASP reference:</strong> {_esc(payload.owasp_ref if payload else '')}</p>
        </div>
        {remediation_block}
      </div>
    </details>"""


_CSS = """
:root {
  --bg: #0d1117; --surface: #161b22; --surface-2: #1c2128; --border: #30363d;
  --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
}
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--text); margin: 0; padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 32px 24px 80px; }
header.report-header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }
header.report-header h1 { margin: 0 0 6px; font-size: 1.7rem; }
header.report-header .subtitle { color: var(--text-dim); font-size: 0.95rem; }
.risk-banner {
  margin-top: 18px; padding: 16px 20px; border-radius: 10px; border: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; background: var(--surface);
}
.risk-banner .risk-score { font-size: 2.2rem; font-weight: 700; }
.risk-banner .risk-label { font-size: 0.9rem; letter-spacing: 0.04em; text-transform: uppercase; color: var(--text-dim); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 24px 0 30px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.card .value { font-size: 1.6rem; font-weight: 700; }
.card .label { color: var(--text-dim); font-size: 0.82rem; margin-top: 4px; }
section { margin-bottom: 32px; }
section h2 { font-size: 1.15rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px; }
.bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 0.88rem; }
.bar-label { width: 90px; color: var(--text-dim); flex-shrink: 0; }
.bar-track { flex: 1; background: var(--surface-2); border-radius: 4px; height: 14px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; }
.bar-count { width: 28px; text-align: right; color: var(--text-dim); flex-shrink: 0; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--text-dim); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }
td.vuln-cell { color: #f85149; font-weight: 600; }
.result-card {
  border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; background: var(--surface);
  overflow: hidden;
}
.result-card summary {
  cursor: pointer; padding: 12px 16px; display: flex; align-items: center; gap: 12px;
  list-style: none; flex-wrap: wrap;
}
.result-card summary::-webkit-details-marker { display: none; }
.result-title { font-weight: 600; }
.result-meta { color: var(--text-dim); font-size: 0.82rem; margin-left: auto; }
.badge { padding: 2px 9px; border-radius: 999px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em; }
.result-body { padding: 4px 16px 18px; border-top: 1px solid var(--border); }
.description { color: var(--text-dim); font-size: 0.88rem; margin: 12px 0; }
.io-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin: 14px 0; }
@media (max-width: 700px) { .io-grid { grid-template-columns: 1fr; } }
.io-grid h4, .analysis h4 { margin: 0 0 6px; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-dim); }
pre {
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
  font-size: 0.82rem; white-space: pre-wrap; word-break: break-word; max-height: 260px; overflow-y: auto; margin: 0;
}
.analysis { font-size: 0.88rem; }
.analysis p { margin: 6px 0; }
.remediation { margin-top: 12px; font-size: 0.85rem; background: #1f2937; border-left: 3px solid var(--accent); padding: 10px 12px; border-radius: 0 6px 6px 0; }
.error-note { margin-top: 10px; font-size: 0.85rem; color: #ff8c42; }
footer { color: var(--text-dim); font-size: 0.78rem; border-top: 1px solid var(--border); padding-top: 16px; margin-top: 40px; }
footer a { color: var(--accent); }
"""


def generate_html_report(
    results: List[TestResult],
    summary: ScanSummary,
    config: ScanConfig,
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target_desc = (
        "Demo mode (no live model)" if config.backend == "mock"
        else f"{config.backend} @ {_esc(config.model)} ({_esc(config.host)})"
    )

    sorted_results = sorted(results, key=lambda r: (-r.severity.rank, r.payload.id if r.payload else ""))
    result_cards = "".join(_result_card(r) for r in sorted_results)

    risk_score = summary.risk_score
    risk_color = (
        "#f85149" if risk_score >= 60 else
        "#ff8c42" if risk_score >= 35 else
        "#d29922" if risk_score >= 15 else
        "#3fb950"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Security Scan Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="report-header">
    <h1>LLM Security &amp; Prompt Injection Scan Report</h1>
    <div class="subtitle">Target: {target_desc} &middot; Generated {generated_at}</div>
    <div class="risk-banner">
      <div>
        <div class="risk-label">Overall Risk</div>
        <div class="risk-score" style="color:{risk_color};">{risk_score:.0f}<span style="font-size:1rem;color:var(--text-dim);">/100</span></div>
      </div>
      <div style="text-align:right;">
        <div class="risk-label">{_esc(summary.risk_label)}</div>
        <div style="color:var(--text-dim);font-size:0.85rem;">{summary.vulnerabilities_found} of {summary.total_tests} tests flagged vulnerable</div>
      </div>
    </div>
  </header>

  <div class="cards">
    <div class="card"><div class="value">{summary.total_tests}</div><div class="label">Total Tests Run</div></div>
    <div class="card"><div class="value" style="color:#f85149;">{summary.vulnerabilities_found}</div><div class="label">Vulnerabilities Found</div></div>
    <div class="card"><div class="value">{summary.duration_seconds:.0f}s</div><div class="label">Scan Duration</div></div>
    <div class="card"><div class="value">{summary.average_latency_ms:.0f}ms</div><div class="label">Avg. Response Latency</div></div>
  </div>

  <section>
    <h2>Severity Distribution</h2>
    {_bar_chart_rows(summary)}
  </section>

  <section>
    <h2>Results by Category</h2>
    <table>
      <thead><tr><th>Category</th><th>Total</th><th>Vulnerable</th><th>Safe</th><th>Hit Rate</th></tr></thead>
      <tbody>{_category_rows(summary)}</tbody>
    </table>
  </section>

  <section>
    <h2>Detailed Findings</h2>
    <p style="color:var(--text-dim);font-size:0.85rem;margin-top:-6px;">
      Sorted by severity. Critical/High findings are expanded by default &mdash; click any row to expand or collapse.
    </p>
    {result_cards}
  </section>

  <footer>
    Generated by the LLM Security &amp; Prompt Injection Scanner (open-source portfolio project).
    Category mappings reference the <strong>OWASP Top 10 for LLM Applications (2026)</strong>.
    Detection is heuristic/pattern-based &mdash; treat findings as a starting point for manual review,
    not a certified audit. See the project README for methodology and limitations.
  </footer>
</div>
</body>
</html>"""


def write_html_report(
    results: List[TestResult],
    summary: ScanSummary,
    config: ScanConfig,
    path: Union[str, Path],
) -> Path:
    html_content = generate_html_report(results, summary, config)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return target
