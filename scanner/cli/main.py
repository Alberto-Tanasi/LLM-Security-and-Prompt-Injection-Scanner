"""
scanner.cli.main
===================

Command-line front-end. Deliberately thin: every real decision (how a
response is scored, what an adapter does, how a report is built) lives
in scanner.core / scanner.analysis / scanner.reporting, exactly as it
does for the GUI. This file is just argument parsing, plain-ANSI
progress output, and wiring.

Run ``python run_cli.py --help`` for the full flag list, or see
README.md > "CLI Usage" for worked examples.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from ..adapters import get_adapter
from ..analysis.analyzer import ResponseAnalyzer
from ..core.config import load_config, resolve_api_key, save_config
from ..core.engine import EngineEvent, ScanEngine
from ..core.models import ScanConfig, ScanSummary, Severity
from ..payloads.loader import filter_payloads, load_payloads

# --- minimal ANSI color helpers (no external dependency) -------------------

class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;220m"
    GREEN = "\033[38;5;114m"
    BLUE = "\033[38;5;75m"
    GRAY = "\033[38;5;245m"


def _use_color(args: argparse.Namespace) -> bool:
    return (not args.no_color) and sys.stdout.isatty()


def _sev_color(sev: Severity) -> str:
    return {
        Severity.CRITICAL: _C.RED, Severity.HIGH: _C.ORANGE, Severity.MEDIUM: _C.YELLOW,
        Severity.LOW: _C.GREEN, Severity.INFO: _C.BLUE, Severity.SAFE: _C.GREEN,
    }.get(sev, _C.GRAY)


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{_C.RESET}" if enabled else text


BANNER = r"""
  _    _    __  __   ____                      _ _
 | |  | |  |  \/  | / ___|  ___  ___ _   _ _ __(_) |_ _   _
 | |  | |  | |\/| | \___ \ / _ \/ __| | | | '__| | __| | | |
 | |__| |__| |  | |  ___) |  __/ (__| |_| | |  | | |_| |_| |
 |_____|__|_|  |_| |____/ \___|\___|\__,_|_|  |_|\__|\__, |
      Scanner - LLM Security & Prompt Injection Tool  |___/
"""

DISCLAIMER = (
    "This tool sends adversarial test prompts to the target model you configure.\n"
    "Only use it against models/systems you own or have explicit authorization to test."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-scanner",
        description="Automated red-teaming CLI for local/API-based LLMs: system prompt "
                    "extraction, indirect prompt injection, and guardrail bypass testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python run_cli.py --backend ollama --model llama3.2\n"
               "  python run_cli.py --backend mock --output-html report.html\n"
               "  python run_cli.py --list-payloads\n"
               "  python run_cli.py --categories prompt_injection guardrail_bypass --output-json out.json\n",
    )
    p.add_argument("--backend", choices=["ollama", "openai", "mock"], default=None,
                    help="Target backend (default: from saved config, or 'ollama')")
    p.add_argument("--host", default=None, help="Backend host URL (default: http://localhost:11434 for ollama)")
    p.add_argument("--model", default=None, help="Model name to test (default: from saved config, or 'llama3.2')")
    p.add_argument("--api-key", default=None, help="API key for the openai backend (or set SCANNER_API_KEY env var)")
    p.add_argument("--system-prompt-file", type=Path, default=None,
                    help="Path to a text file containing the target system prompt to test against")
    p.add_argument("--categories", nargs="+",
                    choices=["prompt_extraction", "prompt_injection", "guardrail_bypass"],
                    default=None, help="Restrict the scan to specific categories (default: all)")
    p.add_argument("--payload-ids", nargs="+", default=None,
                    help="Restrict the scan to specific payload IDs (overrides --categories)")
    p.add_argument("--list-payloads", action="store_true", help="List all available payloads and exit")
    p.add_argument("--output-json", type=Path, default=None, help="Write a JSON report to this path")
    p.add_argument("--output-html", type=Path, default=None, help="Write an HTML report to this path")
    p.add_argument("--timeout", type=int, default=None, help="Per-request timeout in seconds (default: 60)")
    p.add_argument("--delay", type=float, default=None, help="Delay between requests in seconds (default: 0.4)")
    p.add_argument("--temperature", type=float, default=None, help="Sampling temperature (default: 0.7)")
    p.add_argument("--max-tokens", type=int, default=None, help="Max tokens per response (default: 512)")
    p.add_argument("--config", type=Path, default=None, help="Load a saved ScanConfig JSON file")
    p.add_argument("--save-config", type=Path, default=None, help="Save the resulting config to this path and exit")
    p.add_argument("--fail-on-risk", type=float, default=None,
                    help="Exit with status 1 if the final risk score (0-100) meets or exceeds this value; "
                         "useful as a CI/CD gate")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colored output")
    p.add_argument("--quiet", action="store_true", help="Only print the final summary, not per-test progress")
    return p


def _build_config(args: argparse.Namespace) -> ScanConfig:
    base = load_config(args.config) if args.config else load_config()

    if args.backend:
        base.backend = args.backend
    if args.host:
        base.host = args.host
    if args.model:
        base.model = args.model
    if args.timeout is not None:
        base.request_timeout = args.timeout
    if args.delay is not None:
        base.delay_between_requests = args.delay
    if args.temperature is not None:
        base.temperature = args.temperature
    if args.max_tokens is not None:
        base.max_tokens = args.max_tokens
    if args.system_prompt_file:
        base.target_system_prompt = args.system_prompt_file.read_text(encoding="utf-8")
    if args.categories:
        base.categories_enabled = {c: (c in args.categories) for c in
                                    ["prompt_extraction", "prompt_injection", "guardrail_bypass"]}
    if args.payload_ids:
        base.payload_ids_enabled = args.payload_ids

    if base.backend == "ollama" and (not args.host) and base.host.startswith("https://api.openai.com"):
        base.host = "http://localhost:11434"
    if not base.backend:
        base.backend = "ollama"
    if not base.model:
        base.model = "llama3.2"

    return base


def _print_list_payloads(color: bool) -> None:
    payloads = load_payloads()
    by_cat: dict = {}
    for p in payloads:
        by_cat.setdefault(p.category.value, []).append(p)
    for cat, items in by_cat.items():
        print(_paint(f"\n{cat} ({len(items)})", _C.BOLD, color))
        for p in items:
            sev = _paint(p.severity_if_successful.value, _sev_color(p.severity_if_successful), color)
            print(f"  {p.id:32} {p.name:42} [{sev}]")
            print(_paint(f"      {p.technique} - {p.owasp_ref}", _C.DIM, color))


def _print_progress(event: EngineEvent, color: bool, quiet: bool) -> None:
    if event.kind == "status":
        if not quiet:
            print(_paint(f"[{event.index:>2}/{event.total}] {event.message}", _C.GRAY, color))
        return
    if event.kind == "result" and event.result is not None:
        r = event.result
        sev_text = _paint(f"{r.severity.value:<8}", _sev_color(r.severity), color)
        vuln_marker = _paint("VULNERABLE", _C.RED, color) if r.vulnerable else _paint("safe", _C.GREEN, color)
        line = (
            f"  {sev_text} {r.payload.id:32} conf={r.confidence:5.1f}%  {vuln_marker}"
        )
        print(line)
        if not quiet and r.vulnerable:
            print(_paint(f"           -> {r.analysis_notes}", _C.DIM, color))


def _print_summary(summary: ScanSummary, color: bool) -> None:
    print()
    print(_paint("=" * 64, _C.GRAY, color))
    print(_paint("SCAN SUMMARY", _C.BOLD, color))
    print(_paint("=" * 64, _C.GRAY, color))
    print(f"  Model tested:        {summary.model_tested} ({summary.backend})")
    print(f"  Total tests:         {summary.total_tests}")
    print(f"  Vulnerabilities:     {summary.vulnerabilities_found}")
    print(f"  Duration:            {summary.duration_seconds:.1f}s")
    print(f"  Avg. latency:        {summary.average_latency_ms:.0f}ms")
    risk_color = (
        _C.RED if summary.risk_score >= 60 else
        _C.ORANGE if summary.risk_score >= 35 else
        _C.YELLOW if summary.risk_score >= 15 else _C.GREEN
    )
    print(f"  Risk score:          {_paint(f'{summary.risk_score:.0f}/100 - {summary.risk_label}', risk_color, color)}")
    print()
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = summary.by_severity.get(sev.value, 0)
        if count:
            print(f"    {_paint(sev.value, _sev_color(sev), color):<18} {count}")
    print(_paint("=" * 64, _C.GRAY, color))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    color = _use_color(args)

    if args.list_payloads:
        _print_list_payloads(color)
        return 0

    print(_paint(BANNER, _C.BLUE, color))
    print(_paint(DISCLAIMER, _C.DIM, color))
    print()

    config = _build_config(args)

    if args.save_config:
        path = save_config(config, args.save_config)
        print(f"Configuration saved to {path}")
        return 0

    if config.backend == "openai":
        config.api_key = args.api_key or resolve_api_key()
        if not config.api_key:
            print(_paint(
                "No API key found. Pass --api-key or set SCANNER_API_KEY / OPENAI_API_KEY.",
                _C.RED, color,
            ))
            return 2

    try:
        adapter = get_adapter(config.backend, host=config.host, model=config.model, api_key=config.api_key)
    except ValueError as exc:
        print(_paint(str(exc), _C.RED, color))
        return 2

    ok, message = adapter.test_connection()
    status_color = _C.GREEN if ok else _C.RED
    print(f"Connection check: {_paint(message, status_color, color)}")
    if not ok:
        return 2
    print(f"Target: {adapter.describe_target(config.model)}")
    print()

    all_payloads = load_payloads()
    payloads = filter_payloads(all_payloads, config.categories_enabled, config.payload_ids_enabled)
    if not payloads:
        print(_paint("No payloads selected (check --categories / --payload-ids).", _C.RED, color))
        return 2
    print(_paint(f"Running {len(payloads)} of {len(all_payloads)} available payloads...\n", _C.BOLD, color))

    engine = ScanEngine(adapter, config, ResponseAnalyzer())
    results = []
    start = time.time()
    for event in engine.run_iter(payloads):
        _print_progress(event, color, args.quiet)
        if event.kind == "result" and event.result is not None:
            results.append(event.result)
    end = time.time()

    summary = ScanSummary.from_results(results, model_tested=config.model, backend=config.backend,
                                        start_time=start, end_time=end)
    _print_summary(summary, color)

    if args.output_json:
        from ..reporting import write_json_report
        path = write_json_report(results, summary, config, args.output_json)
        print(f"\nJSON report written to: {path}")
    if args.output_html:
        from ..reporting import write_html_report
        path = write_html_report(results, summary, config, args.output_html)
        print(f"HTML report written to: {path}")

    if args.fail_on_risk is not None and summary.risk_score >= args.fail_on_risk:
        print(_paint(
            f"\nRisk score {summary.risk_score:.0f} meets or exceeds --fail-on-risk "
            f"threshold {args.fail_on_risk:.0f} -- exiting with status 1.", _C.RED, color,
        ))
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
