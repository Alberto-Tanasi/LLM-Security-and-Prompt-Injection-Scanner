"""
scanner.reporting.json_report
================================

Structured JSON export. This is the format meant for machines: piping
into a CI/CD gate ("fail the build if risk_score > 40"), feeding a
dashboard, or diffing two scans of the same model to see whether a
patch actually closed a hole.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from ..core.models import ScanConfig, ScanSummary, TestResult

REPORT_SCHEMA_VERSION = 1


def generate_json_report(
    results: List[TestResult],
    summary: ScanSummary,
    config: ScanConfig,
) -> Dict[str, Any]:
    """Build the full JSON-serializable report structure (does not write to disk)."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "LLM Security & Prompt Injection Scanner",
        "target": {
            "backend": config.backend,
            "host": config.host if config.backend != "mock" else "n/a (demo mode)",
            "model": config.model,
        },
        "config": {
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "categories_enabled": config.categories_enabled,
            "canary_tokens_configured": len(config.canary_tokens),
        },
        "summary": summary.to_dict(),
        "results": [r.to_dict() for r in results],
    }


def write_json_report(
    results: List[TestResult],
    summary: ScanSummary,
    config: ScanConfig,
    path: Union[str, Path],
) -> Path:
    report = generate_json_report(results, summary, config)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return target
