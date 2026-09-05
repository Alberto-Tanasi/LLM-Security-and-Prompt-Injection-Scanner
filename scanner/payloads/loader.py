"""
scanner.payloads.loader
==========================

Loads ``data/payloads.json`` into a list of ``Payload`` objects.

The payload *library* is intentionally kept as data (JSON) rather than
Python code: the whole point of the "test all of them, see which to
expand" workflow is that adding payload #26 should mean editing a JSON
array, not touching any importable module. This loader's job is to be
a strict gatekeeper for that file -- catching duplicate ids, missing
fields, or a wrong category name at load time (with a clear error)
rather than letting a typo silently produce a broken scan halfway
through a run.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.models import AttackCategory, Payload, Severity

# data/payloads.json lives two directories up from this file:
# scanner/payloads/loader.py -> scanner/payloads -> scanner -> <project root> -> data/
DEFAULT_PAYLOADS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "payloads.json"

_REQUIRED_FIELDS = {
    "id", "name", "category", "technique", "description", "prompt_template",
}


class PayloadValidationError(Exception):
    """Raised when data/payloads.json is missing, malformed, or fails validation."""


def _validate_raw(raw_payloads: List[Dict[str, Any]]) -> None:
    seen_ids = set()
    seen_canaries = set()
    for i, entry in enumerate(raw_payloads):
        missing = _REQUIRED_FIELDS - entry.keys()
        if missing:
            raise PayloadValidationError(
                f"Payload at index {i} is missing required field(s): {sorted(missing)}"
            )
        pid = entry["id"]
        if pid in seen_ids:
            raise PayloadValidationError(f"Duplicate payload id: '{pid}'")
        seen_ids.add(pid)

        try:
            AttackCategory.from_key(entry["category"])
        except ValueError as exc:
            raise PayloadValidationError(
                f"Payload '{pid}' has an unrecognized category: {entry['category']!r}"
            ) from exc

        sev = entry.get("severity_if_successful", "MEDIUM")
        if sev not in {s.value for s in Severity}:
            raise PayloadValidationError(
                f"Payload '{pid}' has an unrecognized severity: {sev!r}"
            )

        canary = entry.get("canary_token")
        if canary:
            if canary in seen_canaries:
                raise PayloadValidationError(
                    f"Payload '{pid}' reuses canary token '{canary}', which is already "
                    "used by another payload. Canary tokens must be unique so a match "
                    "unambiguously identifies which test succeeded."
                )
            seen_canaries.add(canary)

        if not entry["prompt_template"].strip():
            raise PayloadValidationError(f"Payload '{pid}' has an empty prompt_template.")


def _to_payload(entry: Dict[str, Any]) -> Payload:
    return Payload(
        id=entry["id"],
        name=entry["name"],
        category=AttackCategory.from_key(entry["category"]),
        technique=entry["technique"],
        description=entry["description"],
        prompt_template=entry["prompt_template"],
        severity_if_successful=Severity.from_string(entry.get("severity_if_successful", "MEDIUM")),
        canary_token=entry.get("canary_token"),
        owasp_ref=entry.get("owasp_ref", ""),
        references=list(entry.get("references", [])),
        tags=list(entry.get("tags", [])),
        notes=entry.get("notes", ""),
        enabled=True,
    )


def load_payloads(path: Optional[Path] = None, validate: bool = True) -> List[Payload]:
    """Load, validate, and return all payloads as ``Payload`` objects.

    Parameters
    ----------
    path:
        Override the default ``data/payloads.json`` location (mostly
        useful for tests, which point this at small fixture files).
    validate:
        Set False to skip validation (not recommended -- exists mainly
        so tests can exercise malformed fixtures deliberately).
    """
    target = Path(path) if path else DEFAULT_PAYLOADS_PATH
    if not target.exists():
        raise PayloadValidationError(f"Payload file not found: {target}")

    try:
        with open(target, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PayloadValidationError(f"payloads.json is not valid JSON: {exc}") from exc

    raw_payloads = data.get("payloads", [])
    if not raw_payloads:
        raise PayloadValidationError("payloads.json contains no payloads.")

    if validate:
        _validate_raw(raw_payloads)

    return [_to_payload(entry) for entry in raw_payloads]


def filter_payloads(
    payloads: List[Payload],
    categories_enabled: Optional[Dict[str, bool]] = None,
    payload_ids_enabled: Optional[List[str]] = None,
) -> List[Payload]:
    """Apply the GUI's category checkboxes and/or per-payload selection.

    ``payload_ids_enabled``, if given, takes precedence (it's an exact
    allow-list from the Payload Library tab). Otherwise falls back to
    filtering by category flags only.
    """
    if payload_ids_enabled is not None:
        allowed = set(payload_ids_enabled)
        return [p for p in payloads if p.id in allowed]

    if categories_enabled is None:
        return list(payloads)

    return [p for p in payloads if categories_enabled.get(p.category.short_key, True)]
