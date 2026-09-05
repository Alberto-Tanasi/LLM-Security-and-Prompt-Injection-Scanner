"""
scanner.core.config
=====================

Small helper module for persisting a ``ScanConfig`` to and from disk as
JSON. This is what powers the GUI's "Save Configuration" / "Load
Configuration" buttons, and lets the CLI accept a ``--config`` file
instead of a long list of flags.

Deliberately does not persist ``api_key`` — secrets should live in an
environment variable (``OPENAI_API_KEY`` / ``SCANNER_API_KEY``) rather
than a config file that might end up committed to git.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .models import ScanConfig

DEFAULT_CONFIG_PATH = Path.home() / ".llm_security_scanner" / "config.json"


def ensure_config_dir(path: Path = DEFAULT_CONFIG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def save_config(config: ScanConfig, path: Optional[Path] = None) -> Path:
    """Write ``config`` to disk as pretty-printed JSON and return the path used."""
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    ensure_config_dir(target)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(config.to_dict(), fh, indent=2, ensure_ascii=False)
    return target


def load_config(path: Optional[Path] = None) -> ScanConfig:
    """Load a ``ScanConfig`` from disk, falling back to defaults if missing/corrupt."""
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    if not target.exists():
        return ScanConfig()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return ScanConfig.from_dict(data)
    except (json.JSONDecodeError, OSError, TypeError):
        # A corrupt or unreadable config file should never crash the
        # app on startup -- just fall back to sane defaults.
        return ScanConfig()


def resolve_api_key(env_vars: Optional[list] = None) -> str:
    """Look up an API key from common environment variable names.

    Checked in order; the first one that is set (and non-empty) wins.
    """
    candidates = env_vars or ["SCANNER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    for name in candidates:
        value = os.environ.get(name)
        if value:
            return value
    return ""
