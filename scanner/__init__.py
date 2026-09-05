"""
LLM Security & Prompt Injection Scanner
=========================================

A red-teaming automation framework for locally-hosted and API-based
Large Language Models. Tests for system prompt / hidden-context
extraction, indirect prompt injection, and guardrail (jailbreak) bypasses.

This package is the reusable "core" that both the GUI (scanner.gui)
and the CLI (scanner.cli) are built on top of, so both front-ends stay
in sync and share identical detection logic.

Author's note: this tool is intended for authorized security testing
of models and systems you own or have explicit permission to test.
See README.md, section "Responsible Use", before pointing it at
anything you do not control.
"""

__version__ = "1.0.0"
__author__ = "Portfolio Security Project"
