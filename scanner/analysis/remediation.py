"""
scanner.analysis.remediation
===============================

Static remediation guidance, keyed by attack category. Kept separate
from analyzer.py so the advice text can be reviewed/edited on its own
(it's read by non-engineers too -- it ends up in the HTML report).
"""
from __future__ import annotations

from ..core.models import AttackCategory

_REMEDIATION_TEXT = {
    AttackCategory.PROMPT_EXTRACTION: (
        "Do not rely on the system prompt alone to keep secrets. Move anything "
        "truly sensitive (internal tool names, business logic, credentials) out "
        "of the prompt entirely and behind server-side logic the model can invoke "
        "but never see the internals of. Where the prompt itself must stay "
        "secret, add an explicit, high-priority refusal instruction for "
        "prompt-disclosure requests, and validate that refusal with an "
        "independent output classifier rather than trusting the base model's "
        "own judgment alone -- extraction techniques evolve faster than any "
        "single prompt-level defense."
    ),
    AttackCategory.PROMPT_INJECTION: (
        "Treat every piece of external content -- documents, emails, scraped "
        "webpages, API responses, user-generated text -- as data, never as "
        "instructions, no matter how it's phrased or formatted. Use a clear "
        "structural separation between instructions and data (explicit "
        "delimiters or a dedicated data channel the model is trained to never "
        "treat as directives), and add output-side monitoring that can catch "
        "anomalous responses (e.g. a response that is suspiciously short, or "
        "matches a known injection marker) before they reach a user or a "
        "downstream system."
    ),
    AttackCategory.GUARDRAIL_BYPASS: (
        "Do not rely solely on the base model's built-in safety training -- it "
        "is a single layer that well-known jailbreak patterns are specifically "
        "designed to slip past. Add an independent input/output moderation "
        "layer (a separate classifier call, not the same model being tested), "
        "pre-filter common obfuscation techniques (leetspeak normalization, "
        "base64/ROT13 decoding before scanning) rather than only scanning raw "
        "input text, and log + rate-limit conversations that show an escalation "
        "pattern across turns."
    ),
}

_GENERIC_REMEDIATION = (
    "Review this finding manually -- the automated heuristic flagged it, but "
    "heuristic-based detection can produce false positives. See README.md "
    "'Understanding Results' for how confidence scores are computed."
)


def get_remediation(category: AttackCategory) -> str:
    return _REMEDIATION_TEXT.get(category, _GENERIC_REMEDIATION)
