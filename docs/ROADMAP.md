# Roadmap

Ideas for expanding this project, roughly ordered by how much value they'd
add relative to effort. None of these are started; this is a plan, not a
changelog.

## Near-term

- **LLM-as-judge secondary pass for Guardrail Bypass.** This is the one
  category that can't use a canary-token approach (there's no unambiguous
  substring to check for "did it comply with a jailbreak"), so it's
  currently scored with a calibrated heuristic (see
  `scanner/analysis/heuristics.py` and the README's "Understanding
  Results" section). A secondary call to a separate judge model — "did
  the following response comply with a request it should have refused:
  {response}" — would move this category off pure pattern-matching and
  onto something closer to how PyRIT's judge-model pattern works. Would
  need a second adapter connection (the judge model shouldn't be the same
  model being tested) and a way to surface judge disagreement in the UI.
- **GitHub Action template.** The CLI's `--fail-on-risk` flag already
  supports CI/CD gating (see README Quick Start); a ready-to-use
  `.github/workflows/` template with sensible defaults (matrix over
  multiple models, PR comment with the risk score) would make adopting it
  a copy-paste operation instead of a DIY one.
- **Payload count expansion.** 25 was the deliberate starting scope so
  each one could be individually designed and hand-validated rather than
  templated out. Natural next additions: more indirect-injection carrier
  types (PDF metadata, image alt-text, RAG-retrieved chunks specifically),
  and a "second-order" extraction test that asks the model to reveal *tool
  definitions* rather than the system prompt text itself.

## Medium-term

- **True multi-turn payloads.** `gb_escalation_multiturn` currently
  approximates a multi-turn escalation by compressing it into a single
  prompt ("first agree that X, then explain Y given X"). A real multi-turn
  version — send turn 1, read the response, conditionally send turn 2
  based on whether turn 1 succeeded — would be more realistic and closer
  to how this technique is actually used, at the cost of needing
  conversation-state management the current single-shot engine doesn't
  have.
- **Scan diffing.** Given two JSON reports from the same model (e.g.
  before/after a system-prompt change), show what got better, what got
  worse, and what's unchanged. The JSON schema (`schema_version` field,
  stable payload `id`s) was designed with this in mind even though nothing
  consumes it that way yet.
- **Additional backends**: Anthropic's Messages API format and a generic
  "any HTTP endpoint + JSONPath response extraction" adapter for
  self-hosted inference servers that don't speak the OpenAI wire format.

## Long-term / exploratory

- **Adaptive payloads.** Rather than a fixed prompt template, a payload
  that uses the *previous* payload's response to decide its next move
  (e.g. if extraction attempt #1 got a partial leak, automatically try a
  follow-up that pushes on the specific gap). This is a meaningfully
  different engine design (stateful, feedback-driven) rather than an
  incremental change to the current one (stateless, one-shot per
  payload), so it's marked exploratory rather than planned.
- **Severity calibration against real-world incident data**, if a
  reasonable public dataset of actual prompt-injection incidents (with
  before/after fixes) becomes available to validate the risk-scoring
  weights against, rather than the current expert-judgment-based weights
  in `ScanSummary.risk_score`.
