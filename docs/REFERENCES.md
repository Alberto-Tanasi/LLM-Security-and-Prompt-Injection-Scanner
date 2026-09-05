# References & Standards Mapping

## OWASP Top 10 for LLM Applications

This project maps its three attack categories to the **OWASP Top 10 for LLM
Applications, 2026 edition** (published August 2026, superseding the 2025
edition). The 2026 edition reordered and renamed several categories
relative to 2025 — most relevantly for this project, **"LLM07:2025 System
Prompt Leakage" was renamed to "LLM08:2026 Hidden Context Exposure"** and
moved down the list, while Excessive Agency moved up from 6th to 3rd and
Improper Output Handling moved from 5th to 10th. If you're cross-
referencing against older tooling or write-ups that use 2025 numbering,
that rename is the one most likely to cause confusion.

**OWASP Top 10 for LLM Applications (2026):**

| Rank | Category |
|---|---|
| LLM01:2026 | Prompt Injection |
| LLM02:2026 | Sensitive Information Disclosure |
| LLM03:2026 | Excessive Agency |
| LLM04:2026 | Supply Chain |
| LLM05:2026 | Data and Model Poisoning |
| LLM06:2026 | Unbounded Consumption |
| LLM07:2026 | Misinformation |
| LLM08:2026 | Hidden Context Exposure |
| LLM09:2026 | Vector and Embedding Weaknesses |
| LLM10:2026 | Improper Output Handling |

### This project's mapping

| Scanner category | Primary OWASP reference | Rationale |
|---|---|---|
| System Prompt Extraction | **LLM08:2026** Hidden Context Exposure | Direct match — this category is specifically about a system prompt or other hidden context being exposed to the user. |
| Indirect Prompt Injection | **LLM01:2026** Prompt Injection | OWASP's Prompt Injection category explicitly covers both direct (user types it) and indirect (embedded in external content the model processes) variants; every payload in this scanner's injection category is the indirect subtype. |
| Guardrail Bypass | **LLM01:2026** Prompt Injection | Jailbreak techniques are classified under Prompt Injection in OWASP's taxonomy (the "direct" subtype, as opposed to indirect/data-borne injection above). |

Secondary/related mappings worth knowing about: a successful extraction
finding also touches **LLM02:2026 Sensitive Information Disclosure** if the
leaked system prompt contains genuinely sensitive business data (as the
shipped SecureBank example is designed to demonstrate). A successful
guardrail bypass that reaches a downstream system unfiltered also touches
**LLM10:2026 Improper Output Handling**.

## MITRE ATLAS

[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for
Artificial-Intelligence Systems) is a complementary, more granular
framework cataloguing adversary tactics and techniques against AI systems,
modeled on the structure of MITRE ATT&CK. It's referenced here as a
pointer for further reading rather than mapped payload-by-payload in this
codebase, since ATLAS technique IDs are more granular and update more
frequently than this project's category-level mapping would track well —
check the live ATLAS matrix directly if you need current technique IDs
for a specific payload.

## Related Open-Source Tooling

- **[garak](https://github.com/NVIDIA/garak)** — NVIDIA's open-source LLM
  vulnerability scanner, described in its own documentation as "like
  `nmap` for large language models." CLI-first, `pip install garak`,
  organized around a large library of *probe* modules (attack generators)
  paired with *detector* modules (response classifiers), covering
  jailbreaks, toxicity generation, data leakage, encoding-based attacks,
  hallucination, and more.
- **[PyRIT](https://github.com/Azure/PyRIT)** — Microsoft's Python Risk
  Identification Toolkit for generative AI, an orchestration framework
  built around automating multi-turn adversarial conversations (an
  attacker model generates adversarial prompts, a target model responds,
  and a judge model scores the exchange), with state persisted for
  analysis across a run.

This project deliberately occupies a different niche than either: it
trades broad probe-count coverage (garak has dozens of probe modules; this
project has 25, chosen for a specific 3-category scope) and orchestrated
multi-turn automation (PyRIT's core strength) for a polished, real-time
GUI experience purpose-built around local Ollama testing — closer to "a
focused, visual first tool for someone learning this space" than "a
comprehensive scanner for a security team's existing pipeline." If you
need the latter, garak or PyRIT are the more mature choice; this project's
`BaseLLMAdapter` interface (see `scanner/adapters/base.py`) was written to
make it easy to graduate a payload or technique that works well here into
one of those tools' probe formats later.

## Academic Background

The guardrail-bypass techniques implemented here (persona-override
jailbreaks, fictional framing, encoding-based obfuscation, emotional
appeals, fake-privilege claims) are all long-documented, publicly known
patterns — not novel research. For deeper background on *why* these
categories of technique tend to work against RLHF-trained models, see:
Wei, Haghtalab & Steinhardt, ["Jailbroken: How Does LLM Safety Training
Fail?"](https://arxiv.org/abs/2307.02483) (2023), which frames the failure
modes as falling into "competing objectives" (the model is trained to be
both helpful and harmless, and a jailbreak exploits situations where those
pull in different directions) and "mismatched generalization" (safety
training doesn't generalize to inputs, like base64 or leetspeak, that look
different from anything in the safety-training data but decode to the
same underlying request).
