# UDM Triage Lab — AI SOC Analyst Triage Assistant

**An AI-assisted alert triage assistant for SOC analysts — hosted, free to try, and built so the analyst stays the trust boundary.**

## [▶ Open the app and start triaging](https://soc-analyst-ai-triage-assistant.streamlit.app/)

No install, no signup, no API key. Paste an alert, work through the triage. That's it.

<!-- SCREENSHOT placeholder: when docs/screenshot.png exists, add:
![UDM Triage Lab screenshot](docs/screenshot.png)
-->

---

## Why this exists

Alerts are singular events — a detection fires once, and the analyst's real question is always the same: **true positive or false positive?** Commercial platforms group alerts into "incidents" or "cases," but the grouping is mostly same-host / same-IP logic. There is little real intelligence connecting an alert to the attack it may be part of.

This lab explores a different approach, built on two convictions from years of SOC work:

1. **The analyst is the trust boundary.** AI can accelerate triage dramatically, but its output is a suggestion to be validated, never a verdict. The human gate is structurally enforced, not optional.
2. **Judgment should compound.** Analyst validations and TP/FP verdicts are the most valuable signal in a SOC. The long-term direction is a system that understands attack *patterns* — entities and relationships across alerts and time — not just weighted key-value pairs. Today that means a curated ontology and feedback capture; the roadmap points toward graph-based attack-path modeling.

This is a personal research project to understand how far AI-assisted triage can go and whether analysts actually find it helpful. It is independent — not affiliated with, or a product of, any employer.

## How to use it

1. **[Open the app](https://soc-analyst-ai-triage-assistant.streamlit.app/)**
2. **Paste an alert** — raw text or JSON from CrowdStrike, Defender, Sentinel, Splunk, or any other source. A test alert is fine; that's what the lab is for.
3. **Review the suggested UDM mapping** — the AI proposes normalized field mappings; you confirm, correct, or reject each one. Nothing proceeds without your validation.
4. **Work the enrichment** — ontology context per field, MITRE ATT&CK technique suggestions with their supporting evidence, and a deliberately cautious attack-path hypothesis that separates *observed* activity from *possible previous/next* steps.
5. **Use the hunt queries** — suggested validation queries to confirm or refute the hypothesis in your own environment.
6. **Read the AI triage assessment** — a structured TP/FP-oriented analysis you can accept, adjust, or reject.
7. **Optionally run CTI research** — web research on indicators, restricted by a safety layer that only releases indicator types safe to leave the boundary (public IPs, domains, hashes — never hostnames, usernames, or internal identifiers).
8. **Leave feedback** — your verdict and comments are what this project is actually for: understanding whether AI triage assistance is genuinely helpful to analysts.

## Your data — read this before pasting real alerts

Straight answers, SOC-analyst to SOC-analyst:

- **What happens to what you paste:** validated alert fields are sent to the Anthropic Claude API to generate the mapping, enrichment, and assessment — the same processing pattern as any AI assistant built into a SOC platform.
- **No model training:** your data is **not** used to train any AI model, by me or as part of this app's API usage.
- **What is stored:** nothing, except feedback you explicitly submit (verdict + comments), which is saved to the operator's private Google Sheet (readable only by the operator) — so don't put sensitive details in feedback text.
- **CTI egress control:** external research can only include indicator types explicitly marked safe (public IPs, domains, URLs, hashes, MITRE IDs). Hostnames, usernames, internal IPs, and paths are blocked by design.

**Working with real alerts? Pseudonymize before you paste.** In alert-stage triage, the personal data lives in a handful of field types. Rename them consistently before pasting (same placeholder for the same entity, so correlations survive):

| Replace | With |
|---|---|
| Hostnames (`DE-LT-4711`) | `HOST-A`, `HOST-B`, … |
| Usernames / emails (`m.mueller@…`) | `USER-1`, `USER-1@example.com`, … |
| Private/internal IPs (`10.x`, `192.168.x`) | `10.0.0.1`, `10.0.0.2`, … |
| File paths under user profiles (`C:\Users\mmueller\…`) | `C:\Users\USER-1\…` |

⚠️ **Then check the fields where these identifiers hide:** command lines, URLs, and free-text descriptions routinely embed usernames, personal paths, and hostnames inside them (`--user m.mueller`, `\\DE-LT-4711\share\…`). Sanitize those occurrences too — the labeled fields are not the only place PII lives.

Technique names, hashes, public IPs, domains, process names, timestamps, and detection metadata are what the triage actually needs — the analysis works exactly as well on pseudonymized alerts.

- **Should you paste work data at all?** That remains your organization's call. This is a personal research app, not an enterprise service with a data processing agreement — the same policy question your org already answered for ChatGPT applies here. The guidance above makes the question much easier to answer.

No analytics, no tracking, no ads.

## Under the hood

The code is open — read it, audit the data flows, open an issue:

```
raw alert ──▶ extractor ──▶ field inventory ──▶ AI UDM mapping ──▶ ANALYST GATE
                                                                       │
              ontology enrichment ◀── validated UDM bundle ◀───────────┘
                     │
                     ├──▶ MITRE ATT&CK mapping
                     ├──▶ attack-path hypothesis (observed vs. possible)
                     ├──▶ validation hunt queries
                     ├──▶ AI triage assessment ──▶ ANALYST VERDICT ──▶ feedback (Google Sheet)
                     └──▶ CTI-safe IOC research (filtered egress)
```

Stack: Streamlit · Anthropic Claude API (Haiku 4.5 — chosen deliberately: fast, affordable, and good enough to test the core question) · a curated SOC ontology (`triage/ontology.py`) carrying per-field meaning, investigative importance, analyst questions, and investigation pivots — the heart of the system.

This repo is the app's source, published for transparency. It's not packaged for self-hosting, though nothing stops you from reading or forking it under the license.

## Roadmap

- **PII pseudonymization at intake** — ontology-driven, consistent renaming of hostnames, usernames, private IPs, and personal paths *before* any AI processing, preserving cross-field correlations
- **Close the feedback loop** — analyst-confirmed cases as few-shot context for future triage
- **Ontology as single source of truth** for field governance (privacy sensitivity, CTI egress rules)
- **Graph-based attack modeling** — entities and relationships (user → host, process → process, process → domain) across alerts and time; from alert-centric to campaign-centric analysis
- **Evidence-coverage confidence** for MITRE technique mapping
- **Structured tool-use output** and **model routing** by confidence/severity

## Feedback

The feedback form inside the app is the preferred channel — it's the research signal this project exists to collect. Issues and discussions on this repo are welcome too.

## License

See [LICENSE](LICENSE).
