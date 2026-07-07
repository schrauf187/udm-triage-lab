# UDM Triage Lab — Project Context

## What this is
An AI-assisted SOC alert triage and UDM-normalization MVP (Streamlit).
Pipeline: messy vendor alert (CrowdStrike / Defender / Sentinel / Splunk / etc.)
→ local flatten + field inventory → AI-suggested UDM mapping (analyst-validated)
→ ontology enrichment → MITRE ATT&CK mapping → cautious attack-path hypothesis
→ AI triage summary → platform-aware per-step evidence queries (on demand, per step)
→ optional CTI-safe IOC web research → analyst feedback capture.

**Core philosophy: the analyst is the trust boundary.** Every AI output is a
suggestion requiring human validation, never an automatic verdict.

## Status
MVP. Milestone 3 complete (guided input, auto extractor, feedback interface,
feedback DB, public admin mode). **Preparing a public alpha launch on LinkedIn
within days.** Repo is public. Hosted on Streamlit Community Cloud,
auto-deploys from `main`.

**Implemented since launch prep:** platform-aware per-step evidence queries — the
Next steps tab is now interactive: pick your SIEM/EDR and build a paste-ready
query/console guide per step on demand (one small AI call each, cached per
step+stack). This replaced the generic alert-centric hunts (`query_generator.py`
deprecated).

**Feedback now persists to Google Sheets** (not SQLite — Streamlit Cloud's disk is
ephemeral and wiped every redeploy). Operator setup: a GCP service account with the
Sheets API enabled, a private Sheet shared with the service-account email as Editor,
and two secrets in Streamlit Cloud — `[gcp_service_account]` (the JSON key's fields;
keep `private_key`'s `\n` sequences intact) and `FEEDBACK_SHEET_ID`. The app writes a
header row on first write to the empty sheet, then appends one row per submission.
New deps: `gspread`, `google-auth`.

## Stack
- Streamlit UI — single large `streamlit_app.py` (~3,400 lines)
- `triage/` package — the engine
- Anthropic Claude API — default `claude-haiku-4-5-20251001`; CTI and mapper
  models overridable via `CLAUDE_CTI_WEB_MODEL` / `CLAUDE_MAPPER_MODEL` secrets
- Package mgmt: `uv` (pyproject.toml + uv.lock). Streamlit Cloud reads `requirements.txt`.
- Secrets via `st.secrets`: `ANTHROPIC_API_KEY`, `ADMIN_PASSWORD` — **never commit secrets**

## Running locally
`.streamlit/secrets.toml` (gitignored) holds ANTHROPIC_API_KEY and optionally
ADMIN_PASSWORD (if unset, admin mode is disabled by design — keep that fail-closed
behavior). Run with `streamlit run streamlit_app.py`.

## Architecture map (triage/)
- `raw_extractor.py` — parse raw pasted alert (JSON / key-value / vendor text) into a
  flattened field inventory with per-field sensitivity
- `extractors.py` — flatten JSON, classify UDM fields, extract entities
- `ai_udm_mapper.py` — AI-suggested UDM field mappings (currently free-text JSON + AI repair fallback)
- `ontology.py` — **THE CROWN JEWEL.** Per-field metadata: meaning, importance,
  category, evidence_role, privacy_sensitivity, cti_allowed, cti_transformation,
  mitre_hints, analyst_questions, investigation_pivots. Protect and extend this.
- `mitre_mapper.py` / `mitre_knowledge.py` — MITRE ATT&CK technique mapping (keyword-based)
  and STIX knowledge loading. `mitre_knowledge.download_enterprise_attack()` can fetch
  the ATT&CK dataset on demand.
- `attack_path.py` — kill-chain hypothesis; separates observed / possible-previous /
  possible-next and deliberately does NOT over-claim (e.g. an IP ≠ confirmed C2).
  Currently substring matching over flattened values.
- `cti_safety.py` — filters which indicators may leave the boundary for external CTI research
- `query_generator.py` — **DEPRECATED (2026-07).** Generic alert-centric hunts removed from
  the UI (pseudo-hunts). Module retained pending attack-chain / graph-based hunting once
  cross-alert entity linking exists. Not currently wired in.
- `evidence_bundle.py` / `input_builder.py` — assemble the final analyst-approved UDM bundle
- `feedback_db.py` — analyst feedback persistence to a **private Google Sheet** (append-only,
  one flat row per submission via `gspread`; keeps the same public function names as the old
  SQLite module). Fail-closed if Sheets secrets are absent; retries transient write failures.
- `claude_client.py` — all Anthropic API calls (triage, follow-up reassessment,
  CTI web research via the web_search tool, and `generate_step_query` — the per-step
  platform-aware query builder for the Next steps tab)

## Guardrails (do not break)
- Never commit secrets. `.streamlit/secrets.toml`, `.env`, `*.sqlite` stay gitignored. The
  Google service-account JSON key must NEVER be committed — it lives only in `st.secrets`
  (`[gcp_service_account]` + `FEEDBACK_SHEET_ID`).
- Keep the analyst validation gate — enforce it even in fast/demo flows.
- CTI web research may only send allowed indicators: public IPs, domains, URLs, hashes,
  MITRE IDs, sanitized command patterns. Never hostnames, usernames, internal IPs,
  local paths, or customer identifiers.
- Admin mode must stay fail-closed: no ADMIN_PASSWORD secret configured → admin disabled.
- This is a learning/prototyping MVP. Prefer clear, readable code and explain the
  security reasoning behind changes over clever engineering.

## Milestone 3.9 — Launch cleanup (CURRENT WORK, in this order)
1. **Delete all `*.bak` files** from the tree (~19 milestone snapshots of streamlit_app.py
   plus several in triage/). Milestone history belongs in git history, not the tree.
2. **Remove the committed 53MB `data/mitre/enterprise-attack.json`** —
   `download_enterprise_attack()` fetches it on demand. Add it to .gitignore.
   Verify the code path that downloads it at first run still works.
3. **Fix `pyproject.toml`** — still says `name = "blank-app-template"` /
   "A simple Streamlit app template." Set real name/description. Also sanity-check
   deployability: Python is pinned to 3.13 (.python-version) with requires-python >=3.11,
   and pandas>=3.0 — kept to widely-supported pins that Streamlit Community Cloud runs.
4. **Dedup shadowed functions** (the delicate one — do this in its own branch):
   - `ontology.py`: 7 functions defined 3–4× each (e.g. enrich_field_with_ontology ×3,
     enrich_key_value_table ×4, build_semantic_facts ×4)
   - `cti_safety.py`: build_safe_cti_research_package ×4, has_cti_researchable_indicators ×3
   - `claude_client.py`: 3 functions defined 2–3×
   Python silently uses the LAST definition, so earlier ones are dead shadow code.
   For each duplicated function: diff all copies first, confirm the last is a true
   replacement (not divergent logic), keep the last, delete the shadows. Run the app
   and exercise the affected flows after each file.
5. **Restructure `README.md`** — currently opens with privacy disclaimers and has the
   entire "AI Processing and Data Handling" section duplicated verbatim. New structure:
   one-line hook → what it does → screenshot placeholder → how to run → architecture
   overview → limitations → ONE copy of the privacy section (it's good content, wrong position).
6. **Secrets history check**: run
   `git log --all --full-history -- .streamlit/secrets.toml .env` and
   `git log -p --all | grep -iE "sk-ant"` — report findings. If anything is found,
   STOP and tell me; the key must be rotated before launch.
7. After each completed step: commit with a clear message. Small commits, one concern each.

## Milestone 4+ — IP roadmap (AFTER launch, priority order)
1. **Close the feedback loop.** Feedback is captured (feedback_db.py) and shown in the
   admin panel but NEVER fed back into prompts or ontology — claude_client.py and
   ai_udm_mapper.py don't reference it at all. Build: before triage, retrieve 2–3
   similar past analyst-confirmed cases and inject as few-shot examples. Highest ROI.
2. **Ontology as single source of truth for field governance.** cti_safety.py
   re-implements allow/deny logic instead of reading cti_allowed / privacy_sensitivity
   from the ontology. Wire enforcement to the data model.
3. **Graph schema for attack_path** — model edges (user AUTHENTICATED_AS host,
   process SPAWNED process, process CONNECTED_TO domain) → real traversal instead of
   substring matching.
4. **Evidence-coverage confidence for MITRE** — per technique, define which evidence
   combinations earn high/med/low confidence, instead of keyword presence.
5. **Structured tool-use output** — replace free-text JSON + AI-repair parsing with
   forced tool_choice / input_schema on the Anthropic API.
6. **Model routing by ambiguity** — Haiku fast pass, escalate to Sonnet on low
   confidence or high severity (route on existing importance/severity fields).
7. **Calibration tracking** (per-alert-type AI accuracy from feedback DB) and
   **cross-alert entity linking** (host/user/hash → alert IDs, campaign detection).
8. **Incident/case-level input** — support pasting a case containing multiple alerts
   (alert 1, alert 2, alert 3 with different hosts/users), as modern platforms group alerts
   into incidents. Requires multi-entity handling in extraction, the evidence bundle, and
   attack-path logic. Pairs naturally with cross-alert entity linking (item 7).
9. **AI mapping output-size ceiling — watch and revisit.** The UDM mapper writes a
   fixed-size response (`max_tokens=16000` in ai_udm_mapper.py; ~35–40 suggestions). Large
   alerts hit the ceiling; the current mitigation retries once asking for the top ~20
   most-security-relevant suggestions so the analyst gets a complete result instead of a
   truncated error. **Signal to act:** analysts regularly see the "response was incomplete
   / use Guided UDM Fields" message, or important fields go missing on big incidents.
   Levers in order (cheapest first): (a) raise `max_tokens` further — Haiku 4.5 caps at 64K
   output, but past ~16–32K switch the call to streaming to avoid non-streaming timeouts;
   (b) **structured tool-use output (item 5) is the real fix** — a forced schema eliminates
   truncation/parse failures; (c) huge multi-alert pastes are really incident-level input
   (item 8) — map per-alert, not one giant response; (d) a larger mapper model
   (Sonnet/Opus via the `CLAUDE_MAPPER_MODEL` secret, 128K output) is a quality/cost lever
   that also raises the ceiling — reach for it if mapping *quality* is the complaint, not
   just size. A bigger model is not the first thing to try for size alone.

## Product vision (context for all future work)

The core SOC problem: alerts are singular events triggered by detections, but the analyst's real question — TP or FP — often depends on whether the alert is part of a larger attack unfolding over time. Commercial tools (Google SecOps cases, CrowdStrike incidents) group alerts by same-host/same-IP OR-logic; there is no real intelligence in the grouping.

Vision: use analyst experience (and later threat intelligence) to identify attack patterns over longer periods. This is why alert-centric and IOC-centric hunting matter so much in the app. Since there is no SIEM/EDR connection, the analyst is both the sensor and the ground truth — follow-up evidence and feedback are how the system learns whether something was a real incident. Long-term, the ontology should understand attack paths (entities and relationships over time), not only per-field weights that help the AI produce good analysis.

Data-privacy stance (informed by years of works-council experience): at alert-triage stage, PII lives in hostnames, usernames, emails, private IPs, and user-profile file paths — plus wherever those hide inside command lines, URLs, and free text. Everything else in alert metadata is investigation-safe. Deep personal-data handling belongs to the forensics/IR stage, not alert triage. The product answer is pseudonymization guidance now, and ontology-driven pseudonymization at intake as a roadmap feature (consistent renaming that preserves correlations).

This is Chris's personal research project (not an employer product) to understand AI and agentic AI in SOC work, and to collaborate with analysts on a private basis.

## How Chris likes to work
- Show the diff and reasoning before applying big changes.
- One milestone task at a time; verify after each.
- Flag the security implication of any change touching the CTI filter, the analyst
  gate, or secrets handling.
- Chris is a SOC/security professional — explain security reasoning, don't dumb it down.

## Working agreement (experience level + pace)
Chris is a security/SOC professional but **not a software developer** — expert on the
security substance, not on coding mechanics. So:
- **Explain security reasoning at full depth** (CTI boundary, analyst gate, secrets, threat
  model). **Explain software/engineering mechanics in plain language** — no unexplained
  jargon, say what a change does and why in terms a non-coder can follow.
- **Default pace: plan → Chris's approval → one small change → PR → verify.** One task at a
  time; don't batch unrelated changes; keep commits/PRs small and single-concern.
- **Investigate before building.** When a task has a genuinely uncertain part (e.g. what a
  hosting environment exposes at runtime), find out the reality first, then present the
  options in plain language and let Chris pick before writing code. Don't assume.
- **Wait for an explicit "go"** before implementing anything non-trivial.
- **Safety-first for non-critical code.** A cosmetic or convenience feature must never be
  able to break the app it touches — prefer fail-silent/degrade-gracefully designs.
- Chris verifies changes on the live Streamlit Cloud deploy after merge; tell him exactly
  what he should see to confirm success.
