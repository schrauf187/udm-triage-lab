import json
from typing import Any, Dict
from urllib import response

import anthropic
import streamlit as st


CLAUDE_MODEL = "claude-haiku-4-5-20251001"


def build_triage_prompt(evidence_bundle: Dict[str, Any]) -> str:
    return f"""
You are a cautious SOC triage assistant.

Your job:
- Analyze the provided normalized UDM-style evidence bundle.
- Explain what the alert appears to show.
- Identify why it may be suspicious.
- Identify what evidence is missing.
- Recommend next investigation steps.
- Provide a cautious assessment: TRUE_POSITIVE, FALSE_POSITIVE, LIKELY_TRUE_POSITIVE, LIKELY_FALSE_POSITIVE, or INCONCLUSIVE_NEEDS_MORE_EVIDENCE.

Strict rules:
- Use only the provided evidence.
- Do not invent facts.
- Do not claim threat actor attribution.
- Known groups using a technique are context only, not attribution.
- If evidence is insufficient, choose INCONCLUSIVE_NEEDS_MORE_EVIDENCE.
- Keep the answer useful for a SOC L1/L2 analyst.
- Return valid JSON only. No markdown outside JSON.

Required JSON schema:
{{
  "triage_summary": "short analyst summary",
  "assessment": "TRUE_POSITIVE | FALSE_POSITIVE | LIKELY_TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
  "confidence": "low | medium | high",
  "why_suspicious": ["reason 1", "reason 2"],
  "why_could_be_benign": ["reason 1", "reason 2"],
  "missing_evidence": ["item 1", "item 2"],
  "recommended_next_steps": ["step 1", "step 2"],
  "mitre_interpretation": ["interpretation 1", "interpretation 2"],
  "customer_facing_summary": "short non-alarmist summary for customer communication",
  "analyst_notes": "short internal note for the analyst"
}}

Evidence bundle:
{json.dumps(evidence_bundle, indent=2)}
"""


def ask_claude_for_triage(evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
        }

    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=1600,
        temperature=0.2,
        system=(
            "You are a cautious SOC triage assistant. "
            "You reason only from supplied evidence and return valid JSON only."
        ),
        messages=[
            {
                "role": "user",
                "content": build_triage_prompt(evidence_bundle),
            }
        ],
    )

    text = clean_json_response(response.content[0].text)

    # Claude sometimes wraps JSON in markdown fences like ```json ... ```
    if text.startswith("```"):
        text = text.replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "error": "Claude did not return valid JSON.",
            "raw_response": text,
            "assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "confidence": "low",
            "triage_summary": "Claude returned a non-JSON response. Manual review required.",
        }
def clean_json_response(text: str) -> str:
    """
    Claude may return JSON wrapped in Markdown fences.
    This strips common wrappers before json.loads().
    """
    text = text.strip()

    if text.startswith("```json"):
        text = text.removeprefix("```json").strip()

    if text.startswith("```"):
        text = text.removeprefix("```").strip()

    if text.endswith("```"):
        text = text.removesuffix("```").strip()

    return text