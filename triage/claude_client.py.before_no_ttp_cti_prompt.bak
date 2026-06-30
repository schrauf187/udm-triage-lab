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

def ask_claude_for_followup_reassessment(
    evidence_bundle: Dict[str, Any],
    attack_path: Dict[str, Any],
    original_claude_result: Dict[str, Any],
    followup_evidence: str,
    cti_result: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }

    if not followup_evidence.strip():
        return {
            "error": "No follow-up evidence provided.",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }

    try:
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2000,
            temperature=0.2,
            system=(
                "You are a cautious SOC triage assistant. "
                "You reason only from supplied evidence and return valid JSON only."
            ),
            messages=[
                {
                    "role": "user",
                    "content": build_followup_reassessment_prompt(
                        evidence_bundle=evidence_bundle,
                        attack_path=attack_path,
                        original_claude_result=original_claude_result or {},
                        followup_evidence=followup_evidence,
                        cti_result=cti_result or {},
                    ),
                }
            ],
        )

        text = response.content[0].text.strip()

        # Claude may wrap JSON in markdown fences.
        if text.startswith("```json"):
            text = text.removeprefix("```json").strip()

        if text.startswith("```"):
            text = text.removeprefix("```").strip()

        if text.endswith("```"):
            text = text.removesuffix("```").strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "error": "AI responded, but did not return valid JSON.",
                "raw_response": text,
                "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
                "updated_confidence": "low",
            }

    except Exception as error:
        return {
            "error": f"Unexpected AI API error during follow-up reassessment: {type(error).__name__}: {error}",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }

def build_cti_web_research_prompt(
    cti_package: Dict[str, Any],
    attack_path: Dict[str, Any],
) -> str:
    return f"""
You are a cautious cyber threat intelligence analyst.

You may use web search for public CTI/internet research.

You are given a privacy-filtered CTI research package. It should contain only:
- public IPs
- domains
- URLs
- hashes
- MITRE technique IDs/names
- sanitized command-line behavior patterns

Important:
- Do not ask for hostnames, usernames, local file paths, internal IPs, or customer names.
- Do not infer threat actor attribution from TTP overlap alone.
- Public CTI findings can support or weaken suspicion, but they do not prove compromise by themselves.
- Separate reputation/context from observed host evidence.
- Return valid JSON only. No markdown outside JSON.

Required JSON schema:
{{
  "cti_summary": "short CTI summary",
  "researched_indicators": {{
    "public_ips": [],
    "domains": [],
    "urls": [],
    "hashes": [],
    "mitre_techniques": [],
    "sanitized_commandline_patterns": []
  }},
  "indicator_findings": [
    {{
      "indicator": "indicator value",
      "indicator_type": "ip | domain | url | hash | technique | commandline_pattern",
      "finding": "what public research suggests",
      "risk": "benign | suspicious | malicious | unknown",
      "confidence": "low | medium | high",
      "source_summary": "short source-based explanation"
    }}
  ],
  "confidence_impact": "decreases_confidence | no_change | increases_confidence",
  "attack_path_relevance": "how CTI affects the current attack-path hypothesis",
  "cti_supported_phases": ["phase 1", "phase 2"],
  "cti_not_supported_phases": ["phase 1", "phase 2"],
  "customer_cti_summary": "short non-alarmist customer-facing CTI summary",
  "limitations": ["limitation 1", "limitation 2"],
  "sources": [
    {{
      "title": "source title",
      "url": "source url",
      "relevance": "why this source matters"
    }}
  ]
}}

Privacy-filtered CTI research package:
{json.dumps(cti_package, indent=2)}

Current attack-path hypothesis:
{json.dumps(attack_path, indent=2)}
"""


def _collect_text_and_citations(response) -> tuple[str, list]:
    text_parts = []
    citations = []

    for block in response.content:
        block_type = getattr(block, "type", None)

        if block_type == "text":
            text = getattr(block, "text", "")
            if text:
                text_parts.append(text)

            for citation in getattr(block, "citations", []) or []:
                citations.append(
                    {
                        "title": getattr(citation, "title", ""),
                        "url": getattr(citation, "url", ""),
                        "cited_text": getattr(citation, "cited_text", ""),
                    }
                )

    return "\n".join(text_parts).strip(), citations


def ask_claude_for_cti_web_research(
    cti_package: Dict[str, Any],
    attack_path: Dict[str, Any],
) -> Dict[str, Any]:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "cti_summary": "CTI research could not run because the API key is missing.",
        }

    # Optional override if the default model does not support web search in your account.
    cti_model = st.secrets.get("CLAUDE_CTI_WEB_MODEL", CLAUDE_MODEL)

    try:
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=cti_model,
            max_tokens=2200,
            temperature=0.2,
            system=(
                "You are a cautious cyber threat intelligence analyst. "
                "Use web search only for the provided public indicators and sanitized patterns. "
                "Return valid JSON only."
            ),
            messages=[
                {
                    "role": "user",
                    "content": build_cti_web_research_prompt(
                        cti_package=cti_package,
                        attack_path=attack_path,
                    ),
                }
            ],
            tools=[
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": 1,
                }
            ],
        )

        text, citations = _collect_text_and_citations(response)

        if text.startswith("```json"):
            text = text.removeprefix("```json").strip()

        if text.startswith("```"):
            text = text.removeprefix("```").strip()

        if text.endswith("```"):
            text = text.removesuffix("```").strip()

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            return {
                "error": "AI CTI research returned non-JSON output.",
                "raw_response": text,
                "cti_summary": "CTI research completed, but the response could not be parsed as JSON.",
                "citations": citations,
            }

        if citations:
            result["citations"] = citations

        usage = getattr(response, "usage", None)
        if usage:
            server_tool_use = getattr(usage, "server_tool_use", None)
            if server_tool_use:
                result["web_search_usage"] = {
                    "web_search_requests": getattr(server_tool_use, "web_search_requests", None)
                }

        return result

    except Exception as error:
        return {
            "error": f"Unexpected AI CTI web research error: {type(error).__name__}: {error}",
            "cti_summary": "CTI research failed. Check whether web search is enabled for the organization and whether the selected model supports it.",
        }
# ---------------------------------------------------------------------
# Override: more robust CTI web research prompt and parser
# Fixes non-JSON / truncated JSON caused by verbose sources section.
# ---------------------------------------------------------------------
import json as _cti_json


def _cti_get_attr(obj, name, default=""):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _cti_collect_text_and_citations(response):
    text_parts = []
    citations = []

    for block in getattr(response, "content", []):
        if _cti_get_attr(block, "type") == "text":
            text = _cti_get_attr(block, "text", "")
            if text:
                text_parts.append(text)

            for citation in _cti_get_attr(block, "citations", []) or []:
                citations.append(
                    {
                        "title": _cti_get_attr(citation, "title", ""),
                        "url": _cti_get_attr(citation, "url", ""),
                        "cited_text": _cti_get_attr(citation, "cited_text", ""),
                    }
                )

    return "\n".join(text_parts).strip(), citations


def _cti_parse_json_from_text(text: str):
    clean = text.strip()

    if clean.startswith("```json"):
        clean = clean.removeprefix("```json").strip()

    if clean.startswith("```"):
        clean = clean.removeprefix("```").strip()

    if clean.endswith("```"):
        clean = clean.removesuffix("```").strip()

    try:
        return _cti_json.loads(clean)
    except Exception:
        pass

    # Fallback: parse the first JSON object even if text exists before/after it.
    first_brace = clean.find("{")
    if first_brace == -1:
        raise ValueError("No JSON object found in CTI response.")

    decoder = _cti_json.JSONDecoder()
    parsed, _ = decoder.raw_decode(clean[first_brace:])
    return parsed


def build_cti_web_research_prompt(
    cti_package: dict,
    attack_path: dict,
) -> str:
    return f"""
You are a cautious cyber threat intelligence analyst.

You may use web search only for the privacy-filtered public indicators provided below.

Rules:
- Do not ask for hostnames, usernames, local file paths, internal IPs, or customer names.
- Ignore anything that looks like a UDM field name or placeholder.
- Do not infer threat actor attribution from TTP overlap alone.
- CTI findings can support hunting, but do not prove compromise.
- Keep the response compact.
- Return valid JSON only.
- Do not include long source text inside the JSON.
- Maximum 8 indicator findings.
- Maximum 5 limitations.

Required JSON schema:
{{
  "cti_summary": "short CTI summary",
  "researched_indicators": {{
    "public_ips": [],
    "domains": [],
    "urls": [],
    "hashes": [],
    "mitre_techniques": [],
    "sanitized_commandline_patterns": []
  }},
  "indicator_findings": [
    {{
      "indicator": "indicator value",
      "indicator_type": "ip | domain | url | hash | technique | commandline_pattern",
      "finding": "short finding",
      "risk": "benign | suspicious | malicious | unknown",
      "confidence": "low | medium | high",
      "source_summary": "short summary only"
    }}
  ],
  "confidence_impact": "decreases_confidence | no_change | increases_confidence",
  "attack_path_relevance": "short explanation of how CTI affects the current attack-path hypothesis",
  "cti_supported_phases": ["phase 1", "phase 2"],
  "cti_not_supported_phases": ["phase 1", "phase 2"],
  "customer_cti_summary": "short non-alarmist customer-facing CTI summary",
  "limitations": ["limitation 1", "limitation 2"]
}}

Privacy-filtered CTI research package:
{_cti_json.dumps(cti_package, indent=2)}

Current attack-path hypothesis:
{_cti_json.dumps(attack_path, indent=2)}
"""


def ask_claude_for_cti_web_research(
    cti_package: dict,
    attack_path: dict,
) -> dict:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "cti_summary": "CTI research could not run because the API key is missing.",
        }

    cti_model = st.secrets.get("CLAUDE_CTI_WEB_MODEL", CLAUDE_MODEL)

    try:
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=cti_model,
            max_tokens=4000,
            temperature=0.1,
            system=(
                "You are a cautious cyber threat intelligence analyst. "
                "Use web search only for the supplied public indicators and sanitized patterns. "
                "Return compact valid JSON only."
            ),
            messages=[
                {
                    "role": "user",
                    "content": build_cti_web_research_prompt(
                        cti_package=cti_package,
                        attack_path=attack_path,
                    ),
                }
            ],
            tools=[
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": 1,
                }
            ],
        )

        text, citations = _cti_collect_text_and_citations(response)

        try:
            result = _cti_parse_json_from_text(text)
        except Exception as parse_error:
            return {
                "error": f"AI CTI research returned non-JSON output: {parse_error}",
                "raw_response": text,
                "cti_summary": "CTI research completed, but the response could not be parsed as JSON.",
            }

        if citations:
            result["citations"] = citations

        usage = getattr(response, "usage", None)
        if usage:
            server_tool_use = getattr(usage, "server_tool_use", None)
            if server_tool_use:
                result["web_search_usage"] = {
                    "web_search_requests": getattr(server_tool_use, "web_search_requests", None)
                }

        return result

    except Exception as error:
        return {
            "error": f"Unexpected AI CTI web research error: {type(error).__name__}: {error}",
            "cti_summary": "CTI research failed. Check whether web search is enabled and whether the selected model supports it.",
        }

# ---------------------------------------------------------------------
# Override: follow-up reassessment with CTI context
# Fixes missing build_followup_reassessment_prompt
# ---------------------------------------------------------------------
import json as _followup_json


def _followup_extract_text(response) -> str:
    text_parts = []

    for block in getattr(response, "content", []):
        block_type = getattr(block, "type", None)

        if block_type == "text":
            text = getattr(block, "text", "")
            if text:
                text_parts.append(text)

    return "\n".join(text_parts).strip()


def _followup_parse_json_from_text(text: str) -> dict:
    clean = text.strip()

    if clean.startswith("```json"):
        clean = clean.removeprefix("```json").strip()

    if clean.startswith("```"):
        clean = clean.removeprefix("```").strip()

    if clean.endswith("```"):
        clean = clean.removesuffix("```").strip()

    try:
        return _followup_json.loads(clean)
    except Exception:
        first_brace = clean.find("{")
        if first_brace == -1:
            raise ValueError("No JSON object found in follow-up response.")

        decoder = _followup_json.JSONDecoder()
        parsed, _ = decoder.raw_decode(clean[first_brace:])
        return parsed


def build_followup_reassessment_prompt(
    evidence_bundle: dict,
    attack_path: dict,
    original_claude_result: dict,
    followup_evidence: str,
    cti_result: dict | None = None,
) -> str:
    return f"""
You are a cautious SOC triage assistant.

The analyst has performed initial triage, optional CTI research, and follow-up hunting.

Your job is to re-evaluate the alert using:
- the original normalized evidence bundle
- the original attack-path hypothesis
- the original AI triage result
- the optional CTI internet research result
- the analyst's follow-up hunt results / investigation notes

Strict rules:
- Use only the supplied evidence.
- Do not invent facts.
- Do not claim threat actor attribution.
- CTI reputation alone does not prove compromise.
- CTI findings are hunting context unless confirmed in internal telemetry.
- Internal log evidence is stronger than public CTI.
- If CTI shows an IP/domain is benign shared infrastructure, reduce confidence where appropriate.
- Re-evaluate the MITRE kill chain based on what is internally observed.
- Clearly separate:
  1. observed phases
  2. CTI-supported but not internally confirmed phases
  3. hypothesized phases
  4. not observed phases
- Return valid JSON only. No markdown outside JSON.

Required JSON schema:
{{
  "updated_assessment": "TRUE_POSITIVE | FALSE_POSITIVE | LIKELY_TRUE_POSITIVE | LIKELY_FALSE_POSITIVE | INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
  "updated_confidence": "low | medium | high",
  "what_changed": ["change 1", "change 2"],
  "supporting_evidence": ["evidence 1", "evidence 2"],
  "evidence_against_malicious_activity": ["benign evidence 1", "benign evidence 2"],
  "updated_attack_chain": ["phase 1", "phase 2"],
  "attack_path_opinion": "explain whether the original attack-path hypothesis is supported, weakened, or still unconfirmed",
  "cti_relevance": "explain how the CTI result affects the triage and attack-chain interpretation",
  "confirmed_attack_phases": ["phase 1", "phase 2"],
  "hypothesized_attack_phases": ["phase 1", "phase 2"],
  "cti_supported_but_not_confirmed_phases": ["phase 1", "phase 2"],
  "not_observed_attack_phases": ["phase 1", "phase 2"],
  "remaining_gaps": ["gap 1", "gap 2"],
  "recommended_escalation": "No escalation | Monitor | Escalate to L2 | Escalate to incident response",
  "analyst_summary": "short internal analyst summary",
  "customer_update": "short non-alarmist customer-facing update including CTI and attack-chain context where relevant"
}}

Original evidence bundle:
{_followup_json.dumps(evidence_bundle, indent=2)}

Original attack-path hypothesis:
{_followup_json.dumps(attack_path, indent=2)}

Original AI triage result:
{_followup_json.dumps(original_claude_result or {}, indent=2)}

Optional CTI internet research result:
{_followup_json.dumps(cti_result or {}, indent=2)}

Analyst follow-up evidence / hunt results:
{followup_evidence}
"""


def ask_claude_for_followup_reassessment(
    evidence_bundle: dict,
    attack_path: dict,
    original_claude_result: dict,
    followup_evidence: str,
    cti_result: dict | None = None,
) -> dict:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }

    if not followup_evidence.strip():
        return {
            "error": "No follow-up evidence provided.",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }

    try:
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=3500,
            temperature=0.2,
            system=(
                "You are a cautious SOC triage assistant. "
                "Reason only from supplied evidence. "
                "Return compact valid JSON only."
            ),
            messages=[
                {
                    "role": "user",
                    "content": build_followup_reassessment_prompt(
                        evidence_bundle=evidence_bundle,
                        attack_path=attack_path,
                        original_claude_result=original_claude_result or {},
                        followup_evidence=followup_evidence,
                        cti_result=cti_result or {},
                    ),
                }
            ],
        )

        text = _followup_extract_text(response)

        try:
            return _followup_parse_json_from_text(text)
        except Exception as parse_error:
            return {
                "error": f"AI follow-up reassessment returned non-JSON output: {parse_error}",
                "raw_response": text,
                "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
                "updated_confidence": "low",
            }

    except Exception as error:
        return {
            "error": f"Unexpected AI API error during follow-up reassessment: {type(error).__name__}: {error}",
            "updated_assessment": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "updated_confidence": "low",
        }
