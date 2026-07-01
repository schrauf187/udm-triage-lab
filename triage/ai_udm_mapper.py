import json
from typing import Any, Dict, List

import anthropic
import streamlit as st

try:
    from triage.claude_client import CLAUDE_MODEL
except Exception:
    CLAUDE_MODEL = "claude-haiku-4-5-20251001"


MVP_UDM_FIELDS = [
    "metadata.event_type",
    "metadata.vendor_name",
    "metadata.product_name",
    "metadata.product_event_type",
    "metadata.event_timestamp",
    "metadata.ingested_timestamp",
    "metadata.description",
    "metadata.log_type",

    "principal.ip",
    "principal.hostname",
    "principal.asset.hostname",
    "principal.asset.asset_id",
    "principal.user.userid",
    "principal.user.email_addresses[0]",
    "principal.process.command_line",
    "principal.process.pid",
    "principal.process.file.full_path",
    "principal.process.file.name",
    "principal.process.parent_process.file.full_path",
    "principal.process.parent_process.file.name",

    "target.ip",
    "target.hostname",
    "target.user.userid",
    "target.file.full_path",
    "target.file.name",
    "target.file.sha256",
    "target.process.command_line",
    "target.domain.name",
    "target.url",
    "target.port",
    "target.application",

    "security_result.action",
    "security_result.severity",
    "security_result.priority",
    "security_result.risk_score",
    "security_result.summary",
    "security_result.category",
    "security_result.description",
    "security_result.rule_name",
    "security_result.rule_id",
    "security_result.display_name",
    "security_result.detection_fields",

    "network.application_protocol",
    "network.ip_protocol",
    "network.direction",
    "network.session_id",
    "network.sent_bytes",
    "network.received_bytes",
    "network.src_port",
    "network.dst_port",
    "network.connection.count",

    "process.pid",
    "process.parent_pid",
    "process.command_line",
    "process.file.full_path",
    "process.file.name",
    "process.file.sha256",
    "process.file.md5",

    "file.full_path",
    "file.sha256",
    "file.md5",
    "file.file_name",
    "file.size",

    "network.dns.questions.name",
    "network.dns.answers.data",

    "network.http.method",
    "network.http.request.url",
    "network.http.response.code",
    "network.http.user_agent",

    "authentication.auth_type",
    "authentication.mechanism",
    "authentication.status",
    "extensions.auth.mechanism",
    "extensions.auth.result",
    "extensions.auth.device_trust_type",
    "extensions.auth.conditional_access_status",
    "extensions.auth.user_agent",

    "security_result.attack_details.tactics[0].id",
    "security_result.attack_details.tactics[0].name",
    "security_result.attack_details.tactics[1].id",
    "security_result.attack_details.tactics[1].name",
    "security_result.attack_details.tactics[2].id",
    "security_result.attack_details.tactics[2].name",
    "security_result.attack_details.techniques[0].id",
    "security_result.attack_details.techniques[0].name",
    "security_result.attack_details.techniques[1].id",
    "security_result.attack_details.techniques[1].name",
    "security_result.attack_details.techniques[2].id",
    "security_result.attack_details.techniques[2].name",
    "security_result.attack_details.techniques[3].id",
    "security_result.attack_details.techniques[3].name",
]


def _safe_raw_context_excerpt(raw_alert_content: str, max_chars: int = 6000) -> str:
    """
    Keep enough raw context for the AI to understand the alert,
    but avoid forcing very long command lines into the prompt/output.
    """
    raw_alert_content = raw_alert_content or ""

    if len(raw_alert_content) <= max_chars:
        return raw_alert_content

    return raw_alert_content[:max_chars] + "\n...[raw alert content truncated for mapping safety]..."


def build_udm_mapping_prompt(raw_alert_content: str, field_inventory: List[Dict[str, Any]]) -> str:
    """
    Build JSON-safe prompt for AI-assisted UDM mapping.
    The AI should recommend mappings, not echo long raw values.
    """
    raw_excerpt = _safe_raw_context_excerpt(raw_alert_content)

    output_schema = {
        "mapping_suggestions": [
            {
                "source_field": "exact field name from inventory, or derived.<short_name> only for derived MITRE/event fields",
                "source_value_preview": "short preview, max 120 characters",
                "suggested_udm_field": "UDM field or additional.fields.<vendor>.<field>",
                "suggested_value": None,
                "mapping_type": "direct | derived | preserve_vendor_field",
                "security_relevance": "high | medium | low",
                "confidence": 0.0,
                "reason": "short reason",
                "analyst_action_required": "review",
            }
        ],
        "unmapped_fields": [
            {
                "source_field": "field name",
                "source_value_preview": "short preview, max 120 characters",
                "reason": "why it was not confidently mapped",
            }
        ],
        "alert_type_guess": "short guess of alert type",
        "vendor_guess": "short vendor/product guess",
        "normalization_notes": ["short note 1", "short note 2"],
    }

    prompt = f"""
You are an expert SOC alert normalization assistant.

Your task:
Analyze the raw security alert content and extracted field inventory.
Recommend Google SecOps UDM-style mappings for the available evidence.

Critical JSON safety rules:
- Return VALID JSON only.
- Do not wrap the JSON in markdown.
- Do not include long raw field values in the JSON response.
- Do not copy full command lines, full URLs, long queries, encoded commands, or long descriptions into suggested_value.
- For direct mappings, set suggested_value to null.
- The application will locally retrieve the original value from source_field.
- Use source_value_preview with a maximum of 120 characters.
- Escape all JSON strings correctly.
- Keep reasons short.
- Return at most 35 mapping_suggestions.

Important context:
- This is AI-assisted parser preparation / evidence mapping.
- This is not CTI internet research.
- Do not use web search.
- Do not fabricate values.
- Use only fields and values present in the raw alert content or field inventory.
- The analyst will review, edit, accept, or reject each recommendation.
- Preserve vendor-specific fields as additional.fields.* candidates if useful for traceability.
- If a field cannot be mapped confidently, place it in unmapped_fields.
- Source field names in recommendations MUST exactly match source_field values from the field inventory where possible.
- For MITRE mappings, only suggest them when the alert text or known behavior clearly supports them.
- Confidence must be a number between 0 and 1.

Preferred UDM fields for this MVP:
{json.dumps(MVP_UDM_FIELDS, indent=2)}

Required JSON output schema:
{json.dumps(output_schema, indent=2)}

How to handle derived values:
- For directly mapped source fields, suggested_value MUST be null.
- Only use suggested_value for short derived values such as:
  - metadata.vendor_name = "CrowdStrike"
  - metadata.product_name = "Falcon"
  - metadata.event_type = "PROCESS_LAUNCH"
  - security_result.attack_details.techniques[0].id = "T1059.001"
- Never put long command lines, raw queries, URLs with tokens, or encoded payloads into suggested_value.

Raw alert context excerpt:
{raw_excerpt}

Extracted field inventory:
{json.dumps(field_inventory, indent=2)}
"""
    return prompt


def _extract_response_text(response) -> str:
    text_parts = []

    for block in getattr(response, "content", []):
        if getattr(block, "type", None) == "text":
            block_text = getattr(block, "text", "")
            if block_text:
                text_parts.append(block_text)

    return "\n".join(text_parts).strip()


def _parse_json_from_text(response_text: str) -> Dict[str, Any]:
    """
    Parse JSON even if the model accidentally wraps it in markdown.
    """
    clean = response_text.strip()

    if clean.startswith("```json"):
        clean = clean.removeprefix("```json").strip()

    if clean.startswith("```"):
        clean = clean.removeprefix("```").strip()

    if clean.endswith("```"):
        clean = clean.removesuffix("```").strip()

    try:
        return json.loads(clean)
    except Exception:
        first_brace = clean.find("{")

        if first_brace == -1:
            raise ValueError("No JSON object found in AI mapping response.")

        decoder = json.JSONDecoder()
        parsed, _ = decoder.raw_decode(clean[first_brace:])
        return parsed


def _repair_mapping_json_with_ai(client, model: str, broken_text: str) -> Dict[str, Any]:
    """
    Last-resort repair step if the model returns malformed JSON.
    """
    repair_schema = {
        "mapping_suggestions": [],
        "unmapped_fields": [],
        "alert_type_guess": "",
        "vendor_guess": "",
        "normalization_notes": [],
    }

    repair_prompt = f"""
The following response was intended to be JSON but is malformed.

Fix it into valid compact JSON matching this schema:
{json.dumps(repair_schema, indent=2)}

Rules:
- Return JSON only.
- Do not include markdown.
- Remove or truncate any long broken string values.
- For direct mappings, set suggested_value to null.
- Do not add new facts.

Broken response:
{broken_text[:12000]}
"""

    response = client.messages.create(
        model=model,
        max_tokens=2500,
        temperature=0,
        system="Return valid compact JSON only.",
        messages=[
            {
                "role": "user",
                "content": repair_prompt,
            }
        ],
    )

    repaired_text = _extract_response_text(response)
    return _parse_json_from_text(repaired_text)


def ask_ai_for_udm_mapping_suggestions(
    raw_alert_content: str,
    field_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")

    if not api_key:
        return {
            "error": "Missing ANTHROPIC_API_KEY in .streamlit/secrets.toml",
            "mapping_suggestions": [],
            "unmapped_fields": [],
        }

    model = st.secrets.get("CLAUDE_MAPPER_MODEL", CLAUDE_MODEL)

    try:
        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=model,
            max_tokens=4500,
            temperature=0.1,
            system=(
                "You are a cautious SOC alert normalization assistant. "
                "Return compact valid JSON only. Do not use web search."
            ),
            messages=[
                {
                    "role": "user",
                    "content": build_udm_mapping_prompt(
                        raw_alert_content=raw_alert_content,
                        field_inventory=field_inventory,
                    ),
                }
            ],
        )

        response_text = _extract_response_text(response)

        try:
            result = _parse_json_from_text(response_text)
        except Exception as parse_error:
            try:
                result = _repair_mapping_json_with_ai(
                    client=client,
                    model=model,
                    broken_text=response_text,
                )
                result["repair_note"] = (
                    f"Original AI mapping response required JSON repair: {parse_error}"
                )
            except Exception as repair_error:
                return {
                    "error": (
                        "AI mapping response was not valid JSON and repair failed: "
                        f"{parse_error}; repair error: {repair_error}"
                    ),
                    "raw_response": response_text,
                    "mapping_suggestions": [],
                    "unmapped_fields": [],
                }

        if "mapping_suggestions" not in result:
            result["mapping_suggestions"] = []

        if "unmapped_fields" not in result:
            result["unmapped_fields"] = []

        return result

    except Exception as error:
        return {
            "error": f"Unexpected AI UDM mapping error: {type(error).__name__}: {error}",
            "mapping_suggestions": [],
            "unmapped_fields": [],
        }
