from typing import Any, Dict, List


def build_evidence_bundle(
    parsed_json: Dict[str, Any],
    entities: Dict[str, List[str]],
    semantic_facts: List[Dict[str, Any]],
    mitre_analysis: Dict[str, Any],
    enriched_techniques: List[Dict[str, Any]],
    data_mode: str,
) -> Dict[str, Any]:
    """
    Build a compact, structured evidence bundle for Claude.

    Claude should not receive random UI text.
    It should receive normalized evidence, facts, MITRE hypotheses,
    known missing evidence and current app assessment.
    """
    highest_value_facts = semantic_facts[:15]

    compact_mitre_matches = []

    for match in mitre_analysis.get("matches", []):
        compact_mitre_matches.append(
            {
                "pattern_name": match.get("pattern_name"),
                "severity": match.get("severity"),
                "confidence": match.get("confidence"),
                "reason": match.get("reason"),
                "techniques": match.get("techniques", []),
                "missing_evidence": match.get("missing_evidence", []),
                "recommended_next_steps": match.get("recommended_next_steps", []),
                "evidence": match.get("evidence", []),
            }
        )

    compact_enriched_techniques = []

    for technique in enriched_techniques:
        compact_enriched_techniques.append(
            {
                "id": technique.get("id"),
                "name": technique.get("name"),
                "found_in_mitre": technique.get("found_in_mitre"),
                "tactics": technique.get("tactics", []),
                "platforms": technique.get("platforms", []),
                "data_sources": technique.get("data_sources", []),
                "known_groups": technique.get("known_groups", [])[:15],
                "known_software": technique.get("known_software", [])[:15],
                "description": technique.get("description", "")[:1000],
                "detection": technique.get("detection", "")[:1000],
            }
        )

    return {
        "data_mode": data_mode,
        "important_instruction": (
            "This is an evidence bundle from a SOC triage lab. "
            "Do not assume compromise. Do not perform hard threat actor attribution. "
            "Technique/group overlap is context only."
        ),
        "entities": entities,
        "highest_value_semantic_facts": highest_value_facts,
        "mitre_pattern_analysis": {
            "initial_verdict": mitre_analysis.get("initial_verdict"),
            "overall_severity": mitre_analysis.get("overall_severity"),
            "summary": mitre_analysis.get("summary"),
            "matches": compact_mitre_matches,
        },
        "mitre_knowledge_enrichment": compact_enriched_techniques,
        "raw_udm_preview": parsed_json,
    }