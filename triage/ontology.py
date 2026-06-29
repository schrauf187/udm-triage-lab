from typing import Any, Dict, List

import yaml


def load_udm_ontology(path: str = "ontology/udm_ontology.yaml") -> Dict[str, Any]:
    """
    Load the UDM ontology YAML file.
    """
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def normalize_field_for_matching(field: str) -> str:
    """
    Normalizes array-style UDM fields so they can match ontology entries.

    Example:
    security_result.attack_details.tactics[0].id
    becomes:
    security_result.attack_details.tactics
    """
    if "security_result.attack_details.tactics" in field:
        return "security_result.attack_details.tactics"

    if "security_result.attack_details.techniques" in field:
        return "security_result.attack_details.techniques"

    return field


def enrich_key_value_table(
    key_value_table: List[Dict[str, str]],
    ontology: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Adds ontology meaning, importance, MITRE hints and analyst questions
    to the UDM key-value table.
    """
    enriched_rows = []

    for row in key_value_table:
        field = row.get("udm_field", "")
        ontology_key = normalize_field_for_matching(field)
        ontology_entry = ontology.get(ontology_key, {})

        enriched_row = {
            **row,
            "meaning": ontology_entry.get("meaning", "No ontology entry yet."),
            "importance": ontology_entry.get("importance", 1),
            "category": ontology_entry.get("category", row.get("triage_role", "unknown")),
            "mitre_hints": ", ".join(ontology_entry.get("mitre_hints", [])),
            "analyst_questions": " | ".join(ontology_entry.get("analyst_questions", [])),
        }

        enriched_rows.append(enriched_row)

    enriched_rows.sort(key=lambda item: item.get("importance", 1), reverse=True)

    return enriched_rows


def build_semantic_facts(enriched_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts enriched UDM key-value rows into semantic facts that can later
    be sent to Claude.
    """
    facts = []

    for row in enriched_rows:
        field = row.get("udm_field", "")
        value = row.get("value", "")
        meaning = row.get("meaning", "")
        importance = row.get("importance", 1)
        category = row.get("category", "unknown")
        mitre_hints = row.get("mitre_hints", "")

        if not value or value == "None":
            continue

        fact = {
            "fact": f"{field} = {value}",
            "meaning": meaning,
            "importance": importance,
            "category": category,
            "mitre_hints": mitre_hints,
            "source_field": field,
        }

        facts.append(fact)

    facts.sort(key=lambda item: item.get("importance", 1), reverse=True)

    return facts