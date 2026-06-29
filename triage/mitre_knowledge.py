import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

LOCAL_MITRE_PATH = Path("data/mitre/enterprise-attack.json")


def download_enterprise_attack(force: bool = False) -> Path:
    """
    Download the official MITRE ATT&CK Enterprise STIX JSON file.

    The file is stored locally under:
    data/mitre/enterprise-attack.json
    """
    LOCAL_MITRE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if LOCAL_MITRE_PATH.exists() and not force:
        return LOCAL_MITRE_PATH

    response = requests.get(MITRE_ENTERPRISE_ATTACK_URL, timeout=60)
    response.raise_for_status()

    LOCAL_MITRE_PATH.write_text(response.text, encoding="utf-8")
    return LOCAL_MITRE_PATH


def load_enterprise_attack_json(path: Path = LOCAL_MITRE_PATH) -> Dict[str, Any]:
    """
    Load the locally stored MITRE ATT&CK Enterprise STIX JSON.
    """
    if not path.exists():
        download_enterprise_attack(force=False)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _get_attack_external_id(stix_object: Dict[str, Any]) -> Optional[str]:
    """
    Extract the external ATT&CK ID, such as T1059.001 or G0016.
    """
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")

    return None


def _get_attack_url(stix_object: Dict[str, Any]) -> Optional[str]:
    """
    Extract the official ATT&CK URL.
    """
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")

    return None


def _is_active(stix_object: Dict[str, Any]) -> bool:
    """
    Ignore revoked/deprecated ATT&CK objects.
    """
    return not stix_object.get("revoked", False) and not stix_object.get(
        "x_mitre_deprecated", False
    )


def _extract_tactics(stix_object: Dict[str, Any]) -> List[str]:
    """
    Extract ATT&CK tactics from kill chain phases.
    """
    tactics = []

    for phase in stix_object.get("kill_chain_phases", []):
        phase_name = phase.get("phase_name")
        if phase_name:
            tactics.append(phase_name)

    return list(dict.fromkeys(tactics))


def build_mitre_knowledge() -> Dict[str, Any]:
    """
    Parse MITRE ATT&CK Enterprise STIX into a compact knowledge dictionary.

    Returns:
    {
      "techniques": {
        "T1059.001": {...}
      },
      "groups_by_technique": {
        "T1059.001": ["APT29", "FIN7", ...]
      },
      "software_by_technique": {
        "T1059.001": ["Cobalt Strike", ...]
      }
    }
    """
    attack_data = load_enterprise_attack_json()
    objects = attack_data.get("objects", [])

    techniques_by_stix_id = {}
    techniques_by_attack_id = {}

    groups_by_stix_id = {}
    software_by_stix_id = {}

    groups_by_technique = {}
    software_by_technique = {}

    # First pass: collect techniques, groups, tools, malware
    for obj in objects:
        if not _is_active(obj):
            continue

        object_type = obj.get("type")
        stix_id = obj.get("id")
        attack_id = _get_attack_external_id(obj)

        if not stix_id:
            continue

        if object_type == "attack-pattern" and attack_id:
            technique = {
                "id": attack_id,
                "stix_id": stix_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "url": _get_attack_url(obj),
                "tactics": _extract_tactics(obj),
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }

            techniques_by_stix_id[stix_id] = technique
            techniques_by_attack_id[attack_id] = technique

        elif object_type == "intrusion-set":
            groups_by_stix_id[stix_id] = {
                "name": obj.get("name", ""),
                "id": attack_id,
                "url": _get_attack_url(obj),
            }

        elif object_type in ["malware", "tool"]:
            software_by_stix_id[stix_id] = {
                "name": obj.get("name", ""),
                "id": attack_id,
                "type": object_type,
                "url": _get_attack_url(obj),
            }

    # Second pass: collect relationships
    for obj in objects:
        if not _is_active(obj):
            continue

        if obj.get("type") != "relationship":
            continue

        if obj.get("relationship_type") != "uses":
            continue

        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")

        if target_ref not in techniques_by_stix_id:
            continue

        technique = techniques_by_stix_id[target_ref]
        technique_id = technique["id"]

        if source_ref in groups_by_stix_id:
            group_name = groups_by_stix_id[source_ref]["name"]
            groups_by_technique.setdefault(technique_id, []).append(group_name)

        if source_ref in software_by_stix_id:
            software_name = software_by_stix_id[source_ref]["name"]
            software_by_technique.setdefault(technique_id, []).append(software_name)

    # Deduplicate and sort
    for technique_id in groups_by_technique:
        groups_by_technique[technique_id] = sorted(
            list(dict.fromkeys(groups_by_technique[technique_id]))
        )

    for technique_id in software_by_technique:
        software_by_technique[technique_id] = sorted(
            list(dict.fromkeys(software_by_technique[technique_id]))
        )

    return {
        "techniques": techniques_by_attack_id,
        "groups_by_technique": groups_by_technique,
        "software_by_technique": software_by_technique,
    }


def enrich_technique_ids(
    technique_ids: List[str],
    mitre_knowledge: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Enrich technique IDs like T1059.001 with MITRE context.
    """
    enriched = []

    techniques = mitre_knowledge.get("techniques", {})
    groups_by_technique = mitre_knowledge.get("groups_by_technique", {})
    software_by_technique = mitre_knowledge.get("software_by_technique", {})

    for technique_id in technique_ids:
        technique = techniques.get(technique_id)

        if not technique:
            enriched.append(
                {
                    "id": technique_id,
                    "name": "Unknown technique",
                    "found_in_mitre": False,
                    "description": "",
                    "tactics": [],
                    "platforms": [],
                    "data_sources": [],
                    "detection": "",
                    "url": None,
                    "known_groups": [],
                    "known_software": [],
                }
            )
            continue

        enriched.append(
            {
                **technique,
                "found_in_mitre": True,
                "known_groups": groups_by_technique.get(technique_id, []),
                "known_software": software_by_technique.get(technique_id, []),
            }
        )

    return enriched


def extract_technique_ids_from_mitre_analysis(mitre_analysis: Dict[str, Any]) -> List[str]:
    """
    Extract unique technique IDs from our deterministic mapper output.
    """
    technique_ids = []

    for match in mitre_analysis.get("matches", []):
        for technique in match.get("techniques", []):
            technique_id = technique.get("id")
            if technique_id:
                technique_ids.append(technique_id)

    return list(dict.fromkeys(technique_ids))