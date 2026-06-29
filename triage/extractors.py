import re
from typing import Any, Dict, List


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\"']+")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def flatten_json(data: Any, parent_key: str = "") -> Dict[str, Any]:
    """
    Flatten nested JSON into dot-notation field paths.

    Supports:
    - already-flat UDM fields like "principal.user.userid"
    - nested JSON objects
    - lists/arrays
    """
    flattened = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            flattened.update(flatten_json(value, new_key))

    elif isinstance(data, list):
        for index, value in enumerate(data):
            new_key = f"{parent_key}[{index}]"
            flattened.update(flatten_json(value, new_key))

    else:
        flattened[parent_key] = data

    return flattened


def classify_udm_field(field: str) -> Dict[str, str]:
    """
    Classify a UDM field into a simple SOC triage role.
    This is the first version of our UDM ontology logic.
    """
    field_lower = field.lower()
    root_object = field.split(".")[0] if "." in field else field

    triage_role = "unknown"

    # Alert / detection context
    if "rule_name" in field_lower or "display_name" in field_lower:
        triage_role = "alert name / detection title"

    elif "rule_id" in field_lower:
        triage_role = "detection rule identifier"

    elif "summary" in field_lower or "description" in field_lower:
        triage_role = "alert explanation"

    elif "severity" in field_lower or "priority" in field_lower or "risk_score" in field_lower:
        triage_role = "severity / priority / risk"

    elif (
        "attack_details" in field_lower
        or "mitre" in field_lower
        or "tactic" in field_lower
        or "technique" in field_lower
    ):
        triage_role = "MITRE ATT&CK context"

    # UDM root objects
    elif field_lower.startswith("metadata."):
        triage_role = "event classification"

    elif field_lower.startswith("principal.user"):
        triage_role = "acting user"

    elif field_lower.startswith("principal.asset"):
        triage_role = "source host / acting asset"

    elif field_lower.startswith("principal.ip"):
        triage_role = "source IP / acting IP"

    elif field_lower.startswith("target."):
        triage_role = "target entity / destination"

    elif field_lower.startswith("src."):
        triage_role = "network source"

    elif field_lower.startswith("observer."):
        triage_role = "observing security/control system"

    elif field_lower.startswith("security_result."):
        triage_role = "security control result"

    # Process / execution evidence
    elif "parent_process" in field_lower:
        triage_role = "parent process evidence"

    elif "command_line" in field_lower:
        triage_role = "execution command evidence"

    elif "process" in field_lower:
        triage_role = "process evidence"

    # Network / IOC evidence
    elif "ip" in field_lower:
        triage_role = "ip address"

    elif "url" in field_lower:
        triage_role = "url"

    elif "domain" in field_lower or "hostname" in field_lower:
        triage_role = "host/domain evidence"

    elif (
        "hash" in field_lower
        or "sha256" in field_lower
        or "sha1" in field_lower
        or "md5" in field_lower
    ):
        triage_role = "file hash"

    return {
        "root_object": root_object,
        "triage_role": triage_role,
    }


def build_key_value_table(flattened: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Build a clean UDM key-value table for display and later AI context.

    Output example:
    [
      {
        "udm_field": "principal.user.userid",
        "value": "svc_backup",
        "root_object": "principal",
        "triage_role": "acting user"
      }
    ]
    """
    rows = []

    for field, value in flattened.items():
        classification = classify_udm_field(field)

        rows.append(
            {
                "udm_field": field,
                "value": str(value),
                "root_object": classification["root_object"],
                "triage_role": classification["triage_role"],
            }
        )

    return rows


def extract_entities(flattened: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extract basic SOC entities from flattened UDM-style fields.
    This is intentionally simple for the MVP.
    """
    entities = {
        "users": [],
        "hosts": [],
        "ips": [],
        "urls": [],
        "hashes": [],
        "processes": [],
        "command_lines": [],
        "mitre_techniques": [],
        "mitre_tactics": [],
        "alert_names": [],
        "rule_ids": [],
        "udm_fields": list(flattened.keys()),
    }

    for field, value in flattened.items():
        value_str = str(value)
        field_lower = field.lower()

        # IPs
        for ip in IP_REGEX.findall(value_str):
            entities["ips"].append(ip)

        # URLs
        for url in URL_REGEX.findall(value_str):
            entities["urls"].append(url)

        # Hashes
        for hash_value in HASH_REGEX.findall(value_str):
            entities["hashes"].append(hash_value)

        # Alert / rule fields
        if "rule_name" in field_lower or "display_name" in field_lower:
            if value_str:
                entities["alert_names"].append(value_str)

        if "rule_id" in field_lower:
            if value_str:
                entities["rule_ids"].append(value_str)

        # MITRE fields
        if "technique" in field_lower:
            if value_str:
                entities["mitre_techniques"].append(value_str)

        if "tactic" in field_lower:
            if value_str:
                entities["mitre_tactics"].append(value_str)

        # Users
        if "user" in field_lower and value_str:
            entities["users"].append(value_str)

        # Hosts
        if "hostname" in field_lower and value_str:
            entities["hosts"].append(value_str)

        # Processes
        if "process" in field_lower and value_str.lower().endswith(".exe"):
            entities["processes"].append(value_str)

        # Command lines
        if "command_line" in field_lower and value_str:
            entities["command_lines"].append(value_str)

    # Remove duplicates while preserving order
    for key, values in entities.items():
        if isinstance(values, list):
            entities[key] = list(dict.fromkeys(values))

    return entities