import re
from typing import Any, Dict, List


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\"']+")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def flatten_json(data: Any, parent_key: str = "") -> Dict[str, Any]:
    """
    Flattens nested JSON into dot-notation field paths.

    Example:
    {
      "principal": {
        "user": {
          "userid": "svc_backup"
        }
      }
    }

    becomes:
    {
      "principal.user.userid": "svc_backup"
    }
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


def extract_entities(flattened: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Extracts basic SOC entities from flattened UDM-style fields.
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
        "udm_fields": list(flattened.keys()),
    }

    for field, value in flattened.items():
        value_str = str(value)

        # IPs
        for ip in IP_REGEX.findall(value_str):
            entities["ips"].append(ip)

        # URLs
        for url in URL_REGEX.findall(value_str):
            entities["urls"].append(url)

        # Hashes
        for hash_value in HASH_REGEX.findall(value_str):
            entities["hashes"].append(hash_value)

        # Users
        if "user" in field.lower() and value_str:
            entities["users"].append(value_str)

        # Hosts
        if "hostname" in field.lower() and value_str:
            entities["hosts"].append(value_str)

        # Processes
        if "process" in field.lower() and value_str.endswith(".exe"):
            entities["processes"].append(value_str)

        # Command lines
        if "command_line" in field.lower() and value_str:
            entities["command_lines"].append(value_str)

    # Remove duplicates while preserving order
    for key, values in entities.items():
        if isinstance(values, list):
            entities[key] = list(dict.fromkeys(values))

    return entities