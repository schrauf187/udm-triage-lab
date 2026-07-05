import json
import re
from typing import Any, Dict, List, Tuple


KNOWN_TEXT_LABELS = [
    "Description",
    "Customer ID",
    "Full detection details",
    "Detected",
    "Host name",
    "Agent ID",
    "File name",
    "File path",
    "Command line",
    "SHA 256",
    "SHA256",
    "MD5 Hash",
    "MD5",
    "Platform",
    "IP address",
    "User name",
    "User",
    "Hostname",
    "AlertName",
    "AlertSeverity",
    "ProviderName",
    "ProductName",
    "Tactics",
    "Techniques",
    "Entities",
    "ExtendedProperties",
]


SENSITIVE_FIELD_MARKERS = [
    "tenant",
    "subscription",
    "customer id",
    "customer_id",
    "resourceid",
    "workspace",
    "agent id",
    "detection details",
    "detection_url",
    "url",
    "query",
    "command line",
    "file path",
    "hostname",
    "host name",
    "user name",
    "email",
    "account",
]


GUID_REGEX = re.compile(
    r"\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b"
)

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

HASH_REGEX = re.compile(
    r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
)


# Top-level namespaces commonly seen at the start of vendor / UDM-ish field keys.
# Used only as one signal for "does this line look like a key?" when detecting the
# alternating key/value dump format (see _try_parse_kv_dump).
KV_KEY_NAMESPACES = {
    "vendor", "process", "host", "user", "event", "threat", "source",
    "destination", "agent", "file", "network", "metadata", "security_result",
    "principal", "target", "cps", "ecs", "ngsiem", "parser", "repo", "type",
    "cloud", "url", "dns", "http", "registry", "observer", "related",
}


def _known_ontology_fields() -> set:
    """
    Best-effort set of known ontology field names, used only as a soft signal for
    key detection. Wrapped so it can never break extraction if the ontology module
    changes or fails to import.
    """
    global _ONTOLOGY_FIELDS_CACHE
    try:
        return _ONTOLOGY_FIELDS_CACHE
    except NameError:
        pass
    try:
        from triage.ontology import load_ontology
        _ONTOLOGY_FIELDS_CACHE = set(load_ontology().keys())
    except Exception:
        _ONTOLOGY_FIELDS_CACHE = set()
    return _ONTOLOGY_FIELDS_CACHE


def _is_key_like(line: str) -> bool:
    """
    Heuristic: does this line look like a field KEY (rather than a value)?

    Signals (any one is enough): starts with # or @ (vendor prefixes), contains a
    dot (dotted field path), first token is a known SOC namespace, or the whole
    line matches a known ontology field name. Deliberately does not require the
    value line to be non-key-like — pairing is by position, this only scores the
    key positions to validate the alternating-dump hypothesis.
    """
    key = line.strip()
    if not key:
        return False
    if key.startswith("#") or key.startswith("@"):
        return True
    if "." in key:
        return True
    first_token = re.split(r"[.\s]", key.lstrip("#@"), 1)[0].lower()
    if first_token in KV_KEY_NAMESPACES:
        return True
    if key in _known_ontology_fields():
        return True
    return False


def _try_parse_kv_dump(raw_text: str):
    """
    Detect and parse an alternating-line key/value dump — the format produced when
    an analyst copies an alert out of a vendor UI table (CrowdStrike / Sentinel /
    Splunk field views): key on one line, value on the next, no : or = separators.

    Returns {"raw_fields": {...}, "warnings": [...]} when the input clearly matches
    this format, otherwise None so the caller falls through to existing parsers.
    Keys are preserved verbatim (internal spaces, #/@ prefixes, [0] suffixes).
    Empty values are allowed. Values that happen to be JSON are kept as strings.
    """
    lines = [ln.rstrip() for ln in raw_text.splitlines()]

    # Trim leading and trailing blank lines.
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    # Strip a leading repeated "Key" / "Value" header pasted from a UI table.
    while (
        len(lines) >= 2
        and lines[0].strip().lower() == "key"
        and lines[1].strip().lower() == "value"
    ):
        lines = lines[2:]

    non_empty = [ln for ln in lines if ln.strip()]
    if len(non_empty) < 6:
        return None

    # Structural gate: a clear majority of lines must be separator-free. Colon /
    # equals formats, labelled blocks, and JSON are all separator-heavy and fail here.
    sep_free = sum(1 for ln in non_empty if ":" not in ln and "=" not in ln)
    if sep_free / len(non_empty) < 0.6:
        return None

    # Pair by position; score how many key-position lines actually look like keys.
    pairs: List[Tuple[str, str]] = []
    key_positions = 0
    key_like = 0
    unpaired = 0

    i = 0
    while i < len(lines):
        key = lines[i].strip()
        if not key:
            # Blank in a key position can't start a pair.
            unpaired += 1
            i += 1
            continue
        value = lines[i + 1].strip() if i + 1 < len(lines) else ""
        pairs.append((key, value))
        key_positions += 1
        if _is_key_like(key):
            key_like += 1
        i += 2

    if key_positions == 0:
        return None

    ratio = key_like / key_positions

    # Choose this parser only on a clear majority of key-like keys, so JSON and other
    # formats that slip past the structural gate are still not misrouted here.
    if ratio < 0.6:
        return None

    raw_fields: Dict[str, str] = {}
    for key, value in pairs:
        raw_fields[key] = value

    warnings: List[str] = []
    unclean = (key_positions - key_like) + unpaired
    if ratio < 0.7 or unpaired > 0:
        warnings.append(
            f"Input looks like a key/value dump but {unclean} line(s) could not be "
            "paired cleanly. Review the extracted fields below before using them."
        )

    return {"raw_fields": raw_fields, "warnings": warnings}


def flatten_any(data: Any, prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested JSON-like structures into dot/key paths.

    Example:
    {"Entities": [{"Type": "account", "AccountName": "x"}]}
    -> Entities[0].Type = account
    -> Entities[0].AccountName = x
    """
    flattened: Dict[str, Any] = {}

    if isinstance(data, dict):
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten_any(value, new_key))

    elif isinstance(data, list):
        for index, value in enumerate(data):
            new_key = f"{prefix}[{index}]"
            flattened.update(flatten_any(value, new_key))

    else:
        flattened[prefix] = data

    return flattened


def _try_json_loads(value: str):
    try:
        return json.loads(value)
    except Exception:
        return None


def _expand_json_strings(flattened: Dict[str, Any]) -> Dict[str, Any]:
    """
    Some products store JSON objects as strings, for example Sentinel Entities
    and ExtendedProperties. This expands those when possible.
    """
    expanded = dict(flattened)

    for key, value in list(flattened.items()):
        if not isinstance(value, str):
            continue

        stripped = value.strip()

        if not (
            (stripped.startswith("{") and stripped.endswith("}"))
            or (stripped.startswith("[") and stripped.endswith("]"))
        ):
            continue

        parsed = _try_json_loads(stripped)

        if parsed is None:
            continue

        nested = flatten_any(parsed, key)
        expanded.update(nested)

    return expanded


def _extract_embedded_json(raw_text: str):
    """
    Extract the first JSON object/array embedded in free text (e.g. a JSON blob
    inside a vendor log line). Whole-text JSON is handled separately by the caller
    so that this greedy fallback runs only after key/value-dump detection.
    """
    text = raw_text.strip()

    first_object = text.find("{")
    first_array = text.find("[")

    candidates = [idx for idx in [first_object, first_array] if idx != -1]
    if not candidates:
        return None

    start = min(candidates)

    decoder = json.JSONDecoder()

    try:
        parsed, _ = decoder.raw_decode(text[start:])
        return parsed
    except Exception:
        return None


def _extract_known_label_blocks(raw_text: str) -> Dict[str, str]:
    """
    Extract labelled vendor text such as:
    Host name: DESKTOP-123
    Agent ID: abc
    Command line: powershell.exe ...
    """
    fields: Dict[str, str] = []

    # Build regex matching known labels followed by colon.
    label_pattern = "|".join(re.escape(label) for label in sorted(KNOWN_TEXT_LABELS, key=len, reverse=True))
    regex = re.compile(rf"(?im)(^|\s)({label_pattern})\s*:", re.MULTILINE)

    matches = list(regex.finditer(raw_text))

    extracted: Dict[str, str] = {}

    for index, match in enumerate(matches):
        label = match.group(2).strip()
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(raw_text)

        value = raw_text[value_start:value_end].strip()

        if value:
            extracted[label] = value

    return extracted


def _extract_generic_key_values(raw_text: str) -> Dict[str, str]:
    """
    Extract simple key=value or key: value lines.
    This is intentionally conservative to avoid producing noisy fields.
    """
    extracted: Dict[str, str] = {}

    for line in raw_text.splitlines():
        clean = line.strip()

        if not clean:
            continue

        if len(clean) > 500:
            continue

        match = re.match(r"^([A-Za-z0-9_.\-/\[\] ]{2,80})\s*[:=]\s*(.+)$", clean)

        if not match:
            continue

        key = match.group(1).strip()
        value = match.group(2).strip()

        if key and value:
            extracted[key] = value

    return extracted


def parse_raw_alert_content(raw_text: str) -> Dict[str, Any]:
    """
    Parse raw alert content into extracted key-value fields.
    Supports:
    - JSON
    - JSON embedded in text
    - vendor key-value text dumps
    - labelled EDR/SIEM alert text
    """
    raw_text = raw_text or ""
    raw_text = raw_text.strip()

    if not raw_text:
        return {
            "input_type": "empty",
            "raw_fields": {},
            "flattened_fields": {},
            "warnings": [],
        }

    # 1. Whole-text JSON — unchanged behaviour for real JSON input.
    whole_json = _try_json_loads(raw_text)
    if whole_json is not None:
        flattened = flatten_any(whole_json)
        flattened = _expand_json_strings(flattened)

        return {
            "input_type": "json",
            "raw_fields": flattened,
            "flattened_fields": flattened,
            "warnings": [],
        }

    # 2. Alternating key/value dump (copied from a vendor UI table). Runs BEFORE the
    #    greedy embedded-JSON fallback, which otherwise grabs a stray {"...":null}
    #    snippet and reports an empty inventory as "json" input.
    kv_dump = _try_parse_kv_dump(raw_text)
    if kv_dump is not None:
        raw_fields = kv_dump["raw_fields"]
        return {
            "input_type": "key_value_dump",
            "raw_fields": raw_fields,
            "flattened_fields": raw_fields,
            "warnings": kv_dump.get("warnings", []),
        }

    # 3. JSON embedded inside free text (unchanged fallback).
    embedded_json = _extract_embedded_json(raw_text)
    if embedded_json is not None:
        flattened = flatten_any(embedded_json)
        flattened = _expand_json_strings(flattened)

        return {
            "input_type": "json",
            "raw_fields": flattened,
            "flattened_fields": flattened,
            "warnings": [],
        }

    label_fields = _extract_known_label_blocks(raw_text)
    generic_fields = _extract_generic_key_values(raw_text)

    raw_fields = {}
    raw_fields.update(generic_fields)
    raw_fields.update(label_fields)

    if not raw_fields:
        raw_fields = {
            "raw_alert_text": raw_text,
        }

    return {
        "input_type": "text",
        "raw_fields": raw_fields,
        "flattened_fields": raw_fields,
        "warnings": [],
    }


def _value_type(value: Any) -> str:
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "boolean"

    if isinstance(value, int):
        return "integer"

    if isinstance(value, float):
        return "number"

    value_text = str(value)

    if GUID_REGEX.search(value_text):
        return "guid"

    if EMAIL_REGEX.search(value_text):
        return "email"

    if IP_REGEX.search(value_text):
        return "ip_or_text"

    if HASH_REGEX.search(value_text):
        return "hash_or_text"

    if value_text.startswith("http://") or value_text.startswith("https://"):
        return "url"

    if len(value_text) > 1000:
        return "long_text"

    return "string"


def _sensitivity_for_field(field_name: str, value: Any) -> str:
    field_lower = field_name.lower()
    value_text = str(value)

    if any(marker in field_lower for marker in SENSITIVE_FIELD_MARKERS):
        return "medium"

    if GUID_REGEX.search(value_text):
        return "medium"

    if EMAIL_REGEX.search(value_text):
        return "medium"

    if "\\users\\" in value_text.lower():
        return "high"

    if "encodedcommand" in value_text.lower() or "-encodedcommand" in value_text.lower():
        return "medium"

    if len(value_text) > 3000:
        return "medium"

    return "low"


def _preview_value(value: Any, max_length: int = 350) -> str:
    text = str(value)

    if len(text) <= max_length:
        return text

    return text[:max_length] + "...[truncated]"


def build_field_inventory(raw_fields: Dict[str, Any]) -> List[Dict[str, Any]]:
    inventory = []

    for field_name, value in raw_fields.items():
        if value is None:
            continue

        value_text = str(value)

        if not value_text.strip():
            continue

        sensitivity = _sensitivity_for_field(field_name, value)

        inventory.append(
            {
                "source_field": field_name,
                "value_preview": _preview_value(value),
                "value_type": _value_type(value),
                "sensitivity": sensitivity,
                "length": len(value_text),
            }
        )

    return inventory


def parse_raw_alert_to_field_inventory(raw_text: str) -> Dict[str, Any]:
    parsed = parse_raw_alert_content(raw_text)
    raw_fields = parsed.get("raw_fields", {})
    inventory = build_field_inventory(raw_fields)

    return {
        "input_type": parsed.get("input_type", "unknown"),
        "raw_fields": raw_fields,
        "inventory": inventory,
        "field_count": len(raw_fields),
        "warnings": parsed.get("warnings", []),
    }
