import ipaddress
import re
from typing import Any, Dict, List


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
URL_REGEX = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b(?!(?:exe|dll|ps1|docx|docm|xlsx|tmp|log|json|xml|txt)\b)"
    r"(?:[a-zA-Z0-9-]{2,63}\.)+[a-zA-Z]{2,24}\b"
)

PRIVATE_DOMAIN_SUFFIXES = [
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
    ".intra",
]


COMMAND_PATTERN_TERMS = [
    "powershell",
    "encodedcommand",
    "-enc",
    "nop",
    "hidden",
    "executionpolicy bypass",
    "invoke-webrequest",
    "iwr",
    "invoke-expression",
    "iex",
    "downloadstring",
    "certutil",
    "urlcache",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "schtasks",
    "comsvcs.dll",
    "minidump",
    "lsass",
    "winword",
    "excel",
    "office",
    "macro",
    "scheduled task",
]


def _dedupe(values: List[str]) -> List[str]:
    clean = []
    for value in values:
        if value is None:
            continue
        value = str(value).strip().strip(",;")
        if value:
            clean.append(value)
    return list(dict.fromkeys(clean))


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except ValueError:
        return False


def _normalize_defanged(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )


def _looks_like_local_path(value: str) -> bool:
    value_lower = value.lower()
    return (
        ":\\" in value_lower
        or value_lower.startswith("\\\\")
        or "/users/" in value_lower
        or "/home/" in value_lower
        or "/var/" in value_lower
        or "/etc/" in value_lower
        or "/program files/" in value_lower
        or "c:\\users\\" in value_lower
        or "c:\\programdata\\" in value_lower
        or "c:\\windows\\" in value_lower
    )


def _is_private_domain(domain: str) -> bool:
    domain_lower = domain.lower()
    return any(domain_lower.endswith(suffix) for suffix in PRIVATE_DOMAIN_SUFFIXES)


def _extract_public_ips(text: str) -> List[str]:
    return _dedupe([ip for ip in IP_REGEX.findall(text) if _is_public_ip(ip)])


def _extract_hashes(text: str) -> List[str]:
    return _dedupe(HASH_REGEX.findall(text))


def _extract_urls(text: str) -> List[str]:
    urls = []
    for url in URL_REGEX.findall(text):
        if _looks_like_local_path(url):
            continue
        urls.append(url)
    return _dedupe(urls)


def _extract_domains(text: str) -> List[str]:
    domains = []

    normalized = _normalize_defanged(text)

    for domain in DOMAIN_REGEX.findall(normalized):
        domain = domain.lower()

        if _is_private_domain(domain):
            continue

        if _looks_like_local_path(domain):
            continue

        # Avoid extracting local Windows path fragments or obvious file names.
        if domain.endswith((".exe", ".dll", ".ps1", ".docm", ".docx", ".xlsx")):
            continue

        domains.append(domain)

    return _dedupe(domains)


def _extract_techniques(mitre_analysis: Dict[str, Any]) -> List[str]:
    techniques = []

    for match in mitre_analysis.get("matches", []):
        for technique in match.get("techniques", []):
            if technique.get("id"):
                techniques.append(technique["id"])
            if technique.get("name"):
                techniques.append(technique["name"])

    return _dedupe(techniques)


def _sanitize_command_patterns(text: str) -> List[str]:
    text_lower = text.lower()

    found_terms = []
    for term in COMMAND_PATTERN_TERMS:
        if term in text_lower:
            found_terms.append(term)

    if not found_terms:
        return []

    # Do not include raw paths, filenames, usernames, hostnames, or full command lines.
    return [" ".join(_dedupe(found_terms))]


def build_safe_cti_research_package(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
    followup_evidence: str = "",
) -> Dict[str, Any]:
    """
    Build a privacy-conscious CTI research package.

    This package intentionally excludes:
    - usernames
    - hostnames
    - local file paths
    - process full paths
    - raw command lines
    - internal/private IPs
    """
    flattened_text = "\n".join(f"{field}={value}" for field, value in flattened.items())
    combined_text = f"{flattened_text}\n{followup_evidence or ''}"

    public_ips = _dedupe(
        entities.get("ips", []) + _extract_public_ips(combined_text)
    )
    public_ips = [ip for ip in public_ips if _is_public_ip(ip)]

    hashes = _dedupe(
        entities.get("hashes", []) + _extract_hashes(combined_text)
    )

    urls = _dedupe(
        entities.get("urls", []) + _extract_urls(combined_text)
    )

    domains = _extract_domains(combined_text)

    # Remove domains already present inside URLs if duplicated; keeping them is okay but this reduces noise.
    normalized_urls = [_normalize_defanged(url).lower() for url in urls]
    domains = [
        domain for domain in domains
        if not any(domain in url for url in normalized_urls) or domain not in ["local"]
    ]

    techniques = _extract_techniques(mitre_analysis)
    commandline_patterns = _sanitize_command_patterns(combined_text)

    return {
        "public_ips": _dedupe(public_ips)[:10],
        "domains": _dedupe(domains)[:15],
        "urls": _dedupe(urls)[:10],
        "hashes": _dedupe(hashes)[:10],
        "mitre_techniques": _dedupe(techniques)[:15],
        "sanitized_commandline_patterns": _dedupe(commandline_patterns)[:5],
        "blocked_data_notice": [
            "Hostnames are not sent to CTI research.",
            "Usernames are not sent to CTI research.",
            "Local file paths are not sent to CTI research.",
            "Process full paths are not sent to CTI research.",
            "Internal/private IP addresses are not sent to CTI research.",
            "Raw command lines are not sent; only sanitized behavioral patterns are used.",
        ],
    }


def has_cti_researchable_indicators(cti_package: Dict[str, Any]) -> bool:
    return any(
        cti_package.get(key)
        for key in [
            "public_ips",
            "domains",
            "urls",
            "hashes",
            "mitre_techniques",
            "sanitized_commandline_patterns",
        ]
    )

# ---------------------------------------------------------------------
# Override: safer CTI package builder
# Fixes accidental extraction of UDM field names such as principal.user.userid
# as domains. Only values are searched, not field/key names.
# ---------------------------------------------------------------------
def build_safe_cti_research_package(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
    followup_evidence: str = "",
) -> Dict[str, Any]:
    """
    Build a privacy-conscious CTI research package.

    Important:
    - Searches values, not UDM field names.
    - Excludes usernames, hostnames, local paths, process full paths, raw commands,
      and private/internal IPs.
    """
    values_text = "\n".join(
        str(value)
        for value in flattened.values()
        if value is not None
    )

    combined_text = f"{values_text}\n{followup_evidence or ''}"

    public_ips = _dedupe(
        entities.get("ips", []) + _extract_public_ips(combined_text)
    )
    public_ips = [ip for ip in public_ips if _is_public_ip(ip)]

    hashes = _dedupe(
        entities.get("hashes", []) + _extract_hashes(combined_text)
    )

    urls = _dedupe(
        entities.get("urls", []) + _extract_urls(combined_text)
    )

    domains = _extract_domains(combined_text)

    # Extra guardrail: never send UDM-style field names as domains.
    blocked_domain_fragments = [
        "principal.",
        "security_result.",
        "metadata.",
        "target.",
        "process.",
        "asset.",
        "user.",
        "file.",
    ]

    domains = [
        domain for domain in domains
        if not any(fragment in domain for fragment in blocked_domain_fragments)
    ]

    techniques = _extract_techniques(mitre_analysis)
    commandline_patterns = _sanitize_command_patterns(combined_text)

    return {
        "public_ips": _dedupe(public_ips)[:10],
        "domains": _dedupe(domains)[:15],
        "urls": _dedupe(urls)[:10],
        "hashes": _dedupe(hashes)[:10],
        "mitre_techniques": _dedupe(techniques)[:15],
        "sanitized_commandline_patterns": _dedupe(commandline_patterns)[:5],
        "blocked_data_notice": [
            "Hostnames are not sent to CTI research.",
            "Usernames are not sent to CTI research.",
            "Local file paths are not sent to CTI research.",
            "Process full paths are not sent to CTI research.",
            "Internal/private IP addresses are not sent to CTI research.",
            "Raw command lines are not sent; only sanitized behavioral patterns are used.",
            "UDM field names are not sent as domains.",
        ],
    }
