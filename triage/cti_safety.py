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
            "Reserved/documentation IP ranges such as 203.0.113.0/24 and 198.51.100.0/24 are not sent to CTI research.",
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
            "Reserved/documentation IP ranges such as 203.0.113.0/24 and 198.51.100.0/24 are not sent to CTI research.",
            "Raw command lines are not sent; only sanitized behavioral patterns are used.",
            "UDM field names are not sent as domains.",
        ],
    }


# ---------------------------------------------------------------------
# Override: IOC-only CTI package builder
# MITRE TTPs are intentionally excluded from CTI/IOC research.
# TTPs remain useful in alert-centric hunts, not IOC hunts.
# ---------------------------------------------------------------------
def build_safe_cti_research_package(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
    followup_evidence: str = "",
) -> Dict[str, Any]:
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

    commandline_patterns = _sanitize_command_patterns(combined_text)

    return {
        "public_ips": _dedupe(public_ips)[:10],
        "domains": _dedupe(domains)[:15],
        "urls": _dedupe(urls)[:10],
        "hashes": _dedupe(hashes)[:10],
        "sanitized_commandline_patterns": _dedupe(commandline_patterns)[:5],
        "blocked_data_notice": [
            "Hostnames are not sent to CTI research.",
            "Usernames are not sent to CTI research.",
            "Local file paths are not sent to CTI research.",
            "Process full paths are not sent to CTI research.",
            "Internal/private IP addresses are not sent to CTI research.",
            "Reserved/documentation IP ranges such as 203.0.113.0/24 and 198.51.100.0/24 are not sent to CTI research.",
            "Raw command lines are not sent; only sanitized behavioral patterns are used.",
            "UDM field names are not sent as domains.",
            "MITRE TTPs are not sent to CTI/IOC research; they remain in alert-centric hunts only.",
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
            "sanitized_commandline_patterns",
        ]
    )


# ---------------------------------------------------------------------
# Milestone 3.35 CTI safety override
# Purpose:
# - Prevent vendor console / detection URLs from becoming CTI IOCs.
# - Prevent customer IDs, agent IDs, tenant IDs, alert IDs from being treated as hashes.
# - Keep CTI focused on actual threat indicators.
# ---------------------------------------------------------------------

import ipaddress
import re
from urllib.parse import urlparse


_VENDOR_PORTAL_DOMAINS = {
    "falcon.crowdstrike.com",
    "crowdstrike.com",
    "security.microsoft.com",
    "portal.azure.com",
    "entra.microsoft.com",
    "securitycenter.microsoft.com",
    "splunk.com",
    "splunkcloud.com",
}


_TRACEABILITY_FIELD_MARKERS = [
    "customer",
    "customer_id",
    "tenant",
    "tenantid",
    "subscription",
    "subscriptionid",
    "workspace",
    "resourceid",
    "resource_id",
    "agent id",
    "agent_id",
    "asset_id",
    "vendororiginalid",
    "systemalertid",
    "correlation id",
    "correlation_id",
    "alert id",
    "alert_id",
    "detection id",
    "detection_id",
    "detection_url",
    "detection details",
    "full detection details",
    "alertlink",
    "alert link",
    "console",
    "portal",
    "case id",
    "case_id",
]


_URL_ALLOWED_FIELD_MARKERS = [
    "target.url",
    "target.domain",
    "network.http.request.url",
    "network.dns.questions.name",
    "network.dns.answers.data",
    "url",
    "domain",
    "dns",
]


_HASH_ALLOWED_FIELD_MARKERS = [
    "sha256",
    "sha1",
    "md5",
    "hash",
    "file.hash",
    "file.sha",
    "process.file.sha",
    "target.file.sha",
]


_HASH_BLOCKED_FIELD_MARKERS = [
    "agent",
    "asset",
    "customer",
    "tenant",
    "subscription",
    "workspace",
    "resource",
    "alert",
    "detection",
    "correlation",
    "vendor",
    "systemalert",
    "case",
    "id",
    "url",
    "link",
]


_COMMANDLINE_FIELD_MARKERS = [
    "command_line",
    "commandline",
    "cmdline",
    "process.command",
]


_DOMAIN_REGEX = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b"
)

_URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

_HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _cti_lower(value) -> str:
    return str(value or "").lower()


def _cti_is_traceability_field(field_name: str) -> bool:
    field_lower = _cti_lower(field_name)
    return any(marker in field_lower for marker in _TRACEABILITY_FIELD_MARKERS)


def _cti_is_vendor_portal_domain(domain: str) -> bool:
    domain = _cti_lower(domain).strip(".")

    for blocked in _VENDOR_PORTAL_DOMAINS:
        if domain == blocked or domain.endswith("." + blocked):
            return True

    return False


def _cti_is_public_ip(ip_value: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)

        return bool(ip.is_global)

    except Exception:
        return False


def _cti_event_context(flattened: dict) -> str:
    context_keys = [
        "metadata.event_type",
        "metadata.product_name",
        "metadata.vendor_name",
        "metadata.log_type",
        "security_result.rule_name",
        "security_result.summary",
        "security_result.description",
    ]

    values = []

    for key in context_keys:
        value = flattened.get(key)

        if value:
            values.append(str(value))

    return " ".join(values).lower()


def _cti_should_skip_principal_ip(field_name: str, flattened: dict) -> bool:
    """
    In EDR/process alerts, principal.ip is often the endpoint/host IP,
    not attacker infrastructure. For CTI, prefer target/destination IPs
    unless the event is clearly authentication/login/cloud access.
    """
    field_lower = _cti_lower(field_name)

    if field_lower != "principal.ip":
        return False

    context = _cti_event_context(flattened)

    auth_markers = [
        "login",
        "signin",
        "sign-in",
        "authentication",
        "user_login",
        "aad",
        "entra",
    ]

    edr_markers = [
        "process",
        "process_launch",
        "edr",
        "endpoint",
        "falcon",
        "crowdstrike",
        "defender for endpoint",
    ]

    if any(marker in context for marker in auth_markers):
        return False

    if any(marker in context for marker in edr_markers):
        return True

    return False


def _cti_field_allows_url_or_domain(field_name: str) -> bool:
    field_lower = _cti_lower(field_name)

    if _cti_is_traceability_field(field_lower):
        return False

    return any(marker in field_lower for marker in _URL_ALLOWED_FIELD_MARKERS)


def _cti_field_allows_hash(field_name: str) -> bool:
    field_lower = _cti_lower(field_name)

    if any(marker in field_lower for marker in _HASH_BLOCKED_FIELD_MARKERS):
        # Allow explicit file/process hash fields even if they include words like process/file.
        if "sha256" in field_lower or "sha1" in field_lower or "md5" in field_lower:
            return True

        return False

    return any(marker in field_lower for marker in _HASH_ALLOWED_FIELD_MARKERS)


def _cti_normalize_url(url: str) -> str:
    return url.strip().rstrip(".,);]")


def _cti_extract_domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""

    except Exception:
        return ""


def _cti_sanitize_commandline(value: str) -> list[str]:
    text = _cti_lower(value)
    patterns = []

    if "powershell" in text and ("encodedcommand" in text or " -enc " in text):
        patterns.append("powershell encodedcommand -enc nop")

    if "certutil" in text and "urlcache" in text:
        patterns.append("certutil urlcache download")

    if "bitsadmin" in text:
        patterns.append("bitsadmin file transfer")

    if "mshta" in text:
        patterns.append("mshta script execution")

    if "rundll32" in text:
        patterns.append("rundll32 suspicious execution")

    if "regsvr32" in text:
        patterns.append("regsvr32 suspicious execution")

    if "schtasks" in text:
        patterns.append("scheduled task creation")

    return patterns


def _cti_unique(values: list[str]) -> list[str]:
    clean = []

    for value in values:
        value = str(value).strip()

        if not value:
            continue

        if value not in clean:
            clean.append(value)

    return clean


def build_safe_cti_research_package(
    flattened: dict,
    entities: dict | None = None,
    mitre_analysis: dict | None = None,
    followup_evidence: str = "",
) -> dict:
    """
    Build a CTI-safe IOC package.

    Important:
    This function is intentionally field-aware. It does not treat every URL,
    domain, GUID, or 32-character hex value as a threat indicator.
    """
    entities = entities or {}
    mitre_analysis = mitre_analysis or {}

    public_ips = []
    domains = []
    urls = []
    hashes = []
    sanitized_commandline_patterns = []

    for field_name, value in flattened.items():
        if value is None:
            continue

        field_lower = _cti_lower(field_name)
        value_text = str(value)

        if not value_text.strip():
            continue

        # Command line handling: do not send raw command lines.
        if any(marker in field_lower for marker in _COMMANDLINE_FIELD_MARKERS):
            sanitized_commandline_patterns.extend(_cti_sanitize_commandline(value_text))
            continue

        # IP handling.
        for ip_candidate in _IP_REGEX.findall(value_text):
            if not _cti_is_public_ip(ip_candidate):
                continue

            if _cti_is_traceability_field(field_name):
                continue

            if _cti_should_skip_principal_ip(field_name, flattened):
                continue

            public_ips.append(ip_candidate)

        # URL/domain handling.
        if _cti_field_allows_url_or_domain(field_name):
            for url_candidate in _URL_REGEX.findall(value_text):
                normalized_url = _cti_normalize_url(url_candidate)
                domain = _cti_extract_domain_from_url(normalized_url)

                if domain and _cti_is_vendor_portal_domain(domain):
                    continue

                urls.append(normalized_url)

                if domain:
                    domains.append(domain)

            for domain_candidate in _DOMAIN_REGEX.findall(value_text):
                domain_candidate = domain_candidate.strip().lower()

                if _cti_is_vendor_portal_domain(domain_candidate):
                    continue

                # Avoid treating UDM-looking field fragments as domains.
                if domain_candidate.startswith(
                    (
                        "metadata.",
                        "principal.",
                        "target.",
                        "security_result.",
                        "network.",
                        "process.",
                        "file.",
                        "additional.",
                        "extensions.",
                    )
                ):
                    continue

                domains.append(domain_candidate)

        # Hash handling.
        if _cti_field_allows_hash(field_name):
            for hash_candidate in _HASH_REGEX.findall(value_text):
                # Avoid extracting IDs out of URLs or traceability strings.
                if "http://" in value_text.lower() or "https://" in value_text.lower():
                    continue

                hashes.append(hash_candidate.lower())

    return {
        "public_ips": _cti_unique(public_ips),
        "domains": _cti_unique(domains),
        "urls": _cti_unique(urls),
        "hashes": _cti_unique(hashes),
        "sanitized_commandline_patterns": _cti_unique(sanitized_commandline_patterns),
        "blocked_data_notice": [
            "Hostnames are not sent to CTI research.",
            "Usernames are not sent to CTI research.",
            "Local file paths are not sent to CTI research.",
            "Process full paths are not sent to CTI research.",
            "Internal/private IP addresses are not sent to CTI research.",
            "Reserved/documentation IP ranges such as 203.0.113.0/24 and 198.51.100.0/24 are not sent to CTI research.",
            "Raw command lines are not sent; only sanitized behavioral patterns are used.",
            "UDM field names are not sent as domains.",
            "MITRE TTPs are not sent to CTI/IOC research; they remain in alert-centric hunts only.",
            "Vendor console URLs and detection links are not sent to CTI research.",
            "Customer IDs, tenant IDs, agent IDs, alert IDs, and detection IDs are not treated as file hashes.",
            "For EDR/process alerts, principal.ip is treated as endpoint context and is not automatically sent as CTI infrastructure.",
        ],
    }


def has_cti_researchable_indicators(cti_package: dict) -> bool:
    if not cti_package:
        return False

    searchable_keys = [
        "public_ips",
        "domains",
        "urls",
        "hashes",
        "sanitized_commandline_patterns",
    ]

    for key in searchable_keys:
        if cti_package.get(key):
            return True

    return False

