from typing import Any, Dict, List


def _dedupe(values: List[str]) -> List[str]:
    clean_values = []
    for value in values:
        if value is None:
            continue
        value = str(value).strip()
        if value:
            clean_values.append(value)
    return list(dict.fromkeys(clean_values))


def _quote(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def _regex_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace(".", "\\.")
        .replace("-", "\\-")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _collect_indicators(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
) -> Dict[str, List[str]]:
    hosts = entities.get("hosts", [])
    users = entities.get("users", [])
    ips = entities.get("ips", [])
    urls = entities.get("urls", [])
    hashes = entities.get("hashes", [])
    alert_names = entities.get("alert_names", [])
    rule_ids = entities.get("rule_ids", [])
    processes = entities.get("processes", [])
    command_lines = entities.get("command_lines", [])

    techniques = []
    for match in mitre_analysis.get("matches", []):
        for technique in match.get("techniques", []):
            if technique.get("id"):
                techniques.append(technique["id"])
            if technique.get("name"):
                techniques.append(technique["name"])

    # Also pull some high-value process strings directly from flattened fields.
    for field, value in flattened.items():
        field_lower = field.lower()
        value_str = str(value)

        if "process" in field_lower and value_str:
            processes.append(value_str)

        if "command_line" in field_lower and value_str:
            command_lines.append(value_str)

    return {
        "hosts": _dedupe(hosts),
        "users": _dedupe(users),
        "ips": _dedupe(ips),
        "urls": _dedupe(urls),
        "hashes": _dedupe(hashes),
        "alert_names": _dedupe(alert_names),
        "rule_ids": _dedupe(rule_ids),
        "processes": _dedupe(processes),
        "command_lines": _dedupe(command_lines),
        "techniques": _dedupe(techniques),
    }


def generate_hunt_queries(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
    attack_path: Dict[str, Any],
    lookback: str = "24h",
) -> Dict[str, str]:
    """
    Generates simple alert-centric validation queries.

    MVP principle:
    - Search for more related alerts first.
    - Use evidence we already have: host, user, IP, URL, hash, process, MITRE technique.
    - Keep queries readable and easy to adapt.
    """
    indicators = _collect_indicators(flattened, entities, mitre_analysis)

    all_terms = _dedupe(
        indicators["hosts"]
        + indicators["users"]
        + indicators["ips"]
        + indicators["urls"]
        + indicators["hashes"]
        + indicators["alert_names"]
        + indicators["rule_ids"]
        + indicators["processes"]
        + indicators["techniques"]
    )

    if not all_terms:
        all_terms = ["REPLACE_WITH_HOST_OR_USER_OR_IP"]

    kql_terms = ", ".join(_quote(term) for term in all_terms[:25])
    spl_terms = " OR ".join(_quote(term) for term in all_terms[:25])
    regex_terms = "|".join(_regex_escape(term) for term in all_terms[:20])

    first_host = indicators["hosts"][0] if indicators["hosts"] else "REPLACE_WITH_HOST"
    first_user = indicators["users"][0] if indicators["users"] else "REPLACE_WITH_USER"
    first_ip = indicators["ips"][0] if indicators["ips"] else "REPLACE_WITH_IP"

    kql = f"""// Microsoft Sentinel / Defender XDR - alert-centric validation hunt
let indicators = dynamic([{kql_terms}]);
SecurityAlert
| where TimeGenerated > ago({lookback})
| where tostring(Entities) has_any (indicators)
   or AlertName has_any (indicators)
   or Description has_any (indicators)
   or tostring(ExtendedProperties) has_any (indicators)
   or Techniques has_any (indicators)
| project TimeGenerated, AlertName, ProviderName, ProductName, Severity, Tactics, Techniques, Entities, Description
| order by TimeGenerated desc
"""

    spl = f"""# Splunk - alert-centric validation hunt
index=* earliest=-{lookback}
({spl_terms})
| table _time index sourcetype host user src src_ip dest dest_ip signature rule_name alert_name severity
| sort - _time
"""

    yara_l = f"""// Google SecOps YARA-L - prototype validation hunt
// Validate field names against your parser and UDM mapping before production use.
rule hunt_related_attack_path_alerts {{
  meta:
    description = "Hunt for alerts/events related to the current UDM triage evidence"
    author = "UDM Triage Lab"

  events:
    (
      $e.principal.asset.hostname = "{first_host}" or
      $e.principal.user.userid = "{first_user}" or
      $e.target.ip = "{first_ip}" or
      $e.principal.ip = "{first_ip}" or
      $e.security_result.rule_name = /{regex_terms}/ nocase or
      $e.principal.process.command_line = /{regex_terms}/ nocase
    )

  condition:
    $e
}}
"""

    logscale = f"""// CrowdStrike Next-Gen SIEM / LogScale-style validation hunt
#event_simpleName=/Alert|Detection|Incident|ProcessRollup2|SyntheticProcessRollup2/i
| /{regex_terms}/i
| table([@timestamp, event_simpleName, ComputerName, UserName, DetectName, Severity, CommandLine, ParentBaseFileName, ImageFileName, RemoteAddress])
| sort(@timestamp, order=desc)
"""

    explanation = f"""Validation objective:
Search for other alerts or security events involving the same host, user, IP, URL, process, command line, rule, or MITRE technique.

Current attack-path hypothesis:
{attack_path.get("summary", "No attack-path summary available.")}

Use this to answer:
1. Is this isolated to one alert?
2. Did the same host or user trigger earlier/later alerts?
3. Is there evidence of C2, discovery, persistence, credential access, lateral movement, or exfiltration?
4. Does the activity fit known admin behavior or a broader intrusion path?
"""

    return {
        "validation_objective": explanation,
        "kql": kql,
        "spl": spl,
        "yara_l": yara_l,
        "crowdstrike_ngsiem": logscale,
    }
