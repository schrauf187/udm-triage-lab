from typing import Any, Dict, List


KILL_CHAIN_PHASES = [
    {
        "phase": "Initial Access",
        "description": "How the attacker may have entered the environment.",
        "hunt_focus": "Look for phishing, malicious document delivery, suspicious downloads, VPN/authentication anomalies.",
    },
    {
        "phase": "Execution",
        "description": "Code or commands executed on a system.",
        "hunt_focus": "Look for suspicious process execution, scripts, command-line abuse, LOLBins, parent-child process anomalies.",
    },
    {
        "phase": "Defense Evasion",
        "description": "Attempts to hide, encode, bypass controls, or blend into normal activity.",
        "hunt_focus": "Look for encoded commands, LOLBins, disabled logging, suspicious script flags, masquerading.",
    },
    {
        "phase": "Command and Control",
        "description": "Outbound communication to attacker-controlled or suspicious infrastructure.",
        "hunt_focus": "Look for external connections, rare domains/IPs, beaconing, unusual user-agent strings, suspicious DNS.",
    },
    {
        "phase": "Discovery",
        "description": "Enumeration of users, hosts, domains, shares, processes, or security tools.",
        "hunt_focus": "Look for whoami, net, nltest, ipconfig, systeminfo, discovery PowerShell, AD queries.",
    },
    {
        "phase": "Credential Access",
        "description": "Attempts to access passwords, hashes, tokens, browser credentials, or secrets.",
        "hunt_focus": "Look for LSASS access, credential dumping tools, suspicious vault access, token theft indicators.",
    },
    {
        "phase": "Persistence",
        "description": "Mechanisms used to survive reboot or maintain access.",
        "hunt_focus": "Look for scheduled tasks, services, registry run keys, startup folders, WMI subscriptions.",
    },
    {
        "phase": "Lateral Movement",
        "description": "Movement from one system to another.",
        "hunt_focus": "Look for remote service creation, RDP, SMB, WinRM, PsExec-like behavior, remote PowerShell.",
    },
    {
        "phase": "Collection",
        "description": "Staging or collecting data before exfiltration.",
        "hunt_focus": "Look for archive creation, access to sensitive folders, staging directories, mass file reads.",
    },
    {
        "phase": "Exfiltration",
        "description": "Data leaving the environment.",
        "hunt_focus": "Look for large outbound transfers, unusual destinations, cloud uploads, compression followed by egress.",
    },
    {
        "phase": "Impact",
        "description": "Destructive, disruptive, or ransomware-like activity.",
        "hunt_focus": "Look for encryption, deletion, service stops, shadow copy deletion, mass file modification.",
    },
]


OFFICE_PROCESS_HINTS = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
]


def _dedupe(values: List[str]) -> List[str]:
    return list(dict.fromkeys([value for value in values if value]))


def _lower_values(flattened: Dict[str, Any]) -> str:
    return " ".join(str(value).lower() for value in flattened.values())


def _field_value_contains(flattened: Dict[str, Any], field_hint: str, value_hint: str) -> bool:
    for field, value in flattened.items():
        if field_hint.lower() in field.lower() and value_hint.lower() in str(value).lower():
            return True
    return False


def _extract_technique_ids(
    mitre_analysis: Dict[str, Any],
    enriched_techniques: List[Dict[str, Any]],
) -> List[str]:
    technique_ids = []

    for match in mitre_analysis.get("matches", []):
        for technique in match.get("techniques", []):
            if technique.get("id"):
                technique_ids.append(technique["id"])

    for technique in enriched_techniques:
        if technique.get("id"):
            technique_ids.append(technique["id"])

    return _dedupe(technique_ids)


def _collect_actor_context(enriched_techniques: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    groups = []
    software = []

    for technique in enriched_techniques:
        groups.extend(technique.get("known_groups", []) or [])
        software.extend(technique.get("known_software", []) or [])

    return {
        "known_groups_context": _dedupe(groups)[:20],
        "known_software_context": _dedupe(software)[:20],
    }


def build_attack_path_hypothesis(
    flattened: Dict[str, Any],
    entities: Dict[str, List[str]],
    mitre_analysis: Dict[str, Any],
    enriched_techniques: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Builds a cautious attack-path hypothesis from available alert evidence.

    Important:
    - Observed means directly visible in the alert evidence.
    - Possible previous means it may have happened before this alert.
    - Possible next means it may follow from this alert and should be validated.
    - Known actor/software overlap is context only, not attribution.
    """
    all_values_lower = _lower_values(flattened)
    technique_ids = _extract_technique_ids(mitre_analysis, enriched_techniques)

    observed_phases = []
    possible_previous_phases = []
    possible_next_phases = []
    later_stage_hunt_phases = []

    evidence_by_phase = {phase["phase"]: [] for phase in KILL_CHAIN_PHASES}
    techniques_by_phase = {phase["phase"]: [] for phase in KILL_CHAIN_PHASES}

    has_powershell = "powershell.exe" in all_values_lower or "powershell" in all_values_lower
    has_office_parent = any(process in all_values_lower for process in OFFICE_PROCESS_HINTS)
    has_encoded = "-enc" in all_values_lower or "encoded" in all_values_lower or "base64" in all_values_lower
    has_network_indicator = bool(entities.get("ips") or entities.get("urls"))

    # Execution: directly observed when process/command evidence exists.
    if has_powershell:
        observed_phases.append("Execution")
        evidence_by_phase["Execution"].append("PowerShell execution observed")
        techniques_by_phase["Execution"].extend(
            [tid for tid in technique_ids if tid in ["T1059", "T1059.001"]]
        )

    if has_office_parent:
        observed_phases.append("Execution")
        evidence_by_phase["Execution"].append("Office parent process observed")
        techniques_by_phase["Execution"].append("T1204")

        # Cautious: Office parent suggests possible document/user-execution chain,
        # but does not prove phishing or initial access.
        possible_previous_phases.append("Initial Access")
        evidence_by_phase["Initial Access"].append(
            "Office parent process may indicate document-based execution, but delivery vector is not confirmed"
        )
        techniques_by_phase["Initial Access"].append("T1204")

    # Defense evasion: directly observed when encoded/obfuscated command content exists.
    if has_encoded:
        observed_phases.append("Defense Evasion")
        evidence_by_phase["Defense Evasion"].append("Encoded or obfuscated command content observed")
        techniques_by_phase["Defense Evasion"].extend(
            [tid for tid in technique_ids if tid in ["T1027", "T1112", "T1218", "T1218.005", "T1218.011"]]
        )

    # Command and Control: do NOT mark as observed just because an IP exists.
    # IP/URL means "needs validation" unless your future parser confirms network connection/C2 semantics.
    if has_network_indicator:
        possible_next_phases.append("Command and Control")
        evidence_by_phase["Command and Control"].append(
            "Network destination indicator exists, but C2 communication is not confirmed"
        )
        if "T1071" in technique_ids:
            techniques_by_phase["Command and Control"].append("T1071")

    # Persistence and discovery are common follow-on validation hunts after suspicious execution.
    if "Execution" in observed_phases:
        possible_next_phases.extend(["Discovery", "Persistence"])
        later_stage_hunt_phases.extend(
            [
                "Credential Access",
                "Lateral Movement",
                "Collection",
                "Exfiltration",
                "Impact",
            ]
        )

    possible_previous_steps = []
    possible_next_steps = []
    reasoning = []

    if has_office_parent:
        possible_previous_steps.extend(
            [
                "Possible malicious document opened by a user or automation",
                "Possible phishing, downloaded document, or file-share delivery",
                "Possible legitimate Office automation that needs validation",
            ]
        )
        reasoning.append(
            "Office-to-PowerShell process relationships are commonly investigated as early execution chains, but the delivery vector is not proven by this alert alone."
        )

    if has_powershell:
        possible_next_steps.extend(
            [
                "Check whether PowerShell spawned child processes",
                "Check whether the same host or user triggered later discovery or persistence alerts",
                "Check whether PowerShell initiated external network connections",
            ]
        )
        reasoning.append(
            "PowerShell execution can be legitimate, but suspicious parent-child relationships require validation for follow-on activity."
        )

    if has_encoded:
        possible_next_steps.extend(
            [
                "Decode the command content to validate intent",
                "Check whether the encoded command hides download, execution, persistence, or evasion logic",
            ]
        )
        reasoning.append(
            "Encoded command content increases suspicion but does not prove malicious activity by itself."
        )

    if has_network_indicator:
        possible_next_steps.append(
            "Validate whether the observed destination is benign infrastructure, CDN, internal resource, or suspicious external infrastructure"
        )
        reasoning.append(
            "A network indicator is present, but the alert does not prove command-and-control without connection context, protocol, timing, or reputation."
        )

    if not possible_previous_steps:
        possible_previous_steps.append(
            "Unknown previous phase. Hunt for earlier alerts involving the same host, user, IP, URL, process, or document."
        )

    if not possible_next_steps:
        possible_next_steps.append(
            "Unknown next phase. Hunt for later alerts involving the same host, user, IP, URL, process, or MITRE technique."
        )

    observed_phases = _dedupe(observed_phases)
    possible_previous_phases = _dedupe(possible_previous_phases)
    possible_next_phases = _dedupe(possible_next_phases)
    later_stage_hunt_phases = _dedupe(later_stage_hunt_phases)

    observed_position_parts = []
    if possible_previous_phases:
        observed_position_parts.extend([f"Possible {phase}" for phase in possible_previous_phases])
    observed_position_parts.extend(observed_phases)
    if possible_next_phases:
        observed_position_parts.extend([f"Validate {phase}" for phase in possible_next_phases[:1]])

    observed_position = " / ".join(_dedupe(observed_position_parts)) or "Unknown"

    if "Execution" in observed_phases and "Defense Evasion" in observed_phases:
        confidence = "medium"
    elif observed_phases:
        confidence = "low-medium"
    else:
        confidence = "low"

    kill_chain_table = []

    for phase_def in KILL_CHAIN_PHASES:
        phase = phase_def["phase"]

        status = "Not observed"

        if phase in observed_phases:
            status = "Observed in this alert"
        elif phase in possible_previous_phases:
            status = "Possible previous step"
        elif phase in possible_next_phases:
            status = "Possible next step"
        elif phase in later_stage_hunt_phases:
            status = "Later-stage hunt"

        kill_chain_table.append(
            {
                "phase": phase,
                "status": status,
                "mapped_ttps": ", ".join(_dedupe(techniques_by_phase.get(phase, []))) or "-",
                "evidence_seen": " | ".join(_dedupe(evidence_by_phase.get(phase, []))) or "-",
                "why_it_matters": phase_def["description"],
                "hunt_focus": phase_def["hunt_focus"],
            }
        )

    actor_context = _collect_actor_context(enriched_techniques)

    summary = (
        f"The alert most likely shows {', '.join(observed_phases) or 'an unknown activity stage'}. "
        "Initial access and command-and-control are treated as hypotheses to validate, not confirmed stages. "
        "Additional alerts or telemetry are required to determine whether this is isolated activity or part of a broader intrusion path."
    )

    return {
        "observed_position": observed_position,
        "confidence": confidence,
        "summary": summary,
        "observed_phases": observed_phases,
        "possible_previous_phases": possible_previous_phases,
        "possible_next_phases": possible_next_phases,
        "later_stage_hunt_phases": later_stage_hunt_phases,
        "possible_previous_steps": _dedupe(possible_previous_steps),
        "possible_next_steps": _dedupe(possible_next_steps),
        "reasoning": _dedupe(reasoning),
        "kill_chain_table": kill_chain_table,
        "technique_ids": technique_ids,
        "known_groups_context": actor_context["known_groups_context"],
        "known_software_context": actor_context["known_software_context"],
        "attribution_warning": (
            "Known group or software overlap is context only. It must not be treated as threat actor attribution."
        ),
    }
