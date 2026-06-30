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


TECHNIQUE_TO_PHASES = {
    "T1204": ["Initial Access", "Execution"],
    "T1059": ["Execution"],
    "T1059.001": ["Execution"],
    "T1027": ["Defense Evasion"],
    "T1071": ["Command and Control"],
    "T1105": ["Command and Control"],
    "T1053": ["Persistence"],
    "T1053.005": ["Persistence"],
    "T1112": ["Defense Evasion", "Persistence"],
    "T1218": ["Defense Evasion", "Execution"],
    "T1218.005": ["Defense Evasion", "Execution"],
    "T1218.011": ["Defense Evasion", "Execution"],
}


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


def _extract_technique_ids(mitre_analysis: Dict[str, Any], enriched_techniques: List[Dict[str, Any]]) -> List[str]:
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

    This does not confirm an attack chain.
    It explains where the alert may sit in a larger chain and what to hunt next.
    """
    all_values_lower = _lower_values(flattened)
    technique_ids = _extract_technique_ids(mitre_analysis, enriched_techniques)

    observed_phases = []
    evidence_by_phase = {phase["phase"]: [] for phase in KILL_CHAIN_PHASES}
    techniques_by_phase = {phase["phase"]: [] for phase in KILL_CHAIN_PHASES}

    for technique_id in technique_ids:
        for phase in TECHNIQUE_TO_PHASES.get(technique_id, []):
            observed_phases.append(phase)
            techniques_by_phase[phase].append(technique_id)

    if "powershell.exe" in all_values_lower or "powershell" in all_values_lower:
        observed_phases.append("Execution")
        evidence_by_phase["Execution"].append("PowerShell execution observed")

    if any(process in all_values_lower for process in OFFICE_PROCESS_HINTS):
        observed_phases.append("Execution")
        evidence_by_phase["Execution"].append("Office parent process observed")

    if "-enc" in all_values_lower or "encoded" in all_values_lower or "base64" in all_values_lower:
        observed_phases.append("Defense Evasion")
        evidence_by_phase["Defense Evasion"].append("Encoded or obfuscated command content observed")

    if entities.get("ips") or entities.get("urls"):
        evidence_by_phase["Command and Control"].append(
            "Network destination evidence exists, but C2 is not confirmed"
        )

    observed_phases = _dedupe(observed_phases)

    possible_previous_steps = []
    possible_next_steps = []
    reasoning = []

    if any(process in all_values_lower for process in OFFICE_PROCESS_HINTS):
        possible_previous_steps.extend(
            [
                "Possible malicious document opened by user or automation",
                "Possible phishing or downloaded document delivery",
                "Possible legitimate Office automation that needs validation",
            ]
        )
        reasoning.append(
            "Office-to-PowerShell process relationships are commonly investigated as early execution chains."
        )

    if "powershell" in all_values_lower:
        possible_next_steps.extend(
            [
                "Payload download or script staging",
                "Discovery commands from the same host/user",
                "Persistence via scheduled task, service, registry, or startup location",
                "External communication from PowerShell or child processes",
            ]
        )
        reasoning.append(
            "PowerShell execution can be legitimate, but in suspicious parent-child chains it often requires validation for follow-on activity."
        )

    if "-enc" in all_values_lower or "encoded" in all_values_lower:
        possible_next_steps.extend(
            [
                "Decode command content to validate intent",
                "Check whether obfuscation was used to hide download, execution, or persistence logic",
            ]
        )
        reasoning.append(
            "Encoded command content increases suspicion but does not prove malicious activity by itself."
        )

    if entities.get("ips") or entities.get("urls"):
        possible_next_steps.append(
            "Validate whether the observed destination is benign infrastructure, CDN, internal resource, or suspicious external infrastructure"
        )

    if not possible_previous_steps:
        possible_previous_steps.append("Unknown previous phase. Hunt for earlier alerts involving the same host, user, IP, URL, or process.")

    if not possible_next_steps:
        possible_next_steps.append("Unknown next phase. Hunt for later alerts involving the same host, user, IP, URL, or process.")

    if observed_phases:
        observed_position = " / ".join(observed_phases[:3])
    else:
        observed_position = "Unknown"

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
        elif phase == "Initial Access" and any(process in all_values_lower for process in OFFICE_PROCESS_HINTS):
            status = "Possible previous step"
        elif phase in ["Command and Control", "Discovery", "Persistence"] and "Execution" in observed_phases:
            status = "Possible next step"
        elif phase in ["Credential Access", "Lateral Movement", "Collection", "Exfiltration", "Impact"] and "Execution" in observed_phases:
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
        f"The alert most likely sits around the {observed_position} phase of a possible attack chain. "
        "This is a hypothesis only. Additional alerts or telemetry are required to determine whether this is isolated activity or part of a broader intrusion path."
    )

    return {
        "observed_position": observed_position,
        "confidence": confidence,
        "summary": summary,
        "observed_phases": observed_phases,
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
