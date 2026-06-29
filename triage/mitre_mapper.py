from typing import Any, Dict, List


Technique = Dict[str, str]
Evidence = Dict[str, str]
MitreMatch = Dict[str, Any]


TECHNIQUES = {
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
    },
    "T1218.005": {
        "id": "T1218.005",
        "name": "Mshta",
        "tactic": "Defense Evasion",
    },
    "T1218.011": {
        "id": "T1218.011",
        "name": "Rundll32",
        "tactic": "Defense Evasion",
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Execution / Persistence",
    },
    "T1112": {
        "id": "T1112",
        "name": "Modify Registry",
        "tactic": "Defense Evasion / Persistence",
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
}


OFFICE_PROCESSES = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
]

SCRIPTING_PROCESSES = [
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
]

LOLBINS = [
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "schtasks.exe",
]


def _field_items_containing(flattened: Dict[str, Any], keyword: str) -> List[Evidence]:
    results = []

    for field, value in flattened.items():
        if keyword.lower() in field.lower():
            results.append(
                {
                    "field": field,
                    "value": str(value),
                }
            )

    return results


def _any_value_contains(evidence_items: List[Evidence], terms: List[str]) -> bool:
    combined = " ".join(item["value"].lower() for item in evidence_items)
    return any(term.lower() in combined for term in terms)


def _all_values_text(flattened: Dict[str, Any]) -> str:
    return " ".join(str(value).lower() for value in flattened.values())


def _technique(technique_id: str) -> Technique:
    return TECHNIQUES.get(
        technique_id,
        {
            "id": technique_id,
            "name": "Unknown technique",
            "tactic": "Unknown",
        },
    )


def _deduplicate_matches(matches: List[MitreMatch]) -> List[MitreMatch]:
    seen = set()
    deduped = []

    for match in matches:
        key = match["pattern_name"]
        if key not in seen:
            deduped.append(match)
            seen.add(key)

    return deduped


def _build_match(
    pattern_name: str,
    severity: str,
    confidence: str,
    techniques: List[str],
    reason: str,
    evidence: List[Evidence],
    missing_evidence: List[str],
    recommended_next_steps: List[str],
) -> MitreMatch:
    return {
        "pattern_name": pattern_name,
        "severity": severity,
        "confidence": confidence,
        "techniques": [_technique(technique_id) for technique_id in techniques],
        "reason": reason,
        "evidence": evidence,
        "missing_evidence": missing_evidence,
        "recommended_next_steps": recommended_next_steps,
    }


def map_mitre_hypotheses(flattened: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic MITRE + suspicious pattern mapper.

    This does not claim final attribution or final TP/FP.
    It produces evidence-based hypotheses for analyst review.
    """
    matches: List[MitreMatch] = []

    all_text = _all_values_text(flattened)

    command_line_evidence = _field_items_containing(flattened, "command_line")
    process_evidence = _field_items_containing(flattened, "process")
    parent_process_evidence = _field_items_containing(flattened, "parent_process")
    target_evidence = _field_items_containing(flattened, "target")
    security_action_evidence = _field_items_containing(flattened, "security_result.action")

    has_powershell = (
        "powershell.exe" in all_text
        or "pwsh.exe" in all_text
        or "powershell" in all_text
    )

    has_encoded_command = (
        "-enc" in all_text
        or "-encodedcommand" in all_text
        or "encodedcommand" in all_text
        or "frombase64string" in all_text
    )

    has_office_parent = _any_value_contains(parent_process_evidence, OFFICE_PROCESSES)
    has_scripting_child = _any_value_contains(process_evidence, SCRIPTING_PROCESSES)
    has_mshta = "mshta.exe" in all_text
    has_rundll32 = "rundll32.exe" in all_text
    has_regsvr32 = "regsvr32.exe" in all_text
    has_certutil = "certutil.exe" in all_text
    has_bitsadmin = "bitsadmin.exe" in all_text
    has_schtasks = "schtasks.exe" in all_text
    has_reg_add = "reg add" in all_text
    has_external_target = bool(target_evidence)

    # Pattern 1: Office spawned encoded PowerShell
    if has_office_parent and has_powershell and has_encoded_command:
        matches.append(
            _build_match(
                pattern_name="Office application spawned encoded PowerShell",
                severity="high",
                confidence="medium-high",
                techniques=["T1204", "T1059.001", "T1027"],
                reason=(
                    "An Office parent process appears to have launched PowerShell "
                    "with encoded command-line content. This is a common suspicious "
                    "execution chain and should be investigated."
                ),
                evidence=parent_process_evidence + command_line_evidence,
                missing_evidence=[
                    "Decoded PowerShell command content",
                    "Whether the same command line was seen on other hosts",
                    "User login and email/document context before execution",
                    "File/hash reputation for related payloads",
                    "Destination IP/domain reputation if network activity occurred",
                ],
                recommended_next_steps=[
                    "Decode the PowerShell command.",
                    "Search for the same command line across the environment.",
                    "Check whether the parent Office process opened a suspicious document.",
                    "Review user login context before and after execution.",
                    "Check related network connections and file writes.",
                ],
            )
        )

    # Pattern 2: PowerShell execution
    if has_powershell:
        matches.append(
            _build_match(
                pattern_name="PowerShell execution observed",
                severity="medium",
                confidence="medium",
                techniques=["T1059.001"],
                reason=(
                    "PowerShell execution was observed. PowerShell is legitimate but "
                    "frequently abused for script execution, payload download, and post-exploitation activity."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Full command line",
                    "Decoded command content if encoded",
                    "Parent process",
                    "User and host baseline",
                ],
                recommended_next_steps=[
                    "Review the full PowerShell command line.",
                    "Determine whether the execution was expected for the user and host.",
                    "Check for encoded, download, invoke-expression, or bypass arguments.",
                ],
            )
        )

    # Pattern 3: Encoded or obfuscated command content
    if has_encoded_command:
        matches.append(
            _build_match(
                pattern_name="Encoded or obfuscated command content",
                severity="medium-high",
                confidence="medium",
                techniques=["T1027"],
                reason=(
                    "Encoded or obfuscated command content was observed. This may be used "
                    "to hide execution intent or evade detection."
                ),
                evidence=command_line_evidence,
                missing_evidence=[
                    "Decoded command content",
                    "Whether the encoding is part of a known administrative script",
                    "Process tree and child process activity",
                ],
                recommended_next_steps=[
                    "Decode the command.",
                    "Check whether decoded content downloads files, executes scripts, or disables controls.",
                    "Compare against known admin automation.",
                ],
            )
        )

    # Pattern 4: Office parent process launched scripting process
    if has_office_parent and has_scripting_child:
        matches.append(
            _build_match(
                pattern_name="Office application launched scripting process",
                severity="high",
                confidence="medium",
                techniques=["T1204", "T1059"],
                reason=(
                    "An Office application appears to have launched a scripting process. "
                    "This is often associated with malicious documents or user-driven execution."
                ),
                evidence=parent_process_evidence + process_evidence + command_line_evidence,
                missing_evidence=[
                    "Document name and hash",
                    "Email or download source of the document",
                    "Macro/script execution evidence",
                    "User interaction context",
                ],
                recommended_next_steps=[
                    "Identify the Office document involved.",
                    "Check email gateway or browser download history.",
                    "Search for similar parent-child process chains.",
                ],
            )
        )

    # Pattern 5: Mshta LOLBin
    if has_mshta:
        matches.append(
            _build_match(
                pattern_name="Mshta execution observed",
                severity="medium-high",
                confidence="medium",
                techniques=["T1218.005"],
                reason=(
                    "mshta.exe execution was observed. Mshta can be abused to execute "
                    "HTML applications or remote script content."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Full mshta command line",
                    "URL or file executed by mshta",
                    "Parent process",
                ],
                recommended_next_steps=[
                    "Review mshta command-line arguments.",
                    "Check whether mshta loaded a remote URL or suspicious file.",
                    "Search for mshta usage across the environment.",
                ],
            )
        )

    # Pattern 6: Rundll32 LOLBin
    if has_rundll32:
        matches.append(
            _build_match(
                pattern_name="Rundll32 execution observed",
                severity="medium-high",
                confidence="medium",
                techniques=["T1218.011"],
                reason=(
                    "rundll32.exe execution was observed. Rundll32 is legitimate but "
                    "commonly abused to execute DLL code or evade controls."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "DLL path or export function",
                    "Parent process",
                    "File hash and signature information",
                ],
                recommended_next_steps=[
                    "Review rundll32 arguments.",
                    "Check the referenced DLL path and signature.",
                    "Search for the same rundll32 command across the environment.",
                ],
            )
        )

    # Pattern 7: Regsvr32 LOLBin
    if has_regsvr32:
        matches.append(
            _build_match(
                pattern_name="Regsvr32 execution observed",
                severity="medium-high",
                confidence="medium",
                techniques=["T1218"],
                reason=(
                    "regsvr32.exe execution was observed. Regsvr32 can be abused for "
                    "proxy execution and scriptlet execution."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Full regsvr32 command line",
                    "Referenced scriptlet or DLL",
                    "Network connection context",
                ],
                recommended_next_steps=[
                    "Review regsvr32 arguments.",
                    "Check whether remote scriptlet execution was used.",
                    "Search for similar regsvr32 commands.",
                ],
            )
        )

    # Pattern 8: Certutil download/decode behavior
    if has_certutil:
        matches.append(
            _build_match(
                pattern_name="Certutil execution observed",
                severity="medium",
                confidence="medium",
                techniques=["T1105", "T1027"],
                reason=(
                    "certutil.exe execution was observed. Certutil may be abused for "
                    "file download, encoding, or decoding activity."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Full certutil command line",
                    "Downloaded or decoded file details",
                    "Destination URL/IP",
                ],
                recommended_next_steps=[
                    "Check whether certutil used download or decode arguments.",
                    "Identify created files and reputation.",
                    "Search for the same command across hosts.",
                ],
            )
        )

    # Pattern 9: Bitsadmin download behavior
    if has_bitsadmin:
        matches.append(
            _build_match(
                pattern_name="Bitsadmin execution observed",
                severity="medium",
                confidence="medium",
                techniques=["T1105"],
                reason=(
                    "bitsadmin.exe execution was observed. Bitsadmin may be abused to "
                    "download files in the background."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Full bitsadmin command line",
                    "Remote URL",
                    "Downloaded file path and hash",
                ],
                recommended_next_steps=[
                    "Review bitsadmin command-line arguments.",
                    "Identify download source and destination file.",
                    "Search for similar bitsadmin activity.",
                ],
            )
        )

    # Pattern 10: Scheduled task creation/execution
    if has_schtasks:
        matches.append(
            _build_match(
                pattern_name="Scheduled task activity observed",
                severity="medium",
                confidence="medium",
                techniques=["T1053.005"],
                reason=(
                    "schtasks.exe activity was observed. Scheduled tasks may be used "
                    "for persistence or execution."
                ),
                evidence=process_evidence + command_line_evidence,
                missing_evidence=[
                    "Task name",
                    "Task action",
                    "Task trigger",
                    "User context",
                ],
                recommended_next_steps=[
                    "Identify the task name and command.",
                    "Check whether the task was newly created or modified.",
                    "Validate whether the task is expected on the host.",
                ],
            )
        )

    # Pattern 11: Registry modification via command line
    if has_reg_add:
        matches.append(
            _build_match(
                pattern_name="Registry modification command observed",
                severity="medium",
                confidence="medium",
                techniques=["T1112"],
                reason=(
                    "A registry modification command was observed. Registry changes "
                    "may support persistence, configuration tampering, or defense evasion."
                ),
                evidence=command_line_evidence,
                missing_evidence=[
                    "Registry key path",
                    "Value written",
                    "Whether the key is associated with persistence",
                    "User and process context",
                ],
                recommended_next_steps=[
                    "Review the registry path and value.",
                    "Check whether the key is commonly abused for persistence.",
                    "Compare against baseline configuration.",
                ],
            )
        )

    # Pattern 12: Network target present
    if has_external_target:
        matches.append(
            _build_match(
                pattern_name="Network target present in alert evidence",
                severity="informational",
                confidence="low",
                techniques=["T1071"],
                reason=(
                    "A target or destination value was present. This may be relevant "
                    "for command-and-control, download, or exfiltration analysis, but "
                    "the destination must be validated before drawing conclusions."
                ),
                evidence=target_evidence,
                missing_evidence=[
                    "Whether the destination is internal or external",
                    "Threat intelligence reputation",
                    "Environment prevalence",
                    "Related process or connection context",
                ],
                recommended_next_steps=[
                    "Check destination reputation.",
                    "Search for other hosts communicating with the same destination.",
                    "Correlate the destination with process and user activity.",
                ],
            )
        )

    matches = _deduplicate_matches(matches)

    if not matches:
        return {
            "initial_verdict": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
            "overall_severity": "unknown",
            "summary": "No suspicious deterministic MITRE pattern was matched yet.",
            "matches": [],
        }

    highest_severity = _calculate_overall_severity(matches)

    return {
        "initial_verdict": "INCONCLUSIVE_NEEDS_MORE_EVIDENCE",
        "overall_severity": highest_severity,
        "summary": (
            f"{len(matches)} MITRE/suspicious pattern hypothesis match(es) found. "
            "These are hypotheses and require analyst validation."
        ),
        "matches": matches,
    }


def _calculate_overall_severity(matches: List[MitreMatch]) -> str:
    severity_rank = {
        "informational": 1,
        "low": 2,
        "medium": 3,
        "medium-high": 4,
        "high": 5,
        "critical": 6,
    }

    highest = "low"
    highest_score = 0

    for match in matches:
        severity = match.get("severity", "low")
        score = severity_rank.get(severity, 0)

        if score > highest_score:
            highest = severity
            highest_score = score

    return highest