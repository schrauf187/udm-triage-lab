from __future__ import annotations

from typing import Any, Dict, List


def _entry(
    meaning: str,
    importance: int,
    category: str,
    evidence_role: str,
    privacy_sensitivity: str = "low",
    cti_allowed: bool = False,
    cti_transformation: str = "not_allowed",
    mitre_hints: List[str] | None = None,
    analyst_questions: List[str] | None = None,
    investigation_pivots: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "meaning": meaning,
        "importance": importance,
        "category": category,
        "evidence_role": evidence_role,
        "privacy_sensitivity": privacy_sensitivity,
        "cti_allowed": cti_allowed,
        "cti_transformation": cti_transformation,
        "mitre_hints": mitre_hints or [],
        "analyst_questions": analyst_questions or [],
        "investigation_pivots": investigation_pivots or [],
    }


UDM_ONTOLOGY: Dict[str, Dict[str, Any]] = {
    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    "metadata.event_type": _entry(
        meaning="Classifies the type of event, such as process launch, login, network connection, email event, cloud activity, or file event.",
        importance=9,
        category="event classification",
        evidence_role="event_type",
        analyst_questions=[
            "Does the event type match the alert story?",
            "Is this process, identity, network, email, cloud, or file telemetry?",
        ],
        investigation_pivots=[
            "Use the event type to decide which evidence sources should be queried next.",
            "Validate whether the alert logic is using the correct telemetry category.",
        ],
    ),
    "metadata.vendor_name": _entry(
        meaning="Identifies the vendor that produced the telemetry or alert.",
        importance=5,
        category="source context",
        evidence_role="telemetry_source",
        analyst_questions=[
            "Which security vendor produced this evidence?",
            "Is the vendor source authoritative for this type of activity?",
        ],
    ),
    "metadata.product_name": _entry(
        meaning="Identifies the product that produced the telemetry or alert.",
        importance=5,
        category="source context",
        evidence_role="telemetry_source",
        analyst_questions=[
            "Which detection or telemetry product generated this event?",
            "Is this an EDR, SIEM, identity, proxy, firewall, email, or cloud alert?",
        ],
    ),
    "metadata.product_event_type": _entry(
        meaning="Vendor-specific event type or alert classification.",
        importance=6,
        category="source context",
        evidence_role="vendor_context",
        analyst_questions=[
            "What does the vendor call this event type?",
            "Does the vendor event type provide more precision than the generic event type?",
        ],
    ),
    "metadata.event_timestamp": _entry(
        meaning="Timestamp when the original security event occurred.",
        importance=8,
        category="time",
        evidence_role="timeline_anchor",
        analyst_questions=[
            "When did the suspicious activity happen?",
            "Does the timestamp align with related alerts or follow-up evidence?",
        ],
        investigation_pivots=[
            "Search for related activity on the same user, host, IP, process, or hash around this time.",
        ],
    ),
    "metadata.ingested_timestamp": _entry(
        meaning="Timestamp when the event was ingested into the analytics platform or SIEM.",
        importance=5,
        category="time",
        evidence_role="pipeline_context",
        analyst_questions=[
            "Was there ingestion delay?",
            "Could delayed ingestion affect alert correlation or SLA timing?",
        ],
    ),
    "metadata.description": _entry(
        meaning="Description or context provided by the telemetry source.",
        importance=6,
        category="source context",
        evidence_role="context",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Does this description add investigation context?",
            "Does it include vendor-specific limitations or expected analyst steps?",
        ],
    ),
    "metadata.log_type": _entry(
        meaning="Log type or parser category used by the analytics platform.",
        importance=7,
        category="source context",
        evidence_role="telemetry_source",
        analyst_questions=[
            "Which parser or data source produced this normalized event?",
            "Does this log type match the alert story?",
        ],
    ),

    # ------------------------------------------------------------------
    # Security result / alert context
    # ------------------------------------------------------------------
    "security_result.rule_name": _entry(
        meaning="The name of the detection rule or alert logic that generated the alert.",
        importance=9,
        category="alert context",
        evidence_role="detection_logic",
        analyst_questions=[
            "Does the rule name accurately describe the observed activity?",
            "Is this a high-fidelity rule or a noisy behavioural rule?",
            "Is this rule known to have common false positives?",
        ],
        investigation_pivots=[
            "Search for recent triggers of the same rule.",
            "Check whether this rule triggered for the same entity before.",
        ],
    ),
    "security_result.display_name": _entry(
        meaning="Human-readable alert title or display name.",
        importance=9,
        category="alert context",
        evidence_role="detection_logic",
        analyst_questions=[
            "Does the alert title match the actual evidence?",
            "Is the title too generic or does it describe the suspicious behavior?",
        ],
    ),
    "security_result.rule_id": _entry(
        meaning="Unique identifier for the detection rule.",
        importance=7,
        category="alert context",
        evidence_role="traceability",
        privacy_sensitivity="medium",
        cti_allowed=False,
        analyst_questions=[
            "Is this the expected rule ID?",
            "Is this rule version known to generate false positives?",
        ],
    ),
    "security_result.summary": _entry(
        meaning="Short summary of the alert or detection result.",
        importance=8,
        category="alert explanation",
        evidence_role="alert_summary",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Does the summary explain why this is suspicious?",
            "Does the summary align with the raw evidence?",
        ],
    ),
    "security_result.description": _entry(
        meaning="Detailed description of the alert or detection result.",
        importance=8,
        category="alert explanation",
        evidence_role="alert_description",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Does the description contain required investigation steps?",
            "Does it mention known benign causes or detection limitations?",
        ],
    ),
    "security_result.severity": _entry(
        meaning="Severity assigned by the security product or detection rule.",
        importance=8,
        category="severity",
        evidence_role="risk_context",
        analyst_questions=[
            "Is the severity justified by the available evidence?",
            "Does the severity reflect business impact or only technical behavior?",
        ],
    ),
    "security_result.priority": _entry(
        meaning="Priority assigned to the security result.",
        importance=7,
        category="severity",
        evidence_role="risk_context",
        analyst_questions=[
            "Does the priority align with the business criticality of the affected asset?",
            "Is the priority inherited from the vendor or calculated by the SOC?",
        ],
    ),
    "security_result.risk_score": _entry(
        meaning="Numeric risk score assigned to the security result.",
        importance=8,
        category="severity",
        evidence_role="risk_context",
        analyst_questions=[
            "What evidence contributed to the risk score?",
            "Is the score based on behavior, asset criticality, identity risk, or threat intel?",
        ],
    ),
    "security_result.action": _entry(
        meaning="Security control outcome such as allow, block, quarantine, fail, detect, or alert.",
        importance=10,
        category="security outcome",
        evidence_role="control_outcome",
        analyst_questions=[
            "Was the activity blocked, allowed, quarantined, or only detected?",
            "If allowed, is containment or further validation needed?",
            "If blocked, did execution still partially succeed?",
        ],
        investigation_pivots=[
            "If the action was allow/detect, search for follow-up activity.",
            "If the action was block/quarantine, confirm whether the process or file still executed.",
        ],
    ),
    "security_result.category": _entry(
        meaning="Detection category such as malware, suspicious login, policy violation, cloud control-plane activity, or behavioral anomaly.",
        importance=7,
        category="alert context",
        evidence_role="classification",
        analyst_questions=[
            "Does the category match the observed evidence?",
            "Does the category imply a specific investigation playbook?",
        ],
    ),
    "security_result.detection_fields": _entry(
        meaning="Matched fields, custom details, or evidence returned by the detection rule.",
        importance=9,
        category="alert evidence",
        evidence_role="matched_evidence",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Which exact fields caused the rule to trigger?",
            "Are the matched fields sufficient to validate the detection?",
        ],
        investigation_pivots=[
            "Use detection fields as primary pivots for follow-up hunts.",
        ],
    ),

    # ------------------------------------------------------------------
    # MITRE ATT&CK
    # ------------------------------------------------------------------
    "security_result.attack_details.tactics": _entry(
        meaning="MITRE ATT&CK tactic context associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
        analyst_questions=[
            "Which attack phase does this alert represent?",
            "Is the tactic directly observed or only inferred?",
        ],
        investigation_pivots=[
            "Search for earlier and later tactics around the same user, host, or IP.",
        ],
    ),
    "security_result.attack_details.techniques": _entry(
        meaning="MITRE ATT&CK technique context associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
        analyst_questions=[
            "Do the mapped techniques match the actual evidence?",
            "Are the techniques vendor-supplied, rule-supplied, or AI-inferred?",
        ],
        investigation_pivots=[
            "Search for related techniques in the same attack chain.",
        ],
    ),

    # Indexed MITRE fields used by the MVP
    "security_result.attack_details.tactics[0].id": _entry(
        meaning="MITRE ATT&CK tactic ID associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.tactics[0].name": _entry(
        meaning="MITRE ATT&CK tactic name associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.tactics[1].id": _entry(
        meaning="Additional MITRE ATT&CK tactic ID associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.tactics[1].name": _entry(
        meaning="Additional MITRE ATT&CK tactic name associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.tactics[2].id": _entry(
        meaning="Additional MITRE ATT&CK tactic ID associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.tactics[2].name": _entry(
        meaning="Additional MITRE ATT&CK tactic name associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_phase",
    ),
    "security_result.attack_details.techniques[0].id": _entry(
        meaning="Primary MITRE ATT&CK technique ID associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[0].name": _entry(
        meaning="Primary MITRE ATT&CK technique name associated with the alert.",
        importance=9,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[1].id": _entry(
        meaning="Additional MITRE ATT&CK technique ID associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[1].name": _entry(
        meaning="Additional MITRE ATT&CK technique name associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[2].id": _entry(
        meaning="Additional MITRE ATT&CK technique ID associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[2].name": _entry(
        meaning="Additional MITRE ATT&CK technique name associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[3].id": _entry(
        meaning="Additional MITRE ATT&CK technique ID associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),
    "security_result.attack_details.techniques[3].name": _entry(
        meaning="Additional MITRE ATT&CK technique name associated with the alert.",
        importance=8,
        category="MITRE ATT&CK",
        evidence_role="attack_technique",
    ),

    # ------------------------------------------------------------------
    # Identity / principal
    # ------------------------------------------------------------------
    "principal.user.userid": _entry(
        meaning="The acting user, account, or service principal that initiated the observed activity.",
        importance=9,
        category="identity",
        evidence_role="acting_identity",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this account expected to perform this action?",
            "Is this a service account, admin account, machine account, or normal user?",
            "Has this account shown suspicious activity before or after this alert?",
        ],
        investigation_pivots=[
            "Search recent activity for the same user.",
            "Check sign-in history, role assignments, mailbox activity, and endpoint activity for the same account.",
        ],
    ),
    "principal.user.email_addresses[0]": _entry(
        meaning="Email address associated with the acting user.",
        importance=8,
        category="identity",
        evidence_role="acting_identity",
        privacy_sensitivity="medium",
        cti_allowed=False,
        analyst_questions=[
            "Is this the expected email identity for the activity?",
            "Is the account privileged or externally exposed?",
        ],
        investigation_pivots=[
            "Search identity, email, and cloud logs for the same email address.",
        ],
    ),
    "principal.user.group_identifiers[0]": _entry(
        meaning="Group or role associated with the acting user.",
        importance=8,
        category="identity",
        evidence_role="privilege_context",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this account privileged?",
            "Does group membership increase the business impact of this alert?",
        ],
        investigation_pivots=[
            "Check whether privileged role membership changed recently.",
        ],
    ),
    "target.user.userid": _entry(
        meaning="Target or affected user account.",
        importance=8,
        category="identity",
        evidence_role="target_identity",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this account the victim, target, or object of the action?",
            "Is this account privileged or business-critical?",
        ],
        investigation_pivots=[
            "Search for recent activity affecting this target user.",
        ],
    ),

    # ------------------------------------------------------------------
    # Asset / host
    # ------------------------------------------------------------------
    "principal.hostname": _entry(
        meaning="Source or acting hostname.",
        importance=8,
        category="asset",
        evidence_role="source_asset",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this the host where the activity originated?",
            "Is the host managed and expected to generate this activity?",
        ],
        investigation_pivots=[
            "Search related endpoint, process, file, network, and login activity for this host.",
        ],
    ),
    "principal.asset.hostname": _entry(
        meaning="The source or acting host where the activity originated.",
        importance=9,
        category="asset",
        evidence_role="source_asset",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this asset business-critical?",
            "Is this activity normal for this host?",
            "Is this host part of a known admin, server, workstation, or jump-host pattern?",
        ],
        investigation_pivots=[
            "Search process, network, file, and user activity on the same host.",
            "Check if the same host had alerts before or after this event.",
        ],
    ),
    "principal.asset.asset_id": _entry(
        meaning="Vendor or platform-specific asset identifier, such as an EDR agent ID.",
        importance=7,
        category="asset",
        evidence_role="traceability",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Does the asset ID resolve to the expected host?",
            "Is the asset ID needed for vendor-console investigation?",
        ],
    ),
    "target.hostname": _entry(
        meaning="Destination, affected, or target hostname.",
        importance=8,
        category="asset",
        evidence_role="target_asset",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this the target of the activity?",
            "Is the destination host expected for this user or process?",
        ],
        investigation_pivots=[
            "Search inbound activity and related alerts for the target host.",
        ],
    ),

    # ------------------------------------------------------------------
    # IP / network
    # ------------------------------------------------------------------
    "principal.ip": _entry(
        meaning="Source or acting IP address. For identity alerts this is often the sign-in IP. For network alerts this is the source/client IP. For EDR alerts this may be endpoint context rather than attacker infrastructure.",
        importance=8,
        category="network",
        evidence_role="source_ip",
        privacy_sensitivity="medium",
        cti_allowed=True,
        cti_transformation="only_if_public_and_contextually_relevant",
        mitre_hints=["T1078", "T1133"],
        analyst_questions=[
            "Is this source IP internal, VPN, cloud, proxy, or public internet?",
            "For identity alerts, is this source country or ASN expected?",
            "For EDR alerts, is this merely the endpoint IP rather than attacker infrastructure?",
        ],
        investigation_pivots=[
            "Search other activity from the same source IP.",
            "Check geo, ASN, VPN, TOR, hosting provider, or impossible-travel context.",
        ],
    ),
    "target.ip": _entry(
        meaning="Destination or target IP address involved in the activity.",
        importance=8,
        category="network",
        evidence_role="destination_ip",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="public_ip_only",
        mitre_hints=["T1071", "T1105"],
        analyst_questions=[
            "Is the destination internal or external?",
            "Is the IP known malicious, rare, or newly observed in the environment?",
            "Is the destination expected for the process, user, or application?",
        ],
        investigation_pivots=[
            "Search for the same destination IP across hosts and users.",
            "Check DNS, proxy, firewall, and EDR network events for the same IP.",
        ],
    ),
    "network.application_protocol": _entry(
        meaning="Application-layer protocol such as HTTP, HTTPS, DNS, SMB, RDP, SSH, or LDAP.",
        importance=7,
        category="network",
        evidence_role="protocol_context",
        mitre_hints=["T1071"],
        analyst_questions=[
            "Is this protocol expected for the process and destination?",
            "Could this protocol be used for C2, exfiltration, lateral movement, or admin activity?",
        ],
    ),
    "network.ip_protocol": _entry(
        meaning="IP protocol such as TCP, UDP, or ICMP.",
        importance=5,
        category="network",
        evidence_role="protocol_context",
        analyst_questions=[
            "Does the IP protocol match the expected application protocol?",
        ],
    ),
    "network.direction": _entry(
        meaning="Direction of traffic such as outbound, inbound, or internal.",
        importance=8,
        category="network",
        evidence_role="traffic_direction",
        analyst_questions=[
            "Is the traffic inbound, outbound, or internal?",
            "Does the direction change the interpretation of the activity?",
        ],
    ),
    "network.session_id": _entry(
        meaning="Session identifier for a network connection or proxy event.",
        importance=5,
        category="network",
        evidence_role="traceability",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Can this session ID be used to pivot into the proxy or firewall logs?",
        ],
    ),
    "network.sent_bytes": _entry(
        meaning="Number of bytes sent from source to destination.",
        importance=7,
        category="network",
        evidence_role="volume_context",
        mitre_hints=["T1041", "T1048"],
        analyst_questions=[
            "Is the sent byte volume unusual?",
            "Could the volume indicate upload, exfiltration, or beaconing?",
        ],
    ),
    "network.received_bytes": _entry(
        meaning="Number of bytes received from destination.",
        importance=7,
        category="network",
        evidence_role="volume_context",
        mitre_hints=["T1105"],
        analyst_questions=[
            "Is the received byte volume consistent with a payload download?",
            "Does this support ingress tool transfer or normal browsing?",
        ],
    ),
    "network.src_port": _entry(
        meaning="Source port of a network session.",
        importance=4,
        category="network",
        evidence_role="connection_detail",
    ),
    "network.dst_port": _entry(
        meaning="Destination port of a network session.",
        importance=6,
        category="network",
        evidence_role="connection_detail",
        analyst_questions=[
            "Is this destination port expected for the protocol and application?",
        ],
    ),
    "network.connection.count": _entry(
        meaning="Number of repeated connections or sessions observed.",
        importance=7,
        category="network",
        evidence_role="frequency_context",
        mitre_hints=["T1071"],
        analyst_questions=[
            "Does the connection count suggest beaconing, scanning, brute force, or normal repeated access?",
        ],
    ),

    # ------------------------------------------------------------------
    # Process
    # ------------------------------------------------------------------
    "principal.process.file.full_path": _entry(
        meaning="Full file path of the source or acting process involved in the activity.",
        importance=9,
        category="process",
        evidence_role="process_identity",
        privacy_sensitivity="medium",
        cti_allowed=False,
        cti_transformation="not_allowed",
        mitre_hints=["T1059", "T1218"],
        analyst_questions=[
            "Is this process expected in this path?",
            "Is this a LOLBin or commonly abused Windows binary?",
            "Is the process signed and located in a trusted directory?",
        ],
        investigation_pivots=[
            "Search for the same process path across hosts.",
            "Check parent and child process relationships.",
        ],
    ),
    "principal.process.file.name": _entry(
        meaning="File name of the source or acting process.",
        importance=8,
        category="process",
        evidence_role="process_identity",
        mitre_hints=["T1059", "T1218"],
        analyst_questions=[
            "Is this a commonly abused binary such as powershell.exe, cmd.exe, certutil.exe, mshta.exe, rundll32.exe, regsvr32.exe, or wscript.exe?",
        ],
    ),
    "principal.process.command_line": _entry(
        meaning="Command line used by the source or acting process. This is high-value evidence for execution intent.",
        importance=10,
        category="execution",
        evidence_role="primary_behavior",
        privacy_sensitivity="high",
        cti_allowed=False,
        cti_transformation="sanitized_behavior_pattern_only",
        mitre_hints=["T1059", "T1059.001", "T1027"],
        analyst_questions=[
            "Is the command encoded, obfuscated, suspicious, or unusually long?",
            "Can the command be decoded?",
            "Was the command observed on other hosts?",
            "Does the command launch another process, download a payload, modify persistence, or access credentials?",
        ],
        investigation_pivots=[
            "Search same or similar command-line patterns across hosts.",
            "Search child processes after this command.",
            "Search network connections from this process.",
            "Search file writes created by this process.",
        ],
    ),
    "principal.process.pid": _entry(
        meaning="Process ID of the source or acting process.",
        importance=5,
        category="process",
        evidence_role="process_traceability",
        analyst_questions=[
            "Can the PID be used to reconstruct the process tree?",
        ],
    ),
    "principal.process.parent_process.file.full_path": _entry(
        meaning="Full file path of the parent process that launched the observed process.",
        importance=10,
        category="process relationship",
        evidence_role="process_parent",
        privacy_sensitivity="medium",
        mitre_hints=["T1204", "T1059"],
        analyst_questions=[
            "Is the parent-child process relationship normal?",
            "Is Office spawning PowerShell, cmd, mshta, rundll32, regsvr32, wscript, cscript, certutil, or bitsadmin?",
            "Does the parent process imply user execution, macro execution, or scripted automation?",
        ],
        investigation_pivots=[
            "Search for the same parent-child process relationship across hosts.",
            "Check whether the parent process opened a document, archive, browser, or email attachment.",
        ],
    ),
    "principal.process.parent_process.file.name": _entry(
        meaning="File name of the parent process that launched the observed process.",
        importance=9,
        category="process relationship",
        evidence_role="process_parent",
        mitre_hints=["T1204", "T1059"],
        analyst_questions=[
            "Is the parent process expected to launch the child process?",
            "Is this an Office-to-script, browser-to-script, or archive-to-script execution pattern?",
        ],
    ),
    "process.command_line": _entry(
        meaning="Observed process command line, often used when the process is represented outside principal/target.",
        importance=10,
        category="execution",
        evidence_role="primary_behavior",
        privacy_sensitivity="high",
        cti_allowed=False,
        cti_transformation="sanitized_behavior_pattern_only",
        mitre_hints=["T1059", "T1059.001", "T1027"],
        analyst_questions=[
            "Is the command line suspicious or encoded?",
            "Does it indicate download, persistence, discovery, credential access, or lateral movement?",
        ],
        investigation_pivots=[
            "Search similar command lines across the environment.",
        ],
    ),
    "process.file.full_path": _entry(
        meaning="Full path of the observed process file.",
        importance=9,
        category="process",
        evidence_role="process_identity",
        privacy_sensitivity="medium",
        mitre_hints=["T1059", "T1218"],
        analyst_questions=[
            "Is the process path expected and trusted?",
        ],
    ),
    "process.file.name": _entry(
        meaning="Name of the observed process file.",
        importance=8,
        category="process",
        evidence_role="process_identity",
        mitre_hints=["T1059", "T1218"],
    ),
    "process.pid": _entry(
        meaning="Process ID of the observed process.",
        importance=5,
        category="process",
        evidence_role="process_traceability",
    ),
    "process.parent_pid": _entry(
        meaning="Parent process ID of the observed process.",
        importance=5,
        category="process",
        evidence_role="process_traceability",
    ),
    "process.file.sha256": _entry(
        meaning="SHA256 hash of the observed process file.",
        importance=9,
        category="file hash",
        evidence_role="file_identity",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="hash_only",
        mitre_hints=["T1204", "T1105"],
        analyst_questions=[
            "Is the hash known malicious, unknown, or common benign software?",
            "Was the hash observed on other hosts?",
        ],
        investigation_pivots=[
            "Search the hash across endpoint, SIEM, EDR, and file telemetry.",
            "Run CTI reputation lookup if appropriate.",
        ],
    ),
    "process.file.md5": _entry(
        meaning="MD5 hash of the observed process file.",
        importance=7,
        category="file hash",
        evidence_role="file_identity",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="hash_only",
        analyst_questions=[
            "Is the MD5 known malicious or associated with expected software?",
            "Is a SHA256 also available for stronger identification?",
        ],
    ),

    # ------------------------------------------------------------------
    # Target process / file
    # ------------------------------------------------------------------
    "target.process.command_line": _entry(
        meaning="Command line of a target or affected process.",
        importance=9,
        category="execution",
        evidence_role="target_behavior",
        privacy_sensitivity="high",
        cti_allowed=False,
        cti_transformation="sanitized_behavior_pattern_only",
        mitre_hints=["T1059", "T1027"],
        analyst_questions=[
            "Is the target process command line suspicious?",
            "Does it show execution, persistence, discovery, or credential access?",
        ],
    ),
    "target.file.full_path": _entry(
        meaning="Full path of a target, downloaded, modified, or affected file.",
        importance=8,
        category="file",
        evidence_role="target_file",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Was this file created, modified, executed, quarantined, or deleted?",
            "Is the file path expected for the application or user?",
        ],
        investigation_pivots=[
            "Search file create/write/execute events for this path.",
        ],
    ),
    "target.file.name": _entry(
        meaning="Name of a target, downloaded, modified, or affected file.",
        importance=7,
        category="file",
        evidence_role="target_file",
    ),
    "target.file.sha256": _entry(
        meaning="SHA256 hash of a target, downloaded, modified, or affected file.",
        importance=9,
        category="file hash",
        evidence_role="file_identity",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="hash_only",
        mitre_hints=["T1105", "T1204"],
        analyst_questions=[
            "Is the target file hash known malicious?",
            "Was the same file observed elsewhere?",
        ],
        investigation_pivots=[
            "Search the file hash across all endpoints.",
            "Check CTI reputation for the hash.",
        ],
    ),

    # ------------------------------------------------------------------
    # Generic file
    # ------------------------------------------------------------------
    "file.full_path": _entry(
        meaning="Full path of a file associated with the event.",
        importance=8,
        category="file",
        evidence_role="file_path",
        privacy_sensitivity="medium",
        analyst_questions=[
            "Is this file path expected?",
            "Is the file in a temporary, user-writable, startup, or suspicious directory?",
        ],
    ),
    "file.file_name": _entry(
        meaning="Name of a file associated with the event.",
        importance=7,
        category="file",
        evidence_role="file_name",
    ),
    "file.sha256": _entry(
        meaning="SHA256 hash of a file associated with the event.",
        importance=9,
        category="file hash",
        evidence_role="file_identity",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="hash_only",
        mitre_hints=["T1105", "T1204"],
        analyst_questions=[
            "Is the file hash known malicious, unknown, or benign?",
        ],
        investigation_pivots=[
            "Search file hash across hosts.",
            "Run CTI lookup if appropriate.",
        ],
    ),
    "file.md5": _entry(
        meaning="MD5 hash of a file associated with the event.",
        importance=7,
        category="file hash",
        evidence_role="file_identity",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="hash_only",
        analyst_questions=[
            "Is a stronger SHA256 hash available?",
            "Is the MD5 known malicious or expected?",
        ],
    ),
    "file.size": _entry(
        meaning="Size of a file associated with the event.",
        importance=5,
        category="file",
        evidence_role="file_metadata",
        analyst_questions=[
            "Is the file size consistent with expected software, script, payload, or log file?",
        ],
    ),

    # ------------------------------------------------------------------
    # DNS / HTTP / domain / URL
    # ------------------------------------------------------------------
    "target.domain.name": _entry(
        meaning="Destination or target domain name involved in the activity.",
        importance=8,
        category="network",
        evidence_role="destination_domain",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="public_domain_only",
        mitre_hints=["T1071", "T1105", "T1566"],
        analyst_questions=[
            "Is this domain expected for the application or process?",
            "Is the domain newly registered, rare, typosquatted, or suspicious?",
        ],
        investigation_pivots=[
            "Search DNS, proxy, firewall, and EDR events for the same domain.",
            "Check CTI reputation if the domain is public and not a vendor-console URL.",
        ],
    ),
    "target.url": _entry(
        meaning="Destination or target URL involved in the activity.",
        importance=8,
        category="network",
        evidence_role="destination_url",
        privacy_sensitivity="medium",
        cti_allowed=True,
        cti_transformation="public_url_only",
        mitre_hints=["T1071", "T1105", "T1566.002"],
        analyst_questions=[
            "Is the URL expected, suspicious, phishing-related, or payload-related?",
            "Does the URL contain sensitive tokens or vendor-console traceability data?",
        ],
        investigation_pivots=[
            "Search proxy and endpoint network events for the same URL or domain.",
        ],
    ),
    "target.application": _entry(
        meaning="Application, cloud service, SaaS app, or resource accessed by the actor.",
        importance=8,
        category="application",
        evidence_role="target_application",
        analyst_questions=[
            "Is this application expected for the user or service account?",
            "Is the application sensitive or privileged?",
        ],
        investigation_pivots=[
            "Search other access to the same application by the user, IP, or device.",
        ],
    ),
    "target.port": _entry(
        meaning="Destination or target port.",
        importance=6,
        category="network",
        evidence_role="connection_detail",
        analyst_questions=[
            "Is this port expected for the protocol and destination?",
        ],
    ),
    "network.dns.questions.name": _entry(
        meaning="DNS query name requested by a host or resolver.",
        importance=8,
        category="DNS",
        evidence_role="dns_query",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="public_domain_only",
        mitre_hints=["T1071.004"],
        analyst_questions=[
            "Is the queried domain expected or suspicious?",
            "Is the domain newly observed or rare in the environment?",
        ],
        investigation_pivots=[
            "Search all DNS events for the same domain.",
            "Check which hosts queried the same domain.",
        ],
    ),
    "network.dns.answers.data": _entry(
        meaning="DNS answer data such as resolved IP address, CNAME, or other DNS response values.",
        importance=7,
        category="DNS",
        evidence_role="dns_answer",
        privacy_sensitivity="low",
        cti_allowed=True,
        cti_transformation="public_ip_or_domain_only",
        mitre_hints=["T1071.004"],
        analyst_questions=[
            "What did the suspicious domain resolve to?",
            "Do resolved IPs appear in proxy, firewall, or EDR telemetry?",
        ],
    ),
    "network.http.method": _entry(
        meaning="HTTP method used in a request, such as GET, POST, PUT, or DELETE.",
        importance=5,
        category="HTTP",
        evidence_role="http_context",
        analyst_questions=[
            "Does the method match normal usage?",
            "Could POST/PUT indicate upload or exfiltration?",
        ],
    ),
    "network.http.request.url": _entry(
        meaning="Full HTTP request URL.",
        importance=9,
        category="HTTP",
        evidence_role="http_url",
        privacy_sensitivity="medium",
        cti_allowed=True,
        cti_transformation="public_url_only",
        mitre_hints=["T1071.001", "T1105", "T1566.002"],
        analyst_questions=[
            "Is this URL expected or suspicious?",
            "Does the URL contain a payload path, phishing path, token, or vendor-console link?",
        ],
        investigation_pivots=[
            "Search proxy, EDR, DNS, and firewall telemetry for the same URL/domain.",
        ],
    ),
    "network.http.response.code": _entry(
        meaning="HTTP response status code returned by the destination.",
        importance=5,
        category="HTTP",
        evidence_role="http_context",
        analyst_questions=[
            "Was the request successful?",
            "Could repeated successful responses indicate working C2 or download?",
        ],
    ),
    "network.http.user_agent": _entry(
        meaning="HTTP user-agent string used by the client.",
        importance=7,
        category="HTTP",
        evidence_role="client_fingerprint",
        privacy_sensitivity="low",
        cti_allowed=False,
        mitre_hints=["T1071.001"],
        analyst_questions=[
            "Is the user-agent expected for the process, host, and application?",
            "Is the user-agent rare, scripted, or associated with automation?",
        ],
        investigation_pivots=[
            "Search the same user-agent across proxy or HTTP logs.",
        ],
    ),

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    "authentication.auth_type": _entry(
        meaning="Type of authentication event or flow.",
        importance=7,
        category="authentication",
        evidence_role="auth_context",
        mitre_hints=["T1078"],
        analyst_questions=[
            "What type of authentication occurred?",
            "Does the authentication type match expected access patterns?",
        ],
    ),
    "authentication.mechanism": _entry(
        meaning="Authentication mechanism such as password, MFA, token, SSO, certificate, or OAuth.",
        importance=8,
        category="authentication",
        evidence_role="auth_mechanism",
        mitre_hints=["T1078", "T1550"],
        analyst_questions=[
            "Was MFA used?",
            "Was the mechanism expected for this user and application?",
        ],
    ),
    "authentication.status": _entry(
        meaning="Authentication outcome such as success, failure, challenge, denied, or interrupted.",
        importance=9,
        category="authentication",
        evidence_role="auth_outcome",
        mitre_hints=["T1078", "T1110"],
        analyst_questions=[
            "Was the authentication successful?",
            "If successful, what follow-up activity occurred?",
            "If failed repeatedly, could this be brute force or password spraying?",
        ],
        investigation_pivots=[
            "Search successful and failed sign-ins around this event.",
            "Check follow-up access to sensitive applications or resources.",
        ],
    ),
    "extensions.auth.mechanism": _entry(
        meaning="Extended authentication mechanism, often from identity provider logs.",
        importance=8,
        category="authentication",
        evidence_role="auth_mechanism",
        mitre_hints=["T1078", "T1550"],
        analyst_questions=[
            "Was the authentication mechanism expected?",
            "Was MFA required and satisfied?",
        ],
    ),
    "extensions.auth.result": _entry(
        meaning="Extended authentication result from the identity provider.",
        importance=9,
        category="authentication",
        evidence_role="auth_outcome",
        mitre_hints=["T1078"],
        analyst_questions=[
            "Did the authentication succeed?",
            "Was Conditional Access or MFA involved?",
        ],
    ),
    "extensions.auth.device_trust_type": _entry(
        meaning="Device trust, compliance, or join state associated with authentication.",
        importance=8,
        category="authentication",
        evidence_role="device_trust",
        mitre_hints=["T1078"],
        analyst_questions=[
            "Was the device trusted, compliant, managed, or unknown?",
            "Does device trust reduce or increase the risk of this sign-in?",
        ],
    ),
    "extensions.auth.conditional_access_status": _entry(
        meaning="Conditional Access evaluation result for the authentication event.",
        importance=8,
        category="authentication",
        evidence_role="conditional_access",
        mitre_hints=["T1078"],
        analyst_questions=[
            "Did Conditional Access allow, block, or challenge this session?",
            "Was the access policy result expected?",
        ],
    ),
    "extensions.auth.user_agent": _entry(
        meaning="User-agent observed during authentication.",
        importance=7,
        category="authentication",
        evidence_role="client_fingerprint",
        privacy_sensitivity="low",
        mitre_hints=["T1078"],
        analyst_questions=[
            "Is this user-agent expected for the user, application, and device?",
            "Is it unusual compared to the user's historical sign-ins?",
        ],
    ),

    # ------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------
    "principal.location.country_or_region": _entry(
        meaning="Country or region associated with the source or acting entity.",
        importance=8,
        category="location",
        evidence_role="source_geo",
        mitre_hints=["T1078", "T1133"],
        analyst_questions=[
            "Is this source country expected for the user or service account?",
            "Is the country outside the customer-approved locations?",
        ],
        investigation_pivots=[
            "Search sign-ins from the same country or ASN.",
        ],
    ),
    "principal.location.city": _entry(
        meaning="City associated with the source or acting entity.",
        importance=6,
        category="location",
        evidence_role="source_geo",
        analyst_questions=[
            "Is this city expected for the user?",
            "Does it contribute to impossible travel or geo-anomaly context?",
        ],
    ),
    "target.location.country_or_region": _entry(
        meaning="Country or region associated with the destination or second observed location.",
        importance=7,
        category="location",
        evidence_role="target_geo",
        mitre_hints=["T1078"],
        analyst_questions=[
            "Does this destination or second location make the activity suspicious?",
            "Does this indicate impossible travel or anomalous access?",
        ],
    ),
    "target.location.city": _entry(
        meaning="City associated with the destination or second observed location.",
        importance=6,
        category="location",
        evidence_role="target_geo",
        analyst_questions=[
            "Does this city support impossible-travel or geo-anomaly context?",
        ],
    ),
}


def _wildcard_lookup(field_name: str) -> Dict[str, Any] | None:
    """
    Support indexed UDM-style fields even when only the generic shape is known.
    Example:
    security_result.attack_details.techniques[4].id
    should still get technique metadata.
    """
    if field_name.startswith("security_result.attack_details.techniques[") and field_name.endswith("].id"):
        return UDM_ONTOLOGY.get("security_result.attack_details.techniques[0].id")

    if field_name.startswith("security_result.attack_details.techniques[") and field_name.endswith("].name"):
        return UDM_ONTOLOGY.get("security_result.attack_details.techniques[0].name")

    if field_name.startswith("security_result.attack_details.tactics[") and field_name.endswith("].id"):
        return UDM_ONTOLOGY.get("security_result.attack_details.tactics[0].id")

    if field_name.startswith("security_result.attack_details.tactics[") and field_name.endswith("].name"):
        return UDM_ONTOLOGY.get("security_result.attack_details.tactics[0].name")

    if field_name.startswith("principal.user.email_addresses["):
        return UDM_ONTOLOGY.get("principal.user.email_addresses[0]")

    if field_name.startswith("principal.user.group_identifiers["):
        return UDM_ONTOLOGY.get("principal.user.group_identifiers[0]")

    return None


def get_ontology_entry(field_name: str) -> Dict[str, Any] | None:
    return UDM_ONTOLOGY.get(field_name) or _wildcard_lookup(field_name)


def load_ontology() -> Dict[str, Dict[str, Any]]:
    """
    Main compatibility function used by the app.
    """
    return UDM_ONTOLOGY


def enrich_field_with_ontology(field_name: str, value: Any) -> Dict[str, Any]:
    entry = get_ontology_entry(field_name)

    if not entry:
        return {
            "field": field_name,
            "value": value,
            "meaning": "No ontology entry yet.",
            "importance": 1,
            "category": "unknown",
            "evidence_role": "unknown",
            "privacy_sensitivity": "unknown",
            "cti_allowed": False,
            "cti_transformation": "unknown",
            "mitre_hints": [],
            "analyst_questions": [],
            "investigation_pivots": [],
            "ontology_status": "missing",
        }

    return {
        "field": field_name,
        "value": value,
        "meaning": entry.get("meaning", ""),
        "importance": entry.get("importance", 1),
        "category": entry.get("category", "unknown"),
        "evidence_role": entry.get("evidence_role", "unknown"),
        "privacy_sensitivity": entry.get("privacy_sensitivity", "low"),
        "cti_allowed": entry.get("cti_allowed", False),
        "cti_transformation": entry.get("cti_transformation", "not_allowed"),
        "mitre_hints": entry.get("mitre_hints", []),
        "analyst_questions": entry.get("analyst_questions", []),
        "investigation_pivots": entry.get("investigation_pivots", []),
        "ontology_status": "known",
    }


def enrich_with_ontology(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert flattened UDM/event data into enriched evidence rows.
    """
    rows = []

    for field_name, value in flattened.items():
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        rows.append(enrich_field_with_ontology(field_name, value))

    rows.sort(
        key=lambda row: (
            row.get("ontology_status") != "known",
            -int(row.get("importance", 1)),
            row.get("field", ""),
        )
    )

    return rows


# Compatibility aliases in case existing app code uses older names.
def build_semantic_facts(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    return enrich_with_ontology(flattened)


def build_enriched_table(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    return enrich_with_ontology(flattened)


def get_field_meaning(field_name: str) -> str:
    entry = get_ontology_entry(field_name)
    if not entry:
        return "No ontology entry yet."
    return entry.get("meaning", "No ontology entry yet.")


def get_field_importance(field_name: str) -> int:
    entry = get_ontology_entry(field_name)
    if not entry:
        return 1
    return int(entry.get("importance", 1))


def get_field_category(field_name: str) -> str:
    entry = get_ontology_entry(field_name)
    if not entry:
        return "unknown"
    return entry.get("category", "unknown")


def get_evidence_bundle_context(flattened: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a richer ontology-driven context object for the AI evidence bundle.
    Existing evidence_bundle.py may or may not use this yet, but this function
    gives us a stable interface for the next improvement.
    """
    enriched_rows = enrich_with_ontology(flattened)

    high_value_evidence = [
        row for row in enriched_rows
        if row.get("importance", 0) >= 8 and row.get("ontology_status") == "known"
    ]

    missing_ontology = [
        row for row in enriched_rows
        if row.get("ontology_status") == "missing"
    ]

    analyst_questions = []
    investigation_pivots = []
    mitre_hints = []

    for row in high_value_evidence:
        analyst_questions.extend(row.get("analyst_questions", []))
        investigation_pivots.extend(row.get("investigation_pivots", []))
        mitre_hints.extend(row.get("mitre_hints", []))

    return {
        "enriched_rows": enriched_rows,
        "high_value_evidence": high_value_evidence,
        "missing_ontology_fields": [row.get("field") for row in missing_ontology],
        "analyst_questions": list(dict.fromkeys(analyst_questions)),
        "investigation_pivots": list(dict.fromkeys(investigation_pivots)),
        "mitre_hints": list(dict.fromkeys(mitre_hints)),
    }


# ---------------------------------------------------------------------
# Backward compatibility aliases
# Older app code imports these names.
# ---------------------------------------------------------------------

def load_udm_ontology() -> Dict[str, Dict[str, Any]]:
    return load_ontology()


def enrich_udm_fields(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    return enrich_with_ontology(flattened)


def enrich_flattened_fields(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    return enrich_with_ontology(flattened)


def get_udm_field_meaning(field_name: str) -> str:
    return get_field_meaning(field_name)


def get_udm_field_importance(field_name: str) -> int:
    return get_field_importance(field_name)


def get_udm_field_category(field_name: str) -> str:
    return get_field_category(field_name)


def get_udm_ontology_entry(field_name: str) -> Dict[str, Any] | None:
    return get_ontology_entry(field_name)


def enrich_udm_field(field_name: str, value: Any) -> Dict[str, Any]:
    return enrich_field_with_ontology(field_name, value)


# ---------------------------------------------------------------------
# Extended backward compatibility aliases
# These keep older streamlit_app.py imports working after the ontology rewrite.
# ---------------------------------------------------------------------

def enrich_key_value_table(flattened: Dict[str, Any], ontology: Dict[str, Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """
    Older app compatibility function.
    Enrich a flattened key-value table with ontology context.
    """
    return enrich_with_ontology(flattened)


def generate_semantic_facts(flattened: Dict[str, Any], ontology: Dict[str, Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """
    Older app compatibility function.
    Returns ontology-enriched semantic facts.
    """
    return enrich_with_ontology(flattened)


def build_semantic_facts_from_ontology(flattened: Dict[str, Any], ontology: Dict[str, Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    return enrich_with_ontology(flattened)


def get_ontology_for_field(field_name: str) -> Dict[str, Any] | None:
    return get_ontology_entry(field_name)


def ontology_lookup(field_name: str) -> Dict[str, Any] | None:
    return get_ontology_entry(field_name)


# ---------------------------------------------------------------------
# Final compatibility override for old pipeline shape
# The app sometimes passes a list-based key_value_table instead of a dict.
# ---------------------------------------------------------------------

def _extract_field_value_from_row(row: Any) -> tuple[str | None, Any]:
    """
    Support multiple row shapes used by earlier app versions:
    {"field": "...", "value": "..."}
    {"key": "...", "value": "..."}
    {"Field": "...", "Value": "..."}
    ("field", "value")
    """
    if isinstance(row, dict):
        field_name = (
            row.get("field")
            or row.get("key")
            or row.get("udm_field")
            or row.get("name")
            or row.get("Field")
            or row.get("Key")
        )

        value = None

        for value_key in ["value", "Value", "raw_value", "Raw Value"]:
            if value_key in row:
                value = row[value_key]
                break

        return field_name, value

    if isinstance(row, (list, tuple)) and len(row) >= 2:
        return str(row[0]), row[1]

    return None, None


def _enrich_any_key_value_input(data: Any) -> List[Dict[str, Any]]:
    """
    Accept both old and new pipeline formats.
    """
    if isinstance(data, dict):
        return enrich_with_ontology(data)

    if isinstance(data, list):
        enriched_rows = []

        for row in data:
            field_name, value = _extract_field_value_from_row(row)

            if not field_name:
                continue

            enriched = enrich_field_with_ontology(field_name, value)

            if isinstance(row, dict):
                # Preserve original row fields, then add ontology context.
                merged = dict(row)
                merged.update(enriched)
                enriched_rows.append(merged)
            else:
                enriched_rows.append(enriched)

        enriched_rows.sort(
            key=lambda row: (
                row.get("ontology_status") != "known",
                -int(row.get("importance", 1)),
                row.get("field", ""),
            )
        )

        return enriched_rows

    return []


def enrich_key_value_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    """
    Compatibility function used by streamlit_app.py.

    Accepts:
    - dict flattened UDM data
    - list of key/value rows
    """
    return _enrich_any_key_value_input(key_value_table)


def generate_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_enriched_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


# ---------------------------------------------------------------------
# Milestone 3.6 compatibility override
# Ensure enriched ontology facts contain both new and old field names:
# - field
# - source_field
# This keeps older render_analysis() UI code working.
# ---------------------------------------------------------------------

def enrich_field_with_ontology(field_name: str, value: Any) -> Dict[str, Any]:
    entry = get_ontology_entry(field_name)

    if not entry:
        return {
            "field": field_name,
            "source_field": field_name,
            "key": field_name,
            "value": value,
            "source_value": value,
            "meaning": "No ontology entry yet.",
            "importance": 1,
            "category": "unknown",
            "evidence_role": "unknown",
            "privacy_sensitivity": "unknown",
            "cti_allowed": False,
            "cti_transformation": "unknown",
            "mitre_hints": [],
            "analyst_questions": [],
            "investigation_pivots": [],
            "ontology_status": "missing",
        }

    return {
        "field": field_name,
        "source_field": field_name,
        "key": field_name,
        "value": value,
        "source_value": value,
        "meaning": entry.get("meaning", ""),
        "importance": entry.get("importance", 1),
        "category": entry.get("category", "unknown"),
        "evidence_role": entry.get("evidence_role", "unknown"),
        "privacy_sensitivity": entry.get("privacy_sensitivity", "low"),
        "cti_allowed": entry.get("cti_allowed", False),
        "cti_transformation": entry.get("cti_transformation", "not_allowed"),
        "mitre_hints": entry.get("mitre_hints", []),
        "analyst_questions": entry.get("analyst_questions", []),
        "investigation_pivots": entry.get("investigation_pivots", []),
        "ontology_status": "known",
    }


def enrich_with_ontology(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []

    for field_name, value in flattened.items():
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        rows.append(enrich_field_with_ontology(field_name, value))

    rows.sort(
        key=lambda row: (
            row.get("ontology_status") != "known",
            -int(row.get("importance", 1)),
            row.get("source_field", ""),
        )
    )

    return rows


def _enrich_any_key_value_input(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        return enrich_with_ontology(data)

    if isinstance(data, list):
        enriched_rows = []

        for row in data:
            field_name, value = _extract_field_value_from_row(row)

            if not field_name:
                continue

            enriched = enrich_field_with_ontology(field_name, value)

            if isinstance(row, dict):
                merged = dict(row)
                merged.update(enriched)
                enriched_rows.append(merged)
            else:
                enriched_rows.append(enriched)

        enriched_rows.sort(
            key=lambda row: (
                row.get("ontology_status") != "known",
                -int(row.get("importance", 1)),
                row.get("source_field", ""),
            )
        )

        return enriched_rows

    return []


def enrich_key_value_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def generate_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_enriched_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


# ---------------------------------------------------------------------
# Milestone 3.6 compatibility override
# Add old "fact" key expected by render_analysis().
# ---------------------------------------------------------------------

def _build_fact_text(field_name: str, value: Any, entry: Dict[str, Any] | None) -> str:
    value_preview = str(value)

    if len(value_preview) > 220:
        value_preview = value_preview[:220] + "...[truncated]"

    if not entry:
        return f"{field_name} has value '{value_preview}', but no ontology entry exists yet."

    meaning = entry.get("meaning", "Known UDM field.")
    evidence_role = entry.get("evidence_role", "evidence")
    category = entry.get("category", "unknown")

    return (
        f"{field_name} is {evidence_role} evidence in category '{category}'. "
        f"{meaning} Observed value: '{value_preview}'."
    )


def enrich_field_with_ontology(field_name: str, value: Any) -> Dict[str, Any]:
    entry = get_ontology_entry(field_name)

    if not entry:
        fact_text = _build_fact_text(field_name, value, None)

        return {
            "field": field_name,
            "source_field": field_name,
            "key": field_name,
            "value": value,
            "source_value": value,
            "fact": fact_text,
            "meaning": "No ontology entry yet.",
            "importance": 1,
            "category": "unknown",
            "evidence_role": "unknown",
            "privacy_sensitivity": "unknown",
            "cti_allowed": False,
            "cti_transformation": "unknown",
            "mitre_hints": [],
            "analyst_questions": [],
            "investigation_pivots": [],
            "ontology_status": "missing",
        }

    fact_text = _build_fact_text(field_name, value, entry)

    return {
        "field": field_name,
        "source_field": field_name,
        "key": field_name,
        "value": value,
        "source_value": value,
        "fact": fact_text,
        "meaning": entry.get("meaning", ""),
        "importance": entry.get("importance", 1),
        "category": entry.get("category", "unknown"),
        "evidence_role": entry.get("evidence_role", "unknown"),
        "privacy_sensitivity": entry.get("privacy_sensitivity", "low"),
        "cti_allowed": entry.get("cti_allowed", False),
        "cti_transformation": entry.get("cti_transformation", "not_allowed"),
        "mitre_hints": entry.get("mitre_hints", []),
        "analyst_questions": entry.get("analyst_questions", []),
        "investigation_pivots": entry.get("investigation_pivots", []),
        "ontology_status": "known",
    }


def enrich_with_ontology(flattened: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []

    for field_name, value in flattened.items():
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        rows.append(enrich_field_with_ontology(field_name, value))

    rows.sort(
        key=lambda row: (
            row.get("ontology_status") != "known",
            -int(row.get("importance", 1)),
            row.get("source_field", ""),
        )
    )

    return rows


def _enrich_any_key_value_input(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        return enrich_with_ontology(data)

    if isinstance(data, list):
        enriched_rows = []

        for row in data:
            field_name, value = _extract_field_value_from_row(row)

            if not field_name:
                continue

            enriched = enrich_field_with_ontology(field_name, value)

            if isinstance(row, dict):
                merged = dict(row)
                merged.update(enriched)
                enriched_rows.append(merged)
            else:
                enriched_rows.append(enriched)

        enriched_rows.sort(
            key=lambda row: (
                row.get("ontology_status") != "known",
                -int(row.get("importance", 1)),
                row.get("source_field", ""),
            )
        )

        return enriched_rows

    return []


def enrich_key_value_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def generate_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_semantic_facts(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)


def build_enriched_table(
    key_value_table: Any,
    ontology: Dict[str, Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return _enrich_any_key_value_input(key_value_table)
