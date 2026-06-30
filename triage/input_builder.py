from typing import Dict, Any


def build_udm_from_guided_input(form_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts analyst-friendly form fields into UDM-style key-value pairs.

    The goal is not to perfectly recreate Google SecOps UDM.
    The goal is to use UDM as a neutral SOC triage evidence model.
    """
    udm_alert = {}

    field_mapping = {
        "event_type": "metadata.event_type",
        "vendor_name": "metadata.vendor_name",
        "product_name": "metadata.product_name",

        "alert_name": "security_result.rule_name",
        "rule_id": "security_result.rule_id",
        "alert_title": "security_result.display_name",
        "alert_summary": "security_result.summary",
        "alert_description": "security_result.description",
        "severity": "security_result.severity",
        "priority": "security_result.priority",
        "risk_score": "security_result.risk_score",
        "action": "security_result.action",

        "mitre_tactic_id": "security_result.attack_details.tactics[0].id",
        "mitre_tactic_name": "security_result.attack_details.tactics[0].name",
        "mitre_technique_id": "security_result.attack_details.techniques[0].id",
        "mitre_technique_name": "security_result.attack_details.techniques[0].name",
        "mitre_subtechnique_id": "security_result.attack_details.techniques[0].subtechnique_id",
        "mitre_subtechnique_name": "security_result.attack_details.techniques[0].subtechnique_name",

        "user": "principal.user.userid",
        "host": "principal.asset.hostname",
        "source_ip": "principal.ip",

        "process_path": "principal.process.file.full_path",
        "process_command_line": "principal.process.command_line",
        "parent_process_path": "principal.process.parent_process.file.full_path",

        "target_ip": "target.ip",
        "target_hostname": "target.hostname",
        "target_url": "target.url",
        "target_domain": "target.domain.name",

        "file_hash_sha256": "target.file.sha256",
        "file_hash_sha1": "target.file.sha1",
        "file_hash_md5": "target.file.md5",
    }

    for friendly_field, udm_field in field_mapping.items():
        value = form_data.get(friendly_field)

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        udm_alert[udm_field] = value

    return udm_alert