import json
import streamlit as st

from triage.evidence_bundle import build_evidence_bundle
from triage.claude_client import ask_claude_for_triage

from triage.extractors import flatten_json, extract_entities, build_key_value_table
from triage.ontology import (
    load_udm_ontology,
    enrich_key_value_table,
    build_semantic_facts,
)
from triage.mitre_mapper import map_mitre_hypotheses
from triage.input_builder import build_udm_from_guided_input
from triage.mitre_knowledge import (
    download_enterprise_attack,
    build_mitre_knowledge,
    enrich_technique_ids,
    extract_technique_ids_from_mitre_analysis,
)


st.set_page_config(
    page_title="UDM Triage Lab",
    page_icon="🛡️",
    layout="wide",
)


if "current_alert" not in st.session_state:
    st.session_state.current_alert = None

if "current_alert_source" not in st.session_state:
    st.session_state.current_alert_source = None

if "claude_result" not in st.session_state:
    st.session_state.claude_result = None


sample_alert = {
    "metadata.event_type": "PROCESS_LAUNCH",
    "metadata.vendor_name": "Microsoft",
    "metadata.product_name": "Defender for Endpoint",

    "security_result.rule_name": "Suspicious PowerShell Launched from Office",
    "security_result.rule_id": "CFC-WIN-POWERSHELL-OFFICE-001",
    "security_result.display_name": "Office spawned encoded PowerShell",
    "security_result.summary": "Microsoft Word launched PowerShell with encoded command content.",
    "security_result.description": "This alert identifies suspicious process execution where an Office application starts PowerShell using encoded command-line arguments.",
    "security_result.severity": "HIGH",
    "security_result.priority": "HIGH_PRIORITY",
    "security_result.risk_score": 85,

    "security_result.attack_details.version": "14.1",
    "security_result.attack_details.tactics[0].id": "TA0002",
    "security_result.attack_details.tactics[0].name": "Execution",
    "security_result.attack_details.tactics[1].id": "TA0005",
    "security_result.attack_details.tactics[1].name": "Defense Evasion",
    "security_result.attack_details.techniques[0].id": "T1059",
    "security_result.attack_details.techniques[0].name": "Command and Scripting Interpreter",
    "security_result.attack_details.techniques[0].subtechnique_id": "T1059.001",
    "security_result.attack_details.techniques[0].subtechnique_name": "PowerShell",
    "security_result.attack_details.techniques[1].id": "T1027",
    "security_result.attack_details.techniques[1].name": "Obfuscated Files or Information",

    "principal.user.userid": "svc_backup",
    "principal.asset.hostname": "WIN-SRV-22",
    "principal.process.file.full_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "principal.process.command_line": "powershell.exe -enc SQBFAFgA...",
    "principal.process.parent_process.file.full_path": "C:\\Program Files\\Microsoft Office\\winword.exe",

    "security_result.action": "ALLOW",
    "target.ip": "185.199.108.133",
}


@st.cache_data(show_spinner=False)
def get_mitre_knowledge():
    download_enterprise_attack(force=False)
    return build_mitre_knowledge()


def build_pipeline(parsed_json: dict):
    """
    Shared evidence pipeline used by both Advanced Lab and Analyst App.
    """
    ontology = load_udm_ontology()

    flattened = flatten_json(parsed_json)
    entities = extract_entities(flattened)

    key_value_table = build_key_value_table(flattened)
    enriched_table = enrich_key_value_table(key_value_table, ontology)
    semantic_facts = build_semantic_facts(enriched_table)
    mitre_analysis = map_mitre_hypotheses(flattened)

    try:
        mitre_knowledge = get_mitre_knowledge()
        technique_ids = extract_technique_ids_from_mitre_analysis(mitre_analysis)
        enriched_techniques = enrich_technique_ids(technique_ids, mitre_knowledge)
    except Exception as error:
        enriched_techniques = []
        st.warning(f"MITRE enrichment is currently unavailable: {error}")

    evidence_bundle = build_evidence_bundle(
        parsed_json=parsed_json,
        entities=entities,
        semantic_facts=semantic_facts,
        mitre_analysis=mitre_analysis,
        enriched_techniques=enriched_techniques,
        data_mode=data_mode,
    )

    return {
        "flattened": flattened,
        "entities": entities,
        "enriched_table": enriched_table,
        "semantic_facts": semantic_facts,
        "mitre_analysis": mitre_analysis,
        "enriched_techniques": enriched_techniques,
        "evidence_bundle": evidence_bundle,
    }


def render_simple_claude_result(claude_result: dict):
    """
    Clean user-facing Claude result view for SOC analysts.
    """
    if not claude_result:
        st.info("Generate an AI triage explanation to see the analyst summary.")
        return

    if "error" in claude_result:
        st.error(claude_result["error"])

        if "raw_response" in claude_result:
            st.code(claude_result["raw_response"])

        return

    assessment = claude_result.get("assessment", "unknown")
    confidence = claude_result.get("confidence", "unknown")

    st.markdown("## AI Triage Assessment")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Assessment", assessment)

    with col2:
        st.metric("Confidence", confidence)

    st.markdown("### Triage Summary")
    st.write(claude_result.get("triage_summary", "No summary returned."))

    st.markdown("### Why this may be suspicious")
    for item in claude_result.get("why_suspicious", []):
        st.write(f"- {item}")

    st.markdown("### Why this may be benign")
    for item in claude_result.get("why_could_be_benign", []):
        st.write(f"- {item}")

    st.markdown("### Missing evidence")
    for item in claude_result.get("missing_evidence", []):
        st.write(f"- {item}")

    st.markdown("### Recommended next steps")
    for item in claude_result.get("recommended_next_steps", []):
        st.write(f"- {item}")

    st.markdown("### Customer-facing summary")
    st.info(claude_result.get("customer_facing_summary", "No customer summary returned."))

    with st.expander("Internal analyst notes"):
        st.write(claude_result.get("analyst_notes", "No analyst notes returned."))

    with st.expander("MITRE interpretation"):
        for item in claude_result.get("mitre_interpretation", []):
            st.write(f"- {item}")


def render_analysis(parsed_json: dict):
    """
    Advanced/debug analysis view.
    """
    pipeline = build_pipeline(parsed_json)

    entities = pipeline["entities"]
    enriched_table = pipeline["enriched_table"]
    semantic_facts = pipeline["semantic_facts"]
    mitre_analysis = pipeline["mitre_analysis"]
    enriched_techniques = pipeline["enriched_techniques"]
    evidence_bundle = pipeline["evidence_bundle"]

    st.subheader("1. Parsed / Generated UDM JSON")
    st.json(parsed_json)

    st.subheader("2. UDM Key-Value Intelligence Table")
    st.caption(
        "This is the structured evidence layer. It combines UDM key-value pairs with ontology meaning, importance and MITRE hints."
    )

    st.dataframe(
        enriched_table,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("3. Highest-Value Semantic Facts")
    st.caption("These facts become the clean evidence bundle for Claude.")

    for fact in semantic_facts[:10]:
        with st.expander(
            f"Importance {fact['importance']} | {fact['source_field']}"
        ):
            st.write(f"**Fact:** {fact['fact']}")
            st.write(f"**Meaning:** {fact['meaning']}")
            st.write(f"**Category:** {fact['category']}")

            if fact["mitre_hints"]:
                st.write(f"**MITRE hints:** {fact['mitre_hints']}")

    st.subheader("4. Suspicious Pattern & MITRE Hypotheses")
    st.caption(
        "Deterministic first-pass mapping based on UDM evidence. These are hypotheses, not final attribution or confirmed compromise."
    )

    st.write(f"**Initial verdict:** {mitre_analysis['initial_verdict']}")
    st.write(f"**Overall severity:** {mitre_analysis['overall_severity']}")
    st.write(f"**Summary:** {mitre_analysis['summary']}")

    if not mitre_analysis["matches"]:
        st.info("No deterministic suspicious pattern matched yet.")
    else:
        for match in mitre_analysis["matches"]:
            with st.expander(
                f"{match['severity'].upper()} | {match['pattern_name']} | Confidence: {match['confidence']}"
            ):
                st.write(f"**Reason:** {match['reason']}")

                st.markdown("**Mapped MITRE techniques:**")
                for technique in match["techniques"]:
                    st.write(
                        f"- `{technique['id']}` — {technique['name']} ({technique['tactic']})"
                    )

                st.markdown("**Evidence:**")
                for item in match["evidence"]:
                    st.code(f"{item['field']}: {item['value']}")

                st.markdown("**Missing evidence:**")
                for item in match["missing_evidence"]:
                    st.write(f"- {item}")

                st.markdown("**Recommended next steps:**")
                for step in match["recommended_next_steps"]:
                    st.write(f"- {step}")

    st.subheader("5. MITRE ATT&CK Knowledge Enrichment")
    st.caption(
        "This section enriches detected technique IDs with official MITRE ATT&CK Enterprise context."
    )

    if not enriched_techniques:
        st.info("No MITRE techniques to enrich yet.")
    else:
        for technique in enriched_techniques:
            title = f"{technique['id']} — {technique['name']}"

            if not technique.get("found_in_mitre", False):
                title = f"{technique['id']} — not found in local MITRE data"

            with st.expander(title):
                st.write(f"**Found in MITRE:** {technique.get('found_in_mitre', False)}")

                if technique.get("url"):
                    st.write(f"**MITRE URL:** {technique['url']}")

                st.write("**Tactics:**")
                st.write(technique.get("tactics", []) or "None listed")

                st.write("**Platforms:**")
                st.write(technique.get("platforms", []) or "None listed")

                st.write("**Data sources:**")
                st.write(technique.get("data_sources", []) or "None listed")

                description = technique.get("description", "")
                if description:
                    st.markdown("**Description:**")
                    st.write(description[:1500] + ("..." if len(description) > 1500 else ""))

                detection = technique.get("detection", "")
                if detection:
                    st.markdown("**Detection guidance:**")
                    st.write(detection[:1500] + ("..." if len(detection) > 1500 else ""))

                known_groups = technique.get("known_groups", [])
                if known_groups:
                    st.markdown("**Known groups using this technique:**")
                    st.write(", ".join(known_groups[:25]))

                known_software = technique.get("known_software", [])
                if known_software:
                    st.markdown("**Known software/tools using this technique:**")
                    st.write(", ".join(known_software[:25]))

                st.warning(
                    "Group/software overlap is context only. This is not threat actor attribution."
                )

    st.subheader("6. Claude AI Triage Explanation")
    st.caption(
        "Claude receives the structured evidence bundle and produces a cautious SOC triage explanation."
    )

    with st.expander("Preview evidence bundle sent to Claude"):
        st.json(evidence_bundle)

    if data_mode == "Real":
        st.warning(
            "You selected Real mode. Only send real customer data to Claude if this is approved for your environment."
        )

    if st.button("Generate Claude Triage Explanation", key="advanced_generate_claude_triage"):
        with st.spinner("Claude is analyzing the evidence bundle..."):
            st.session_state.claude_result = ask_claude_for_triage(evidence_bundle)

    render_simple_claude_result(st.session_state.claude_result)

    st.subheader("7. Extracted SOC Entities")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### Alert Names")
        st.write(entities["alert_names"] or "None detected")

        st.markdown("### Rule IDs")
        st.write(entities["rule_ids"] or "None detected")

        st.markdown("### Users")
        st.write(entities["users"] or "None detected")

        st.markdown("### Hosts")
        st.write(entities["hosts"] or "None detected")

    with col2:
        st.markdown("### MITRE Tactics")
        st.write(entities["mitre_tactics"] or "None detected")

        st.markdown("### MITRE Techniques")
        st.write(entities["mitre_techniques"] or "None detected")

        st.markdown("### IPs")
        st.write(entities["ips"] or "None detected")

        st.markdown("### URLs")
        st.write(entities["urls"] or "None detected")

    with col3:
        st.markdown("### Processes")
        st.write(entities["processes"] or "None detected")

        st.markdown("### Command Lines")
        st.write(entities["command_lines"] or "None detected")

        st.markdown("### Hashes")
        st.write(entities["hashes"] or "None detected")


def render_guided_builder():
    st.subheader("Guided Alert Builder")
    st.caption(
        "Fill analyst-friendly fields. The app converts them into UDM-style key-value pairs behind the scenes."
    )

    with st.form("guided_alert_builder"):
        st.markdown("### Alert context")

        col1, col2, col3 = st.columns(3)

        with col1:
            event_type = st.selectbox(
                "Event type",
                ["PROCESS_LAUNCH", "USER_LOGIN", "NETWORK_CONNECTION", "FILE_CREATION", "GENERIC_EVENT"],
            )
            vendor_name = st.text_input("Vendor", value="Microsoft")
            product_name = st.text_input("Product", value="Defender for Endpoint")
            severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=2)

        with col2:
            alert_name = st.text_input(
                "Alert name",
                value="Suspicious PowerShell Launched from Office",
            )
            rule_id = st.text_input(
                "Rule ID",
                value="CFC-WIN-POWERSHELL-OFFICE-001",
            )
            alert_title = st.text_input(
                "Alert title",
                value="Office spawned encoded PowerShell",
            )
            action = st.selectbox("Security action", ["ALLOW", "BLOCK", "DETECT", "QUARANTINE", "FAIL"], index=0)

        with col3:
            priority = st.selectbox(
                "Priority",
                ["LOW_PRIORITY", "MEDIUM_PRIORITY", "HIGH_PRIORITY", "CRITICAL_PRIORITY"],
                index=2,
            )
            risk_score = st.number_input("Risk score", min_value=0, max_value=100, value=85)
            alert_summary = st.text_area(
                "Alert summary",
                value="Microsoft Word launched PowerShell with encoded command content.",
                height=90,
            )

        alert_description = st.text_area(
            "Alert description",
            value="This alert identifies suspicious process execution where an Office application starts PowerShell using encoded command-line arguments.",
            height=100,
        )

        st.markdown("### MITRE context")

        col4, col5, col6 = st.columns(3)

        with col4:
            mitre_tactic_id = st.text_input("MITRE tactic ID", value="TA0002")
            mitre_tactic_name = st.text_input("MITRE tactic name", value="Execution")

        with col5:
            mitre_technique_id = st.text_input("MITRE technique ID", value="T1059")
            mitre_technique_name = st.text_input(
                "MITRE technique name",
                value="Command and Scripting Interpreter",
            )

        with col6:
            mitre_subtechnique_id = st.text_input("MITRE subtechnique ID", value="T1059.001")
            mitre_subtechnique_name = st.text_input("MITRE subtechnique name", value="PowerShell")

        st.markdown("### Entity and process context")

        col7, col8, col9 = st.columns(3)

        with col7:
            user = st.text_input("User", value="svc_backup")
            host = st.text_input("Host", value="WIN-SRV-22")
            source_ip = st.text_input("Source IP", value="")

        with col8:
            process_path = st.text_input(
                "Process path / name",
                value="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            )
            process_command_line = st.text_area(
                "Command line",
                value="powershell.exe -enc SQBFAFgA...",
                height=80,
            )
            parent_process_path = st.text_input(
                "Parent process path / name",
                value="C:\\Program Files\\Microsoft Office\\winword.exe",
            )

        with col9:
            target_ip = st.text_input("Target IP", value="185.199.108.133")
            target_hostname = st.text_input("Target hostname", value="")
            target_url = st.text_input("Target URL", value="")
            target_domain = st.text_input("Target domain", value="")

        st.markdown("### File hash context")

        col10, col11, col12 = st.columns(3)

        with col10:
            file_hash_sha256 = st.text_input("SHA256", value="")

        with col11:
            file_hash_sha1 = st.text_input("SHA1", value="")

        with col12:
            file_hash_md5 = st.text_input("MD5", value="")

        submitted = st.form_submit_button("Build & Analyze UDM Alert")

    if submitted:
        form_data = {
            "event_type": event_type,
            "vendor_name": vendor_name,
            "product_name": product_name,
            "alert_name": alert_name,
            "rule_id": rule_id,
            "alert_title": alert_title,
            "alert_summary": alert_summary,
            "alert_description": alert_description,
            "severity": severity,
            "priority": priority,
            "risk_score": risk_score,
            "action": action,
            "mitre_tactic_id": mitre_tactic_id,
            "mitre_tactic_name": mitre_tactic_name,
            "mitre_technique_id": mitre_technique_id,
            "mitre_technique_name": mitre_technique_name,
            "mitre_subtechnique_id": mitre_subtechnique_id,
            "mitre_subtechnique_name": mitre_subtechnique_name,
            "user": user,
            "host": host,
            "source_ip": source_ip,
            "process_path": process_path,
            "process_command_line": process_command_line,
            "parent_process_path": parent_process_path,
            "target_ip": target_ip,
            "target_hostname": target_hostname,
            "target_url": target_url,
            "target_domain": target_domain,
            "file_hash_sha256": file_hash_sha256,
            "file_hash_sha1": file_hash_sha1,
            "file_hash_md5": file_hash_md5,
        }

        generated_udm = build_udm_from_guided_input(form_data)

        st.session_state.current_alert = generated_udm
        st.session_state.current_alert_source = "Analyst App - Guided Alert Builder"
        st.session_state.claude_result = None

        st.success("Guided input converted into UDM-style key-value pairs. Alert loaded for analysis.")


def render_analyst_app():
    """
    Clean user-facing app mode.
    Uses the guided builder as input, then shows a simplified Claude result.
    """
    st.subheader("SOC Alert Triage Assistant")
    st.caption(
        "Fill in the key alert details. The app converts them into a normalized UDM-style evidence model behind the scenes."
    )

    render_guided_builder()

    if st.session_state.current_alert is None:
        st.info("Build an alert using the guided form above to start the analyst workflow.")
        return

    st.divider()
    st.caption(f"Current alert source: {st.session_state.current_alert_source}")

    pipeline = build_pipeline(st.session_state.current_alert)

    mitre_analysis = pipeline["mitre_analysis"]
    semantic_facts = pipeline["semantic_facts"]
    entities = pipeline["entities"]
    evidence_bundle = pipeline["evidence_bundle"]

    st.markdown("### Initial deterministic assessment")
    st.write(f"**Initial verdict:** {mitre_analysis['initial_verdict']}")
    st.write(f"**Overall severity:** {mitre_analysis['overall_severity']}")
    st.write(f"**Summary:** {mitre_analysis['summary']}")

    if mitre_analysis["matches"]:
        with st.expander("Show matched suspicious patterns"):
            for match in mitre_analysis["matches"]:
                st.markdown(f"**{match['pattern_name']}**")
                st.write(f"Severity: {match['severity']}")
                st.write(f"Confidence: {match['confidence']}")
                st.write(match["reason"])

    if st.button("Generate AI Triage Summary", key="analyst_app_generate_claude"):
        with st.spinner("Claude is analyzing the evidence bundle..."):
            st.session_state.claude_result = ask_claude_for_triage(evidence_bundle)

    render_simple_claude_result(st.session_state.claude_result)

    with st.expander("Show technical evidence details"):
        st.markdown("#### Generated UDM JSON")
        st.json(st.session_state.current_alert)

        st.markdown("#### Extracted entities")
        st.json(entities)

        st.markdown("#### Top semantic facts")
        st.json(semantic_facts[:10])

        st.markdown("#### MITRE analysis")
        st.json(mitre_analysis)

        st.markdown("#### Evidence bundle sent to Claude")
        st.json(evidence_bundle)


st.title("🛡️ UDM Triage Lab")
st.caption("Paste UDM-style alert JSON or build an alert using analyst-friendly fields.")

st.warning(
    "Lab/demo use only. Do not paste real customer-sensitive data unless this runs in an approved private environment."
)

data_mode = st.radio(
    "Data mode",
    ["Mock", "Anonymized", "Real"],
    horizontal=True,
)

main_tab_lab, main_tab_analyst = st.tabs(["Advanced Lab", "Analyst App"])

with main_tab_lab:
    st.subheader("Advanced Lab")
    st.caption(
        "Developer/debug mode for raw UDM JSON, ontology inspection, MITRE enrichment and evidence bundle review."
    )

    with st.expander("Show sample UDM alert"):
        st.code(json.dumps(sample_alert, indent=2), language="json")

    udm_input = st.text_area(
        "Paste UDM JSON here",
        height=300,
        value=json.dumps(sample_alert, indent=2),
        key="advanced_raw_udm_json_input",
    )

    if st.button("Analyze Pasted Alert", key="advanced_analyze_pasted_alert"):
        if not udm_input.strip():
            st.error("Please paste JSON first.")
        else:
            try:
                parsed_json = json.loads(udm_input)

            except json.JSONDecodeError as error:
                st.error("Invalid JSON.")
                st.code(str(error))

            else:
                st.session_state.current_alert = parsed_json
                st.session_state.current_alert_source = "Advanced Lab - Pasted UDM JSON"
                st.session_state.claude_result = None
                st.success("Valid JSON detected. Alert loaded for analysis.")

    if st.session_state.current_alert is not None:
        st.divider()
        st.caption(f"Current alert source: {st.session_state.current_alert_source}")
        render_analysis(st.session_state.current_alert)
    else:
        st.info("Paste a UDM alert above and click Analyze to start advanced analysis.")


with main_tab_analyst:
    render_analyst_app()