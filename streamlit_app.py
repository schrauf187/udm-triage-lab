import json
import streamlit as st


from triage.extractors import flatten_json, extract_entities, build_key_value_table
from triage.ontology import (
    load_udm_ontology,
    enrich_key_value_table,
    build_semantic_facts,
)
  
from triage.mitre_mapper import map_mitre_hypotheses
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

st.title("🛡️ UDM Triage Lab")
st.caption("Paste UDM-style alert JSON and extract SOC triage context.")

st.warning(
    "Lab/demo use only. Do not paste real customer-sensitive data unless this runs in an approved private environment."
)

data_mode = st.radio(
    "Data mode",
    ["Mock", "Anonymized", "Real"],
    horizontal=True,
)

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

with st.expander("Show sample UDM alert"):
    st.code(json.dumps(sample_alert, indent=2), language="json")

udm_input = st.text_area(
    "Paste UDM JSON here",
    height=300,
    value=json.dumps(sample_alert, indent=2),
)

if st.button("Analyze Alert"):
    if not udm_input.strip():
        st.error("Please paste JSON first.")

    else:
        try:
            parsed_json = json.loads(udm_input)
            st.success("Valid JSON detected.")

            ontology = load_udm_ontology()

            flattened = flatten_json(parsed_json)
            entities = extract_entities(flattened)

            key_value_table = build_key_value_table(flattened)
            enriched_table = enrich_key_value_table(key_value_table, ontology)
            semantic_facts = build_semantic_facts(enriched_table)
            mitre_analysis = map_mitre_hypotheses(flattened)
           
            mitre_knowledge = get_mitre_knowledge()
            technique_ids = extract_technique_ids_from_mitre_analysis(mitre_analysis)
            enriched_techniques = enrich_technique_ids(technique_ids, mitre_knowledge)

            st.subheader("1. Parsed JSON")
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
            st.caption("These facts will later become the clean evidence bundle for Claude.")

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

            st.subheader("6. Extracted SOC Entities")

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

            st.subheader("7. Current MVP Status")
            st.info(
                "Milestone 3 complete: deterministic MITRE pattern mapping is now working."
            )

        except json.JSONDecodeError as error:
            st.error("Invalid JSON.")
            st.code(str(error))

        except FileNotFoundError:
            st.error(
                "Ontology file not found. Please create ontology/udm_ontology.yaml."
            )