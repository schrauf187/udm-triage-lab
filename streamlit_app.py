import streamlit as st
import json


from triage.extractors import flatten_json, extract_entities


st.set_page_config(
    page_title="UDM Triage Lab",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ UDM Triage Lab")
st.caption("Paste UDM-style alert JSON and extract the first SOC triage entities.")

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
    "principal.user.userid": "svc_backup",
    "principal.asset.hostname": "WIN-SRV-22",
    "principal.process.file.full_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "principal.process.command_line": "powershell.exe -enc SQBFAFgA...",
    "principal.process.parent_process.file.full_path": "C:\\Program Files\\Microsoft Office\\winword.exe",
    "security_result.action": "ALLOW",
    "target.ip": "185.199.108.133",
}

with st.expander("Show sample UDM alert"):
    st.code(json.dumps(sample_alert, indent=2), language="json")

udm_input = st.text_area(
    "Paste UDM JSON here",
    height=300,
    placeholder="Paste your UDM-style alert JSON here...",
)

if st.button("Analyze Alert"):
    if not udm_input.strip():
        st.error("Please paste JSON first.")

    else:
        try:
            parsed_json = json.loads(udm_input)
            st.success("Valid JSON detected.")

            flattened = flatten_json(parsed_json)
            entities = extract_entities(flattened)

            st.subheader("1. Parsed JSON")
            st.json(parsed_json)

            st.subheader("2. Flattened UDM Fields")
            st.write(f"Detected **{len(flattened)}** UDM-style fields.")

            for field, value in flattened.items():
                st.code(f"{field}: {value}")

            st.subheader("3. Extracted SOC Entities")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown("### Users")
                st.write(entities["users"] or "None detected")

                st.markdown("### Hosts")
                st.write(entities["hosts"] or "None detected")

            with col2:
                st.markdown("### IPs")
                st.write(entities["ips"] or "None detected")

                st.markdown("### URLs")
                st.write(entities["urls"] or "None detected")

            with col3:
                st.markdown("### Processes")
                st.write(entities["processes"] or "None detected")

                st.markdown("### Command Lines")
                st.write(entities["command_lines"] or "None detected")

            st.subheader("4. Current MVP Status")
            st.info(
                "Milestone 1 complete: JSON validation, UDM field flattening, and basic entity extraction are working."
            )

        except json.JSONDecodeError as error:
            st.error("Invalid JSON.")
            st.code(str(error))