import json
import os
import subprocess
import streamlit as st
from html import escape

from triage.raw_extractor import parse_raw_alert_to_field_inventory
from triage.ai_udm_mapper import ask_ai_for_udm_mapping_suggestions
from triage.feedback_db import (
    get_feedback_stats,
    init_feedback_db,
    list_mapping_decisions,
    list_recent_feedback,
    save_feedback_submission,
)

from triage.cti_safety import (
    build_safe_cti_research_package,
    has_cti_researchable_indicators,
)

from triage.attack_path import build_attack_path_hypothesis
from triage.query_generator import generate_hunt_queries
from triage.evidence_bundle import build_evidence_bundle

from triage.claude_client import (
    ask_claude_for_triage,
    ask_claude_for_followup_reassessment,
    ask_claude_for_cti_web_research,
)

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


@st.cache_data(show_spinner=False)
def get_app_version():
    """Return "<shorthash> · <YYYY-MM-DD> · <subject>" for the running commit, or None.

    Reads git at runtime. On Streamlit Community Cloud the app runs from a git
    clone, so the .git directory and git binary are present and this reflects
    the actually-deployed commit. Pinned to this file's own directory so the
    process working directory can't affect it.

    The commit subject (first line of the message) is truncated to ~60 chars so
    the footer can't wrap. Hash + date are the core: if they fail, return None.
    The subject is best-effort in its own guard — if only it fails, the footer
    still shows "<shorthash> · <date>".

    Fail-silent by design: any problem (no git, no .git, timeout, non-zero
    exit) returns None so a cosmetic footer can never crash the app.
    """
    try:
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        short_hash = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, timeout=2, check=True,
        ).stdout.strip()
        if not short_hash:
            return None
        commit_date = subprocess.run(
            ["git", "show", "-s", "--format=%cs", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, timeout=2, check=True,
        ).stdout.strip()

        # Best-effort commit subject; a failure here must not lose hash + date.
        subject = None
        try:
            subject = subprocess.run(
                ["git", "show", "-s", "--format=%s", "HEAD"],
                cwd=repo_dir, capture_output=True, text=True, timeout=2, check=True,
            ).stdout.strip()
            if len(subject) > 60:
                subject = subject[:59].rstrip() + "…"
        except Exception:
            subject = None

        parts = [short_hash]
        if commit_date:
            parts.append(commit_date)
        if subject:
            parts.append(subject)
        return " · ".join(parts)
    except Exception:
        return None


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

if "followup_result" not in st.session_state:
    st.session_state.followup_result = None

if "cti_result" not in st.session_state:
    st.session_state.cti_result = None

if "cti_researched" not in st.session_state:
    st.session_state.cti_researched = False

if "cti_package" not in st.session_state:
    st.session_state.cti_package = None

if "auto_extractor_raw_content" not in st.session_state:
    st.session_state.auto_extractor_raw_content = ""

if "auto_extractor_parsed" not in st.session_state:
    st.session_state.auto_extractor_parsed = None

if "auto_extractor_ai_mapping" not in st.session_state:
    st.session_state.auto_extractor_ai_mapping = None

if "auto_extractor_audit" not in st.session_state:
    st.session_state.auto_extractor_audit = []

if "feedback_submissions" not in st.session_state:
    st.session_state.feedback_submissions = []

if "last_feedback_submission" not in st.session_state:
    st.session_state.last_feedback_submission = None

if "last_feedback_db_result" not in st.session_state:
    st.session_state.last_feedback_db_result = None

sample_alert = {
    "metadata.event_type": "PROCESS_LAUNCH",
    "metadata.vendor_name": "Microsoft",
    "metadata.product_name": "Defender for Endpoint",
    "metadata.description": "Public demo alert for UDM Triage Lab. This sample uses EICAR test indicators and fictional host/user context.",

    "security_result.rule_name": "Suspicious Office Child Process With Encoded PowerShell",
    "security_result.rule_id": "DEMO-MDE-OFFICE-PS-EICAR-001",
    "security_result.display_name": "Office spawned encoded PowerShell and attempted test-file download",
    "security_result.summary": "Microsoft Word launched PowerShell with encoded command content and attempted to download the EICAR anti-malware test file.",
    "security_result.description": "This public demo alert simulates a suspicious Office-to-PowerShell execution chain. The external indicator is the EICAR anti-malware test file, which is safe and commonly used to validate security controls.",
    "security_result.severity": "HIGH",
    "security_result.priority": "HIGH_PRIORITY",
    "security_result.risk_score": 82,
    "security_result.action": "BLOCK",

    "security_result.attack_details.version": "17.0",
    "security_result.attack_details.tactics[0].id": "TA0002",
    "security_result.attack_details.tactics[0].name": "Execution",
    "security_result.attack_details.tactics[1].id": "TA0005",
    "security_result.attack_details.tactics[1].name": "Defense Evasion",
    "security_result.attack_details.tactics[2].id": "TA0011",
    "security_result.attack_details.tactics[2].name": "Command and Control",

    "security_result.attack_details.techniques[0].id": "T1059",
    "security_result.attack_details.techniques[0].name": "Command and Scripting Interpreter",
    "security_result.attack_details.techniques[0].subtechnique_id": "T1059.001",
    "security_result.attack_details.techniques[0].subtechnique_name": "PowerShell",
    "security_result.attack_details.techniques[1].id": "T1027",
    "security_result.attack_details.techniques[1].name": "Obfuscated Files or Information",
    "security_result.attack_details.techniques[2].id": "T1105",
    "security_result.attack_details.techniques[2].name": "Ingress Tool Transfer",
    "security_result.attack_details.techniques[3].id": "T1204",
    "security_result.attack_details.techniques[3].name": "User Execution",

    "principal.user.userid": "j.smith",
    "principal.user.email_addresses[0]": "j.smith@example-corp.local",
    "principal.asset.hostname": "ADMIN-SRV-01",
    "principal.asset.ip[0]": "10.20.30.15",
    "principal.asset.asset_id": "DEMO-ASSET-ADMIN-SRV-01",
    "principal.asset.platform": "WINDOWS",

    "principal.process.file.full_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "principal.process.file.sha256": "8f3a2f6d9b4e4f1a7c9d6e5b2a1c0d9f8e7a6b5c4d3e2f1a9b8c7d6e5f4a3b2c1",
    "principal.process.command_line": "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <base64-redacted>",
    "principal.process.parent_process.file.full_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "principal.process.parent_process.command_line": "WINWORD.EXE C:\\Users\\j.smith\\Downloads\\Quarterly_Bonus_Review.docm",

    "target.url": "https://secure.eicar.org/eicar.com.txt",
    "target.domain.name": "secure.eicar.org",
    "target.file.full_path": "C:\\ProgramData\\AdobeCache\\invoice_viewer.com",
    "target.file.sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "target.file.names[0]": "invoice_viewer.com",

    "network.http.method": "GET",
    "network.http.user_agent": "Mozilla/5.0 PowerShell/7.4",
    "network.direction": "OUTBOUND",

    "additional.fields.demo_context": "Safe public demo. Host, user, and internal IP are fictional. External indicator is EICAR test infrastructure.",
    "additional.fields.expected_cti_result": "CTI should identify EICAR as a safe anti-malware test file, not real malware.",
    "additional.fields.analyst_learning_goal": "Validate Office child process behavior, encoded PowerShell, external file retrieval, CTI-safe indicator handling, and analyst feedback flow."
}

def inject_compact_ui_css():
    st.markdown(
        """
        <style>
        .compact-card {
            border: 1px solid rgba(128, 128, 128, 0.25);
            border-radius: 12px;
            padding: 0.75rem 0.9rem;
            margin-bottom: 0.75rem;
            background: rgba(250, 250, 250, 0.03);
        }

        .compact-card-title {
            font-size: 0.95rem;
            font-weight: 700;
            margin-bottom: 0.35rem;
        }

        .compact-bullets {
            margin-top: 0.2rem;
            margin-bottom: 0.2rem;
            padding-left: 1.1rem;
        }

        .compact-bullets li {
            font-size: 0.86rem;
            line-height: 1.25;
            margin-bottom: 0.22rem;
        }

        .compact-info {
            font-size: 0.9rem;
            line-height: 1.35;
        }

        .small-muted {
            font-size: 0.78rem;
            opacity: 0.72;
        }

        div[data-testid="stMetric"] {
            border: 1px solid rgba(128, 128, 128, 0.22);
            border-radius: 12px;
            padding: 0.55rem 0.7rem;
            background: rgba(250, 250, 250, 0.025);
        }

        div[data-testid="stMetric"] label {
            font-size: 0.78rem !important;
        }

        div[data-testid="stMetric"] div {
            font-size: 0.95rem !important;
        }

        .block-container {
            padding-top: 1.5rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

inject_compact_ui_css()
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

    # 1. Build attack-path hypothesis first
    attack_path = build_attack_path_hypothesis(
        flattened=flattened,
        entities=entities,
        mitre_analysis=mitre_analysis,
        enriched_techniques=enriched_techniques,
    )

    # 2. Then generate hunt queries using that attack path
    hunt_queries = generate_hunt_queries(
        flattened=flattened,
        entities=entities,
        mitre_analysis=mitre_analysis,
        attack_path=attack_path,
    )

    # 3. Build Claude evidence bundle
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
        "attack_path": attack_path,
        "hunt_queries": hunt_queries,
    }

def render_compact_bullets(items, icon: str = "•", empty_message: str = "None returned."):
    """
    Render all bullets, but visually compact.
    Content is not reduced.
    """
    if not items:
        st.markdown(
            f"<div class='small-muted'>{escape(empty_message)}</div>",
            unsafe_allow_html=True,
        )
        return

    bullet_html = "<ul class='compact-bullets'>"

    for item in items:
        bullet_html += f"<li>{escape(icon)} {escape(str(item))}</li>"

    bullet_html += "</ul>"

    st.markdown(bullet_html, unsafe_allow_html=True)

def render_simple_claude_result(claude_result: dict):
    """
    Compact user-facing Claude result view for SOC analysts.
    Shows all content, but with smaller typography and tighter layout.
    """
    if not claude_result:
        st.info("Generate AI triage assistance to receive an investigation assessment, suspicious and benign context, missing evidence, and recommended next steps.")
        return

    if "error" in claude_result:
        st.error(claude_result["error"])

        if "raw_response" in claude_result:
            st.code(claude_result["raw_response"])

        return

    assessment = claude_result.get("assessment", "unknown")
    confidence = claude_result.get("confidence", "unknown")
    triage_summary = claude_result.get("triage_summary", "No summary returned.")

    st.markdown("### 🤖 AI triage result")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Assessment", assessment)

    with col2:
        st.metric("Confidence", confidence)

    st.markdown(
        f"""
        <div class="compact-card">
            <div class="compact-card-title">🧠 What happened?</div>
            <div class="compact-info">{escape(triage_summary)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    reasoning_tabs = st.tabs(
        [
            "🚨 Suspicious",
            "🟢 Benign",
            "🧩 Missing evidence",
            "🧭 Next steps",
        ]
    )

    with reasoning_tabs[0]:
        st.markdown(
            "<div class='compact-card-title'>Why this may be suspicious</div>",
            unsafe_allow_html=True,
        )
        render_compact_bullets(
            claude_result.get("why_suspicious", []),
            icon="🚨",
            empty_message="No suspicious reasoning returned.",
        )

    with reasoning_tabs[1]:
        st.markdown(
            "<div class='compact-card-title'>Why this may be benign</div>",
            unsafe_allow_html=True,
        )
        render_compact_bullets(
            claude_result.get("why_could_be_benign", []),
            icon="🟢",
            empty_message="No benign explanations returned.",
        )

    with reasoning_tabs[2]:
        st.markdown(
            "<div class='compact-card-title'>Missing evidence to validate TP/FP</div>",
            unsafe_allow_html=True,
        )
        render_compact_bullets(
            claude_result.get("missing_evidence", []),
            icon="🧩",
            empty_message="No missing evidence returned.",
        )

    with reasoning_tabs[3]:
        st.markdown(
            "<div class='compact-card-title'>Recommended next investigation steps</div>",
            unsafe_allow_html=True,
        )
        render_compact_bullets(
            claude_result.get("recommended_next_steps", []),
            icon="🧭",
            empty_message="No next steps returned.",
        )

    with st.expander("🧾 Customer-facing summary"):
        st.info(claude_result.get("customer_facing_summary", "No customer summary returned."))

    with st.expander("🧬 Internal analyst notes and MITRE interpretation"):
        st.markdown("#### Analyst notes")
        st.markdown(
            f"<div class='compact-info'>{escape(claude_result.get('analyst_notes', 'No analyst notes returned.'))}</div>",
            unsafe_allow_html=True,
        )

        st.markdown("#### MITRE interpretation")
        render_compact_bullets(
            claude_result.get("mitre_interpretation", []),
            icon="🧬",
            empty_message="No MITRE interpretation returned.",
        )

    with st.expander("🛠️ Raw AI response JSON"):
        st.json(claude_result)

def render_attack_path_visualizer(attack_path: dict, hunt_queries: dict, compact: bool = False):
    """
    Prototype attack-path / kill-chain layout based on MITRE TTPs and extracted evidence.
    """
    st.markdown("### Attack Path Hypothesis")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Likely position", attack_path.get("observed_position", "Unknown"))

    with col2:
        st.metric("Confidence", attack_path.get("confidence", "unknown"))

    st.info(attack_path.get("summary", "No attack-path summary available."))

    st.markdown("#### Kill-chain interpretation")

    stage_rows = []

    for row in attack_path.get("kill_chain_table", []):
        status = row.get("status", "Not observed")

        if status == "Observed in this alert":
            visual_status = "✅ Observed"
        elif status == "Possible previous step":
            visual_status = "⬅️ Possible previous"
        elif status == "Possible next step":
            visual_status = "🔎 Possible next"
        elif status == "Later-stage hunt":
            visual_status = "🧭 Hunt later stage"
        else:
            visual_status = "⚪ Not observed"

        stage_rows.append(
            {
                "Phase": row.get("phase"),
                "Status": visual_status,
                "Mapped TTPs": row.get("mapped_ttps"),
                "Evidence seen": row.get("evidence_seen"),
                "Validation focus": row.get("hunt_focus"),
            }
        )

    st.dataframe(
        stage_rows,
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Why this attack path hypothesis was created", expanded=not compact):
        st.markdown("#### Reasoning")
        for item in attack_path.get("reasoning", []):
            st.write(f"- {item}")

        st.markdown("#### Possible previous steps")
        for item in attack_path.get("possible_previous_steps", []):
            st.write(f"- {item}")

        st.markdown("#### Possible next steps")
        for item in attack_path.get("possible_next_steps", []):
            st.write(f"- {item}")

    known_groups = attack_path.get("known_groups_context", [])
    known_software = attack_path.get("known_software_context", [])

    if known_groups or known_software:
        with st.expander("Known MITRE actor/software overlap — context only"):
            if known_groups:
                st.markdown("#### Known groups using related techniques")
                st.write(", ".join(known_groups))

            if known_software:
                st.markdown("#### Known software/tools using related techniques")
                st.write(", ".join(known_software))

            st.warning(attack_path.get("attribution_warning"))

    st.markdown("### Alert-centric hunts")
    st.caption(
        "These are alert-centric hunts. The goal is to find related alerts or events for the same host, user, IP, URL, process, or MITRE technique. If any hunt returns a hit, paste the relevant rows or analyst notes into the follow-up evidence section so the AI can re-evaluate the case and MITRE kill chain."
    )

    with st.expander("Validation objective", expanded=not compact):
        st.write(hunt_queries.get("validation_objective", ""))

    query_tabs = st.tabs(["KQL", "SPL", "YARA-L", "CrowdStrike NGSIEM"])

    with query_tabs[0]:
        st.code(hunt_queries.get("kql", ""), language="kql")

    with query_tabs[1]:
        st.code(hunt_queries.get("spl", ""), language="spl")

    with query_tabs[2]:
        st.code(hunt_queries.get("yara_l", ""), language="yara")

    with query_tabs[3]:
        st.code(hunt_queries.get("crowdstrike_ngsiem", ""), language="text")

def render_analysis(parsed_json: dict):
    """
    Advanced/debug analysis view.
    """
    pipeline = build_pipeline(parsed_json)

    entities = pipeline["entities"]
    flattened = pipeline["flattened"]
    enriched_table = pipeline["enriched_table"]
    semantic_facts = pipeline["semantic_facts"]
    mitre_analysis = pipeline["mitre_analysis"]
    enriched_techniques = pipeline["enriched_techniques"]
    evidence_bundle = pipeline["evidence_bundle"]
    attack_path = pipeline["attack_path"]
    hunt_queries = pipeline["hunt_queries"]

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


    st.subheader("6. Attack Path Hypothesis & Validation Hunts")
    render_attack_path_visualizer(
        attack_path=attack_path,
        hunt_queries=hunt_queries,
        compact=False,
    )

    st.subheader("7. AI Triage Explanation")
    st.caption(
        "The Triage AI receives the structured evidence bundle and produces a cautious SOC triage explanation."
    )

    with st.expander("Preview evidence bundle sent to Claude"):
        st.json(evidence_bundle)

    if data_mode == "Real":
        st.warning(
            "You selected Real mode. Only send real customer data to Claude if this is approved for your environment."
        )

    if st.button("Generate AI Triage Explanation", key="advanced_generate_claude_triage"):
        with st.spinner("AI is analyzing the evidence bundle..."):
            st.session_state.claude_result = ask_claude_for_triage(evidence_bundle)

    render_simple_claude_result(st.session_state.claude_result)


    st.subheader("8. Extracted SOC Entities")

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



def remove_empty_udm_values(data: dict) -> dict:
    """
    Remove empty optional UDM fields before sending the alert into the pipeline.
    This keeps the ontology table, AI prompt, and CTI package clean.
    """
    clean = {}

    for key, value in data.items():
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        if value in [[], {}, ""]:
            continue

        clean[key] = value

    return clean


def _reset_analysis_state_for_new_alert():
    """
    Reset AI / CTI / follow-up state whenever a new alert is loaded.
    """
    st.session_state.claude_result = None
    st.session_state.followup_result = None
    st.session_state.cti_result = None
    st.session_state.cti_researched = False
    st.session_state.cti_package = None


def _load_alert_into_session(alert: dict, source: str):
    """
    Load an alert into the shared app session.
    """
    st.session_state.current_alert = alert
    st.session_state.current_alert_source = source
    _reset_analysis_state_for_new_alert()


def _safe_widget_key(prefix: str, field_name: str) -> str:
    """
    Turn a UDM field name into a safe Streamlit widget key.
    """
    return (
        f"{prefix}_{field_name}"
        .replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("/", "_")
        .replace(" ", "_")
        .replace("-", "_")
    )


def _is_multiline_udm_field(field_name: str) -> bool:
    """
    Fields that are usually long and should use a text_area instead of text_input.
    """
    multiline_markers = [
        "description",
        "summary",
        "command_line",
        "detection_fields",
        "request.url",
        "user_agent",
    ]
    return any(marker in field_name for marker in multiline_markers)


UDM_GUIDED_FIELD_SECTIONS = {
    "Metadata": [
        "metadata.event_type",
        "metadata.vendor_name",
        "metadata.product_name",
        "metadata.product_event_type",
        "metadata.event_timestamp",
        "metadata.ingested_timestamp",
        "metadata.description",
        "metadata.log_type",
    ],
    "Principal": [
        "principal.ip",
        "principal.hostname",
        "principal.asset.hostname",
        "principal.asset.asset_id",
        "principal.user.userid",
        "principal.user.email_addresses[0]",
        "principal.process.command_line",
        "principal.process.pid",
        "principal.process.file.full_path",
        "principal.process.file.name",
        "principal.process.parent_process.file.full_path",
        "principal.process.parent_process.file.name",
    ],
    "Target": [
        "target.ip",
        "target.hostname",
        "target.user.userid",
        "target.file.full_path",
        "target.file.name",
        "target.file.sha256",
        "target.process.command_line",
        "target.domain.name",
        "target.url",
        "target.port",
        "target.application",
    ],
    "Security Result": [
        "security_result.action",
        "security_result.severity",
        "security_result.priority",
        "security_result.risk_score",
        "security_result.summary",
        "security_result.category",
        "security_result.description",
        "security_result.rule_name",
        "security_result.rule_id",
        "security_result.display_name",
        "security_result.detection_fields",
    ],
    "Network": [
        "network.application_protocol",
        "network.ip_protocol",
        "network.direction",
        "network.session_id",
        "network.sent_bytes",
        "network.received_bytes",
        "network.src_port",
        "network.dst_port",
        "network.connection.count",
    ],
    "Process": [
        "process.pid",
        "process.parent_pid",
        "process.command_line",
        "process.file.full_path",
        "process.file.name",
        "process.file.sha256",
    ],
    "File": [
        "file.full_path",
        "file.sha256",
        "file.md5",
        "file.file_name",
        "file.size",
    ],
    "DNS": [
        "network.dns.questions.name",
        "network.dns.answers.data",
    ],
    "HTTP": [
        "network.http.method",
        "network.http.request.url",
        "network.http.response.code",
        "network.http.user_agent",
    ],
    "Authentication": [
        "authentication.auth_type",
        "authentication.mechanism",
        "authentication.status",
        "extensions.auth.mechanism",
        "extensions.auth.result",
        "extensions.auth.device_trust_type",
        "extensions.auth.conditional_access_status",
        "extensions.auth.user_agent",
    ],
    "MITRE": [
        "security_result.attack_details.tactics[0].id",
        "security_result.attack_details.tactics[0].name",
        "security_result.attack_details.tactics[1].id",
        "security_result.attack_details.tactics[1].name",
        "security_result.attack_details.tactics[2].id",
        "security_result.attack_details.tactics[2].name",
        "security_result.attack_details.techniques[0].id",
        "security_result.attack_details.techniques[0].name",
        "security_result.attack_details.techniques[1].id",
        "security_result.attack_details.techniques[1].name",
        "security_result.attack_details.techniques[2].id",
        "security_result.attack_details.techniques[2].name",
        "security_result.attack_details.techniques[3].id",
        "security_result.attack_details.techniques[3].name",
    ],
}


UDM_FIELD_PLACEHOLDERS = {
    "metadata.event_type": "PROCESS_LAUNCH / USER_LOGIN / NETWORK_CONNECTION / EMAIL_TRANSACTION / USER_RESOURCE_ACCESS",
    "metadata.vendor_name": "Microsoft / CrowdStrike / Zscaler / Google / Palo Alto",
    "metadata.product_name": "Defender for Endpoint / Falcon / Entra ID / ZIA / Azure",
    "metadata.log_type": "EDR_DETECTION / AAD_SIGNIN / WEB_PROXY / AZURE_ACTIVITY",
    "principal.user.userid": "user or service account",
    "principal.user.email_addresses[0]": "user@example.com",
    "principal.asset.hostname": "WIN-SRV-22",
    "principal.ip": "203.0.113.45",
    "principal.process.command_line": "powershell.exe -enc ...",
    "target.ip": "45.83.12.91",
    "target.domain.name": "example-domain.com",
    "target.url": "hxxps://example-domain[.]com/path",
    "security_result.rule_name": "Detection / rule name",
    "security_result.summary": "Short alert summary",
    "security_result.description": "Longer alert description",
    "network.application_protocol": "HTTP / HTTPS / DNS / SMB",
    "network.direction": "OUTBOUND / INBOUND / INTERNAL",
    "network.http.user_agent": "Mozilla/5.0 ...",
    "authentication.mechanism": "MFA / Password / Token / SSO",
    "authentication.status": "SUCCESS / FAILURE",
}



UDM_SECTION_DISPLAY_NAMES = {
    "Metadata": "Alert / Incident Metadata",
    "Principal": "Source / Acting Entity",
    "Target": "Destination / Affected Entity",
    "Security Result": "Detection / Security Result",
    "Network": "Network Session",
    "Process": "Process Evidence",
    "File": "File Evidence",
    "DNS": "DNS Evidence",
    "HTTP": "HTTP Evidence",
    "Authentication": "Authentication Context",
    "MITRE": "MITRE ATT&CK Context",
}


UDM_FIELD_LABELS = {
    "metadata.event_type": "Event type",
    "metadata.vendor_name": "Vendor",
    "metadata.product_name": "Product",
    "metadata.product_event_type": "Vendor event type",
    "metadata.event_timestamp": "Event timestamp",
    "metadata.ingested_timestamp": "Ingested timestamp",
    "metadata.description": "Metadata description",
    "metadata.log_type": "Log type",

    "principal.ip": "Source / acting IP",
    "principal.hostname": "Source hostname",
    "principal.asset.hostname": "Source asset hostname",
    "principal.asset.asset_id": "Source asset ID",
    "principal.user.userid": "Acting user ID",
    "principal.user.email_addresses[0]": "Acting user email",
    "principal.process.command_line": "Source process command line",
    "principal.process.pid": "Source process PID",
    "principal.process.file.full_path": "Source process full path",
    "principal.process.file.name": "Source process name",
    "principal.process.parent_process.file.full_path": "Parent process full path",
    "principal.process.parent_process.file.name": "Parent process name",

    "target.ip": "Destination / target IP",
    "target.hostname": "Destination hostname",
    "target.user.userid": "Target user ID",
    "target.file.full_path": "Target file full path",
    "target.file.name": "Target file name",
    "target.file.sha256": "Target file SHA256",
    "target.process.command_line": "Target process command line",
    "target.domain.name": "Destination domain",
    "target.url": "Destination URL",
    "target.port": "Destination port",
    "target.application": "Target application",

    "security_result.action": "Detection action",
    "security_result.severity": "Severity",
    "security_result.priority": "Priority",
    "security_result.risk_score": "Risk score",
    "security_result.summary": "Alert summary",
    "security_result.category": "Detection category",
    "security_result.description": "Alert description",
    "security_result.rule_name": "Rule name",
    "security_result.rule_id": "Rule ID",
    "security_result.display_name": "Display name",
    "security_result.detection_fields": "Detection fields / matched evidence",

    "network.application_protocol": "Application protocol",
    "network.ip_protocol": "IP protocol",
    "network.direction": "Direction",
    "network.session_id": "Session ID",
    "network.sent_bytes": "Sent bytes",
    "network.received_bytes": "Received bytes",
    "network.src_port": "Source port",
    "network.dst_port": "Destination port",
    "network.connection.count": "Connection count",

    "process.pid": "Process PID",
    "process.parent_pid": "Parent PID",
    "process.command_line": "Observed process command line",
    "process.file.full_path": "Observed process full path",
    "process.file.name": "Observed process name",
    "process.file.sha256": "Observed process SHA256",

    "file.full_path": "File full path",
    "file.sha256": "File SHA256",
    "file.md5": "File MD5",
    "file.file_name": "File name",
    "file.size": "File size",

    "network.dns.questions.name": "DNS query name",
    "network.dns.answers.data": "DNS answer data",

    "network.http.method": "HTTP method",
    "network.http.request.url": "HTTP request URL",
    "network.http.response.code": "HTTP response code",
    "network.http.user_agent": "HTTP user agent",

    "authentication.auth_type": "Authentication type",
    "authentication.mechanism": "Authentication mechanism",
    "authentication.status": "Authentication status",
    "extensions.auth.mechanism": "Auth mechanism",
    "extensions.auth.result": "Auth result",
    "extensions.auth.device_trust_type": "Device trust type",
    "extensions.auth.conditional_access_status": "Conditional access status",
    "extensions.auth.user_agent": "Auth user agent",

    "security_result.attack_details.tactics[0].id": "MITRE tactic 1 ID",
    "security_result.attack_details.tactics[0].name": "MITRE tactic 1 name",
    "security_result.attack_details.tactics[1].id": "MITRE tactic 2 ID",
    "security_result.attack_details.tactics[1].name": "MITRE tactic 2 name",
    "security_result.attack_details.tactics[2].id": "MITRE tactic 3 ID",
    "security_result.attack_details.tactics[2].name": "MITRE tactic 3 name",
    "security_result.attack_details.techniques[0].id": "MITRE technique 1 ID",
    "security_result.attack_details.techniques[0].name": "MITRE technique 1 name",
    "security_result.attack_details.techniques[1].id": "MITRE technique 2 ID",
    "security_result.attack_details.techniques[1].name": "MITRE technique 2 name",
    "security_result.attack_details.techniques[2].id": "MITRE technique 3 ID",
    "security_result.attack_details.techniques[2].name": "MITRE technique 3 name",
    "security_result.attack_details.techniques[3].id": "MITRE technique 4 ID",
    "security_result.attack_details.techniques[3].name": "MITRE technique 4 name",
}


UDM_FIELD_HELP = {
    "metadata.event_type": "High-level event type, for example PROCESS_LAUNCH, USER_LOGIN, NETWORK_CONNECTION, EMAIL_TRANSACTION, USER_RESOURCE_ACCESS.",
    "metadata.product_event_type": "Original event type from the vendor product, if available.",
    "metadata.log_type": "Useful for identifying the data source, for example EDR_DETECTION, AAD_SIGNIN, WEB_PROXY, AZURE_ACTIVITY.",
    "metadata.event_timestamp": "When the security event happened.",
    "metadata.ingested_timestamp": "When the event arrived in the SIEM/data platform.",

    "principal.ip": "The source or acting IP. For identity alerts this is often the sign-in IP. For network alerts this is the client/source IP.",
    "principal.asset.hostname": "The source/acting host, device, or workload that generated the activity.",
    "principal.user.userid": "The acting user or service account.",
    "principal.user.email_addresses[0]": "Email address of the acting user. Useful for identity and email investigations.",
    "principal.process.command_line": "Command line of the source/acting process. Sensitive: this is not sent raw to CTI research.",
    "principal.process.file.full_path": "Full path of the source/acting process, for example powershell.exe path. Sensitive: not sent to CTI research.",

    "target.ip": "The destination, target, or second IP. For impossible travel this may represent the second sign-in IP. For network alerts this is the remote IP.",
    "target.hostname": "Destination or affected host name.",
    "target.domain.name": "Destination domain. This can be used for CTI if it is public and not customer-sensitive.",
    "target.url": "Destination URL. This can be used for CTI if it is public and not customer-sensitive.",
    "target.application": "Application or cloud service accessed, for example Microsoft Azure Portal.",
    "target.file.sha256": "SHA256 of the target/downloaded file. Good CTI indicator if public and non-sensitive.",

    "security_result.action": "What the security product did, for example ALLOW, BLOCK, DETECT, QUARANTINE.",
    "security_result.category": "Detection category, for example malware, identity, suspicious_login, cloud_control_plane.",
    "security_result.detection_fields": "Any matched fields or evidence returned by the detection rule.",
    "security_result.risk_score": "Numeric score if the product provides one.",

    "network.direction": "Traffic direction, for example OUTBOUND, INBOUND, INTERNAL.",
    "network.application_protocol": "Application protocol such as HTTP, HTTPS, DNS, SMB, RDP.",
    "network.connection.count": "Number of repeated connections, useful for beaconing or repeated access patterns.",

    "network.dns.questions.name": "Queried DNS name. Useful for domain/IOC hunting and CTI.",
    "network.dns.answers.data": "DNS answer such as resolved IPs or CNAMEs.",
    "network.http.request.url": "Full HTTP URL if available. Useful for proxy, phishing, malware, or CTI analysis.",
    "network.http.user_agent": "Browser/client user-agent. Useful for identity, proxy, and cloud anomaly analysis.",

    "authentication.mechanism": "How authentication happened, for example MFA, password, token, SSO.",
    "authentication.status": "Authentication outcome such as SUCCESS or FAILURE.",
    "extensions.auth.device_trust_type": "Device trust/compliance status, useful for identity risk.",
    "extensions.auth.conditional_access_status": "Conditional Access result, useful for Entra ID investigations.",
    "extensions.auth.user_agent": "User-agent from authentication logs.",

    "security_result.attack_details.techniques[0].id": "MITRE technique ID such as T1059.001 or T1078. Useful for alert grouping, not IOC hunting.",
}


def _friendly_udm_label(field_name: str) -> str:
    return UDM_FIELD_LABELS.get(field_name, field_name)


def _friendly_udm_help(field_name: str) -> str:
    base_help = UDM_FIELD_HELP.get(field_name, "")
    udm_note = f"UDM field: {field_name}"

    if base_help:
        return f"{base_help}\n\n{udm_note}"

    return udm_note


def _get_values_from_flattened(flattened: dict, field_names: list[str]) -> list[str]:
    values = []

    for field_name in field_names:
        value = flattened.get(field_name)

        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        values.append(str(value))

    return list(dict.fromkeys(values))


def _display_values(values: list[str], fallback: str = "None detected") -> str:
    clean = [str(value) for value in values if str(value).strip()]
    return ", ".join(clean) if clean else fallback


def render_guided_udm_input_form():
    """
    Open UDM-style analyst input.
    This is intentionally not the full UDM model, but the MVP field set
    needed for EDR, SIEM, identity, network, cloud, email, DNS, HTTP, and auth alerts.
    """
    st.markdown("### Guided UDM Fields")
    st.caption(
        "Fill only what you have. Empty fields are removed before analysis. "
        "Use this for structured UDM-style alert creation."
    )

    with st.form("guided_udm_key_value_builder"):
        field_values = {}

        st.info(
            "You do not need to fill every field. Start with Metadata, Security Result, Principal, Target, and MITRE if available."
        )

        for section_name, fields in UDM_GUIDED_FIELD_SECTIONS.items():
            expanded = section_name in ["Metadata", "Security Result", "Principal", "Target", "MITRE"]

            section_display_name = UDM_SECTION_DISPLAY_NAMES.get(section_name, section_name)
            with st.expander(section_display_name, expanded=expanded):
                cols = st.columns(2)

                for index, field_name in enumerate(fields):
                    widget_key = _safe_widget_key("guided_udm", field_name)
                    placeholder = UDM_FIELD_PLACEHOLDERS.get(field_name, "")

                    with cols[index % 2]:
                        if _is_multiline_udm_field(field_name):
                            field_values[field_name] = st.text_area(
                                _friendly_udm_label(field_name),
                                value="",
                                placeholder=placeholder,
                                height=80,
                                help=_friendly_udm_help(field_name),
                                key=widget_key,
                            )
                        else:
                            field_values[field_name] = st.text_input(
                                _friendly_udm_label(field_name),
                                value="",
                                placeholder=placeholder,
                                help=_friendly_udm_help(field_name),
                                key=widget_key,
                            )

        submitted = st.form_submit_button("Build & Analyze Alert from UDM Fields")

    if submitted:
        generated_udm = remove_empty_udm_values(field_values)

        if not generated_udm:
            st.error("Please fill at least one UDM field before building the alert.")
            return

        _load_alert_into_session(
            generated_udm,
            "Analyst App - Guided UDM Fields",
        )

        st.success("UDM key-value alert loaded for analysis.")


def render_raw_alert_json_input(key_prefix: str, source_label: str):
    """
    Raw alert input for full JSON testing.
    Supports flat UDM key-value JSON and nested vendor JSON.
    """
    st.markdown("### Raw Alert JSON")
    st.caption(
        "Paste a full alert JSON here. It can be flat UDM-style key-value JSON or nested vendor JSON. "
        "The pipeline will flatten it and extract entities."
    )

    default_json = json.dumps(sample_alert, indent=2)

    raw_alert_json = st.text_area(
        "Paste full alert JSON",
        height=480,
        value=default_json,
        key=f"{key_prefix}_raw_alert_json_input",
    )

    if st.button("Analyze Raw Alert JSON", key=f"{key_prefix}_analyze_raw_alert_json"):
        if not raw_alert_json.strip():
            st.error("Please paste JSON first.")
            return

        try:
            parsed_json = json.loads(raw_alert_json)

        except json.JSONDecodeError as error:
            st.error("Invalid JSON.")
            st.code(str(error))
            return

        if not isinstance(parsed_json, dict):
            st.error("The alert JSON must be a JSON object.")
            return

        _load_alert_into_session(
            parsed_json,
            source_label,
        )

        st.success("Raw alert JSON loaded for analysis.")



def _mapping_default_decision(suggestion: dict) -> str:
    confidence = suggestion.get("confidence", 0)

    try:
        confidence = float(confidence)
    except Exception:
        confidence = 0

    if suggestion.get("mapping_type") == "preserve_vendor_field":
        return "Accept"

    if confidence >= 0.75:
        return "Accept"

    return "Edit"


def _get_raw_value_for_suggestion(raw_fields: dict, suggestion: dict):
    source_field = suggestion.get("source_field", "")
    suggested_value = suggestion.get("suggested_value", "")

    if source_field in raw_fields:
        return raw_fields[source_field]

    if suggested_value not in [None, ""]:
        return suggested_value

    return suggestion.get("source_value_preview", "")


def render_auto_alert_extractor_input():
    """
    AI-assisted raw alert extraction and UDM mapping workbench.

    Demo/NFR mode:
    The analyst explicitly confirms that pasted alert content may be sent to the AI model.
    No internet CTI research happens in this stage.
    """
    st.markdown("### Auto Alert Extractor")
    st.caption(
        "Paste raw alert text, JSON, key-value data, or a vendor export. "
        "The app extracts fields and asks the AI to recommend UDM mappings. "
        "The analyst must approve mappings before the final evidence bundle is created."
    )

    st.warning(
        "Auto Alert Extractor may send the pasted alert content to the configured Anthropic Claude API model "
        "for UDM mapping assistance. This is not internet CTI research and it is not a model-training pipeline. "
        "Use real alert evidence only when your organization allows this type of third-party API processing or "
        "ensure you properly pseudonymize. AI suggestions remain recommendations and must be reviewed by an analyst."
    )

    raw_content = st.text_area(
        "Paste raw alert data",
        height=420,
        value=st.session_state.auto_extractor_raw_content,
        placeholder=(
            "Paste CrowdStrike, Sentinel, Defender, Splunk, Palo Alto, proxy, DNS, email, cloud, or identity alert data here.\n\n"
            "Supported examples:\n"
            "- Raw JSON\n"
            "- Key-value alert dump\n"
            "- Vendor detection text\n"
            "- SIEM alert export"
        ),
        key="auto_extractor_raw_text_input",
    )

    st.session_state.auto_extractor_raw_content = raw_content

    col_extract, col_ai = st.columns(2)

    with col_extract:
        if st.button("1. Extract fields locally", key="auto_extractor_extract_fields"):
            parsed = parse_raw_alert_to_field_inventory(raw_content)
            st.session_state.auto_extractor_parsed = parsed
            st.session_state.auto_extractor_ai_mapping = None

    parsed = st.session_state.auto_extractor_parsed

    if parsed:
        field_count = parsed.get("field_count", 0)
        input_type = parsed.get("input_type", "unknown")

        if field_count == 0:
            # Never present an empty inventory as a success.
            st.error(
                "No fields could be extracted locally from this input. Check the "
                "format, or paste the raw alert JSON / key-value dump."
            )
        else:
            st.success(f"Extracted {field_count} fields from {input_type} input.")

        for warning in parsed.get("warnings", []):
            st.warning(warning)

        with st.expander("Extracted field inventory", expanded=True):
            st.dataframe(
                parsed.get("inventory", []),
                use_container_width=True,
                hide_index=True,
            )

        with st.expander("Raw extracted key-value fields"):
            st.json(parsed.get("raw_fields", {}))

    analyst_ack = st.checkbox(
        "I understand that this alert/incident content will be sent to the AI model for automated UDM mapping. "
        "I have pseudonymized all my PII fields and read the data privacy section of the app.",
        key="auto_extractor_ai_ack",
    )

    with col_ai:
        if st.button("2. Generate AI UDM mapping suggestions", key="auto_extractor_generate_ai_mapping"):
            if not parsed:
                st.error("Extract fields locally first.")
            elif not analyst_ack:
                st.error("Please confirm the AI mapping notice before generating suggestions.")
            else:
                with st.spinner("AI is analyzing the extracted fields and recommending UDM mappings..."):
                    st.session_state.auto_extractor_ai_mapping = ask_ai_for_udm_mapping_suggestions(
                        raw_alert_content=raw_content,
                        field_inventory=parsed.get("inventory", []),
                    )

    ai_mapping = st.session_state.auto_extractor_ai_mapping

    if not ai_mapping:
        return

    if "error" in ai_mapping:
        st.error(ai_mapping["error"])
        return

    st.markdown("### AI mapping suggestions")

    col_a, col_b = st.columns(2)

    with col_a:
        st.info(f"Alert type guess: {ai_mapping.get('alert_type_guess', 'unknown')}")

    with col_b:
        st.info(f"Vendor/product guess: {ai_mapping.get('vendor_guess', 'unknown')}")

    notes = ai_mapping.get("normalization_notes", [])
    if notes:
        with st.expander("Normalization notes"):
            render_compact_bullets(notes, icon="📝", empty_message="No notes returned.")

    suggestions = ai_mapping.get("mapping_suggestions", [])

    if not suggestions:
        st.warning("No mapping suggestions returned.")
        return

    raw_fields = parsed.get("raw_fields", {})

    st.caption(
        "Review each suggestion. Accept, edit, or reject it. "
        "Only accepted or edited mappings are used to build the final UDM evidence bundle."
    )

    with st.form("auto_extractor_mapping_validation_form"):
        validated_rows = []

        for index, suggestion in enumerate(suggestions):
            source_field = suggestion.get("source_field", f"unknown_{index}")
            suggested_udm = suggestion.get("suggested_udm_field", "")
            confidence = suggestion.get("confidence", "unknown")
            reason = suggestion.get("reason", "")
            relevance = suggestion.get("security_relevance", "unknown")
            mapping_type = suggestion.get("mapping_type", "unknown")
            source_preview = suggestion.get("source_value_preview", "")

            with st.expander(
                f"{index + 1}. {source_field} → {suggested_udm} | confidence {confidence}",
                expanded=index < 8,
            ):
                st.markdown(
                    f"""
                    <div class="compact-info">
                    <b>Source field:</b> {escape(str(source_field))}<br>
                    <b>Value preview:</b> {escape(str(source_preview))}<br>
                    <b>Mapping type:</b> {escape(str(mapping_type))}<br>
                    <b>Security relevance:</b> {escape(str(relevance))}<br>
                    <b>Reason:</b> {escape(str(reason))}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                decision = st.selectbox(
                    "Decision",
                    ["Accept", "Edit", "Reject"],
                    index=["Accept", "Edit", "Reject"].index(_mapping_default_decision(suggestion)),
                    key=f"auto_map_decision_{index}",
                )

                edited_udm_field = st.text_input(
                    "UDM field",
                    value=suggested_udm,
                    key=f"auto_map_udm_field_{index}",
                )

                value_to_use = _get_raw_value_for_suggestion(raw_fields, suggestion)

                edited_value = st.text_area(
                    "Value to use",
                    value=str(value_to_use),
                    height=90,
                    key=f"auto_map_value_{index}",
                )

                validated_rows.append(
                    {
                        "decision": decision,
                        "source_field": source_field,
                        "udm_field": edited_udm_field.strip(),
                        "value": edited_value,
                        "original_suggestion": suggestion,
                    }
                )

        build_bundle = st.form_submit_button("Build Final UDM Evidence Bundle from Approved Mappings")

    if build_bundle:
        final_udm = {}
        audit_rows = []

        for row in validated_rows:
            decision = row["decision"]

            if decision == "Reject":
                audit_rows.append(
                    {
                        "decision": "Reject",
                        "source_field": row["source_field"],
                        "suggested_udm_field": row["original_suggestion"].get("suggested_udm_field", ""),
                        "approved_udm_field": "",
                    }
                )
                continue

            udm_field = row["udm_field"]
            value = row["value"]

            if not udm_field or value in [None, ""]:
                continue

            final_udm[udm_field] = value

            audit_rows.append(
                {
                    "decision": decision,
                    "source_field": row["source_field"],
                    "suggested_udm_field": row["original_suggestion"].get("suggested_udm_field", ""),
                    "approved_udm_field": udm_field,
                    "confidence": row["original_suggestion"].get("confidence", ""),
                    "reason": row["original_suggestion"].get("reason", ""),
                }
            )

        if not final_udm:
            st.error("No approved mappings produced a final UDM bundle.")
            return

        st.session_state.auto_extractor_audit = audit_rows

        _load_alert_into_session(
            final_udm,
            "Analyst App - Auto Alert Extractor validated mapping",
        )

        st.success("Final UDM evidence bundle created and loaded for analysis.")

        with st.expander("Final UDM evidence bundle", expanded=True):
            st.json(final_udm)

        with st.expander("Mapping audit trail"):
            st.json(audit_rows)

    unmapped = ai_mapping.get("unmapped_fields", [])
    if unmapped:
        with st.expander("Unmapped fields"):
            st.dataframe(
                unmapped,
                use_container_width=True,
                hide_index=True,
            )


def render_analyst_input_area():
    """
    Analyst App input area with three modes:
    1. Guided UDM fields
    2. Raw full alert JSON
    3. Auto Alert Extractor / AI-assisted UDM mapping
    """
    st.markdown("## Input alert")

    input_tabs = st.tabs(
        [
            "Guided UDM Fields",
            "Raw Alert JSON",
            "Auto Alert Extractor",
        ]
    )

    with input_tabs[0]:
        render_guided_udm_input_form()

    with input_tabs[1]:
        render_raw_alert_json_input(
            key_prefix="analyst_app",
            source_label="Analyst App - Raw Alert JSON",
        )

    with input_tabs[2]:
        render_auto_alert_extractor_input()


def render_guided_builder():
    """
    Compatibility wrapper.
    Older parts of the app may still call render_guided_builder().
    """
    render_analyst_input_area()


def render_cti_research_result(cti_result: dict):
    """
    Compact display for optional AI CTI internet research.
    """
    if not cti_result:
        st.info("No CTI internet research has been run yet.")
        return

    if "error" in cti_result:
        st.error(cti_result["error"])

        if "raw_response" in cti_result:
            st.code(cti_result["raw_response"])

        return

    st.markdown("### 🌐 AI CTI research result")

    st.markdown(
        f"""
        <div class="compact-card">
            <div class="compact-card-title">🧠 CTI summary</div>
            <div class="compact-info">{escape(cti_result.get("cti_summary", "No CTI summary returned."))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Confidence impact", cti_result.get("confidence_impact", "unknown"))

    with col2:
        usage = cti_result.get("web_search_usage", {}).get("web_search_requests", "unknown")
        st.metric("Web searches used", usage)

    st.caption(
        "Web research can misattribute or blend campaigns — treat associations as leads, not "
        "conclusions. Their real value is sparking your next question: what would this mean in "
        "my environment, and what should I rule out (e.g. internal privilege escalation, an "
        "existing C2 connection)?"
    )

    with st.expander("Indicator findings", expanded=True):
        findings = cti_result.get("indicator_findings", [])

        if not findings:
            st.write("No indicator findings returned.")
        else:
            for finding in findings:
                st.markdown(f"**{finding.get('indicator', 'unknown')}**")
                st.markdown(
                    f"""
                    <div class="compact-info">
                    <b>Type:</b> {escape(str(finding.get("indicator_type", "unknown")))}<br>
                    <b>Risk:</b> {escape(str(finding.get("risk", "unknown")))}<br>
                    <b>Confidence:</b> {escape(str(finding.get("confidence", "unknown")))}<br>
                    <b>Finding:</b> {escape(str(finding.get("finding", "")))}<br>
                    <b>Source summary:</b> {escape(str(finding.get("source_summary", "")))}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                broader = finding.get("broader_picture", "")
                if broader:
                    st.caption(f"Broader picture: {broader}")

                actors = finding.get("associated_actors", []) or []
                if actors:
                    st.markdown("**Associated actors / campaigns** — leads to validate:")
                    for actor in actors:
                        name = actor.get("name", "unknown")
                        note = actor.get("note", "")
                        url = actor.get("source_url", "")
                        line = f"- {name}"
                        if note:
                            line += f" — {note}"
                        if url:
                            line += f" ([source]({url}))"
                        st.markdown(line)

                pivots = finding.get("pivot_iocs", []) or []
                if pivots:
                    st.markdown("**Candidate pivot IOCs — validate before hunting:**")
                    for pivot in pivots:
                        pivot_indicator = pivot.get("indicator", "unknown")
                        pivot_type = pivot.get("type", "")
                        note = pivot.get("note", "")
                        url = pivot.get("source_url", "")
                        line = f"- `{pivot_indicator}`"
                        if pivot_type:
                            line += f" ({pivot_type})"
                        if note:
                            line += f" — {note}"
                        if url:
                            line += f" ([source]({url}))"
                        st.markdown(line)

                st.divider()

    with st.expander("Attack-path relevance"):
        st.write(cti_result.get("attack_path_relevance", "No attack-path relevance returned."))

        st.markdown("#### CTI-supported phases")
        render_compact_bullets(
            cti_result.get("cti_supported_phases", []),
            icon="✅",
            empty_message="No supported phases returned.",
        )

        st.markdown("#### CTI-not-supported phases")
        render_compact_bullets(
            cti_result.get("cti_not_supported_phases", []),
            icon="⚪",
            empty_message="No unsupported phases returned.",
        )

    with st.expander("Customer-facing CTI summary"):
        st.info(cti_result.get("customer_cti_summary", "No customer CTI summary returned."))

    with st.expander("Sources & further research", expanded=True):
        # Deduplicate every URL the research surfaced: top-level sources[], API
        # citation metadata, and inline source_url values inside findings/actors/pivots.
        seen_urls: dict[str, str] = {}
        source_order: list[str] = []

        def _add_source(url: str, title: str):
            url = (url or "").strip()
            if not url or url in seen_urls:
                return
            seen_urls[url] = title or url
            source_order.append(url)

        for source in cti_result.get("sources", []) or []:
            _add_source(source.get("url", ""), source.get("title", ""))
        for citation in cti_result.get("citations", []) or []:
            _add_source(citation.get("url", ""), citation.get("title", ""))
        for finding in cti_result.get("indicator_findings", []) or []:
            for actor in finding.get("associated_actors", []) or []:
                _add_source(actor.get("source_url", ""), actor.get("name", ""))
            for pivot in finding.get("pivot_iocs", []) or []:
                _add_source(pivot.get("source_url", ""), pivot.get("indicator", ""))

        if source_order:
            st.markdown("#### Sources cited")
            for url in source_order:
                st.write(f"- [{seen_urls[url]}]({url})")
        else:
            st.write("No public sources were returned for this run.")

        queries = cti_result.get("search_queries", []) or []
        if queries:
            st.markdown("#### Web searches run")
            for query in queries:
                st.write(f"- `{query}`")

        st.caption("Sources are starting points — keep digging; these are leads, not verdicts.")

    with st.expander("Raw CTI JSON"):
        st.json(cti_result)




def _quote_query_value(value: str) -> str:
    value = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value}"'


def _regex_escape_light(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace(".", "\\.")
        .replace("-", "\\-")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("/", "\\/")
    )


def extract_cti_leads(cti_result: dict) -> list[str]:
    """
    Extract IOC-style CTI leads only.

    MITRE TTPs are intentionally excluded here because this section is for IOC hunts.
    TTPs remain useful in the alert validation hunts above.
    """
    if not cti_result or "error" in cti_result:
        return []

    leads = []

    researched = cti_result.get("researched_indicators", {})

    for key in [
        "public_ips",
        "domains",
        "urls",
        "hashes",
        "sanitized_commandline_patterns",
    ]:
        values = researched.get(key, [])
        if isinstance(values, list):
            leads.extend(values)

    for finding in cti_result.get("indicator_findings", []):
        indicator = finding.get("indicator")
        indicator_type = str(finding.get("indicator_type", "")).lower()

        # Do not add MITRE technique/TTP entries into IOC hunts.
        if indicator_type in ["technique", "ttp", "mitre"]:
            continue

        if indicator:
            leads.append(indicator)

    clean = []

    for lead in leads:
        lead = str(lead).strip()

        if not lead:
            continue

        # Extra guardrail against MITRE/TTP values.
        if lead.upper().startswith("T") and len(lead) <= 10:
            continue

        if lead not in clean:
            clean.append(lead)

    return clean[:30]


def generate_cti_informed_hunts(cti_result: dict) -> dict:
    """
    Generate IOC hunts from CTI-derived public indicators.

    These are not confirmed customer-environment findings until the analyst finds
    them in internal telemetry.
    """
    leads = extract_cti_leads(cti_result)

    if not leads:
        return {}

    quoted = ", ".join(_quote_query_value(lead) for lead in leads)
    spl_terms = " OR ".join(_quote_query_value(lead) for lead in leads)
    regex_terms = "|".join(_regex_escape_light(lead) for lead in leads[:20])

    kql = f"""// Microsoft Sentinel / Defender XDR - IOC hunt from CTI
// These are CTI-derived IOCs / public indicators.
// They are NOT confirmed internal evidence until found in your environment.
let ioc_leads = dynamic([{quoted}]);
let lookback = 24h;

SecurityAlert
| where TimeGenerated > ago(lookback)
| where tostring(Entities) has_any (ioc_leads)
   or AlertName has_any (ioc_leads)
   or Description has_any (ioc_leads)
   or tostring(ExtendedProperties) has_any (ioc_leads)
| project TimeGenerated, AlertName, ProviderName, ProductName, Severity, Tactics, Techniques, Entities, Description
| order by TimeGenerated desc;

// Endpoint network telemetry:
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteIP has_any (ioc_leads)
   or RemoteUrl has_any (ioc_leads)
   or InitiatingProcessCommandLine has_any (ioc_leads)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc;

// Endpoint process telemetry:
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where ProcessCommandLine has_any (ioc_leads)
   or InitiatingProcessCommandLine has_any (ioc_leads)
   or FileName has_any (ioc_leads)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc;

// File/hash telemetry:
DeviceFileEvents
| where Timestamp > ago(lookback)
| where SHA256 has_any (ioc_leads)
   or SHA1 has_any (ioc_leads)
   or MD5 has_any (ioc_leads)
   or FolderPath has_any (ioc_leads)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp desc;
"""

    spl = f"""# Splunk - IOC hunt from CTI
# These are CTI-derived IOCs / public indicators.
# They are NOT confirmed internal evidence until found in logs.
index=* earliest=-24h
({spl_terms})
| table _time index sourcetype host user src src_ip dest dest_ip url domain signature rule_name alert_name severity process command_line file_hash
| sort - _time
"""

    yara_l = f"""// Google SecOps YARA-L - IOC hunt from CTI
// Validate field names against parser/UDM mappings before production use.
rule hunt_cti_ioc_leads {{
  meta:
    description = "Hunt for CTI-derived IOC leads from UDM Triage Lab"
    author = "UDM Triage Lab"

  events:
    (
      $e.target.ip = /{regex_terms}/ nocase or
      $e.principal.ip = /{regex_terms}/ nocase or
      $e.target.url = /{regex_terms}/ nocase or
      $e.target.domain.name = /{regex_terms}/ nocase or
      $e.principal.process.command_line = /{regex_terms}/ nocase or
      $e.target.file.sha256 = /{regex_terms}/ nocase
    )

  condition:
    $e
}}
"""

    crowdstrike = f"""// CrowdStrike Next-Gen SIEM / LogScale-style IOC hunt from CTI
// These are CTI-derived IOCs / public indicators.
// Validate field names in your environment.
#event_simpleName=/Alert|Detection|Incident|ProcessRollup2|SyntheticProcessRollup2|DnsRequest|NetworkConnectIP4|FileWritten/i
| /{regex_terms}/i
| table([@timestamp, event_simpleName, ComputerName, UserName, DetectName, Severity, CommandLine, ParentBaseFileName, ImageFileName, RemoteAddress, DomainName, SHA256HashData])
| sort(@timestamp, order=desc)
"""

    return {
        "kql": kql,
        "spl": spl,
        "yara_l": yara_l,
        "crowdstrike_ngsiem": crowdstrike,
        "leads": leads,
    }


def render_cti_informed_hunts(cti_result: dict):
    """
    Render IOC hunts after CTI has run.
    """
    if not cti_result:
        st.info("Run CTI internet research to generate IOC hunts.")
        return

    if "error" in cti_result:
        st.warning("IOC hunts are unavailable because CTI research returned an error.")
        return

    hunts = generate_cti_informed_hunts(cti_result)

    if not hunts:
        st.info("No CTI-derived IOCs were available for additional hunting.")
        return

    st.markdown("### 🎯 IOC hunts from CTI")
    st.caption(
        "These hunts use CTI-derived IOCs and public indicators only. "
        "MITRE TTPs are intentionally not included here because they are not IOC search terms. "
        "Use the alert validation hunts above for TTP-based alert grouping. "
        "If any IOC is found in your environment, paste the matching rows into the follow-up evidence section. "
        "Only internal telemetry hits should be treated as confirmed evidence."
    )

    with st.expander("CTI-derived IOC leads used in these hunts", expanded=True):
        render_compact_bullets(
            hunts.get("leads", []),
            icon="🎯",
            empty_message="No CTI IOC leads available.",
        )

    tabs = st.tabs(["KQL", "SPL", "YARA-L", "CrowdStrike NGSIEM"])

    with tabs[0]:
        st.code(hunts.get("kql", ""), language="kql")

    with tabs[1]:
        st.code(hunts.get("spl", ""), language="spl")

    with tabs[2]:
        st.code(hunts.get("yara_l", ""), language="yara")

    with tabs[3]:
        st.code(hunts.get("crowdstrike_ngsiem", ""), language="text")


def render_followup_reassessment_result(followup_result: dict):
    """
    Compact display for AI follow-up reassessment after analyst hunt results.
    """
    if not followup_result:
        st.info("Paste follow-up evidence and run re-evaluation to update TP/FP confidence.")
        return

    if "error" in followup_result:
        st.error(followup_result["error"])

        if "raw_response" in followup_result:
            st.code(followup_result["raw_response"])

        return

    updated_assessment = followup_result.get("updated_assessment", "unknown")
    updated_confidence = followup_result.get("updated_confidence", "unknown")
    escalation = followup_result.get("recommended_escalation", "unknown")

    st.markdown("### 🔁 Re-evaluated triage result")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Updated assessment", updated_assessment)

    with col2:
        st.metric("Updated confidence", updated_confidence)

    with col3:
        st.metric("Escalation", escalation)

    st.markdown(
        f"""
        <div class="compact-card">
            <div class="compact-card-title">🧠 Analyst summary</div>
            <div class="compact-info">{escape(followup_result.get("analyst_summary", "No analyst summary returned."))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tabs = st.tabs(
        [
            "🔄 What changed",
            "✅ Supporting evidence",
            "🟢 Benign evidence",
            "🧭 Updated chain",
            "🧩 Remaining gaps",
        ]
    )

    with tabs[0]:
        render_compact_bullets(
            followup_result.get("what_changed", []),
            icon="🔄",
            empty_message="No changes returned.",
        )

    with tabs[1]:
        render_compact_bullets(
            followup_result.get("supporting_evidence", []),
            icon="✅",
            empty_message="No supporting evidence returned.",
        )

    with tabs[2]:
        render_compact_bullets(
            followup_result.get("evidence_against_malicious_activity", []),
            icon="🟢",
            empty_message="No benign evidence returned.",
        )

    with tabs[3]:
        render_compact_bullets(
            followup_result.get("updated_attack_chain", []),
            icon="🧭",
            empty_message="No updated attack chain returned.",
        )

    with tabs[4]:
        render_compact_bullets(
            followup_result.get("remaining_gaps", []),
            icon="🧩",
            empty_message="No remaining gaps returned.",
        )

    with st.expander("🧭 Attack-path opinion"):
        st.write(followup_result.get("attack_path_opinion", "No attack-path opinion returned."))
        st.write(f"**CTI relevance:** {followup_result.get('cti_relevance', 'No CTI relevance returned.')}")

        st.markdown("#### Confirmed phases")
        render_compact_bullets(
            followup_result.get("confirmed_attack_phases", []),
            icon="✅",
            empty_message="No confirmed phases returned.",
        )

        st.markdown("#### Hypothesized phases")
        render_compact_bullets(
            followup_result.get("hypothesized_attack_phases", []),
            icon="🔎",
            empty_message="No hypothesized phases returned.",
        )

        st.markdown("#### Not observed phases")
        render_compact_bullets(
            followup_result.get("not_observed_attack_phases", []),
            icon="⚪",
            empty_message="No not-observed phases returned.",
        )

    with st.expander("🧾 Customer update"):
        st.info(followup_result.get("customer_update", "No customer update returned."))

    with st.expander("🛠️ Raw re-evaluation JSON"):
        st.json(followup_result)




def render_cti_followup_testing_panel(parsed_json: dict, key_prefix: str):
    """
    Reusable testing panel for CTI, IOC hunts, and follow-up reassessment.
    Used by Advanced Lab so raw JSON testing has feature parity with Analyst App.
    """
    st.markdown("### 🌐 AI CTI research, IOC hunts, and follow-up testing")
    st.caption(
        "Use this panel to test CTI and re-evaluation directly from raw Advanced Lab JSON. "
        "CTI runs once per loaded alert and uses only safe public IOC-style values."
    )

    pipeline = build_pipeline(parsed_json)

    entities = pipeline["entities"]
    mitre_analysis = pipeline["mitre_analysis"]
    evidence_bundle = pipeline["evidence_bundle"]
    attack_path = pipeline["attack_path"]

    cti_package = build_safe_cti_research_package(
        flattened=pipeline["flattened"],
        entities=entities,
        mitre_analysis=mitre_analysis,
        followup_evidence="",
    )

    st.session_state.cti_package = cti_package

    with st.expander("Preview safe CTI research package"):
        st.json(cti_package)

    if not has_cti_researchable_indicators(cti_package):
        st.info("No safe CTI-searchable indicators were found.")

    elif st.session_state.cti_researched:
        st.success(
            "CTI internet research has already been run for this alert. "
            "It will not run again unless you load a new alert."
        )
        render_cti_research_result(st.session_state.cti_result)

    else:
        if st.button("Run AI CTI Internet Research Once", key=f"{key_prefix}_cti_research_once"):
            with st.spinner("AI is researching safe public indicators on the internet..."):
                st.session_state.cti_result = ask_claude_for_cti_web_research(
                    cti_package=cti_package,
                    attack_path=attack_path,
                )
                st.session_state.cti_researched = True

        render_cti_research_result(st.session_state.cti_result)

    st.markdown("### 🎯 IOC hunts from CTI")
    render_cti_informed_hunts(st.session_state.cti_result)

    st.markdown("### 🔁 Follow-up evidence re-evaluation")

    followup_evidence = st.text_area(
        "Paste hunt results / investigation notes",
        height=240,
        placeholder=(
            "Paste hits from alert validation hunts or IOC hunts here.\\n"
            "Examples:\\n"
            "- Same host had certutil download after PowerShell\\n"
            "- IOC domain seen on 3 hosts\\n"
            "- No persistence, discovery, or credential access found\\n"
        ),
        key=f"{key_prefix}_followup_evidence",
    )

    if st.button("Re-evaluate with Follow-up Evidence", key=f"{key_prefix}_followup_reassess"):
        with st.spinner("AI is re-evaluating the case using the follow-up evidence..."):
            st.session_state.followup_result = ask_claude_for_followup_reassessment(
                evidence_bundle=evidence_bundle,
                attack_path=attack_path,
                original_claude_result=st.session_state.claude_result or {},
                followup_evidence=followup_evidence,
                cti_result=st.session_state.cti_result or {},
            )

    render_followup_reassessment_result(st.session_state.followup_result)



def _feedback_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _safe_json_hash(data) -> str:
    import hashlib
    import json

    try:
        raw = json.dumps(data, sort_keys=True, default=str)
    except Exception:
        raw = str(data)

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _comma_split_clean(value: str) -> list[str]:
    if not value:
        return []

    parts = []

    for item in value.replace("\n", ",").split(","):
        clean = item.strip()

        if clean:
            parts.append(clean)

    return list(dict.fromkeys(parts))


def _feedback_extract_alert_summary(current_alert: dict, pipeline: dict) -> dict:
    flattened = pipeline.get("flattened", {}) if pipeline else {}
    entities = pipeline.get("entities", {}) if pipeline else {}

    return {
        "alert_hash": _safe_json_hash(current_alert),
        "input_source": st.session_state.get("current_alert_source", "unknown"),
        "vendor": flattened.get("metadata.vendor_name") or flattened.get("VendorName") or "",
        "product": flattened.get("metadata.product_name") or flattened.get("ProductName") or "",
        "event_type": flattened.get("metadata.event_type") or flattened.get("Type") or "",
        "rule_name": (
            flattened.get("security_result.rule_name")
            or flattened.get("security_result.display_name")
            or flattened.get("AlertName")
            or flattened.get("DisplayName")
            or ""
        ),
        "severity": flattened.get("security_result.severity") or flattened.get("AlertSeverity") or "",
        "detected_tactics": entities.get("mitre_tactics", []),
        "detected_techniques": entities.get("mitre_techniques", []),
    }


def _feedback_default_ttp_string(pipeline: dict) -> str:
    if not pipeline:
        return ""

    entities = pipeline.get("entities", {}) or {}
    techniques = entities.get("mitre_techniques", []) or []

    return ", ".join(techniques)



def render_feedback_database_status():
    """
    Milestone 3.72:
    Small SQLite feedback database status and review panel.
    """
    with st.expander("Feedback database status", expanded=False):
        try:
            db_path = init_feedback_db()
            stats = get_feedback_stats()

            st.success(f"Feedback database ready: {db_path}")

            c1, c2, c3 = st.columns(3)

            with c1:
                st.metric("Feedback submissions", stats.get("total_feedback_submissions", 0))

            with c2:
                st.metric("Alert sessions", stats.get("total_alert_sessions", 0))

            with c3:
                st.metric("Mapping decisions", stats.get("total_mapping_decisions", 0))

            st.markdown("#### Verdict counts")
            st.dataframe(
                stats.get("verdict_counts", []),
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("#### Helpfulness counts")
            st.dataframe(
                stats.get("helpfulness_counts", []),
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("#### Recent feedback")
            st.dataframe(
                list_recent_feedback(limit=10),
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("#### Recent mapping decisions")
            st.dataframe(
                list_mapping_decisions(limit=20),
                use_container_width=True,
                hide_index=True,
            )

        except Exception as error:
            st.error(f"Feedback database error: {type(error).__name__}: {error}")


def render_feedback_learning_interface(current_alert: dict, pipeline: dict, context_label: str = "Analyst App"):
    """
    Milestone 3.71:
    Session-only feedback and learning interface.

    The database comes in Milestone 3.72.
    """
    if not current_alert:
        return

    st.markdown("## 🧪 Feedback & learning")
    st.caption(
        "This feedback is stored only in the current Streamlit session for now. "
        "Milestone 3.72 will persist it into SQLite."
    )

    alert_summary = _feedback_extract_alert_summary(current_alert, pipeline)
    default_ttps = _feedback_default_ttp_string(pipeline)

    with st.expander("Feedback context", expanded=False):
        st.json(alert_summary)

    with st.form("feedback_learning_form"):
        st.markdown("### Investigation outcome")

        col1, col2, col3 = st.columns(3)

        with col1:
            helpfulness = st.selectbox(
                "Was this investigation helpful?",
                ["Yes", "Partly", "No"],
                index=1,
                key="feedback_helpfulness",
            )

        with col2:
            analyst_verdict = st.selectbox(
                "Analyst verdict",
                [
                    "Needs More Evidence",
                    "True Positive",
                    "False Positive",
                    "Benign Expected Activity",
                    "Inconclusive",
                ],
                index=0,
                key="feedback_analyst_verdict",
            )

        with col3:
            confidence_after = st.selectbox(
                "Confidence after investigation",
                ["Low", "Medium", "High"],
                index=1,
                key="feedback_confidence_after",
            )

        escalation_use = st.radio(
            "Would you use this output for customer escalation?",
            ["Yes", "No", "Needs rewrite"],
            horizontal=True,
            key="feedback_escalation_use",
        )

        st.markdown("### TTP learning")

        confirmed_ttps = st.text_input(
            "Confirmed TTPs",
            value="",
            placeholder="Example: T1059.001, T1027, T1105",
            help="TTPs that the analyst believes are supported by the evidence.",
            key="feedback_confirmed_ttps",
        )

        rejected_ttps = st.text_input(
            "Suggested but not confirmed TTPs",
            value="",
            placeholder="Example: T1071, T1053.005",
            help="TTPs that were suggested or hypothesized but not proven.",
            key="feedback_rejected_ttps",
        )

        additional_ttps = st.text_input(
            "Additional TTPs found during investigation",
            value="",
            placeholder="Example: T1082, T1003",
            help="TTPs discovered by the analyst that were missing from the AI output.",
            key="feedback_additional_ttps",
        )

        if default_ttps:
            st.caption(f"Detected / suggested TTPs from this alert: {default_ttps}")

        st.markdown("### Investigation learning")

        missing_log_sources = st.text_area(
            "Missing log sources or evidence",
            height=80,
            placeholder="Example: Need proxy logs, DNS logs, EDR process tree, Entra sign-in logs, cloud audit logs...",
            key="feedback_missing_log_sources",
        )

        useful_hunts = st.text_area(
            "Useful hunts / pivots",
            height=80,
            placeholder="Which generated hunts or pivots were useful?",
            key="feedback_useful_hunts",
        )

        bad_hunts = st.text_area(
            "Bad or noisy hunts / pivots",
            height=80,
            placeholder="Which hunts were not useful, too noisy, or wrong?",
            key="feedback_bad_hunts",
        )

        st.markdown("### Product quality ratings")

        q1, q2, q3, q4, q5 = st.columns(5)

        with q1:
            ai_summary_quality = st.slider("AI summary", 1, 5, 3, key="feedback_ai_summary_quality")

        with q2:
            udm_mapping_quality = st.slider("UDM mapping", 1, 5, 3, key="feedback_udm_mapping_quality")

        with q3:
            ontology_quality = st.slider("Ontology", 1, 5, 3, key="feedback_ontology_quality")

        with q4:
            hunt_quality = st.slider("Hunts", 1, 5, 3, key="feedback_hunt_quality")

        with q5:
            cti_quality = st.slider("CTI", 1, 5, 3, key="feedback_cti_quality")

        st.markdown("### Free-text feedback")

        what_helpful = st.text_area(
            "What was helpful?",
            height=90,
            placeholder="Example: The UDM mapping saved time, the attack path was useful, the CTI filter was safe...",
            key="feedback_what_helpful",
        )

        what_wrong_or_missing = st.text_area(
            "What was wrong or missing?",
            height=90,
            placeholder="Example: Wrong TTP, missing ontology field, bad hunt, CTI over/under-filtered...",
            key="feedback_what_wrong_or_missing",
        )

        submit_feedback = st.form_submit_button("Submit Feedback")

    if submit_feedback:
        feedback_record = {
            "created_at": _feedback_now_iso(),
            "context_label": context_label,
            "alert_summary": alert_summary,
            "helpfulness": helpfulness,
            "analyst_verdict": analyst_verdict,
            "confidence_after": confidence_after,
            "would_use_for_customer_escalation": escalation_use,
            "confirmed_ttps": _comma_split_clean(confirmed_ttps),
            "rejected_ttps": _comma_split_clean(rejected_ttps),
            "additional_ttps_found": _comma_split_clean(additional_ttps),
            "missing_log_sources": missing_log_sources,
            "useful_hunts": useful_hunts,
            "bad_hunts": bad_hunts,
            "quality": {
                "ai_summary": ai_summary_quality,
                "udm_mapping": udm_mapping_quality,
                "ontology": ontology_quality,
                "hunts": hunt_quality,
                "cti": cti_quality,
            },
            "what_helpful": what_helpful,
            "what_wrong_or_missing": what_wrong_or_missing,
            "mapping_audit": st.session_state.get("auto_extractor_audit", []),
            "cti_was_run": bool(st.session_state.get("cti_researched", False)),
            "has_followup_reassessment": bool(st.session_state.get("followup_result")),
        }

        st.session_state.feedback_submissions.append(feedback_record)
        st.session_state.last_feedback_submission = feedback_record

        try:
            db_result = save_feedback_submission(feedback_record)
            st.session_state.last_feedback_db_result = db_result

            st.success(
                "Feedback captured and saved to SQLite database. "
                f"Mapping decisions saved: {db_result.get('mapping_decisions_saved', 0)}"
            )

        except Exception as error:
            st.session_state.last_feedback_db_result = None
            st.warning(
                "Feedback captured in the current session, but database save failed: "
                f"{type(error).__name__}: {error}"
            )

    if st.session_state.get("last_feedback_submission"):
        with st.expander("Latest feedback submission", expanded=False):
            st.json(st.session_state.last_feedback_submission)

    if st.session_state.get("last_feedback_db_result"):
        with st.expander("Latest database save result", expanded=False):
            st.json(st.session_state.last_feedback_db_result)

    if st.session_state.get("admin_unlocked", False):
        render_feedback_database_status()

    if st.session_state.get("feedback_submissions"):
        total_feedback = len(st.session_state.feedback_submissions)
        st.caption(f"Feedback submissions in this session: {total_feedback}")

        with st.expander("Session feedback history", expanded=False):
            for index, item in enumerate(st.session_state.feedback_submissions, start=1):
                summary = item.get("alert_summary", {})
                st.markdown(
                    f"**{index}. {item.get('created_at', '')}** — "
                    f"{summary.get('rule_name', 'unknown alert')} — "
                    f"{item.get('analyst_verdict', 'unknown verdict')} — "
                    f"Helpful: {item.get('helpfulness', 'unknown')}"
                )



def _is_admin_unlocked() -> bool:
    """
    Fail-closed MVP admin gate.

    Public release behavior:
    - If ADMIN_PASSWORD is not configured, admin mode is disabled.
    - If ADMIN_PASSWORD is configured, admin mode requires the password.

    Configure in Streamlit secrets:
    ADMIN_PASSWORD = "your-long-random-admin-password"
    """
    admin_password = st.secrets.get("ADMIN_PASSWORD", "")

    if not admin_password:
        with st.sidebar.expander("Admin login", expanded=False):
            st.info(
                "Admin mode is disabled because ADMIN_PASSWORD is not configured."
            )
        return False

    if st.session_state.get("admin_unlocked"):
        with st.sidebar.expander("Admin session", expanded=False):
            st.success("Admin mode unlocked.")

            if st.button("Lock admin mode", key="lock_admin_mode"):
                st.session_state.admin_unlocked = False
                st.rerun()

        return True

    with st.sidebar.expander("Admin login", expanded=False):
        entered_password = st.text_input(
            "Admin password",
            type="password",
            key="admin_password_input",
        )

        if st.button("Unlock admin mode", key="unlock_admin_mode"):
            if entered_password == admin_password:
                st.session_state.admin_unlocked = True
                st.success("Admin mode unlocked.")
                st.rerun()
            else:
                st.error("Wrong admin password.")

    return False


def render_admin_ontology_mapping_panel(current_alert: dict):
    """
    Admin-only ontology visibility, similar to Advanced Lab but focused on ontology enrichment.
    """
    st.markdown("## Ontology Mapping Review")

    if not current_alert:
        st.info("Load an alert first to review ontology mapping.")
        return

    try:
        pipeline = build_pipeline(current_alert)
        enriched_table = pipeline.get("enriched_table", [])
        semantic_facts = pipeline.get("semantic_facts", [])

        st.markdown("### Enriched ontology table")
        st.dataframe(
            enriched_table,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("### High-value semantic facts")
        high_value = [
            row for row in semantic_facts
            if int(row.get("importance", 1)) >= 8
        ]

        if high_value:
            for fact in high_value[:25]:
                st.markdown(
                    f"""
                    <div class="compact-info">
                    <b>{escape(str(fact.get("source_field", fact.get("field", ""))))}</b>
                    — Importance {escape(str(fact.get("importance", "")))}<br>
                    <b>Role:</b> {escape(str(fact.get("evidence_role", "")))}<br>
                    <b>Meaning:</b> {escape(str(fact.get("meaning", "")))}<br>
                    <b>Fact:</b> {escape(str(fact.get("fact", "")))}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No high-value ontology facts found yet.")

        missing_fields = [
            row.get("source_field", row.get("field", ""))
            for row in enriched_table
            if row.get("ontology_status") == "missing"
        ]

        st.markdown("### Missing ontology fields")

        if missing_fields:
            st.warning(f"{len(missing_fields)} fields have no ontology entry yet.")
            st.json(missing_fields)
        else:
            st.success("All current fields have ontology coverage.")

    except Exception as error:
        st.error(f"Ontology mapping review failed: {type(error).__name__}: {error}")



def render_admin_feedback_comments_table():
    """
    Admin-only long-form feedback view.
    This is the most useful table for product learning.
    """
    import pandas as pd
    from triage.feedback_db import list_feedback_admin_comments

    st.markdown("### Feedback comments & learning notes")
    st.caption(
        "Long-form analyst feedback across missing evidence, useful hunts, noisy hunts, TTP learning, and product-quality comments."
    )

    rows = list_feedback_admin_comments(limit=200)

    if not rows:
        st.info("No detailed feedback comments stored yet.")
        return

    df = pd.DataFrame(rows)

    preferred_columns = [
        "submitted_at",
        "vendor",
        "product",
        "rule_name",
        "severity",
        "helpfulness",
        "analyst_verdict",
        "confidence_after",
        "would_use_for_customer_escalation",
        "confirmed_ttps",
        "suggested_but_not_confirmed_ttps",
        "additional_ttps_found",
        "missing_log_sources_or_evidence",
        "useful_hunts_or_pivots",
        "bad_or_noisy_hunts_or_pivots",
        "what_was_helpful",
        "what_was_wrong_or_missing",
        "ai_summary_quality",
        "udm_mapping_quality",
        "ontology_quality",
        "hunts_quality",
        "cti_quality",
        "cti_was_run",
        "has_followup_reassessment",
    ]

    available_columns = [col for col in preferred_columns if col in df.columns]
    df = df[available_columns]

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=420,
    )

    csv_data = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "Download feedback comments CSV",
        data=csv_data,
        file_name="udm_triage_lab_feedback_comments.csv",
        mime="text/csv",
        key="download_feedback_comments_csv",
    )



def render_admin_database_review_panel():
    """
    Admin-only feedback database review.
    """
    st.markdown("## Feedback Database Review")

    render_feedback_database_status()

    st.divider()
    render_admin_feedback_comments_table()

    st.caption(
        "This reads the local SQLite feedback database. On Streamlit Community Cloud, "
        "local database persistence may be temporary. Export regularly during alpha testing."
    )


def render_public_app_shell():
    """
    Clean public UI for LinkedIn alpha.
    """
    st.markdown("# UDM Triage Lab")
    st.caption("AI-assisted SOC alert normalization, triage, CTI-safe IOC research, and analyst feedback.")

    public_tabs = st.tabs(
        [
            "Analyst Workbench",
            "How to Use & Privacy",
        ]
    )

    with public_tabs[0]:
        render_analyst_app()

    with public_tabs[1]:
        render_public_guide_and_privacy()


def render_admin_product_lab_shell():
    """
    Admin/Product Lab UI for Chris.
    Keeps the current analyst experience and adds ontology and database visibility.
    """
    st.markdown("# UDM Triage Lab — Admin / Product Lab")

    admin_tabs = st.tabs(
        [
            "Analyst Workbench",
            "Ontology Mapping",
            "Feedback Database",
            "How to Use & Privacy",
        ]
    )

    with admin_tabs[0]:
        render_analyst_app()

    with admin_tabs[1]:
        render_admin_ontology_mapping_panel(st.session_state.get("current_alert"))

    with admin_tabs[2]:
        render_admin_database_review_panel()

    with admin_tabs[3]:
        render_public_guide_and_privacy()


def render_app_shell():
    """
    Top-level app routing:
    - Public users see clean analyst UI.
    - Admin sees product lab with ontology and DB review.

    data_mode is kept as a hidden internal default for backward compatibility
    with the existing evidence bundle pipeline.
    """
    global data_mode

    data_mode = "Analyst supplied alert data"

    admin_unlocked = _is_admin_unlocked()

    if admin_unlocked:
        mode = st.sidebar.radio(
            "App mode",
            ["Public Analyst View", "Admin / Product Lab"],
            index=1,
            key="app_mode_selector",
        )
    else:
        mode = "Public Analyst View"

    if mode == "Admin / Product Lab":
        render_admin_product_lab_shell()
    else:
        render_public_app_shell()


def render_analyst_app():
    """
    Clean user-facing app mode.
    Uses the guided builder as input, then shows a compact phased analyst workflow.
    """
    st.subheader("SOC Alert Triage Assistant")
    st.caption(
        "Fill in the key alert details. The app converts them into a normalized UDM-style evidence model behind the scenes."
    )

    st.info(
        "Demo tip: for a quick walkthrough, open the Raw Alert JSON tab and click Analyze the preloaded demo alert. "
        "This shows the full workflow without needing your own alert data."
    )

    st.success(
        "🙏 🙂 Please share feedback before you leave. "
        "Your notes help improve the AI summary, UDM mapping, ontology, hunts, CTI filtering, and overall analyst workflow."
    )

    render_analyst_input_area()

    if st.session_state.current_alert is None:
        st.info("Build an alert using the guided form above to start the analyst workflow.")
        return

    st.divider()

    pipeline = build_pipeline(st.session_state.current_alert)
    flattened = pipeline["flattened"]

    mitre_analysis = pipeline["mitre_analysis"]
    semantic_facts = pipeline["semantic_facts"]
    entities = pipeline["entities"]
    evidence_bundle = pipeline["evidence_bundle"]
    attack_path = pipeline["attack_path"]
    hunt_queries = pipeline["hunt_queries"]

    st.markdown("## 1. 📊 Triage snapshot")

    snapshot_col1, snapshot_col2, snapshot_col3, snapshot_col4 = st.columns(4)

    with snapshot_col1:
        st.metric("Initial verdict", mitre_analysis.get("initial_verdict", "unknown"))

    with snapshot_col2:
        st.metric("Severity", mitre_analysis.get("overall_severity", "unknown"))

    with snapshot_col3:
        st.metric("Attack phase", attack_path.get("observed_position", "Unknown"))

    with snapshot_col4:
        st.metric("Path confidence", attack_path.get("confidence", "unknown"))

    st.caption(f"Current alert source: {st.session_state.current_alert_source}")

    st.markdown("## 2. 🧠 What happened?")

    st.markdown(
        f"""
        <div class="compact-card">
            <div class="compact-card-title">🧩 Deterministic first-pass summary</div>
            <div class="compact-info">{escape(mitre_analysis.get("summary", "No deterministic summary available."))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    entity_col1, entity_col2, entity_col3 = st.columns(3)

    source_users = _get_values_from_flattened(
        flattened,
        [
            "principal.user.userid",
            "principal.user.email_addresses[0]",
            "target.user.userid",
        ],
    ) or entities.get("users", [])

    source_hosts = _get_values_from_flattened(
        flattened,
        [
            "principal.hostname",
            "principal.asset.hostname",
            "src.hostname",
            "source.hostname",
        ],
    ) or entities.get("hosts", [])

    source_ips = _get_values_from_flattened(
        flattened,
        [
            "principal.ip",
            "principal.asset.ip",
            "src.ip",
            "source.ip",
        ],
    )

    destination_ips = _get_values_from_flattened(
        flattened,
        [
            "target.ip",
            "destination.ip",
            "dest.ip",
        ],
    )

    destination_domains = _get_values_from_flattened(
        flattened,
        [
            "target.domain.name",
            "network.dns.questions.name",
            "network.email.sender_domain",
        ],
    )

    destination_urls = _get_values_from_flattened(
        flattened,
        [
            "target.url",
            "network.http.request.url",
        ],
    )

    target_applications = _get_values_from_flattened(
        flattened,
        [
            "target.application",
            "target.resource.name",
            "target.resource.type",
        ],
    )

    with entity_col1:
        st.markdown("#### 👤 Source / acting entity")
        st.markdown(
            f"""
            <div class="compact-info">
            <b>Users:</b> {escape(_display_values(source_users))}<br>
            <b>Hosts:</b> {escape(_display_values(source_hosts))}<br>
            <b>Source IPs:</b> {escape(_display_values(source_ips))}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with entity_col2:
        st.markdown("#### 🌐 Destination / target")
        st.markdown(
            f"""
            <div class="compact-info">
            <b>Destination IPs:</b> {escape(_display_values(destination_ips))}<br>
            <b>Domains:</b> {escape(_display_values(destination_domains))}<br>
            <b>URLs:</b> {escape(_display_values(destination_urls))}<br>
            <b>Applications/resources:</b> {escape(_display_values(target_applications))}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with entity_col3:
        st.markdown("#### 🧬 MITRE")
        st.markdown(
            f"""
            <div class="compact-info">
            <b>Tactics:</b> {escape(", ".join(entities.get("mitre_tactics", [])) or "None detected")}<br>
            <b>Techniques:</b> {escape(", ".join(entities.get("mitre_techniques", [])) or "None detected")}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with st.expander("🚨 Show matched suspicious patterns"):
        if not mitre_analysis.get("matches"):
            st.write("No deterministic suspicious pattern matched.")
        else:
            for match in mitre_analysis["matches"]:
                st.markdown(f"**{match['pattern_name']}**")
                st.markdown(
                    f"""
                    <div class="compact-info">
                    <b>Severity:</b> {escape(str(match.get("severity", "unknown")))}<br>
                    <b>Confidence:</b> {escape(str(match.get("confidence", "unknown")))}<br>
                    <b>Reason:</b> {escape(str(match.get("reason", "")))}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.divider()

    st.markdown("## 3. 🧠 AI triage assistance")

    if st.button("Generate Triage Assessment", key="analyst_app_generate_claude"):
        with st.spinner("AI is analyzing the evidence bundle..."):
            st.session_state.claude_result = ask_claude_for_triage(evidence_bundle)

    render_simple_claude_result(st.session_state.claude_result)

    st.markdown("## 4. 🧭 Attack path and alert validation hunts")
    st.info(
        "🔎 Why alert-centric hunting matters: a single alert rarely tells the full story. "
        "The real investigation value comes from checking related activity on the same host, user, IP, domain, hash, or technique. "
        "Use the alert validation hunts and follow-up evidence section to decide whether this is an isolated event, "
        "part of a broader attack path, or benign activity."
    )


    render_attack_path_visualizer(
        attack_path=attack_path,
        hunt_queries=hunt_queries,
        compact=True,
    )

    st.markdown("## 5. 🌐 AI CTI research and IOC hunts")

    st.warning(
        "This optional CTI research sends only selected public indicators to external internet research: "
        "public IPs, domains, URLs, hashes, and sanitized command-line patterns. "
        "Hostnames, usernames, local file paths, process full paths, internal IPs, raw command lines, and MITRE TTPs are blocked from IOC research."
    )

    cti_package = build_safe_cti_research_package(
        flattened=pipeline["flattened"],
        entities=entities,
        mitre_analysis=mitre_analysis,
        followup_evidence="",
    )

    st.session_state.cti_package = cti_package

    with st.expander("Preview safe CTI research package"):
        st.json(cti_package)

    if not has_cti_researchable_indicators(cti_package):
        st.info("No safe CTI-searchable indicators were found.")

    elif st.session_state.cti_researched:
        st.success("CTI internet research has already been run for this alert. It will not run again unless you load a new alert.")
        render_cti_research_result(st.session_state.cti_result)

    else:
        if st.button("Run AI CTI Internet Research Once", key="analyst_app_cti_research_once"):
            with st.spinner("AI is researching safe public indicators on the internet..."):
                st.session_state.cti_result = ask_claude_for_cti_web_research(
                    cti_package=cti_package,
                    attack_path=attack_path,
                )
                st.session_state.cti_researched = True

        render_cti_research_result(st.session_state.cti_result)

    render_cti_informed_hunts(st.session_state.cti_result)

    st.markdown("## 6. 🔁 Follow-up evidence re-evaluation")

    st.caption(
        "After running the alert validation hunts and optional IOC hunts, paste any hits, relevant rows, or analyst notes here. "
        "The AI will re-evaluate whether this looks like a true positive, false positive, or still inconclusive, and update the MITRE kill-chain interpretation."
    )

    followup_evidence = st.text_area(
        "Paste hunt results / investigation notes",
        height=220,
        placeholder=(
            "Example:\n"
            "- Alert validation hunt found additional related Defender alert\n"
            "- IOC hunt found the CTI domain on the same host\n"
            "- PowerShell spawned certutil.exe\n"
            "- Scheduled task created 4 minutes later\n"
            "- No approved change ticket found\n"
        ),
        key="analyst_followup_evidence",
    )

    if st.button("Re-evaluate with Follow-up Evidence", key="analyst_app_followup_reassess"):
        with st.spinner("AI is re-evaluating the case using the follow-up evidence..."):
            st.session_state.followup_result = ask_claude_for_followup_reassessment(
                evidence_bundle=evidence_bundle,
                attack_path=attack_path,
                original_claude_result=st.session_state.claude_result or {},
                followup_evidence=followup_evidence,
                cti_result=st.session_state.cti_result or {},
            )

    render_followup_reassessment_result(st.session_state.followup_result)

    st.divider()

    render_feedback_learning_interface(
        current_alert=st.session_state.current_alert,
        pipeline=pipeline,
        context_label="Analyst App",
    )

    st.markdown("---")

    with st.expander("🛠️ Technical details"):
        st.markdown("#### Generated UDM JSON")
        st.json(st.session_state.current_alert)

        st.markdown("#### Extracted entities")
        st.json(entities)

        st.markdown("#### Top semantic facts")
        st.json(semantic_facts[:10])

        st.markdown("#### MITRE analysis")
        st.json(mitre_analysis)

        st.markdown("#### Attack path hypothesis")
        st.json(attack_path)

        st.markdown("#### Evidence bundle sent to AI")
        st.json(evidence_bundle)




def render_public_guide_and_privacy():
    """
    Public-facing guide and privacy explanation for alpha users.
    """
    st.markdown("# How to use UDM Triage Lab")

    st.info(
        "An experimental SOC analyst assistant: it converts messy security alerts into "
        "structured UDM-style evidence, then supports triage, CTI-safe IOC research, "
        "follow-up reassessment, and analyst feedback. "
        "**The analyst is the trust boundary — every AI output is a suggestion for you "
        "to validate, never a verdict.**"
    )

    st.markdown("## Recommended workflow")

    st.markdown(
"""
1. **Input alert** — Start in the Analyst Workbench. Fastest demo: open *Raw Alert JSON* and click Analyze on the preloaded demo alert. Use *Auto Alert Extractor* for messy raw alerts, or *Guided UDM Fields* for tight control over what data is included.
2. **Review normalized evidence** — the app converts the alert into a UDM-style evidence model: vendor, product, rule, severity, user, host, process, IPs, domains, URLs, hashes, MITRE context.
3. **Validate UDM mappings** — with Auto Alert Extractor, the AI suggests how raw fields map to UDM evidence fields. You are the quality gate: accept, edit, or reject each mapping.
4. **Build the final evidence bundle** — only approved mappings and analyst-provided fields become the controlled investigation context for everything downstream.
5. **Run AI triage assistance** — why the alert may be suspicious, why it could be benign, what evidence is missing, what to do next.
6. **Work the attack path & validation hunts** — a single alert rarely tells the full story. Use the alert-centric hunts (same host, user, IP, domain, hash, process, technique) to decide: isolated event, part of a broader attack path, or benign.
7. **Review MITRE context and similar TTPs** — how the alert may fit a larger attacker behavior chain; look for related techniques and comparable behavior.
8. **Optional: CTI research & IOC hunts** — manually triggered, sends only selected safe public IOC-style values (public IPs, domains, URLs, hashes, sanitized command patterns). Use the IOC hunts across your SIEM, EDR, proxy, DNS, firewall, identity, and cloud data.
9. **Paste follow-up evidence** — hunt results, timeline notes, SIEM/EDR findings, CTI observations. The more relevant follow-up evidence, the better the final reassessment can judge TP / FP / needs-more-investigation.
10. **Submit feedback** — was the output helpful, which TTPs were confirmed or wrong, what was missing, which hunts were useful. This feedback is the point of the project.
"""
    )

    st.markdown("---")

    st.markdown("## Your data & privacy")

    st.markdown(
"""
**What happens to your input:** when you use Auto Alert Extractor, AI Summary, Follow-up Reassessment, or CTI Research, selected content is sent to the Anthropic Claude API (commercial API) to generate recommendations — the same processing pattern as AI assistants built into commercial SOC platforms.

**No model training:** per Anthropic's commercial API terms, inputs and outputs are not used to train Anthropic models by default. Anthropic describes standard API retention as automatic deletion within 30 days, with listed exceptions. This app does not train any model on your data.

**What this app stores:** nothing, except feedback you explicitly submit (verdict + comments), in a small local database the operator can read. Don't put sensitive details in feedback text. On Streamlit Community Cloud this storage may not persist.
"""
    )

    st.markdown("### Working with real alerts? Pseudonymize before you paste.")

    st.markdown(
r"""
In alert-stage triage, personal data lives in a handful of field types. Rename them consistently before pasting (same placeholder for the same entity, so correlations survive):

| Replace | With |
|---|---|
| Hostnames (`DE-LT-4711`) | `HOST-A`, `HOST-B`, … |
| Usernames / emails (`m.mueller@…`) | `USER-1`, `USER-1@example.com`, … |
| Private/internal IPs | `10.0.0.1`, `10.0.0.2`, … |
| File paths under user profiles | `C:\Users\USER-1\…` |
"""
    )

    st.warning(
        r"⚠️ **Then check where these identifiers hide:** command lines, URLs, and "
        r"free-text descriptions routinely embed usernames, personal paths, and hostnames "
        r"(`--user m.mueller`, `\\DE-LT-4711\share\…`). Sanitize those occurrences too."
    )

    st.markdown(
        "Technique names, hashes, public IPs, domains, process names, timestamps, and "
        "detection metadata are what the triage actually needs — the analysis works "
        "exactly as well on pseudonymized alerts."
    )

    st.markdown(
        "**Maximum-control alternative:** use local extraction only, review the extracted "
        "fields, and manually copy only approved fields into *Guided UDM Fields*. Then only "
        "what you typed is ever sent for AI reasoning."
    )

    st.markdown(
        "**Authorization is yours:** submit real alert data only when your organization or "
        "customer policy allows this type of third-party API processing. This is a personal "
        "research app, not an enterprise service with a data processing agreement. When in "
        "doubt: pseudonymize, or use synthetic/lab data."
    )

    st.markdown("### Never paste")

    st.error(
        "API keys, passwords, access tokens, private keys, certificates, session cookies, "
        "credentials — and any regulated or contractually restricted data you are not "
        "authorized to process."
    )

    st.markdown("### Feature differences at a glance")

    st.markdown(
"""
- **Auto Alert Extractor** — may send pasted alert content to the AI for UDM mapping suggestions. No internet research. Analyst validation required before the evidence bundle is built.
- **AI Summary & Follow-up Reassessment** — use only the final analyst-approved evidence bundle. With Guided UDM Fields, only fields you entered are included.
- **CTI Internet Research** — optional, manual, strictest filtering: only safe public IOC-style indicators; blocks hostnames, usernames, private IPs, local paths, raw command lines, customer/tenant IDs, vendor console URLs, and traceability IDs where possible. Vendor console URLs are preserved for traceability but never treated as threat IOCs.
"""
    )

    st.markdown("### AI output is not a verdict")

    st.success(
        "UDM mappings, triage summaries, CTI results, and follow-up conclusions are "
        "recommendations requiring analyst review. Do not escalate, close, or classify an "
        "incident based only on AI output."
    )

    st.markdown("### Alpha limitations")

    st.markdown(
        "UDM mappings may need editing · the ontology is still expanding · CTI filtering is "
        "conservative by design · feedback storage may not persist on Streamlit Community "
        "Cloud · no direct SIEM/EDR connection — the tool is for analyst learning, triage "
        "support, and product feedback."
    )



# ---------------------------------------------------------------------
# App entrypoint
# Public users see the clean Analyst View.
# Admin users can unlock the Product Lab with ontology and DB visibility.
# ---------------------------------------------------------------------

render_app_shell()


# Discreet version footer at the very bottom of the page. Small grey text via
# st.caption; shows "v: dev" if the running commit can't be resolved.
_app_version = get_app_version()
st.caption(f"v: {_app_version}" if _app_version else "v: dev")
