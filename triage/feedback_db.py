from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_DB_PATH = Path("data/udm_triage_lab_feedback.sqlite3")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def _ensure_parent_dir(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)


def get_feedback_db_path() -> Path:
    return DEFAULT_DB_PATH


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    resolved_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    _ensure_parent_dir(resolved_path)

    conn = sqlite3.connect(resolved_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_feedback_db(db_path: Path | str | None = None) -> Path:
    resolved_path = Path(db_path) if db_path else DEFAULT_DB_PATH

    with get_connection(resolved_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                alert_hash TEXT,
                input_source TEXT,
                vendor TEXT,
                product TEXT,
                event_type TEXT,
                rule_name TEXT,
                severity TEXT,
                detected_tactics_json TEXT,
                detected_techniques_json TEXT,
                raw_alert_stored INTEGER DEFAULT 0,
                notes TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback_submissions (
                id TEXT PRIMARY KEY,
                alert_session_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                context_label TEXT,
                helpfulness TEXT,
                analyst_verdict TEXT,
                confidence_after TEXT,
                would_use_for_customer_escalation TEXT,
                confirmed_ttps_json TEXT,
                rejected_ttps_json TEXT,
                additional_ttps_found_json TEXT,
                missing_log_sources TEXT,
                useful_hunts TEXT,
                bad_hunts TEXT,
                quality_json TEXT,
                what_helpful TEXT,
                what_wrong_or_missing TEXT,
                cti_was_run INTEGER DEFAULT 0,
                has_followup_reassessment INTEGER DEFAULT 0,
                full_feedback_json TEXT,
                FOREIGN KEY(alert_session_id) REFERENCES alert_sessions(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mapping_decisions (
                id TEXT PRIMARY KEY,
                alert_session_id TEXT NOT NULL,
                feedback_submission_id TEXT,
                created_at TEXT NOT NULL,
                source_field TEXT,
                decision TEXT,
                suggested_udm_field TEXT,
                approved_udm_field TEXT,
                confidence TEXT,
                reason TEXT,
                full_mapping_json TEXT,
                FOREIGN KEY(alert_session_id) REFERENCES alert_sessions(id),
                FOREIGN KEY(feedback_submission_id) REFERENCES feedback_submissions(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_run_notes (
                id TEXT PRIMARY KEY,
                alert_session_id TEXT,
                created_at TEXT NOT NULL,
                task_type TEXT,
                model_name TEXT,
                success INTEGER,
                notes TEXT,
                FOREIGN KEY(alert_session_id) REFERENCES alert_sessions(id)
            )
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback_submissions(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON feedback_submissions(analyst_verdict)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_hash ON alert_sessions(alert_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mapping_source_field ON mapping_decisions(source_field)")

        conn.commit()

    return resolved_path


def save_feedback_submission(
    feedback_record: Dict[str, Any],
    db_path: Path | str | None = None,
) -> Dict[str, Any]:
    """
    Save one analyst feedback submission and its mapping audit.

    Privacy posture:
    - Does not store raw alert content.
    - Stores alert hash and validated alert metadata.
    - Stores feedback and approved/rejected mapping decisions.
    """
    resolved_path = init_feedback_db(db_path)

    alert_summary = feedback_record.get("alert_summary", {}) or {}

    alert_session_id = str(uuid.uuid4())
    feedback_id = str(uuid.uuid4())
    created_at = feedback_record.get("created_at") or _now_iso()

    mapping_audit = feedback_record.get("mapping_audit", []) or []

    with get_connection(resolved_path) as conn:
        conn.execute(
            """
            INSERT INTO alert_sessions (
                id,
                created_at,
                alert_hash,
                input_source,
                vendor,
                product,
                event_type,
                rule_name,
                severity,
                detected_tactics_json,
                detected_techniques_json,
                raw_alert_stored,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_session_id,
                created_at,
                alert_summary.get("alert_hash", ""),
                alert_summary.get("input_source", ""),
                alert_summary.get("vendor", ""),
                alert_summary.get("product", ""),
                alert_summary.get("event_type", ""),
                alert_summary.get("rule_name", ""),
                alert_summary.get("severity", ""),
                _json_dumps(alert_summary.get("detected_tactics", [])),
                _json_dumps(alert_summary.get("detected_techniques", [])),
                0,
                "Raw alert content is not stored by default.",
            ),
        )

        conn.execute(
            """
            INSERT INTO feedback_submissions (
                id,
                alert_session_id,
                created_at,
                context_label,
                helpfulness,
                analyst_verdict,
                confidence_after,
                would_use_for_customer_escalation,
                confirmed_ttps_json,
                rejected_ttps_json,
                additional_ttps_found_json,
                missing_log_sources,
                useful_hunts,
                bad_hunts,
                quality_json,
                what_helpful,
                what_wrong_or_missing,
                cti_was_run,
                has_followup_reassessment,
                full_feedback_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                feedback_id,
                alert_session_id,
                created_at,
                feedback_record.get("context_label", ""),
                feedback_record.get("helpfulness", ""),
                feedback_record.get("analyst_verdict", ""),
                feedback_record.get("confidence_after", ""),
                feedback_record.get("would_use_for_customer_escalation", ""),
                _json_dumps(feedback_record.get("confirmed_ttps", [])),
                _json_dumps(feedback_record.get("rejected_ttps", [])),
                _json_dumps(feedback_record.get("additional_ttps_found", [])),
                feedback_record.get("missing_log_sources", ""),
                feedback_record.get("useful_hunts", ""),
                feedback_record.get("bad_hunts", ""),
                _json_dumps(feedback_record.get("quality", {})),
                feedback_record.get("what_helpful", ""),
                feedback_record.get("what_wrong_or_missing", ""),
                1 if feedback_record.get("cti_was_run") else 0,
                1 if feedback_record.get("has_followup_reassessment") else 0,
                _json_dumps(feedback_record),
            ),
        )

        for mapping in mapping_audit:
            conn.execute(
                """
                INSERT INTO mapping_decisions (
                    id,
                    alert_session_id,
                    feedback_submission_id,
                    created_at,
                    source_field,
                    decision,
                    suggested_udm_field,
                    approved_udm_field,
                    confidence,
                    reason,
                    full_mapping_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    alert_session_id,
                    feedback_id,
                    created_at,
                    mapping.get("source_field", ""),
                    mapping.get("decision", ""),
                    mapping.get("suggested_udm_field", ""),
                    mapping.get("approved_udm_field", ""),
                    str(mapping.get("confidence", "")),
                    mapping.get("reason", ""),
                    _json_dumps(mapping),
                ),
            )

        conn.commit()

    return {
        "db_path": str(resolved_path),
        "alert_session_id": alert_session_id,
        "feedback_submission_id": feedback_id,
        "mapping_decisions_saved": len(mapping_audit),
    }


def _rows_to_dicts(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(row) for row in rows]


def list_recent_feedback(limit: int = 20, db_path: Path | str | None = None) -> List[Dict[str, Any]]:
    resolved_path = init_feedback_db(db_path)

    with get_connection(resolved_path) as conn:
        rows = conn.execute(
            """
            SELECT
                f.created_at,
                a.input_source,
                a.vendor,
                a.product,
                a.rule_name,
                a.severity,
                f.helpfulness,
                f.analyst_verdict,
                f.confidence_after,
                f.would_use_for_customer_escalation,
                f.cti_was_run,
                f.has_followup_reassessment
            FROM feedback_submissions f
            JOIN alert_sessions a ON a.id = f.alert_session_id
            ORDER BY f.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return _rows_to_dicts(rows)


def get_feedback_stats(db_path: Path | str | None = None) -> Dict[str, Any]:
    resolved_path = init_feedback_db(db_path)

    with get_connection(resolved_path) as conn:
        total_feedback = conn.execute(
            "SELECT COUNT(*) AS count FROM feedback_submissions"
        ).fetchone()["count"]

        total_alerts = conn.execute(
            "SELECT COUNT(*) AS count FROM alert_sessions"
        ).fetchone()["count"]

        total_mappings = conn.execute(
            "SELECT COUNT(*) AS count FROM mapping_decisions"
        ).fetchone()["count"]

        verdict_rows = conn.execute(
            """
            SELECT analyst_verdict, COUNT(*) AS count
            FROM feedback_submissions
            GROUP BY analyst_verdict
            ORDER BY count DESC
            """
        ).fetchall()

        helpfulness_rows = conn.execute(
            """
            SELECT helpfulness, COUNT(*) AS count
            FROM feedback_submissions
            GROUP BY helpfulness
            ORDER BY count DESC
            """
        ).fetchall()

        mapping_decision_rows = conn.execute(
            """
            SELECT decision, COUNT(*) AS count
            FROM mapping_decisions
            GROUP BY decision
            ORDER BY count DESC
            """
        ).fetchall()

    return {
        "db_path": str(resolved_path),
        "total_feedback_submissions": total_feedback,
        "total_alert_sessions": total_alerts,
        "total_mapping_decisions": total_mappings,
        "verdict_counts": _rows_to_dicts(verdict_rows),
        "helpfulness_counts": _rows_to_dicts(helpfulness_rows),
        "mapping_decision_counts": _rows_to_dicts(mapping_decision_rows),
    }


def list_mapping_decisions(limit: int = 50, db_path: Path | str | None = None) -> List[Dict[str, Any]]:
    resolved_path = init_feedback_db(db_path)

    with get_connection(resolved_path) as conn:
        rows = conn.execute(
            """
            SELECT
                created_at,
                source_field,
                decision,
                suggested_udm_field,
                approved_udm_field,
                confidence,
                reason
            FROM mapping_decisions
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return _rows_to_dicts(rows)



def list_feedback_admin_comments(limit: int = 200) -> list[dict]:
    """
    Admin-focused feedback export.

    Returns one row per feedback submission with the long-form analyst comments
    that are most useful for product learning.
    """
    import json
    import sqlite3

    init_feedback_db()

    def _table_columns(conn, table_name: str) -> set[str]:
        try:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            return {row[1] for row in rows}
        except Exception:
            return set()

    def _clean(value):
        if value is None:
            return ""
        if isinstance(value, list):
            return ", ".join(str(item) for item in value if item is not None)
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    def _deep_get(payload, candidate_keys):
        if not isinstance(payload, dict):
            return ""

        def walk(obj, wanted_key):
            if isinstance(obj, dict):
                if wanted_key in obj and obj[wanted_key] not in (None, "", []):
                    return obj[wanted_key]
                for value in obj.values():
                    found = walk(value, wanted_key)
                    if found not in (None, "", []):
                        return found
            elif isinstance(obj, list):
                for item in obj:
                    found = walk(item, wanted_key)
                    if found not in (None, "", []):
                        return found
            return ""

        for key in candidate_keys:
            found = walk(payload, key)
            if found not in (None, "", []):
                return _clean(found)

        return ""

    def _first(row_dict, payload, candidate_keys):
        for key in candidate_keys:
            value = row_dict.get(key)
            if value not in (None, "", []):
                return _clean(value)

        return _deep_get(payload, candidate_keys)

    with get_connection() as conn:
        conn.row_factory = sqlite3.Row

        feedback_cols = _table_columns(conn, "feedback_submissions")
        session_cols = _table_columns(conn, "alert_sessions")

        feedback_select = []
        for col in feedback_cols:
            feedback_select.append(f"f.{col} AS {col}")

        session_select = []
        for col in ["vendor", "product", "rule_name", "severity", "event_type", "input_source"]:
            if col in session_cols:
                session_select.append(f"s.{col} AS {col}")

        if not feedback_select:
            return []

        join_sql = ""
        if "alert_session_id" in feedback_cols and "id" in session_cols:
            join_sql = "LEFT JOIN alert_sessions s ON f.alert_session_id = s.id"

        order_col = "created_at" if "created_at" in feedback_cols else "id"

        sql = f"""
            SELECT
                {", ".join(feedback_select + session_select)}
            FROM feedback_submissions f
            {join_sql}
            ORDER BY f.{order_col} DESC
            LIMIT ?
        """

        rows = conn.execute(sql, (limit,)).fetchall()

    output = []

    for row in rows:
        row_dict = dict(row)

        raw_payload = row_dict.get("full_feedback_json") or "{}"
        try:
            payload = json.loads(raw_payload) if isinstance(raw_payload, str) else {}
        except Exception:
            payload = {}

        output.append(
            {
                "submitted_at": _first(row_dict, payload, ["created_at", "submitted_at"]),
                "vendor": _first(row_dict, payload, ["vendor"]),
                "product": _first(row_dict, payload, ["product"]),
                "rule_name": _first(row_dict, payload, ["rule_name"]),
                "severity": _first(row_dict, payload, ["severity"]),
                "helpfulness": _first(row_dict, payload, ["helpfulness"]),
                "analyst_verdict": _first(row_dict, payload, ["analyst_verdict"]),
                "confidence_after": _first(row_dict, payload, ["confidence_after"]),
                "would_use_for_customer_escalation": _first(
                    row_dict,
                    payload,
                    ["would_use_for_customer_escalation", "customer_escalation"],
                ),
                "confirmed_ttps": _first(
                    row_dict,
                    payload,
                    ["confirmed_ttps", "confirmed_ttp", "confirmed_tactics_techniques"],
                ),
                "suggested_but_not_confirmed_ttps": _first(
                    row_dict,
                    payload,
                    [
                        "suggested_but_not_confirmed_ttps",
                        "rejected_ttps",
                        "not_confirmed_ttps",
                        "suggested_not_confirmed_ttps",
                    ],
                ),
                "additional_ttps_found": _first(
                    row_dict,
                    payload,
                    ["additional_ttps_found", "additional_ttps"],
                ),
                "missing_log_sources_or_evidence": _first(
                    row_dict,
                    payload,
                    [
                        "missing_log_sources_or_evidence",
                        "missing_log_sources",
                        "missing_evidence",
                    ],
                ),
                "useful_hunts_or_pivots": _first(
                    row_dict,
                    payload,
                    ["useful_hunts_or_pivots", "useful_hunts", "useful_pivots"],
                ),
                "bad_or_noisy_hunts_or_pivots": _first(
                    row_dict,
                    payload,
                    [
                        "bad_or_noisy_hunts_or_pivots",
                        "bad_hunts",
                        "noisy_hunts",
                        "bad_or_noisy_hunts",
                    ],
                ),
                "what_was_helpful": _first(
                    row_dict,
                    payload,
                    ["what_was_helpful", "free_text_helpful", "helpful_feedback"],
                ),
                "what_was_wrong_or_missing": _first(
                    row_dict,
                    payload,
                    [
                        "what_was_wrong_or_missing",
                        "free_text_wrong_or_missing",
                        "wrong_or_missing_feedback",
                    ],
                ),
                "ai_summary_quality": _first(row_dict, payload, ["ai_summary_quality"]),
                "udm_mapping_quality": _first(row_dict, payload, ["udm_mapping_quality"]),
                "ontology_quality": _first(row_dict, payload, ["ontology_quality"]),
                "hunts_quality": _first(row_dict, payload, ["hunts_quality"]),
                "cti_quality": _first(row_dict, payload, ["cti_quality"]),
                "cti_was_run": _first(row_dict, payload, ["cti_was_run"]),
                "has_followup_reassessment": _first(
                    row_dict,
                    payload,
                    ["has_followup_reassessment"],
                ),
            }
        )

    return output
