"""
Feedback persistence — Google Sheets backed.

Why Sheets and not SQLite: Streamlit Community Cloud's filesystem is ephemeral, so a
local SQLite file is wiped on every redeploy — taking all captured feedback with it.
Feedback is the core research signal of this project, so it must live outside the
container. It now persists to a private Google Sheet owned by the operator.

Design:
- One flat worksheet, one row per feedback submission. `COLUMNS` is the single source of
  truth for column order (header row and every data row line up by it).
- The old relational `mapping_decisions` table collapses into a JSON column on the row;
  the tiny admin stats/lists are computed in plain Python from the rows.
- Append-only: the app never updates or deletes rows.
- Fail-closed: if the Google Sheets secrets are absent, storage is disabled (no crash,
  no user-facing error) and the admin panel shows a clear "not configured" note.
- Credentials come only from st.secrets — nothing touches the repo, logs, or error text.

Public API is unchanged from the old SQLite module so streamlit_app.py imports keep
working: init_feedback_db, save_feedback_submission, get_feedback_stats,
list_recent_feedback, list_mapping_decisions, list_feedback_admin_comments.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import streamlit as st

try:
    import gspread
    from google.oauth2.service_account import Credentials
    _GSPREAD_IMPORT_ERROR = None
except Exception as import_error:  # pragma: no cover - only if deps missing at runtime
    gspread = None
    Credentials = None
    _GSPREAD_IMPORT_ERROR = import_error


# Sheets scope is enough to open the sheet by key and append rows. The sheet is shared
# with the service account directly, so no Drive scope is needed.
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

# Number of times to retry a Sheets write before giving up, and the base backoff. Most
# transient "Google had a bad moment" blips clear within a second or two.
_WRITE_ATTEMPTS = 3
_WRITE_BACKOFF_SECONDS = 1.5

# Single source of truth for the flat row schema. Header row and every data row use this
# exact order. Mirrors the fields the old SQLite schema captured.
COLUMNS: List[str] = [
    "created_at",
    "alert_hash",
    "input_source",
    "vendor",
    "product",
    "event_type",
    "rule_name",
    "severity",
    "detected_tactics",
    "detected_techniques",
    "context_label",
    "helpfulness",
    "analyst_verdict",
    "confidence_after",
    "would_use_for_customer_escalation",
    "confirmed_ttps",
    "rejected_ttps",
    "additional_ttps_found",
    "missing_log_sources",
    "useful_hunts",
    "bad_hunts",
    "generated_query_usefulness",
    "quality",
    "what_helpful",
    "what_wrong_or_missing",
    "cti_was_run",
    "has_followup_reassessment",
    "mapping_decisions",
    "alert_session_id",
    "feedback_submission_id",
    "full_feedback_json",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def _json_loads_list(value: Any) -> List[Dict[str, Any]]:
    """Parse a JSON list stored in a cell; always return a list of dicts, never raise."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not value or not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


# --- connection ---------------------------------------------------------------------

def feedback_store_is_configured() -> bool:
    """True only if the Sheets deps loaded and both secrets are present."""
    if gspread is None or Credentials is None:
        return False
    try:
        info = st.secrets.get("gcp_service_account")
        sheet_id = st.secrets.get("FEEDBACK_SHEET_ID")
    except Exception:
        return False
    return bool(info) and bool(sheet_id)


def _get_worksheet():
    """
    Return the first worksheet of the configured Google Sheet, or None if storage is not
    configured. Raises only on a genuine connection failure (handled by callers).
    """
    if not feedback_store_is_configured():
        return None

    info = dict(st.secrets["gcp_service_account"])
    sheet_id = st.secrets["FEEDBACK_SHEET_ID"]

    creds = Credentials.from_service_account_info(info, scopes=SCOPES)
    client = gspread.authorize(creds)
    return client.open_by_key(sheet_id).sheet1


def _store_label() -> str:
    """Human-friendly label for the admin status line; never raises."""
    if not feedback_store_is_configured():
        return "Not configured (add Google Sheets secrets)"
    try:
        worksheet = _get_worksheet()
        return f"Google Sheet: {worksheet.spreadsheet.title}"
    except Exception:
        return "Google Sheet (configured)"


def init_feedback_db(db_path: Any = None) -> str:
    """
    Kept for import/call-site compatibility with the old SQLite module. Returns a short,
    human-readable label for the feedback store (shown in the admin panel).
    """
    return _store_label()


# --- write path ---------------------------------------------------------------------

def _record_to_rowdict(feedback_record: Dict[str, Any]) -> Dict[str, Any]:
    alert_summary = feedback_record.get("alert_summary", {}) or {}
    mapping_audit = feedback_record.get("mapping_audit", []) or []

    return {
        "created_at": feedback_record.get("created_at") or _now_iso(),
        "alert_hash": alert_summary.get("alert_hash", ""),
        "input_source": alert_summary.get("input_source", ""),
        "vendor": alert_summary.get("vendor", ""),
        "product": alert_summary.get("product", ""),
        "event_type": alert_summary.get("event_type", ""),
        "rule_name": alert_summary.get("rule_name", ""),
        "severity": alert_summary.get("severity", ""),
        "detected_tactics": _json_dumps(alert_summary.get("detected_tactics", [])),
        "detected_techniques": _json_dumps(alert_summary.get("detected_techniques", [])),
        "context_label": feedback_record.get("context_label", ""),
        "helpfulness": feedback_record.get("helpfulness", ""),
        "analyst_verdict": feedback_record.get("analyst_verdict", ""),
        "confidence_after": feedback_record.get("confidence_after", ""),
        "would_use_for_customer_escalation": feedback_record.get("would_use_for_customer_escalation", ""),
        "confirmed_ttps": _json_dumps(feedback_record.get("confirmed_ttps", [])),
        "rejected_ttps": _json_dumps(feedback_record.get("rejected_ttps", [])),
        "additional_ttps_found": _json_dumps(feedback_record.get("additional_ttps_found", [])),
        "missing_log_sources": feedback_record.get("missing_log_sources", ""),
        "useful_hunts": feedback_record.get("useful_hunts", ""),
        "bad_hunts": feedback_record.get("bad_hunts", ""),
        "generated_query_usefulness": feedback_record.get("generated_query_usefulness", ""),
        "quality": _json_dumps(feedback_record.get("quality", {})),
        "what_helpful": feedback_record.get("what_helpful", ""),
        "what_wrong_or_missing": feedback_record.get("what_wrong_or_missing", ""),
        "cti_was_run": 1 if feedback_record.get("cti_was_run") else 0,
        "has_followup_reassessment": 1 if feedback_record.get("has_followup_reassessment") else 0,
        "mapping_decisions": _json_dumps(mapping_audit),
        "alert_session_id": str(uuid.uuid4()),
        "feedback_submission_id": str(uuid.uuid4()),
        "full_feedback_json": _json_dumps(feedback_record),
    }


def _ensure_header(worksheet) -> None:
    """Write the header row once, only if the sheet is still empty."""
    first_row = worksheet.row_values(1)
    if not first_row:
        worksheet.append_row(COLUMNS, value_input_option="RAW")


def save_feedback_submission(
    feedback_record: Dict[str, Any],
    db_path: Any = None,
) -> Dict[str, Any]:
    """
    Append one analyst feedback submission as a row in the Google Sheet.

    Never raises. Returns a status dict the caller uses to pick the right message:
      {"ok": True, ...}                              -> saved
      {"ok": False, "disabled": True, "note": ...}   -> storage not configured
      {"ok": False, "error": "..."}                  -> transient/other failure after retries

    On the first write to an empty sheet, the header row is written before the data row.
    Append-only; nothing is ever updated or deleted.
    """
    if not feedback_store_is_configured():
        return {
            "ok": False,
            "disabled": True,
            "note": "Feedback storage (Google Sheets) is not configured.",
            "mapping_decisions_saved": 0,
        }

    rowdict = _record_to_rowdict(feedback_record)
    row = [rowdict[column] for column in COLUMNS]
    mapping_count = len(feedback_record.get("mapping_audit", []) or [])

    last_error = None
    for attempt in range(_WRITE_ATTEMPTS):
        try:
            worksheet = _get_worksheet()
            _ensure_header(worksheet)
            worksheet.append_row(row, value_input_option="RAW")
            return {
                "ok": True,
                "store": "google_sheets",
                "feedback_submission_id": rowdict["feedback_submission_id"],
                "mapping_decisions_saved": mapping_count,
            }
        except Exception as error:  # transient network / rate limit / config
            last_error = error
            if attempt < _WRITE_ATTEMPTS - 1:
                time.sleep(_WRITE_BACKOFF_SECONDS * (attempt + 1))

    # All retries failed. Return a clean status — the caller shows a graceful message and
    # keeps the submission in session_state so the analyst can resubmit. We intentionally
    # do NOT surface the raw exception text to the UI.
    return {
        "ok": False,
        "error": type(last_error).__name__ if last_error else "unknown",
        "mapping_decisions_saved": 0,
    }


# --- read path (admin) --------------------------------------------------------------

def _read_all_records() -> List[Dict[str, Any]]:
    """
    All feedback rows as dicts keyed by the header row. Returns [] on an empty sheet, an
    unconfigured store, or any read error — never raises.
    """
    if not feedback_store_is_configured():
        return []
    try:
        worksheet = _get_worksheet()
        return worksheet.get_all_records()  # [] if only a header row, or empty
    except Exception:
        return []


def _sorted_recent(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Most recent first, by created_at (rows are appended oldest-first)."""
    return sorted(records, key=lambda r: str(r.get("created_at", "")), reverse=True)


def _count_by(records: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for record in records:
        value = str(record.get(key, "") or "")
        counts[value] = counts.get(value, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{key: name, "count": count} for name, count in ordered]


def get_feedback_stats(db_path: Any = None) -> Dict[str, Any]:
    records = _read_all_records()

    total_mappings = 0
    decision_counts: Dict[str, int] = {}
    for record in records:
        for mapping in _json_loads_list(record.get("mapping_decisions")):
            total_mappings += 1
            decision = str(mapping.get("decision", "") or "")
            decision_counts[decision] = decision_counts.get(decision, 0) + 1

    mapping_decision_counts = [
        {"decision": name, "count": count}
        for name, count in sorted(decision_counts.items(), key=lambda item: item[1], reverse=True)
    ]

    return {
        "db_path": _store_label(),
        "total_feedback_submissions": len(records),
        # One row == one alert session in the flat model, so these are equal.
        "total_alert_sessions": len(records),
        "total_mapping_decisions": total_mappings,
        "verdict_counts": _count_by(records, "analyst_verdict"),
        "helpfulness_counts": _count_by(records, "helpfulness"),
        "mapping_decision_counts": mapping_decision_counts,
    }


def list_recent_feedback(limit: int = 20, db_path: Any = None) -> List[Dict[str, Any]]:
    recent = _sorted_recent(_read_all_records())[:limit]
    projected_columns = [
        "created_at",
        "input_source",
        "vendor",
        "product",
        "rule_name",
        "severity",
        "helpfulness",
        "analyst_verdict",
        "confidence_after",
        "would_use_for_customer_escalation",
        "cti_was_run",
        "has_followup_reassessment",
    ]
    return [{column: record.get(column, "") for column in projected_columns} for record in recent]


def list_mapping_decisions(limit: int = 50, db_path: Any = None) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for record in _sorted_recent(_read_all_records()):
        created_at = record.get("created_at", "")
        for mapping in _json_loads_list(record.get("mapping_decisions")):
            output.append(
                {
                    "created_at": created_at,
                    "source_field": mapping.get("source_field", ""),
                    "decision": mapping.get("decision", ""),
                    "suggested_udm_field": mapping.get("suggested_udm_field", ""),
                    "approved_udm_field": mapping.get("approved_udm_field", ""),
                    "confidence": str(mapping.get("confidence", "")),
                    "reason": mapping.get("reason", ""),
                }
            )
            if len(output) >= limit:
                return output
    return output


def _clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _deep_get(payload: Any, candidate_keys: List[str]) -> str:
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


def _first(record: Dict[str, Any], payload: Dict[str, Any], candidate_keys: List[str]) -> str:
    for key in candidate_keys:
        value = record.get(key)
        if value not in (None, "", []):
            return _clean(value)
    return _deep_get(payload, candidate_keys)


def list_feedback_admin_comments(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Admin-focused feedback export: one row per submission with the long-form analyst
    comments most useful for product learning. Values are looked up first on the row's
    own columns, then deep inside the stored full_feedback_json as a fallback.
    """
    records = _sorted_recent(_read_all_records())[:limit]

    output: List[Dict[str, Any]] = []
    for record in records:
        raw_payload = record.get("full_feedback_json") or "{}"
        try:
            payload = json.loads(raw_payload) if isinstance(raw_payload, str) else {}
        except Exception:
            payload = {}

        output.append(
            {
                "submitted_at": _first(record, payload, ["created_at", "submitted_at"]),
                "vendor": _first(record, payload, ["vendor"]),
                "product": _first(record, payload, ["product"]),
                "rule_name": _first(record, payload, ["rule_name"]),
                "severity": _first(record, payload, ["severity"]),
                "helpfulness": _first(record, payload, ["helpfulness"]),
                "analyst_verdict": _first(record, payload, ["analyst_verdict"]),
                "confidence_after": _first(record, payload, ["confidence_after"]),
                "would_use_for_customer_escalation": _first(
                    record, payload, ["would_use_for_customer_escalation", "customer_escalation"]
                ),
                "confirmed_ttps": _first(record, payload, ["confirmed_ttps"]),
                "suggested_but_not_confirmed_ttps": _first(
                    record, payload, ["rejected_ttps", "suggested_but_not_confirmed_ttps"]
                ),
                "additional_ttps_found": _first(record, payload, ["additional_ttps_found", "additional_ttps"]),
                "missing_log_sources_or_evidence": _first(
                    record, payload, ["missing_log_sources", "missing_log_sources_or_evidence"]
                ),
                "useful_hunts_or_pivots": _first(record, payload, ["useful_hunts", "useful_hunts_or_pivots"]),
                "bad_or_noisy_hunts_or_pivots": _first(
                    record, payload, ["bad_hunts", "bad_or_noisy_hunts_or_pivots"]
                ),
                "generated_query_usefulness": _first(record, payload, ["generated_query_usefulness"]),
                "what_was_helpful": _first(record, payload, ["what_helpful", "what_was_helpful"]),
                "what_was_wrong_or_missing": _first(
                    record, payload, ["what_wrong_or_missing", "what_was_wrong_or_missing"]
                ),
                "cti_was_run": _first(record, payload, ["cti_was_run"]),
                "has_followup_reassessment": _first(record, payload, ["has_followup_reassessment"]),
            }
        )

    return output
