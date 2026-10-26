"""
Audit Engine for Agent Permission Governor.
Provides structured, immutable event logging and audit trail retrieval in SQLite.
Logs every request, decision, approval transition, and execution event.
"""

from __future__ import annotations
import json
from typing import Any, Optional

from config import DB_PATH
from db import get_db, insert_audit_event, utc_now_iso

# Canonical audit event types
EVENT_REQUEST_RECEIVED = "REQUEST_RECEIVED"
EVENT_EVALUATION_COMPLETED = "EVALUATION_COMPLETED"
EVENT_APPROVAL_PENDING = "APPROVAL_PENDING"
EVENT_APPROVAL_GRANTED = "APPROVAL_GRANTED"
EVENT_APPROVAL_REJECTED = "APPROVAL_REJECTED"
EVENT_EXECUTION_ATTEMPTED = "EXECUTION_ATTEMPTED"
EVENT_EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
EVENT_EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
EVENT_EXECUTION_FAILED = "EXECUTION_FAILED"
EVENT_GOVERNOR_FAIL_CLOSED = "GOVERNOR_FAIL_CLOSED_ERROR"

def log_audit_event(
    event: str,
    request_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    db_path: str = DB_PATH,
) -> int:
    """
    Append an immutable event record to the audit_log table.
    """
    event_details = details or {}
    return insert_audit_event(
        request_id=request_id,
        event=event,
        details=event_details,
        db_path=db_path,
    )

def get_audit_trail(
    request_id: Optional[str] = None,
    event: Optional[str] = None,
    limit: int = 100,
    db_path: str = DB_PATH,
) -> list[dict[str, Any]]:
    """
    Retrieve audit log records with optional filtering by request_id or event type.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []
        
        if request_id:
            query += " AND request_id = ?"
            params.append(request_id)
        if event:
            query += " AND event = ?"
            params.append(event)
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        trail: list[dict[str, Any]] = []
        for r in rows:
            entry = dict(r)
            try:
                entry["details"] = json.loads(entry.get("details_json", "{}"))
            except Exception:
                entry["details"] = entry.get("details_json", "{}")
            trail.append(entry)
            
        return trail

def verify_audit_coverage(
    request_id: str,
    db_path: str = DB_PATH,
) -> bool:
    """
    Verify whether a given request has a complete audit record covering
    both REQUEST_RECEIVED and an authorization decision.
    """
    events = {e["event"] for e in get_audit_trail(request_id=request_id, limit=50, db_path=db_path)}
    has_received = EVENT_REQUEST_RECEIVED in events
    has_decision = EVENT_EVALUATION_COMPLETED in events or EVENT_GOVERNOR_FAIL_CLOSED in events
    return has_received and has_decision
