"""
Human-in-the-Loop Approval Queue for Agent Permission Governor.
Manages pending requests, review actions (Approve/Reject), and audit state transitions.
Ensures that pending or rejected requests CANNOT execute.
"""

from __future__ import annotations
import json
import uuid
from typing import Any, Optional

from audit import (
    EVENT_APPROVAL_GRANTED,
    EVENT_APPROVAL_PENDING,
    EVENT_APPROVAL_REJECTED,
    log_audit_event,
)
from config import DB_PATH
from db import get_db, insert_approval, update_approval_status, utc_now_iso

def create_approval(
    request_id: str,
    db_path: str = DB_PATH,
) -> str:
    """
    Register a request in the approvals queue with PENDING status.
    """
    approval_id = f"appr_{uuid.uuid4().hex[:12]}"
    insert_approval(
        approval_id=approval_id,
        request_id=request_id,
        status="PENDING",
        reviewer=None,
        decided_at=None,
        db_path=db_path,
    )
    log_audit_event(
        event=EVENT_APPROVAL_PENDING,
        request_id=request_id,
        details={"approval_id": approval_id, "status": "PENDING"},
        db_path=db_path,
    )
    return approval_id

def get_approval(
    request_id: str,
    db_path: str = DB_PATH,
) -> Optional[dict[str, Any]]:
    """Fetch approval record for a specific request ID."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM approvals WHERE request_id = ?", (request_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def list_pending_approvals(
    db_path: str = DB_PATH,
) -> list[dict[str, Any]]:
    """
    List all requests currently awaiting human review, joined with action request
    and risk assessment details.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 
                a.id AS approval_id,
                a.request_id,
                a.status,
                a.reviewer,
                a.decided_at,
                r.agent_id,
                r.action_type,
                r.resource,
                r.resource_sensitivity,
                r.task_context,
                r.instruction_source,
                r.payload,
                r.created_at AS requested_at,
                d.risk_score,
                d.injection_score,
                d.reasons_json
            FROM approvals a
            JOIN action_requests r ON a.request_id = r.id
            LEFT JOIN decisions d ON a.request_id = d.request_id
            WHERE a.status = 'PENDING'
            ORDER BY r.created_at DESC
            """
        )
        rows = cursor.fetchall()
        
        pending_list: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            try:
                item["payload"] = json.loads(item["payload"]) if item.get("payload") else {}
            except Exception:
                pass
            try:
                item["reasons"] = json.loads(item["reasons_json"]) if item.get("reasons_json") else []
            except Exception:
                item["reasons"] = []
            pending_list.append(item)
            
        return pending_list

def approve(
    request_id: str,
    reviewer: str,
    db_path: str = DB_PATH,
) -> dict[str, Any]:
    """
    Grant explicit human approval for a pending request.
    Transitions status: PENDING -> APPROVED.
    """
    if not reviewer or not reviewer.strip():
        raise ValueError("Reviewer identity cannot be blank.")
        
    approval_rec = get_approval(request_id, db_path=db_path)
    if not approval_rec:
        raise ValueError(f"No approval record found for request '{request_id}'.")
        
    if approval_rec["status"] != "PENDING":
        return {
            "success": False,
            "error": f"Request '{request_id}' has already been decided with status: {approval_rec['status']}.",
            "status": approval_rec["status"],
        }
        
    update_approval_status(
        request_id=request_id,
        status="APPROVED",
        reviewer=reviewer.strip(),
        db_path=db_path,
    )
    
    log_audit_event(
        event=EVENT_APPROVAL_GRANTED,
        request_id=request_id,
        details={
            "status": "APPROVED",
            "reviewer": reviewer.strip(),
            "timestamp": utc_now_iso(),
        },
        db_path=db_path,
    )
    
    return {
        "success": True,
        "request_id": request_id,
        "status": "APPROVED",
        "reviewer": reviewer.strip(),
    }

def reject(
    request_id: str,
    reviewer: str,
    db_path: str = DB_PATH,
) -> dict[str, Any]:
    """
    Explicitly reject a pending request.
    Transitions status: PENDING -> REJECTED.
    """
    if not reviewer or not reviewer.strip():
        raise ValueError("Reviewer identity cannot be blank.")
        
    approval_rec = get_approval(request_id, db_path=db_path)
    if not approval_rec:
        raise ValueError(f"No approval record found for request '{request_id}'.")
        
    if approval_rec["status"] != "PENDING":
        return {
            "success": False,
            "error": f"Request '{request_id}' has already been decided with status: {approval_rec['status']}.",
            "status": approval_rec["status"],
        }
        
    update_approval_status(
        request_id=request_id,
        status="REJECTED",
        reviewer=reviewer.strip(),
        db_path=db_path,
    )
    
    log_audit_event(
        event=EVENT_APPROVAL_REJECTED,
        request_id=request_id,
        details={
            "status": "REJECTED",
            "reviewer": reviewer.strip(),
            "timestamp": utc_now_iso(),
        },
        db_path=db_path,
    )
    
    return {
        "success": True,
        "request_id": request_id,
        "status": "REJECTED",
        "reviewer": reviewer.strip(),
    }
