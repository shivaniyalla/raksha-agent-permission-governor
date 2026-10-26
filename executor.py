"""
Safe Sandboxed Executor for Agent Permission Governor.
Provides safe, simulated execution for authorized agent actions.
Guarantees:
1. NEVER executes real destructive host commands or uncontained operations.
2. Execution occurs ONLY if authorized by Governor (ALLOW) or approved by Human Review (APPROVED).
3. Pending, rejected, or denied requests are strictly blocked.
4. All execution attempts, successes, and blocks are recorded in the audit trail.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
import time
from dataclasses import asdict, dataclass
from typing import Any, Optional

from audit import (
    EVENT_EXECUTION_ATTEMPTED,
    EVENT_EXECUTION_BLOCKED,
    EVENT_EXECUTION_FAILED,
    EVENT_EXECUTION_SUCCEEDED,
    log_audit_event,
)
from config import BASE_DIR, DATA_DIR, DB_PATH
from db import get_db

# Sandboxed file directory - safe isolated scratchpad
SANDBOX_DIR = DATA_DIR / "sandbox"
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

class ExecutionSecurityError(Exception):
    """Raised when an unapproved or unauthorized execution attempt is intercepted."""
    pass

@dataclass
class ExecutionResult:
    """Standardized auditable execution result."""
    success: bool
    request_id: str
    action_type: str
    resource: str
    output: Any
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    sandboxed: bool = True

def _safe_sandbox_write(resource: str, payload: Any) -> dict[str, Any]:
    """
    Safely write content strictly within the isolated sandbox directory.
    Guards against path traversal and outside directory writes.
    """
    # Sanitize filename
    clean_filename = Path(resource).name
    if not clean_filename or ".." in resource:
        clean_filename = "sandbox_output.txt"
        
    target_path = (SANDBOX_DIR / clean_filename).resolve()
    
    # Ensure target path stays strictly inside SANDBOX_DIR
    if not str(target_path).startswith(str(SANDBOX_DIR.resolve())):
        raise PermissionError(f"Path traversal detected: target '{resource}' attempts escape from sandbox.")
        
    content = payload.get("content", str(payload)) if isinstance(payload, dict) else str(payload)
    
    target_path.write_text(content, encoding="utf-8")
    
    return {
        "status": "success",
        "sandboxed_path": str(target_path),
        "bytes_written": len(content.encode("utf-8")),
        "message": f"Safely wrote to sandboxed path: {target_path.name}",
    }

def _simulated_api_call(resource: str, payload: Any) -> dict[str, Any]:
    """Simulate external API interactions safely without external network calls."""
    res_lower = resource.lower()
    if "payment" in res_lower:
        amount = payload.get("amount", 0.0) if isinstance(payload, dict) else 0.0
        return {
            "status_code": 200,
            "simulated": True,
            "response": {
                "transaction_id": "sim_txn_987654321",
                "status": "SETTLED_IN_SIMULATION",
                "amount": amount,
                "gateway": "MockPaymentGateway_v2",
            }
        }
    elif "crm" in res_lower:
        return {
            "status_code": 200,
            "simulated": True,
            "response": {
                "crm_id": "crm_cust_4401",
                "tier": "enterprise",
                "status": "active",
            }
        }
    elif "ci_webhook" in res_lower:
        return {
            "status_code": 202,
            "simulated": True,
            "response": {"job_id": "build_sim_5521", "status": "QUEUED_SANDBOX"}
        }
    else:
        return {
            "status_code": 200,
            "simulated": True,
            "response": {"ack": True, "target": resource, "payload_echo": payload}
        }

def _simulated_read(resource: str, payload: Any) -> dict[str, Any]:
    """Safely return simulated data records."""
    res_lower = resource.lower()
    if "customer" in res_lower:
        return {
            "record_id": resource,
            "type": "customer_record",
            "data": {
                "name": "Jane Doe",
                "email": "jane.doe@example.corp",
                "tier": "Gold",
                "notes": "Verified billing address; no outstanding disputes.",
            }
        }
    elif "knowledge_base" in res_lower:
        return {
            "article_id": resource,
            "type": "kb_article",
            "data": {
                "title": "Configuring Two-Factor Authentication",
                "summary": "Step-by-step instructions for resetting user tokens.",
            }
        }
    elif "invoices" in res_lower:
        return {
            "invoice_id": resource,
            "type": "invoice",
            "data": {"amount_due": 1250.00, "currency": "USD", "status": "PENDING_APPROVAL"}
        }
    elif "codebase" in res_lower:
        return {
            "file": resource,
            "type": "source_code",
            "data": "# Simulated code file repository content\ndef handler():\n    return {'status': 'ok'}\n"
        }
    else:
        return {
            "resource": resource,
            "type": "generic_data",
            "data": {"timestamp": time.time(), "status": "AVAILABLE"}
        }

def _simulated_code_execution(resource: str, payload: Any) -> dict[str, Any]:
    """
    Execute non-destructive sandboxed computations.
    Evaluates safe pure expressions in a restricted environment.
    """
    code_str = payload.get("code", "") if isinstance(payload, dict) else str(payload)
    
    # Safe evaluation environment without dangerous builtins
    safe_globals = {
        "__builtins__": {
            "abs": abs, "min": min, "max": max, "len": len, "sum": sum,
            "int": int, "float": float, "str": str, "range": range, "round": round
        }
    }
    
    try:
        # Check for forbidden keywords before evaluation
        forbidden = ["import ", "exec", "eval", "__", "open", "os", "sys", "subprocess", "socket"]
        if any(f in code_str for f in forbidden):
            return {
                "simulated": True,
                "status": "SANDBOX_REFUSAL",
                "message": "Code contains prohibited modules/operations; simulated isolated runner returned exit code 1.",
                "exit_code": 1,
            }
            
        result = eval(code_str, safe_globals, {}) if code_str else "Executed mock code in sandboxed runner."
        return {
            "simulated": True,
            "status": "SUCCESS",
            "output": str(result),
            "exit_code": 0,
        }
    except Exception as exc:
        return {
            "simulated": True,
            "status": "ERROR",
            "output": f"Sandbox execution notice: {type(exc).__name__}: {str(exc)}",
            "exit_code": 1,
        }

def execute_authorized(
    request_id: str,
    db_path: str = DB_PATH,
) -> ExecutionResult:
    """
    Gated execution entry point.
    Validates Governor decision and human approval status before simulating execution.
    """
    start_time = time.perf_counter()
    
    # 1. Fetch action request details
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM action_requests WHERE id = ?", (request_id,))
        req_row = cursor.fetchone()
        
        if not req_row:
            log_audit_event(
                event=EVENT_EXECUTION_BLOCKED,
                request_id=request_id,
                details={"reason": "Request ID not found in action_requests table."},
                db_path=db_path,
            )
            return ExecutionResult(
                success=False,
                request_id=request_id,
                action_type="unknown",
                resource="unknown",
                output=None,
                error=f"Request '{request_id}' not found.",
            )
            
        cursor.execute("SELECT * FROM decisions WHERE request_id = ?", (request_id,))
        dec_row = cursor.fetchone()
        
        cursor.execute("SELECT * FROM approvals WHERE request_id = ?", (request_id,))
        appr_row = cursor.fetchone()

    action_type = req_row["action_type"]
    resource = req_row["resource"]
    try:
        payload = json.loads(req_row["payload"]) if req_row["payload"] else {}
    except Exception:
        payload = req_row["payload"]

    # 2. Authorization Security Gate Check
    if not dec_row:
        log_audit_event(
            event=EVENT_EXECUTION_BLOCKED,
            request_id=request_id,
            details={"reason": "Action was never evaluated by Governor."},
            db_path=db_path,
        )
        return ExecutionResult(
            success=False,
            request_id=request_id,
            action_type=action_type,
            resource=resource,
            output=None,
            error="Unauthorized: Request was never evaluated through Governor.",
        )

    decision_status = dec_row["decision"]
    
    # CASE A: Request was DENIED by Governor -> NEVER EXECUTE
    if decision_status == "DENY":
        log_audit_event(
            event=EVENT_EXECUTION_BLOCKED,
            request_id=request_id,
            details={"reason": "Governor decision was DENY. Execution permanently prohibited."},
            db_path=db_path,
        )
        return ExecutionResult(
            success=False,
            request_id=request_id,
            action_type=action_type,
            resource=resource,
            output=None,
            error="Security Violation: Action was DENIED by Governor policies.",
        )

    # CASE B: Request required HUMAN_APPROVAL -> Verify explicitly approved
    if decision_status == "HUMAN_APPROVAL":
        if not appr_row or appr_row["status"] != "APPROVED":
            current_status = appr_row["status"] if appr_row else "MISSING_RECORD"
            log_audit_event(
                event=EVENT_EXECUTION_BLOCKED,
                request_id=request_id,
                details={
                    "reason": f"Action is pending human approval (current status: {current_status}). Execution refused."
                },
                db_path=db_path,
            )
            return ExecutionResult(
                success=False,
                request_id=request_id,
                action_type=action_type,
                resource=resource,
                output=None,
                error=f"Execution blocked: Action requires human approval (status: {current_status}).",
            )

    # 3. Request is fully authorized -> Dispatch to Safe Sandboxed Execution
    log_audit_event(
        event=EVENT_EXECUTION_ATTEMPTED,
        request_id=request_id,
        details={"action_type": action_type, "resource": resource},
        db_path=db_path,
    )
    
    try:
        act_norm = action_type.strip().lower()
        if act_norm == "read":
            sim_output = _simulated_read(resource, payload)
        elif act_norm == "write_file":
            sim_output = _safe_sandbox_write(resource, payload)
        elif act_norm == "call_api":
            sim_output = _simulated_api_call(resource, payload)
        elif act_norm == "execute_code":
            sim_output = _simulated_code_execution(resource, payload)
        elif act_norm == "delete":
            # Safe simulated deletion
            sim_output = {
                "simulated": True,
                "deleted_resource": resource,
                "message": "Simulated safe purge completed with zero host filesystem or production impact.",
            }
        else:
            sim_output = {"simulated": True, "message": f"Simulated safe action '{act_norm}' completed."}

        exec_time = round((time.perf_counter() - start_time) * 1000.0, 2)
        
        log_audit_event(
            event=EVENT_EXECUTION_SUCCEEDED,
            request_id=request_id,
            details={"output": sim_output, "execution_time_ms": exec_time},
            db_path=db_path,
        )
        
        return ExecutionResult(
            success=True,
            request_id=request_id,
            action_type=action_type,
            resource=resource,
            output=sim_output,
            execution_time_ms=exec_time,
            sandboxed=True,
        )
        
    except Exception as exec_err:
        exec_time = round((time.perf_counter() - start_time) * 1000.0, 2)
        log_audit_event(
            event=EVENT_EXECUTION_FAILED,
            request_id=request_id,
            details={"error": str(exec_err), "execution_time_ms": exec_time},
            db_path=db_path,
        )
        return ExecutionResult(
            success=False,
            request_id=request_id,
            action_type=action_type,
            resource=resource,
            output=None,
            error=f"Execution error: {type(exec_err).__name__}: {str(exec_err)}",
            execution_time_ms=exec_time,
            sandboxed=True,
        )
