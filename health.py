"""
Health Check and System Status Monitor for Agent Permission Governor.
Performs non-destructive diagnostics on Governor core, SQLite database,
sandbox file system, and audit logging subsystems.
"""

from __future__ import annotations
import os
import tempfile
import time
from typing import Any

from config import DB_PATH, ENVIRONMENT
from db import get_db, utc_now_iso
from executor import SANDBOX_DIR

STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADED = "DEGRADED"
STATUS_UNHEALTHY = "UNHEALTHY"

def check_system_health(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Execute comprehensive multi-subsystem diagnostic health checks.
    Guarantees:
        - Diagnostic checks are non-destructive and safe.
        - Failures are clearly classified.
        - Health failure never allows unsafe execution.
    """
    timestamp = utc_now_iso()
    subsystems: dict[str, dict[str, Any]] = {}
    overall_status = STATUS_HEALTHY
    
    # 1. Database Check
    db_start = time.perf_counter()
    try:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.execute("SELECT COUNT(*) AS c FROM policies")
            policy_count = cursor.fetchone()["c"]
        db_latency = round((time.perf_counter() - db_start) * 1000.0, 2)
        subsystems["database"] = {
            "status": STATUS_HEALTHY,
            "latency_ms": db_latency,
            "policies_loaded": policy_count,
            "path": db_path,
        }
    except Exception as exc:
        overall_status = STATUS_UNHEALTHY
        subsystems["database"] = {
            "status": STATUS_UNHEALTHY,
            "error": f"{type(exc).__name__}: {str(exc)}",
            "path": db_path,
        }

    # 2. Governor Engine Availability
    gov_start = time.perf_counter()
    try:
        from governor import evaluate, ActionRequest
        test_req = ActionRequest(
            agent_id="security_agent_01",
            action_type="read",
            resource="audit_logs",
            task_context="Health diagnostic self-test",
            instruction_source="system",
        )
        req_id, dec = evaluate(test_req, db_path=db_path)
        gov_latency = round((time.perf_counter() - gov_start) * 1000.0, 2)
        
        # In a healthy state, security_agent reading audit_logs is allowed
        if dec.decision == "ALLOW":
            subsystems["governor"] = {
                "status": STATUS_HEALTHY,
                "latency_ms": gov_latency,
                "diagnostic_request_id": req_id,
            }
        else:
            subsystems["governor"] = {
                "status": STATUS_DEGRADED,
                "latency_ms": gov_latency,
                "warning": f"Diagnostic decision was {dec.decision} instead of ALLOW.",
            }
            if overall_status == STATUS_HEALTHY:
                overall_status = STATUS_DEGRADED
    except Exception as exc:
        overall_status = STATUS_UNHEALTHY
        subsystems["governor"] = {
            "status": STATUS_UNHEALTHY,
            "error": f"Governor diagnostic fault: {type(exc).__name__}: {str(exc)}",
        }

    # 3. Safe Sandboxed Executor Check
    try:
        if not SANDBOX_DIR.exists():
            SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
            
        test_file = SANDBOX_DIR / ".health_probe.tmp"
        test_file.write_text("health_check_probe", encoding="utf-8")
        content = test_file.read_text(encoding="utf-8")
        if test_file.exists():
            test_file.unlink()
            
        if content == "health_check_probe":
            subsystems["executor"] = {
                "status": STATUS_HEALTHY,
                "sandbox_path": str(SANDBOX_DIR.resolve()),
                "write_verified": True,
            }
        else:
            subsystems["executor"] = {
                "status": STATUS_DEGRADED,
                "sandbox_path": str(SANDBOX_DIR.resolve()),
                "warning": "Sandbox probe content verification mismatch.",
            }
            if overall_status == STATUS_HEALTHY:
                overall_status = STATUS_DEGRADED
    except Exception as exc:
        overall_status = STATUS_UNHEALTHY
        subsystems["executor"] = {
            "status": STATUS_UNHEALTHY,
            "error": f"Sandbox filesystem access error: {type(exc).__name__}: {str(exc)}",
        }

    # 4. Audit Subsystem Check
    try:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM audit_log")
            audit_records = cursor.fetchone()["count"]
        subsystems["audit"] = {
            "status": STATUS_HEALTHY,
            "records_count": audit_records,
        }
    except Exception as exc:
        overall_status = STATUS_UNHEALTHY
        subsystems["audit"] = {
            "status": STATUS_UNHEALTHY,
            "error": f"Audit query error: {type(exc).__name__}: {str(exc)}",
        }

    return {
        "status": overall_status,
        "overall_status": overall_status,
        "environment": ENVIRONMENT,
        "timestamp": timestamp,
        "subsystems": subsystems,
    }
