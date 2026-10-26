"""
Monitoring and Security Alerts Engine for Agent Permission Governor.
Analyzes real SQLite audit log records to detect adversarial patterns, repeated policy
violations, injection campaigns, and anomalous execution failures.
Generates structured security alerts without hardcoding or fabricating data.
"""

from __future__ import annotations
import json
import uuid
from typing import Any, Optional

from config import (
    ALERT_DENY_REPEAT_THRESHOLD,
    ALERT_INJECTION_REPEAT_THRESHOLD,
    DB_PATH,
)
from db import (
    get_db,
    get_security_alerts,
    insert_security_alert,
    resolve_security_alert,
    utc_now_iso,
)

# Severity classifications
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Alert Event Types
ALERT_REPEATED_INJECTIONS = "REPEATED_PROMPT_INJECTIONS"
ALERT_REPEATED_DENIALS = "REPEATED_POLICY_DENIALS"
ALERT_EXECUTION_FAILURE_SPIKE = "EXECUTION_FAILURE_SPIKE"
ALERT_CRITICAL_FAIL_CLOSED = "GOVERNOR_FAIL_CLOSED_DETECTED"
ALERT_HIGH_RISK_SURGE = "HIGH_RISK_ACTION_SURGE"

def scan_and_generate_alerts(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """
    Scan real SQLite decisions and audit log events to generate actionable security alerts.
    Does not duplicate already open alerts for the same underlying pattern.
    """
    new_alerts: list[dict[str, Any]] = []
    
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Check for Critical Fail-Closed Events in audit_log
        cursor.execute(
            """
            SELECT request_id, details_json, created_at
            FROM audit_log
            WHERE event = 'GOVERNOR_FAIL_CLOSED_ERROR'
            ORDER BY id DESC LIMIT 10
            """
        )
        fail_closed_rows = cursor.fetchall()
        for r in fail_closed_rows:
            req_id = r["request_id"]
            # Check if alert already exists for this request
            cursor.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE request_id = ? AND event_type = ?",
                (req_id, ALERT_CRITICAL_FAIL_CLOSED)
            )
            if cursor.fetchone()["count"] == 0:
                alert_id = f"alt_fc_{uuid.uuid4().hex[:8]}"
                insert_security_alert(
                    alert_id=alert_id,
                    severity=SEVERITY_CRITICAL,
                    event_type=ALERT_CRITICAL_FAIL_CLOSED,
                    reason="Governor encountered internal fault and executed fail-closed block.",
                    request_id=req_id,
                    status="OPEN",
                    db_path=db_path,
                )
                new_alerts.append({"id": alert_id, "event_type": ALERT_CRITICAL_FAIL_CLOSED, "severity": SEVERITY_CRITICAL})

        # 2. Check for Repeated Prompt Injections (by agent_id or overall)
        cursor.execute(
            """
            SELECT r.agent_id, COUNT(*) AS count
            FROM decisions d
            JOIN action_requests r ON d.request_id = r.id
            WHERE d.injection_score >= 60.0
            GROUP BY r.agent_id
            HAVING count >= ?
            """,
            (ALERT_INJECTION_REPEAT_THRESHOLD,)
        )
        injection_violators = cursor.fetchall()
        for v in injection_violators:
            ag_id = v["agent_id"]
            cursor.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE agent_id = ? AND event_type = ? AND status = 'OPEN'",
                (ag_id, ALERT_REPEATED_INJECTIONS)
            )
            if cursor.fetchone()["count"] == 0:
                alert_id = f"alt_inj_{uuid.uuid4().hex[:8]}"
                insert_security_alert(
                    alert_id=alert_id,
                    severity=SEVERITY_HIGH,
                    event_type=ALERT_REPEATED_INJECTIONS,
                    reason=f"Agent '{ag_id}' generated {v['count']} prompt injection attempts exceeding safety threshold.",
                    agent_id=ag_id,
                    status="OPEN",
                    db_path=db_path,
                )
                new_alerts.append({"id": alert_id, "event_type": ALERT_REPEATED_INJECTIONS, "severity": SEVERITY_HIGH})

        # 3. Check for Repeated DENY decisions from the same agent
        cursor.execute(
            """
            SELECT r.agent_id, COUNT(*) AS count
            FROM decisions d
            JOIN action_requests r ON d.request_id = r.id
            WHERE d.decision = 'DENY'
            GROUP BY r.agent_id
            HAVING count >= ?
            """,
            (ALERT_DENY_REPEAT_THRESHOLD,)
        )
        deny_violators = cursor.fetchall()
        for d in deny_violators:
            ag_id = d["agent_id"]
            cursor.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE agent_id = ? AND event_type = ? AND status = 'OPEN'",
                (ag_id, ALERT_REPEATED_DENIALS)
            )
            if cursor.fetchone()["count"] == 0:
                alert_id = f"alt_den_{uuid.uuid4().hex[:8]}"
                insert_security_alert(
                    alert_id=alert_id,
                    severity=SEVERITY_MEDIUM,
                    event_type=ALERT_REPEATED_DENIALS,
                    reason=f"Agent '{ag_id}' accumulated {d['count']} unauthorized policy denials.",
                    agent_id=ag_id,
                    status="OPEN",
                    db_path=db_path,
                )
                new_alerts.append({"id": alert_id, "event_type": ALERT_REPEATED_DENIALS, "severity": SEVERITY_MEDIUM})

        # 4. Check for Execution Failures
        cursor.execute(
            """
            SELECT COUNT(*) AS count FROM audit_log
            WHERE event = 'EXECUTION_FAILED'
            """
        )
        fail_exec_count = cursor.fetchone()["count"]
        if fail_exec_count >= 2:
            cursor.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE event_type = ? AND status = 'OPEN'",
                (ALERT_EXECUTION_FAILURE_SPIKE,)
            )
            if cursor.fetchone()["count"] == 0:
                alert_id = f"alt_ef_{uuid.uuid4().hex[:8]}"
                insert_security_alert(
                    alert_id=alert_id,
                    severity=SEVERITY_HIGH,
                    event_type=ALERT_EXECUTION_FAILURE_SPIKE,
                    reason=f"Execution layer logged {fail_exec_count} execution errors in the sandbox.",
                    status="OPEN",
                    db_path=db_path,
                )
                new_alerts.append({"id": alert_id, "event_type": ALERT_EXECUTION_FAILURE_SPIKE, "severity": SEVERITY_HIGH})

    return new_alerts

def get_active_alerts(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all open alerts requiring administrative attention."""
    # First run a live scan to ensure up-to-date alerts
    scan_and_generate_alerts(db_path=db_path)
    return get_security_alerts(status="OPEN", db_path=db_path)

def resolve_alert(alert_id: str, db_path: str = DB_PATH) -> bool:
    """Mark an active alert as RESOLVED."""
    return resolve_security_alert(alert_id=alert_id, db_path=db_path)

def get_monitoring_summary(db_path: str = DB_PATH) -> dict[str, Any]:
    """Provide a real-time count summary of security alerts."""
    scan_and_generate_alerts(db_path=db_path)
    all_alerts = get_security_alerts(limit=100, db_path=db_path)
    open_alerts = [a for a in all_alerts if a["status"] == "OPEN"]
    
    critical_count = sum(1 for a in open_alerts if a["severity"] == SEVERITY_CRITICAL)
    high_count = sum(1 for a in open_alerts if a["severity"] == SEVERITY_HIGH)
    medium_count = sum(1 for a in open_alerts if a["severity"] == SEVERITY_MEDIUM)
    
    return {
        "total_alerts": len(all_alerts),
        "open_alerts": len(open_alerts),
        "resolved_alerts": len(all_alerts) - len(open_alerts),
        "critical_open": critical_count,
        "high_open": high_count,
        "medium_open": medium_count,
        "active_alerts_list": open_alerts[:10],
    }
