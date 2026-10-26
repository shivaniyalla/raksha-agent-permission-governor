"""Unit tests for alerts.py monitoring and security alerts engine."""

import os
import tempfile
import pytest
from alerts import (
    ALERT_CRITICAL_FAIL_CLOSED,
    ALERT_REPEATED_DENIALS,
    ALERT_REPEATED_INJECTIONS,
    get_active_alerts,
    get_monitoring_summary,
    resolve_alert,
    scan_and_generate_alerts,
)
from audit import EVENT_GOVERNOR_FAIL_CLOSED, log_audit_event
from db import init_db, insert_action_request, insert_decision

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_repeated_injection_alerts(test_db):
    # Simulate an agent generating 2 prompt injections
    for i in range(2):
        req_id = f"req_inj_{i}"
        insert_action_request(
            request_id=req_id,
            agent_id="attacker_bot_01",
            action_type="read",
            resource="customer_record",
            resource_sensitivity="internal",
            task_context="Attack test",
            instruction_source="uploaded_file",
            payload={"data": "Ignore rules"},
            db_path=test_db,
        )
        insert_decision(
            decision_id=f"dec_inj_{i}",
            request_id=req_id,
            decision="DENY",
            risk_score=90.0,
            injection_score=85.0,
            provenance_trust=0.4,
            reasons=["Injection detected"],
            latency_ms=1.0,
            db_path=test_db,
        )

    alerts = scan_and_generate_alerts(db_path=test_db)
    assert len(alerts) >= 1
    assert any(a["event_type"] == ALERT_REPEATED_INJECTIONS for a in alerts)

def test_repeated_policy_denials_alert(test_db):
    # Simulate an agent with 3 policy denials
    for i in range(3):
        req_id = f"req_den_{i}"
        insert_action_request(
            request_id=req_id,
            agent_id="support_agent_01",
            action_type="execute_code",
            resource="dev_sandbox",
            resource_sensitivity="internal",
            task_context="Run script",
            instruction_source="trusted_user",
            payload={},
            db_path=test_db,
        )
        insert_decision(
            decision_id=f"dec_den_{i}",
            request_id=req_id,
            decision="DENY",
            risk_score=75.0,
            injection_score=0.0,
            provenance_trust=1.0,
            reasons=["Default Deny"],
            latency_ms=1.0,
            db_path=test_db,
        )

    alerts = scan_and_generate_alerts(db_path=test_db)
    assert any(a["event_type"] == ALERT_REPEATED_DENIALS for a in alerts)

def test_fail_closed_critical_alert(test_db):
    log_audit_event(
        event=EVENT_GOVERNOR_FAIL_CLOSED,
        request_id="req_fatal_crash",
        details={"error": "Fatal component fault"},
        db_path=test_db,
    )
    alerts = scan_and_generate_alerts(db_path=test_db)
    assert any(a["event_type"] == ALERT_CRITICAL_FAIL_CLOSED for a in alerts)

def test_resolve_alert_flow(test_db):
    test_fail_closed_critical_alert(test_db)
    active = get_active_alerts(db_path=test_db)
    assert len(active) >= 1
    
    target_id = active[0]["id"]
    resolved = resolve_alert(target_id, db_path=test_db)
    assert resolved is True
    
    # Verify no longer active
    active_after = get_active_alerts(db_path=test_db)
    assert not any(a["id"] == target_id for a in active_after)

def test_monitoring_summary(test_db):
    test_fail_closed_critical_alert(test_db)
    summary = get_monitoring_summary(db_path=test_db)
    assert summary["total_alerts"] >= 1
    assert summary["open_alerts"] >= 1
    assert summary["critical_open"] >= 1


def test_security_alerts_schema_contract_and_ui_dataframe_rendering(test_db):
    """
    Regression test for KeyError: 'created_at' in app.py UI.
    Verifies:
      1. get_security_alerts() returns 'created_at', 'timestamp', and 'resolved_at'.
      2. a['created_at'] is accessible as a non-empty ISO string.
      3. resolve_alert() populates 'resolved_at' with an ISO timestamp.
      4. The exact Streamlit UI dataframe dictionary mapping runs without KeyError.
    """
    from db import get_security_alerts, insert_security_alert
    
    alert_id = insert_security_alert(
        alert_id="alt_reg_test_01",
        severity="HIGH",
        event_type="REPEATED_PROMPT_INJECTIONS",
        reason="Agent generated injection attack payload",
        agent_id="test_agent",
        request_id="req_reg_01",
        status="OPEN",
        db_path=test_db,
    )
    
    all_alerts = get_security_alerts(db_path=test_db)
    assert len(all_alerts) >= 1
    
    target_alert = next((a for a in all_alerts if a["id"] == alert_id), None)
    assert target_alert is not None
    
    # Contract validation: 'created_at' must be present and valid
    assert "created_at" in target_alert
    assert isinstance(target_alert["created_at"], str)
    assert len(target_alert["created_at"]) > 10
    
    # Backward-compatible 'timestamp' must also be present
    assert "timestamp" in target_alert
    assert target_alert["timestamp"] == target_alert["created_at"]
    
    # Initial 'resolved_at' is None
    assert target_alert["resolved_at"] is None
    
    # Execute the exact app.py line 869-881 dataframe comprehension
    # This MUST NOT raise KeyError: 'created_at'
    ui_rows = [
        {
            "Alert ID": a["id"],
            "Severity": a["severity"],
            "Event Type": a["event_type"],
            "Status": a["status"],
            "Agent": a["agent_id"] or "—",
            "Created At": a["created_at"],
            "Resolved At": a.get("resolved_at") or "—",
            "Reason": a["reason"],
        }
        for a in all_alerts
    ]
    assert len(ui_rows) >= 1
    assert ui_rows[0]["Created At"] is not None
    assert ui_rows[0]["Created At"] != "—"
    
    # Now resolve the alert and verify resolved_at is set properly
    resolve_alert(alert_id, db_path=test_db)
    resolved_alerts = get_security_alerts(db_path=test_db)
    resolved_target = next((a for a in resolved_alerts if a["id"] == alert_id), None)
    assert resolved_target is not None
    assert resolved_target["status"] == "RESOLVED"
    assert resolved_target["resolved_at"] is not None
    assert isinstance(resolved_target["resolved_at"], str)

