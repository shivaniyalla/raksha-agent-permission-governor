"""Unit tests for approval.py."""

import os
import tempfile
import pytest
from approval import approve, create_approval, get_approval, list_pending_approvals, reject
from audit import get_audit_trail
from db import init_db, insert_action_request

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_create_and_list_pending_approval(test_db):
    req_id = insert_action_request(
        request_id="req_high_risk_99",
        agent_id="dev_agent_01",
        action_type="delete",
        resource="temporary_build_artifacts",
        resource_sensitivity="internal",
        task_context="Cleanup",
        instruction_source="trusted_user",
        payload={},
        db_path=test_db,
    )
    
    appr_id = create_approval(req_id, db_path=test_db)
    assert appr_id.startswith("appr_")
    
    pending = list_pending_approvals(db_path=test_db)
    assert len(pending) >= 1
    item = next(p for p in pending if p["request_id"] == req_id)
    assert item["status"] == "PENDING"
    assert item["agent_id"] == "dev_agent_01"

def test_approve_lifecycle(test_db):
    req_id = insert_action_request(
        request_id="req_appr_01",
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Vendor payment",
        instruction_source="trusted_user",
        payload={"amount": 450},
        db_path=test_db,
    )
    create_approval(req_id, db_path=test_db)
    
    result = approve(req_id, reviewer="lead_auditor_bob", db_path=test_db)
    assert result["success"] is True
    assert result["status"] == "APPROVED"
    assert result["reviewer"] == "lead_auditor_bob"
    
    # Verify in DB
    rec = get_approval(req_id, db_path=test_db)
    assert rec["status"] == "APPROVED"
    assert rec["reviewer"] == "lead_auditor_bob"
    
    # Audit log check
    trail = get_audit_trail(request_id=req_id, event="APPROVAL_GRANTED", db_path=test_db)
    assert len(trail) == 1
    assert trail[0]["details"]["reviewer"] == "lead_auditor_bob"

def test_reject_lifecycle(test_db):
    req_id = insert_action_request(
        request_id="req_rej_01",
        agent_id="dev_agent_01",
        action_type="delete",
        resource="production_records",
        resource_sensitivity="pii",
        task_context="Purge",
        instruction_source="trusted_user",
        payload={},
        db_path=test_db,
    )
    create_approval(req_id, db_path=test_db)
    
    result = reject(req_id, reviewer="security_lead_carol", db_path=test_db)
    assert result["success"] is True
    assert result["status"] == "REJECTED"
    
    # Double decision prevention
    second_attempt = approve(req_id, reviewer="alice", db_path=test_db)
    assert second_attempt["success"] is False
    assert "already been decided" in second_attempt["error"]
