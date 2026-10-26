"""Unit tests for db.py."""

import os
import tempfile
import pytest
from db import (
    get_agent,
    get_all_agents,
    get_all_policies,
    get_policies_for_role,
    init_db,
    insert_action_request,
    insert_approval,
    insert_audit_event,
    insert_decision,
    reset_db,
    update_approval_status,
)

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_db_initialization_and_seeding(test_db):
    agents = get_all_agents(db_path=test_db)
    assert len(agents) >= 4
    agent_ids = {a["id"] for a in agents}
    assert "support_agent_01" in agent_ids
    assert "dev_agent_01" in agent_ids

    policies = get_all_policies(db_path=test_db)
    assert len(policies) >= 10
    
    support_policies = get_policies_for_role("support_agent", db_path=test_db)
    assert len(support_policies) >= 3

def test_get_agent(test_db):
    agent = get_agent("support_agent_01", db_path=test_db)
    assert agent is not None
    assert agent["role"] == "support_agent"

    missing = get_agent("nonexistent_agent", db_path=test_db)
    assert missing is None

def test_insert_and_audit(test_db):
    req_id = insert_action_request(
        request_id="req_test_01",
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_99",
        resource_sensitivity="pii",
        task_context="Customer inquiry",
        instruction_source="trusted_user",
        payload={"query": "test"},
        db_path=test_db,
    )
    assert req_id == "req_test_01"

    dec_id = insert_decision(
        decision_id="dec_test_01",
        request_id=req_id,
        decision="ALLOW",
        risk_score=25.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Valid policy"],
        latency_ms=1.2,
        db_path=test_db,
    )
    assert dec_id == "dec_test_01"

    audit_id = insert_audit_event(
        request_id=req_id,
        event="TEST_EVENT",
        details={"status": "ok"},
        db_path=test_db,
    )
    assert audit_id > 0

def test_approval_lifecycle(test_db):
    insert_action_request(
        request_id="req_high_risk_01",
        agent_id="dev_agent_01",
        action_type="delete",
        resource="temporary_build_artifacts",
        resource_sensitivity="internal",
        task_context="Cleanup disk",
        instruction_source="trusted_user",
        payload={},
        db_path=test_db,
    )
    insert_approval(
        approval_id="appr_01",
        request_id="req_high_risk_01",
        status="PENDING",
        db_path=test_db,
    )
    
    updated = update_approval_status(
        request_id="req_high_risk_01",
        status="APPROVED",
        reviewer="lead_dev_alice",
        db_path=test_db,
    )
    assert updated is True

def test_reset_db(test_db):
    reset_db(test_db)
    agents = get_all_agents(db_path=test_db)
    assert len(agents) >= 4
