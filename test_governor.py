"""Unit tests for governor.py."""

import os
import tempfile
import pytest
from db import init_db, get_db
from governor import ActionRequest, evaluate

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_governor_allowed_read(test_db):
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_456",
        resource_sensitivity="internal",
        task_context="Customer requested address verification",
        instruction_source="trusted_user",
        payload={"customer_id": 456},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert req_id.startswith("req_")
    assert decision.decision == "ALLOW"
    assert decision.risk_score <= 40.0
    
    # Verify persistence
    with get_db(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM decisions WHERE request_id = ?", (req_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["decision"] == "ALLOW"

def test_governor_unauthorized_deny(test_db):
    req = {
        "agent_id": "support_agent_01",
        "action_type": "execute_code",
        "resource": "dev_sandbox",
        "resource_sensitivity": "internal",
        "task_context": "Run cleanup script",
        "instruction_source": "trusted_user",
    }
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "DENY"
    assert any("Default Deny" in r for r in decision.reasons)

def test_governor_human_approval_routing(test_db):
    # Finance agent calling payment gateway (requires approval per policy)
    req = ActionRequest(
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Process monthly vendor invoice payment",
        instruction_source="trusted_user",
        payload={"vendor_id": "V-99", "amount": 1250.00},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "HUMAN_APPROVAL"
    
    # Verify approval record was created in PENDING status
    with get_db(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM approvals WHERE request_id = ?", (req_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "PENDING"

def test_governor_fail_closed_on_invalid_db():
    # Pass an invalid database path to trigger fail-closed behavior
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record",
    )
    req_id, decision = evaluate(req, db_path="/nonexistent_directory/invalid.db")
    assert decision.decision == "DENY"
    assert any("FAIL-CLOSED" in r for r in decision.reasons)

def test_governor_payload_size_limit(test_db):
    large_payload = {"data": "X" * (70 * 1024)}  # 70 KB > 64 KB limit
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_123",
        resource_sensitivity="internal",
        task_context="Customer inquiry",
        instruction_source="trusted_user",
        payload=large_payload,
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "DENY"
    assert any("64 KB" in r for r in decision.reasons)

def test_governor_execute_authorized_allow(test_db):
    from governor import execute_authorized
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_99",
        resource_sensitivity="internal",
        task_context="Customer inquiry",
        instruction_source="trusted_user",
        payload={"customer_id": 99},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "ALLOW"
    
    # Execute through Governor gateway
    exec_res = execute_authorized(req_id, db_path=test_db)
    assert exec_res.success is True
    assert exec_res.sandboxed is True
    assert "customer_record" in exec_res.output["type"]

def test_governor_execute_blocks_deny(test_db):
    from governor import execute_authorized
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="execute_code",
        resource="dev_sandbox",
        task_context="Triage ticket",
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "DENY"
    
    # Governor execution gateway MUST block DENY
    exec_res = execute_authorized(req_id, db_path=test_db)
    assert exec_res.success is False
    assert "DENIED" in str(exec_res.error)

def test_governor_execute_blocks_pending(test_db):
    from governor import execute_authorized
    req = ActionRequest(
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Pay vendor",
        payload={"amount": 900},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "HUMAN_APPROVAL"
    
    # Governor execution gateway MUST block PENDING
    exec_res = execute_authorized(req_id, db_path=test_db)
    assert exec_res.success is False
    assert "human approval" in str(exec_res.error).lower()
    assert "pending" in str(exec_res.error).lower()

def test_governor_execute_blocks_rejected(test_db):
    from approval import reject
    from governor import execute_authorized
    req = ActionRequest(
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Pay vendor",
        payload={"amount": 900},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "HUMAN_APPROVAL"
    
    # Reject in approval queue
    reject(req_id, reviewer="lead_accountant", db_path=test_db)
    
    # Governor execution gateway MUST block REJECTED
    exec_res = execute_authorized(req_id, db_path=test_db)
    assert exec_res.success is False
    assert "REJECTED" in str(exec_res.error)

def test_governor_execute_authorized_approved(test_db):
    from approval import approve
    from governor import execute_authorized
    req = ActionRequest(
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Pay vendor",
        payload={"amount": 900},
    )
    req_id, decision = evaluate(req, db_path=test_db)
    assert decision.decision == "HUMAN_APPROVAL"
    
    # Explicitly approve
    approve(req_id, reviewer="finance_vp", db_path=test_db)
    
    # Governor execution gateway MUST execute successfully
    exec_res = execute_authorized(req_id, db_path=test_db)
    assert exec_res.success is True
    assert exec_res.output["simulated"] is True
    assert exec_res.output["response"]["status"] == "SETTLED_IN_SIMULATION"

def test_direct_executor_protection(test_db):
    from executor import execute_authorized as direct_exec
    # Unregistered request directly invoked on executor must be refused
    exec_res = direct_exec("fake_unregistered_id", db_path=test_db)
    assert exec_res.success is False
    assert "not found" in str(exec_res.error).lower()
