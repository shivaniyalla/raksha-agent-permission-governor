"""Unit tests for executor.py."""

import os
import tempfile
import pytest
from approval import approve, create_approval, reject
from audit import get_audit_trail
from db import init_db, insert_action_request, insert_decision
from executor import execute_authorized, SANDBOX_DIR

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_executor_blocks_denied_request(test_db):
    req_id = insert_action_request(
        request_id="req_denied_01",
        agent_id="support_agent_01",
        action_type="execute_code",
        resource="sandbox",
        resource_sensitivity="internal",
        task_context="Run script",
        instruction_source="trusted_user",
        payload={"code": "1+1"},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_01",
        request_id=req_id,
        decision="DENY",
        risk_score=85.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Default Deny"],
        latency_ms=1.1,
        db_path=test_db,
    )
    
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is False
    assert "DENIED" in str(result.error)
    
    trail = get_audit_trail(request_id=req_id, event="EXECUTION_BLOCKED", db_path=test_db)
    assert len(trail) >= 1

def test_executor_blocks_pending_approval_request(test_db):
    req_id = insert_action_request(
        request_id="req_pending_01",
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Process invoice",
        instruction_source="trusted_user",
        payload={"amount": 500},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_02",
        request_id=req_id,
        decision="HUMAN_APPROVAL",
        risk_score=70.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Requires approval"],
        latency_ms=1.5,
        db_path=test_db,
    )
    create_approval(req_id, db_path=test_db)
    
    # Attempt execution before approval -> MUST BE BLOCKED
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is False
    assert "human approval" in str(result.error).lower()
    assert "pending" in str(result.error).lower()

def test_executor_blocks_rejected_request(test_db):
    req_id = insert_action_request(
        request_id="req_rej_exec_01",
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Process invoice",
        instruction_source="trusted_user",
        payload={"amount": 500},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_03",
        request_id=req_id,
        decision="HUMAN_APPROVAL",
        risk_score=70.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Requires approval"],
        latency_ms=1.5,
        db_path=test_db,
    )
    create_approval(req_id, db_path=test_db)
    reject(req_id, reviewer="supervisor_bob", db_path=test_db)
    
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is False
    assert "REJECTED" in str(result.error)

def test_executor_executes_after_approval(test_db):
    req_id = insert_action_request(
        request_id="req_approved_exec_01",
        agent_id="finance_agent_01",
        action_type="call_api",
        resource="payment_gateway",
        resource_sensitivity="confidential",
        task_context="Process invoice",
        instruction_source="trusted_user",
        payload={"amount": 750},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_04",
        request_id=req_id,
        decision="HUMAN_APPROVAL",
        risk_score=70.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Requires approval"],
        latency_ms=1.5,
        db_path=test_db,
    )
    create_approval(req_id, db_path=test_db)
    approve(req_id, reviewer="lead_bob", db_path=test_db)
    
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is True
    assert result.sandboxed is True
    assert result.output["simulated"] is True
    assert result.output["response"]["status"] == "SETTLED_IN_SIMULATION"
    
    trail = get_audit_trail(request_id=req_id, event="EXECUTION_SUCCEEDED", db_path=test_db)
    assert len(trail) == 1

def test_executor_safe_sandbox_write(test_db):
    req_id = insert_action_request(
        request_id="req_write_01",
        agent_id="dev_agent_01",
        action_type="write_file",
        resource="dev_sandbox_output.txt",
        resource_sensitivity="internal",
        task_context="Save test results",
        instruction_source="trusted_user",
        payload={"content": "Unit test build log data: SUCCESS"},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_05",
        request_id=req_id,
        decision="ALLOW",
        risk_score=35.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Allowed"],
        latency_ms=1.0,
        db_path=test_db,
    )
    
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is True
    assert "dev_sandbox_output.txt" in result.output["sandboxed_path"]
    assert os.path.exists(result.output["sandboxed_path"])

def test_executor_refuses_malicious_code_execution(test_db):
    req_id = insert_action_request(
        request_id="req_code_01",
        agent_id="dev_agent_01",
        action_type="execute_code",
        resource="dev_sandbox",
        resource_sensitivity="internal",
        task_context="Run script",
        instruction_source="trusted_user",
        payload={"code": "import os; os.system('echo pwned')"},
        db_path=test_db,
    )
    insert_decision(
        decision_id="dec_06",
        request_id=req_id,
        decision="ALLOW",
        risk_score=40.0,
        injection_score=0.0,
        provenance_trust=1.0,
        reasons=["Allowed"],
        latency_ms=1.0,
        db_path=test_db,
    )
    
    result = execute_authorized(req_id, db_path=test_db)
    assert result.success is True
    assert result.output["status"] == "SANDBOX_REFUSAL"
    assert result.output["exit_code"] == 1
