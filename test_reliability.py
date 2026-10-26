"""Unit tests for Phase 4 Reliability and Fail-Closed Hardening."""

import os
import tempfile
import pytest
from db import init_db
from governor import ActionRequest, evaluate, execute_authorized

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_malformed_request_dict_handling(test_db):
    # Malformed dictionary with unexpected non-standard types
    malformed = {
        "agent_id": None,
        "action_type": 12345,  # Non-string
        "resource": None,
        "payload": object(),  # Non-serializable object
    }
    req_id, dec = evaluate(malformed, db_path=test_db)
    assert dec.decision == "DENY"
    assert dec.risk_score == 100.0
    assert any("fail-closed" in r.lower() for r in dec.reasons)

def test_unexpected_internal_engine_crash(test_db, monkeypatch):
    # Force an unexpected crash inside check_permission to test Governor fail-closed resilience
    def crashed_permission(*args, **kwargs):
        raise RuntimeError("Simulated fatal component crash in permission engine")
        
    monkeypatch.setattr("governor.check_permission", crashed_permission)
    
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_1",
    )
    req_id, dec = evaluate(req, db_path=test_db)
    assert dec.decision == "DENY"
    assert dec.risk_score == 100.0
    assert any("CRITICAL GOVERNOR FAIL-CLOSED EVENT" in r for r in dec.reasons)

def test_database_connection_failure_fails_closed():
    # Invalid directory path causing SQLite connection failure
    req = ActionRequest(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_1",
    )
    req_id, dec = evaluate(req, db_path="/nonexistent_directory/broken.db")
    assert dec.decision == "DENY"
    assert dec.risk_score == 100.0

def test_executor_gateway_fail_closed_on_unexpected_error(test_db, monkeypatch):
    def crashed_executor(*args, **kwargs):
        raise RuntimeError("Simulated fatal execution engine crash")
        
    monkeypatch.setattr("executor.execute_authorized", crashed_executor)
    
    exec_res = execute_authorized("req_any_test", db_path=test_db)
    assert exec_res.success is False
    assert "fail-closed" in exec_res.error.lower()
