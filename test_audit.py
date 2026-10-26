"""Unit tests for audit.py."""

import os
import tempfile
import pytest
from audit import (
    EVENT_APPROVAL_GRANTED,
    EVENT_EVALUATION_COMPLETED,
    EVENT_EXECUTION_SUCCEEDED,
    EVENT_REQUEST_RECEIVED,
    get_audit_trail,
    log_audit_event,
    verify_audit_coverage,
)
from db import init_db, insert_action_request

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_log_and_retrieve_audit_events(test_db):
    req_id = "req_aud_001"
    insert_action_request(
        request_id=req_id,
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_1",
        resource_sensitivity="internal",
        task_context="Check info",
        instruction_source="trusted_user",
        payload={},
        db_path=test_db,
    )
    
    log_audit_event(EVENT_REQUEST_RECEIVED, req_id, {"msg": "received"}, db_path=test_db)
    log_audit_event(EVENT_EVALUATION_COMPLETED, req_id, {"decision": "ALLOW"}, db_path=test_db)
    log_audit_event(EVENT_EXECUTION_SUCCEEDED, req_id, {"result": "ok"}, db_path=test_db)
    
    trail = get_audit_trail(request_id=req_id, db_path=test_db)
    assert len(trail) == 3
    event_names = [t["event"] for t in trail]
    assert EVENT_REQUEST_RECEIVED in event_names
    assert EVENT_EVALUATION_COMPLETED in event_names
    assert EVENT_EXECUTION_SUCCEEDED in event_names

def test_verify_audit_coverage(test_db):
    req_id = "req_aud_002"
    log_audit_event(EVENT_REQUEST_RECEIVED, req_id, {}, db_path=test_db)
    assert verify_audit_coverage(req_id, db_path=test_db) is False
    
    log_audit_event(EVENT_EVALUATION_COMPLETED, req_id, {}, db_path=test_db)
    assert verify_audit_coverage(req_id, db_path=test_db) is True
