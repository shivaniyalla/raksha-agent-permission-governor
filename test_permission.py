"""Unit tests for permission_engine.py."""

import os
import tempfile
import pytest
from db import init_db
from permission_engine import check_permission, match_resource

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_resource_matching():
    assert match_resource("*", "any_resource") is True
    assert match_resource("customer_record", "customer_record") is True
    assert match_resource("customer_record", "customer_record_123") is True
    assert match_resource("customer_record", "customer_record/456") is True
    assert match_resource("customer_record", "other_resource") is False

def test_authorized_support_agent(test_db):
    result = check_permission(
        agent_id="support_agent_01",
        action_type="read",
        resource="customer_record_999",
        db_path=test_db,
    )
    assert result.is_allowed is True
    assert result.role == "support_agent"
    assert result.matched_policy is not None
    assert "Least-privilege permission granted" in result.reasons[0]

def test_unauthorized_action_default_deny(test_db):
    # Support agent trying to execute code
    result = check_permission(
        agent_id="support_agent_01",
        action_type="execute_code",
        resource="dev_sandbox",
        db_path=test_db,
    )
    assert result.is_allowed is False
    assert result.role == "support_agent"
    assert "Default Deny" in result.reasons[0]

def test_unauthorized_resource_default_deny(test_db):
    # Support agent trying to read invoices (finance domain)
    result = check_permission(
        agent_id="support_agent_01",
        action_type="read",
        resource="invoices",
        db_path=test_db,
    )
    assert result.is_allowed is False
    assert "Default Deny" in result.reasons[0]

def test_unknown_agent_id(test_db):
    result = check_permission(
        agent_id="rogue_bot_999",
        action_type="read",
        resource="customer_record",
        db_path=test_db,
    )
    assert result.is_allowed is False
    assert "not registered" in result.reasons[0]
