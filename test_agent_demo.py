"""Unit tests for agent_demo.py."""

import os
import tempfile
import pytest
from agent_demo import propose_action, offline_fallback_intent_parser
from db import init_db
from governor import ActionRequest, evaluate

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_offline_fallback_read_customer():
    goal = "Please read customer 101 record to check billing address"
    proposal = offline_fallback_intent_parser(goal, agent_role="support_agent")
    assert proposal["agent_id"] == "support_agent_01"
    assert proposal["action_type"] == "read"
    assert "customer" in proposal["resource"]
    assert proposal["instruction_source"] == "trusted_user"

def test_offline_fallback_delete_intent():
    goal = "Purge and delete temporary files"
    proposal = offline_fallback_intent_parser(goal, agent_role="dev_agent")
    assert proposal["action_type"] == "delete"

def test_offline_fallback_payment_intent():
    goal = "Pay vendor invoice via payment gateway"
    proposal = offline_fallback_intent_parser(goal, agent_role="finance_agent")
    assert proposal["action_type"] in ("call_api", "write_file", "read")
    assert "payment" in proposal["resource"]

def test_proposed_action_evaluates_through_governor(test_db):
    proposal = propose_action("Read customer details for support inquiry", agent_role="support_agent", use_claude=False)
    req = ActionRequest(**proposal)
    req_id, decision = evaluate(req, db_path=test_db)
    assert req_id.startswith("req_")
    assert decision.decision in ("ALLOW", "DENY", "HUMAN_APPROVAL")
