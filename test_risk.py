"""Unit tests for risk_engine.py."""

from risk_engine import compute_risk, evaluate_task_alignment, evaluate_operational_risk

def test_low_risk_read_action():
    assessment = compute_risk(
        action_type="read",
        resource="customer_record_123",
        resource_sensitivity="internal",
        task_context="Lookup customer record for address inquiry",
        instruction_source="trusted_user",
    )
    # Read (15*0.35 = 5.25) + internal (20*0.25 = 5.0) + context (0) + op (0) = ~10.25
    assert assessment.risk_score <= 35.0
    assert assessment.risk_score >= 5.0

def test_context_mismatch_penalty():
    # Passive support task, but action is delete
    penalty, reason = evaluate_task_alignment(
        task_context="Customer asked for billing summary",
        action_type="delete",
        resource="customer_record",
    )
    assert penalty >= 35.0
    assert "Critical Context Mismatch" in reason

def test_high_risk_delete_irreversible():
    assessment = compute_risk(
        action_type="delete",
        resource="production_records",
        resource_sensitivity="pii",
        task_context="Lookup customer record",
        instruction_source="trusted_user",
    )
    # Delete (85) + PII (55) + Op (35) + Mismatch (40) -> High risk
    assert assessment.risk_score >= 65.0

def test_operational_risk_external_api():
    op_score, op_reason = evaluate_operational_risk(
        action_type="call_api",
        resource="payment_gateway",
        payload={"amount": 500},
    )
    assert op_score >= 30.0
    assert "blast radius" in op_reason.lower()

def test_untrusted_provenance_risk_escalation():
    trusted = compute_risk(
        action_type="write_file",
        resource="ticket_notes",
        resource_sensitivity="internal",
        task_context="Update ticket notes with user comment",
        instruction_source="trusted_user",
    )
    untrusted = compute_risk(
        action_type="write_file",
        resource="ticket_notes",
        resource_sensitivity="internal",
        task_context="Update ticket notes with user comment",
        instruction_source="web_content",
    )
    assert untrusted.risk_score > trusted.risk_score
