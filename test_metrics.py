"""Unit tests for metrics.py."""

import os
import tempfile
import pytest
from approval import create_approval, approve, reject
from audit import EVENT_EVALUATION_COMPLETED, EVENT_REQUEST_RECEIVED, log_audit_event
from db import init_db, insert_action_request, insert_decision
from metrics import (
    calculate_evaluation_accuracy,
    compute_percentile,
    get_approval_queue_metrics,
    get_audit_coverage_metrics,
    get_authorization_metrics,
    get_dashboard_summary,
    get_injection_metrics,
    get_latency_metrics,
    get_reliability_metrics,
)

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_compute_percentile():
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    p50 = compute_percentile(values, 50.0)
    p95 = compute_percentile(values, 95.0)
    assert 5.0 <= p50 <= 6.0
    assert 9.0 <= p95 <= 10.0

def test_metrics_empty_db(test_db):
    lat = get_latency_metrics(db_path=test_db)
    assert lat["p50_ms"] == 0.0
    assert lat["count"] == 0
    
    auth = get_authorization_metrics(db_path=test_db)
    assert auth["total_decisions"] == 0

def test_metrics_with_real_data(test_db):
    # Populate test data in DB
    latencies = [1.2, 1.8, 2.4, 3.0, 12.5]
    for i, lat in enumerate(latencies):
        req_id = f"req_m_{i}"
        decision = "ALLOW" if i < 3 else ("DENY" if i == 3 else "HUMAN_APPROVAL")
        inj_score = 90.0 if decision == "DENY" else 0.0
        
        insert_action_request(
            request_id=req_id,
            agent_id="support_agent_01",
            action_type="read",
            resource=f"customer_{i}",
            resource_sensitivity="internal",
            task_context="Customer inquiry",
            instruction_source="trusted_user",
            payload={},
            db_path=test_db,
        )
        insert_decision(
            decision_id=f"dec_m_{i}",
            request_id=req_id,
            decision=decision,
            risk_score=20.0 + (i * 15),
            injection_score=inj_score,
            provenance_trust=1.0,
            reasons=["Test reason"],
            latency_ms=lat,
            db_path=test_db,
        )
        log_audit_event(EVENT_REQUEST_RECEIVED, req_id, {}, db_path=test_db)
        log_audit_event(EVENT_EVALUATION_COMPLETED, req_id, {}, db_path=test_db)
        
        if decision == "HUMAN_APPROVAL":
            create_approval(req_id, db_path=test_db)
            approve(req_id, reviewer="lead_reviewer", db_path=test_db)

    # 1. Latency metrics
    lat_res = get_latency_metrics(db_path=test_db)
    assert lat_res["count"] == 5
    assert lat_res["p50_ms"] == 2.4
    assert lat_res["p95_ms"] > 2.4

    # 2. Authorization breakdown
    auth_res = get_authorization_metrics(db_path=test_db)
    assert auth_res["total_decisions"] == 5
    assert auth_res["allowed_count"] == 3
    assert auth_res["denied_count"] == 1
    assert auth_res["human_approval_count"] == 1
    assert auth_res["blocked_actions_percentage"] == 20.0

    # 3. Injection metrics
    inj_res = get_injection_metrics(db_path=test_db)
    assert inj_res["total_scanned"] == 5
    assert inj_res["injections_detected"] == 1
    assert inj_res["detection_rate_percentage"] == 20.0

    # 4. Approvals metrics
    appr_res = get_approval_queue_metrics(db_path=test_db)
    assert appr_res["total_enqueued"] == 1
    assert appr_res["approved_count"] == 1
    assert appr_res["resolution_rate_percentage"] == 100.0

    # 5. Audit coverage
    audit_res = get_audit_coverage_metrics(db_path=test_db)
    assert audit_res["audit_coverage_percentage"] == 100.0

    # 6. Reliability
    rel_res = get_reliability_metrics(db_path=test_db)
    assert rel_res["reliability_percentage"] == 100.0

    # 7. Dashboard summary
    summary = get_dashboard_summary(db_path=test_db)
    assert "latency" in summary
    assert "authorization" in summary
    assert "injection" in summary

def test_calculate_evaluation_accuracy():
    eval_data = [
        {"expected": "ALLOW", "actual": "ALLOW"},
        {"expected": "ALLOW", "actual": "ALLOW"},
        {"expected": "DENY", "actual": "DENY"},
        {"expected": "DENY", "actual": "DENY"},
        {"expected": "ALLOW", "actual": "DENY"},  # False positive
    ]
    res = calculate_evaluation_accuracy(eval_data)
    assert res["total_evaluated"] == 5
    assert res["correct"] == 4
    assert res["accuracy_percentage"] == 80.0
    assert res["false_positives"] == 1
    assert res["false_positive_rate"] == 20.0
