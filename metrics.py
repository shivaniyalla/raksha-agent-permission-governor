"""
Metrics Engine for Agent Permission Governor.
Computes real, non-fabricated metrics directly from SQLite audit logs, decisions, and approval records.
Provides performance, security, and governance KPI calculations.
"""

from __future__ import annotations
import math
from typing import Any, Optional

from config import DB_PATH
from db import get_db

def compute_percentile(values: list[float], percentile: float) -> float:
    """Calculate the p-th percentile from an ordered list of numeric values."""
    if not values:
        return 0.0
    k = (len(values) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(values[int(k)])
    d0 = values[int(f)] * (c - k)
    d1 = values[int(c)] * (k - f)
    return round(float(d0 + d1), 3)

def get_latency_metrics(db_path: str = DB_PATH) -> dict[str, float]:
    """
    Compute real p50 and p95 decision latency from decisions table.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT latency_ms FROM decisions ORDER BY latency_ms ASC")
        rows = cursor.fetchall()
        
    latencies = [float(r["latency_ms"]) for r in rows if r["latency_ms"] is not None]
    
    if not latencies:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "count": 0}
        
    return {
        "p50_ms": compute_percentile(latencies, 50.0),
        "p95_ms": compute_percentile(latencies, 95.0),
        "avg_ms": round(sum(latencies) / len(latencies), 3),
        "min_ms": round(min(latencies), 3),
        "max_ms": round(max(latencies), 3),
        "count": len(latencies),
    }

def get_authorization_metrics(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Compute breakdown of decisions: ALLOW, DENY, and HUMAN_APPROVAL.
    Calculates blocked unauthorized actions count and percentage.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT decision, COUNT(*) AS count FROM decisions GROUP BY decision")
        counts = {r["decision"]: r["count"] for r in cursor.fetchall()}
        
    total = sum(counts.values())
    allowed = counts.get("ALLOW", 0)
    denied = counts.get("DENY", 0)
    human_approval = counts.get("HUMAN_APPROVAL", 0)
    
    blocked_pct = round((denied / total * 100.0), 2) if total > 0 else 0.0
    approval_rate = round((human_approval / total * 100.0), 2) if total > 0 else 0.0
    
    return {
        "total_decisions": total,
        "allowed_count": allowed,
        "denied_count": denied,
        "human_approval_count": human_approval,
        "blocked_actions_count": denied,
        "blocked_actions_percentage": blocked_pct,
        "human_approval_rate_percentage": approval_rate,
    }

def get_injection_metrics(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Compute prompt injection detection metrics from real decisions data.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT injection_score FROM decisions")
        scores = [float(r["injection_score"]) for r in cursor.fetchall() if r["injection_score"] is not None]
        
    total = len(scores)
    detected = sum(1 for s in scores if s >= 60.0)
    suspicious = sum(1 for s in scores if 35.0 <= s < 60.0)
    
    detection_rate = round((detected / total * 100.0), 2) if total > 0 else 0.0
    avg_score = round(sum(scores) / total, 2) if total > 0 else 0.0
    
    return {
        "total_scanned": total,
        "injections_detected": detected,
        "suspicious_injections": suspicious,
        "detection_rate_percentage": detection_rate,
        "average_injection_score": avg_score,
    }

def get_approval_queue_metrics(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Compute human approval queue performance and resolution rates.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, COUNT(*) AS count FROM approvals GROUP BY status")
        counts = {r["status"]: r["count"] for r in cursor.fetchall()}
        
    total_enqueued = sum(counts.values())
    pending = counts.get("PENDING", 0)
    approved = counts.get("APPROVED", 0)
    rejected = counts.get("REJECTED", 0)
    
    resolved = approved + rejected
    resolution_rate = round((resolved / total_enqueued * 100.0), 2) if total_enqueued > 0 else 0.0
    approval_pct = round((approved / resolved * 100.0), 2) if resolved > 0 else 0.0
    
    return {
        "total_enqueued": total_enqueued,
        "pending_count": pending,
        "approved_count": approved,
        "rejected_count": rejected,
        "resolution_rate_percentage": resolution_rate,
        "human_grant_rate_percentage": approval_pct,
    }

def get_audit_coverage_metrics(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Verify complete audit coverage across all action requests.
    A fully covered request contains both request interception and decision logs.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT id) AS count FROM action_requests")
        req_count = cursor.fetchone()["count"]
        
        cursor.execute(
            """
            SELECT COUNT(DISTINCT request_id) AS count
            FROM audit_log
            WHERE event IN ('EVALUATION_COMPLETED', 'GOVERNOR_FAIL_CLOSED_ERROR')
            """
        )
        decided_audited = cursor.fetchone()["count"]
        
    coverage_pct = round((decided_audited / req_count * 100.0), 2) if req_count > 0 else 100.0
    
    return {
        "total_requests": req_count,
        "audited_requests": decided_audited,
        "audit_coverage_percentage": min(coverage_pct, 100.0),
    }

def get_reliability_metrics(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Measure system reliability and error rates.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM audit_log WHERE event = 'GOVERNOR_FAIL_CLOSED_ERROR'")
        error_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) AS count FROM decisions")
        total_decisions = cursor.fetchone()["count"]
        
    total_ops = total_decisions + error_count
    if total_ops == 0:
        return {"total_evaluations": 0, "fail_closed_errors": 0, "reliability_percentage": 100.0}
        
    reliability = round(((total_decisions) / total_ops * 100.0), 2)
    return {
        "total_evaluations": total_ops,
        "successful_evaluations": total_decisions,
        "fail_closed_errors": error_count,
        "reliability_percentage": reliability,
    }

def calculate_evaluation_accuracy(results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calculate accuracy, false positive rate, and detection rates against labelled test sets.
    Expected labels: ALLOW, DENY, HUMAN_APPROVAL.
    """
    if not results:
        return {"accuracy_pct": 0.0, "total": 0, "correct": 0, "false_positives": 0}
        
    total = len(results)
    correct = 0
    false_positives = 0  # Benign action (expected ALLOW) that was DENIED
    false_negatives = 0  # Malicious/injection (expected DENY) that was ALLOWED
    
    for item in results:
        expected = item.get("expected")
        actual = item.get("actual")
        
        if expected == actual:
            correct += 1
        elif expected == "ALLOW" and actual == "DENY":
            false_positives += 1
        elif expected == "DENY" and actual == "ALLOW":
            false_negatives += 1
            
    accuracy = round((correct / total * 100.0), 2)
    fp_rate = round((false_positives / total * 100.0), 2)
    fn_rate = round((false_negatives / total * 100.0), 2)
    
    return {
        "total_evaluated": total,
        "correct": correct,
        "accuracy_percentage": accuracy,
        "false_positives": false_positives,
        "false_positive_rate": fp_rate,
        "false_negatives": false_negatives,
        "false_negative_rate": fn_rate,
    }

def get_dashboard_summary(db_path: str = DB_PATH) -> dict[str, Any]:
    """
    Consolidated helper for the Streamlit dashboard combining all KPI modules.
    """
    latency = get_latency_metrics(db_path)
    auth = get_authorization_metrics(db_path)
    injection = get_injection_metrics(db_path)
    approvals = get_approval_queue_metrics(db_path)
    audit = get_audit_coverage_metrics(db_path)
    reliability = get_reliability_metrics(db_path)
    
    return {
        "latency": latency,
        "authorization": auth,
        "injection": injection,
        "approvals": approvals,
        "audit": audit,
        "reliability": reliability,
    }
