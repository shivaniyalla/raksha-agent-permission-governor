"""Unit tests for policy_engine.py."""

from permission_engine import PermissionResult
from policy_engine import evaluate_policy
from provenance import ProvenanceResult
from risk_engine import RiskAssessment

def test_unauthorized_permission_leads_to_deny():
    perm = PermissionResult(
        is_allowed=False,
        role="support_agent",
        matched_policy=None,
        reasons=["Default Deny: Unauthorized"],
    )
    risk = RiskAssessment(risk_score=10.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="trusted_user", trust_score=1.0, is_untrusted=False, risk_multiplier=1.0, reasons=[])
    
    decision = evaluate_policy(perm, risk, prov)
    assert decision.decision == "DENY"

def test_injection_score_forces_deny():
    perm = PermissionResult(
        is_allowed=True,
        role="support_agent",
        matched_policy={"id": 1, "max_risk": 50, "requires_approval": 0},
        reasons=["Allowed"],
    )
    risk = RiskAssessment(risk_score=15.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="trusted_user", trust_score=1.0, is_untrusted=False, risk_multiplier=1.0, reasons=[])
    
    # Injection score >= 0.60
    decision = evaluate_policy(perm, risk, prov, injection_score=0.85)
    assert decision.decision == "DENY"
    assert any("Adversarial Defense Triggered" in r for r in decision.reasons)

def test_explicit_approval_policy_triggers_human_approval():
    perm = PermissionResult(
        is_allowed=True,
        role="finance_agent",
        matched_policy={"id": 10, "max_risk": 70, "requires_approval": 1},
        reasons=["Allowed by policy"],
    )
    risk = RiskAssessment(risk_score=35.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="trusted_user", trust_score=1.0, is_untrusted=False, risk_multiplier=1.0, reasons=[])
    
    decision = evaluate_policy(perm, risk, prov)
    assert decision.decision == "HUMAN_APPROVAL"
    assert any("Mandatory Governance Policy" in r for r in decision.reasons)

def test_risk_exceeding_max_risk_triggers_human_approval():
    perm = PermissionResult(
        is_allowed=True,
        role="support_agent",
        matched_policy={"id": 1, "max_risk": 40, "requires_approval": 0},
        reasons=["Allowed"],
    )
    # Risk is 55, exceeding policy max_risk of 40
    risk = RiskAssessment(risk_score=55.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="trusted_user", trust_score=1.0, is_untrusted=False, risk_multiplier=1.0, reasons=[])
    
    decision = evaluate_policy(perm, risk, prov)
    assert decision.decision == "HUMAN_APPROVAL"

def test_untrusted_provenance_mutating_action_triggers_approval():
    perm = PermissionResult(
        is_allowed=True,
        role="dev_agent",
        matched_policy={"id": 5, "max_risk": 65, "requires_approval": 0},
        reasons=["Allowed"],
    )
    risk = RiskAssessment(risk_score=35.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="web_content", trust_score=0.30, is_untrusted=True, risk_multiplier=1.5, reasons=[])
    
    # Mutating action 'write_file' from untrusted web_content
    decision = evaluate_policy(perm, risk, prov, action_type="write_file")
    assert decision.decision == "HUMAN_APPROVAL"
    assert any("Untrusted Provenance Safeguard" in r for r in decision.reasons)

def test_safe_authorized_allows():
    perm = PermissionResult(
        is_allowed=True,
        role="support_agent",
        matched_policy={"id": 1, "max_risk": 40, "requires_approval": 0},
        reasons=["Allowed"],
    )
    risk = RiskAssessment(risk_score=20.0, contributing_factors={}, reasons=[])
    prov = ProvenanceResult(source="trusted_user", trust_score=1.0, is_untrusted=False, risk_multiplier=1.0, reasons=[])
    
    decision = evaluate_policy(perm, risk, prov, action_type="read")
    assert decision.decision == "ALLOW"
