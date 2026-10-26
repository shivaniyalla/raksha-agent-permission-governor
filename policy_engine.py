"""
Policy Engine for Agent Permission Governor.
Synthesizes permission checks, risk assessment, provenance trust, and injection scores
into a unified authorization decision: ALLOW, DENY, or HUMAN_APPROVAL.

Enforces deterministic rule supremacy: Rules make the final binding decision.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional

from config import (
    CRITICAL_RISK_THRESHOLD,
    HUMAN_APPROVAL_RISK_THRESHOLD,
    INJECTION_DENY_THRESHOLD,
    INJECTION_SUSPICIOUS_THRESHOLD,
)
from permission_engine import PermissionResult
from provenance import ProvenanceResult
from risk_engine import RiskAssessment

@dataclass
class DecisionResult:
    """Consolidated authorization decision."""
    decision: str  # "ALLOW", "DENY", "HUMAN_APPROVAL"
    risk_score: float
    injection_score: float
    provenance_trust: float
    reasons: list[str]
    contributing_factors: dict[str, Any]

def evaluate_policy(
    permission: PermissionResult,
    risk: RiskAssessment,
    provenance: ProvenanceResult,
    injection_score: float = 0.0,
    injection_reasons: Optional[list[str]] = None,
    action_type: str = "read",
) -> DecisionResult:
    """
    Synthesize all governance components into an explainable, deterministic decision.
    
    Priority of evaluation:
    1. Permission Default-Deny: If unauthorized -> DENY.
    2. Prompt Injection Hard Block: If injection score >= threshold -> DENY.
    3. Critical Risk Barrier: If risk exceeds critical threshold without prior sign-off -> DENY.
    4. Explicit Approval Policy: If policy requires human sign-off -> HUMAN_APPROVAL.
    5. Policy Max-Risk Exceeded: If risk exceeds policy cap -> HUMAN_APPROVAL.
    6. High Operational Risk: If risk >= HUMAN_APPROVAL_RISK_THRESHOLD -> HUMAN_APPROVAL.
    7. Suspicious Injection or Untrusted Mutating Origin -> HUMAN_APPROVAL.
    8. Safe & Authorized -> ALLOW.
    """
    # Normalize injection score: handles both 0-100 scale and decimal 0.0-1.0 fractions gracefully
    norm_injection = (injection_score * 100.0) if (0.0 < injection_score <= 1.0) else injection_score

    reasons: list[str] = []
    factors: dict[str, Any] = {
        "permission_granted": permission.is_allowed,
        "role": permission.role,
        "policy_id": permission.matched_policy["id"] if permission.matched_policy else None,
        "policy_max_risk": permission.matched_policy["max_risk"] if permission.matched_policy else None,
        "requires_approval_policy": bool(permission.matched_policy["requires_approval"]) if permission.matched_policy else False,
        "risk_score": risk.risk_score,
        "injection_score": round(norm_injection, 1),
        "provenance_source": provenance.source,
        "provenance_trust": provenance.trust_score,
        "is_untrusted_provenance": provenance.is_untrusted,
        **risk.contributing_factors,
    }

    # Include specific detector reasons
    reasons.extend(permission.reasons)
    if injection_reasons:
        reasons.extend(injection_reasons)
        
    # --- RULE 1: PERMISSION ENGINE CHECK (STRICT LEAST PRIVILEGE) ---
    if not permission.is_allowed:
        return DecisionResult(
            decision="DENY",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 2: INJECTION DEFENSE (FAIL CLOSED AGAINST ADVERSARIAL ATTEMPTS) ---
    if norm_injection >= INJECTION_DENY_THRESHOLD:
        reasons.append(
            f"Adversarial Defense Triggered: Injection confidence score {norm_injection:.1f}/100 "
            f"meets or exceeds deny threshold ({INJECTION_DENY_THRESHOLD:.1f}/100). Immediate DENY."
        )
        return DecisionResult(
            decision="DENY",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 3: CRITICAL UNBOUNDED RISK ---
    if risk.risk_score >= CRITICAL_RISK_THRESHOLD:
        reasons.append(
            f"Critical Risk Block: Computed risk score {risk.risk_score:.1f} exceeds "
            f"absolute critical threshold ({CRITICAL_RISK_THRESHOLD:.1f}). Action DENIED."
        )
        return DecisionResult(
            decision="DENY",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 4: EXPLICIT HUMAN APPROVAL POLICY ---
    if permission.matched_policy and permission.matched_policy["requires_approval"] == 1:
        reasons.append(
            f"Mandatory Governance Policy: Policy #{permission.matched_policy['id']} "
            f"mandates explicit Human-in-the-Loop approval before execution."
        )
        reasons.extend(risk.reasons)
        return DecisionResult(
            decision="HUMAN_APPROVAL",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 5: RISK EXCEEDS POLICY MAX RISK ---
    if permission.matched_policy and risk.risk_score > permission.matched_policy["max_risk"]:
        reasons.append(
            f"Risk Ceiling Exceeded: Computed risk ({risk.risk_score:.1f}) exceeds the configured policy "
            f"limit of {permission.matched_policy['max_risk']} for role '{permission.role}'. Routing for Human Approval."
        )
        reasons.extend(risk.reasons)
        return DecisionResult(
            decision="HUMAN_APPROVAL",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 6: SYSTEM HIGH RISK THRESHOLD ---
    if risk.risk_score >= HUMAN_APPROVAL_RISK_THRESHOLD:
        reasons.append(
            f"High Operational Risk: Risk score {risk.risk_score:.1f} crosses governance "
            f"approval boundary ({HUMAN_APPROVAL_RISK_THRESHOLD:.1f}). Pausing for human review."
        )
        reasons.extend(risk.reasons)
        return DecisionResult(
            decision="HUMAN_APPROVAL",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 7: SUSPICIOUS INJECTION SCORE OR UNTRUSTED PROVENANCE ON STATE MUTATION ---
    if norm_injection >= INJECTION_SUSPICIOUS_THRESHOLD:
        reasons.append(
            f"Suspicious Instruction Escaped: Injection score {norm_injection:.1f}/100 is elevated; "
            f"routing for human verification."
        )
        return DecisionResult(
            decision="HUMAN_APPROVAL",
            risk_score=risk.risk_score,
            injection_score=round(norm_injection, 1),
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    is_mutating = action_type.strip().lower() in ("write_file", "call_api", "execute_code", "delete")
    if provenance.is_untrusted and is_mutating:
        reasons.append(
            f"Untrusted Provenance Safeguard: Origin '{provenance.source}' (trust: {provenance.trust_score:.2f}) "
            f"attempted state-mutating action '{action_type}'. Escalating for Human Review."
        )
        reasons.extend(risk.reasons)
        return DecisionResult(
            decision="HUMAN_APPROVAL",
            risk_score=risk.risk_score,
            injection_score=injection_score,
            provenance_trust=provenance.trust_score,
            reasons=reasons,
            contributing_factors=factors,
        )

    # --- RULE 8: FULLY COMPLIANT AND AUTHORIZED ---
    reasons.append("Action authorized: Request satisfies least-privilege policy, low risk, and validated provenance.")
    reasons.extend(risk.reasons)
    return DecisionResult(
        decision="ALLOW",
        risk_score=risk.risk_score,
        injection_score=injection_score,
        provenance_trust=provenance.trust_score,
        reasons=reasons,
        contributing_factors=factors,
    )
