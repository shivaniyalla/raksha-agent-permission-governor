"""
Dynamic Risk Engine for Agent Permission Governor.
Computes a comprehensive risk score (0 to 100) based on:
1. Action Type (read, write_file, call_api, execute_code, delete)
2. Resource Sensitivity (public, internal, confidential, PII)
3. Task Context Alignment (does the intended action and resource match the stated task?)
4. Operational Risk (reversibility, external blast radius)
5. Data Provenance Multiplier (untrusted origins escalate risk)
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Optional

from provenance import ProvenanceResult, evaluate_provenance

@dataclass
class RiskAssessment:
    """Detailed risk assessment outcome."""
    risk_score: float
    contributing_factors: dict[str, Any]
    reasons: list[str]

ACTION_BASE_SCORES: dict[str, float] = {
    "read": 15.0,
    "write_file": 40.0,
    "call_api": 50.0,
    "execute_code": 75.0,
    "delete": 85.0,
}

SENSITIVITY_SCORES: dict[str, float] = {
    "public": 0.0,
    "internal": 20.0,
    "confidential": 45.0,
    "pii": 55.0,
}

# Context mismatch keywords indicating high divergence between stated goal and destructive/invasive operations
DESTRUCTIVE_ACTIONS = {"delete", "drop", "truncate", "wipe", "format", "purge", "destroy"}
EXECUTION_ACTIONS = {"execute_code", "run_script", "shell", "bash", "powershell", "eval", "exec"}

def evaluate_task_alignment(
    task_context: str,
    action_type: str,
    resource: str,
    payload: Any = None,
) -> tuple[float, str]:
    """
    Evaluate whether the agent's proposed action and resource logically align
    with the stated task context.
    Returns (context_penalty, rationale).
    """
    ctx_lower = task_context.lower().strip()
    action_lower = action_type.lower().strip()
    resource_lower = resource.lower().strip()
    payload_str = str(payload).lower() if payload else ""
    
    if not ctx_lower:
        return 35.0, "Missing task context: inability to verify operational alignment with stated purpose (+35 risk)."
        
    # Check 1: Destructive action requested without explicit destructive task intent
    destructive_intent_keywords = ["delete", "remove", "clean", "purge", "destroy", "drop", "wipe", "erase", "cleanup"]
    has_destructive_intent = any(k in ctx_lower for k in destructive_intent_keywords)
    if action_lower in DESTRUCTIVE_ACTIONS and not has_destructive_intent:
        return 40.0, f"Critical Context Mismatch: Action is destructive '{action_type}' but task context ('{task_context}') does not authorize deletion (+40 risk)."

    # Check 2: Code execution requested without execution intent
    execution_intent_keywords = ["execute", "run", "script", "code", "compile", "build", "ci", "job", "test", "sandbox"]
    has_execution_intent = any(k in ctx_lower for k in execution_intent_keywords)
    if action_lower in EXECUTION_ACTIONS and not has_execution_intent:
        return 35.0, f"Critical Context Mismatch: Action requests code execution but task context ('{task_context}') does not authorize script execution (+35 risk)."

    # Check 3: Check if target resource matches stated context
    context_tokens = set(re.findall(r"\b\w{3,}\b", ctx_lower))
    resource_tokens = set(re.findall(r"\b\w{3,}\b", resource_lower))
    
    overlap = context_tokens.intersection(resource_tokens)
    
    # Generic semantic mapping
    semantic_matches = {
        "customer": ["customer_record", "customer", "crm", "ticket"],
        "ticket": ["ticket_notes", "ticket", "support"],
        "invoice": ["invoices", "invoice", "payment", "billing"],
        "code": ["codebase", "dev_sandbox", "repo", "git"],
        "build": ["temporary_build_artifacts", "ci_webhook", "dev_sandbox"],
        "audit": ["audit_logs", "system_config", "siem_export"],
    }
    
    has_semantic_match = False
    for kw, related in semantic_matches.items():
        if kw in ctx_lower:
            if any(rel in resource_lower for rel in related):
                has_semantic_match = True
                break
                
    if overlap or has_semantic_match:
        return 0.0, "Task context alignment verified: Action and resource match stated workflow intent."
        
    # Mild mismatch / neutral
    return 15.0, "Moderate context divergence: Target resource was not explicitly mentioned or clearly implied in task context (+15 risk)."

def evaluate_operational_risk(
    action_type: str,
    resource: str,
    payload: Any = None,
) -> tuple[float, str]:
    """
    Assess operational irreversibility and blast radius.
    Returns (operational_risk_score, rationale).
    """
    action = action_type.lower().strip()
    resource_lower = resource.lower().strip()
    payload_str = str(payload).lower() if payload else ""
    
    operational_score = 0.0
    notes = []
    
    # Reversibility
    if action in DESTRUCTIVE_ACTIONS or "delete" in resource_lower or "drop" in payload_str:
        operational_score += 35.0
        notes.append("Irreversible operation: Action performs permanent deletion/modification (+35).")
    elif action in ("write_file", "call_api"):
        operational_score += 15.0
        notes.append("State-mutating operation (+15).")
    elif action == "execute_code":
        operational_score += 25.0
        notes.append("Arbitrary code execution environment impact (+25).")
    else: # read
        operational_score += 0.0
        notes.append("Reversible read-only operation (0).")
        
    # Blast Radius (External vs Internal)
    external_indicators = ["payment", "gateway", "external", "webhook", "email", "smtp", "public_api", "transfer"]
    if any(ind in resource_lower or ind in payload_str for ind in external_indicators):
        operational_score += 20.0
        notes.append("High external blast radius: Interacts with third-party service or financial gateway (+20).")
    else:
        notes.append("Contained internal blast radius.")
        
    return min(operational_score, 50.0), " | ".join(notes)

def compute_risk(
    action_type: str,
    resource: str,
    resource_sensitivity: str,
    task_context: str,
    instruction_source: str = "trusted_user",
    payload: Any = None,
    provenance_result: Optional[ProvenanceResult] = None,
) -> RiskAssessment:
    """
    Compute unified dynamic risk score (0 to 100).
    """
    reasons: list[str] = []
    
    # 1. Action Type Base Risk
    act_norm = action_type.strip().lower()
    action_base = ACTION_BASE_SCORES.get(act_norm, 50.0)
    reasons.append(f"Action Base Risk: '{act_norm}' rated at {action_base:.1f}/100.")
    
    # 2. Resource Sensitivity Risk
    sens_norm = resource_sensitivity.strip().lower()
    sens_score = SENSITIVITY_SCORES.get(sens_norm, 20.0)
    reasons.append(f"Resource Sensitivity: '{sens_norm}' rated at {sens_score:.1f}/100.")
    
    # 3. Task Context Alignment
    context_penalty, ctx_reason = evaluate_task_alignment(
        task_context=task_context,
        action_type=act_norm,
        resource=resource,
        payload=payload,
    )
    reasons.append(ctx_reason)
    
    # 4. Operational Risk & Blast Radius
    op_score, op_reason = evaluate_operational_risk(
        action_type=act_norm,
        resource=resource,
        payload=payload,
    )
    reasons.append(f"Operational Risk: {op_reason}")
    
    # 5. Base Dynamic Risk Formulation
    # Formulation balances base permissions with operational impacts & context penalties
    raw_score = (
        (action_base * 0.45) +
        (sens_score * 0.35) +
        (op_score * 0.30) +
        (context_penalty * 0.30)
    )
    
    # 6. Provenance Multiplier
    if provenance_result is None:
        provenance_result = evaluate_provenance(
            instruction_source=instruction_source,
            payload=payload,
            task_context=task_context,
        )
        
    final_score = raw_score * provenance_result.risk_multiplier
    if provenance_result.risk_multiplier > 1.0:
        reasons.append(
            f"Provenance Risk Escalation: Untrusted source '{provenance_result.source}' "
            f"applied {provenance_result.risk_multiplier:.2f}x multiplier."
        )
        
    # Cap score between 0.0 and 100.0
    final_score = min(max(final_score, 0.0), 100.0)
    final_score = round(final_score, 2)
    
    contributing_factors = {
        "action_base_risk": action_base,
        "resource_sensitivity_risk": sens_score,
        "operational_risk": op_score,
        "context_penalty": context_penalty,
        "provenance_multiplier": provenance_result.risk_multiplier,
        "final_risk_score": final_score,
    }
    
    return RiskAssessment(
        risk_score=final_score,
        contributing_factors=contributing_factors,
        reasons=reasons,
    )
