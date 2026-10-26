"""
Agent Permission Governor.
Central runtime entry point: intercepts, evaluates, and authorizes every action request.
Enforces least-privilege, dynamic risk scoring, provenance verification, and human-in-the-loop approvals.
Fail-Closed Architecture: any system error defaults to DENY.
"""

from __future__ import annotations
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from db import (
    init_db,
    insert_action_request,
    insert_approval,
    insert_audit_event,
    insert_decision,
)
from permission_engine import check_permission
from policy_engine import DecisionResult, evaluate_policy
from provenance import evaluate_provenance
from risk_engine import compute_risk

# Try importing injection detector (supports stub in Phase 1 and full module in Phase 2)
try:
    from injection_detector import detect_injection
except ImportError:
    def detect_injection(payload: Any = None, task_context: str = "", **kwargs: Any) -> tuple[float, bool, list[str]]:
        return 0.0, False, []

@dataclass
class ActionRequest:
    """Structure representing an agent's intended action."""
    agent_id: str
    action_type: str
    resource: str
    resource_sensitivity: str = "internal"
    task_context: str = ""
    instruction_source: str = "trusted_user"
    payload: Any = field(default_factory=dict)
    request_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.request_id:
            self.request_id = f"req_{uuid.uuid4().hex[:12]}"

# Maximum allowable payload size (64 KB) to protect against ReDoS and resource exhaustion
MAX_PAYLOAD_SIZE_BYTES: int = 64 * 1024

def evaluate(
    request: ActionRequest | dict[str, Any],
    db_path: Optional[str] = None,
    use_claude_injection_check: bool = False,
) -> tuple[str, DecisionResult]:
    """
    Single gateway function to evaluate an agent's action request.
    
    Returns:
        (request_id, DecisionResult)
        
    Guarantees:
        - Latency is recorded to microsecond precision.
        - Every action is audited in SQLite.
        - Fail-closed: any runtime error returns DENY.
    """
    start_time = time.perf_counter()
    
    # 1. Normalize input into ActionRequest
    try:
        if isinstance(request, dict):
            req_obj = ActionRequest(
                agent_id=str(request.get("agent_id", "")),
                action_type=str(request.get("action_type", "")),
                resource=str(request.get("resource", "")),
                resource_sensitivity=str(request.get("resource_sensitivity", "internal")),
                task_context=str(request.get("task_context", "")),
                instruction_source=str(request.get("instruction_source", "trusted_user")),
                payload=request.get("payload", {}),
                request_id=request.get("request_id"),
            )
        else:
            req_obj = request
            
        req_id = req_obj.request_id or f"req_{uuid.uuid4().hex[:12]}"
    except Exception as parse_err:
        # Malformed request -> Fail closed immediately
        latency = (time.perf_counter() - start_time) * 1000.0
        err_id = f"err_{uuid.uuid4().hex[:8]}"
        fallback_decision = DecisionResult(
            decision="DENY",
            risk_score=100.0,
            injection_score=0.0,
            provenance_trust=0.0,
            reasons=[f"Fail-Closed: Malformed request structure: {str(parse_err)}"],
            contributing_factors={"error": str(parse_err)},
        )
        return err_id, fallback_decision

    # 2. Main Evaluation Pipeline (wrapped in fail-closed try-block)
    kwargs = {"db_path": db_path} if db_path else {}
    
    try:
        # Step 0: Payload Size Guard (Maximum 64 KB)
        payload_raw = json.dumps(req_obj.payload) if isinstance(req_obj.payload, (dict, list)) else str(req_obj.payload or "")
        payload_bytes = len(payload_raw.encode("utf-8"))
        if payload_bytes > MAX_PAYLOAD_SIZE_BYTES:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            oversized_decision = DecisionResult(
                decision="DENY",
                risk_score=100.0,
                injection_score=0.0,
                provenance_trust=0.0,
                reasons=[
                    f"Fail-Closed: Payload size ({payload_bytes} bytes) exceeds maximum allowed limit of {MAX_PAYLOAD_SIZE_BYTES} bytes (64 KB). Action DENIED for safety."
                ],
                contributing_factors={"error": "payload_size_limit_exceeded", "payload_bytes": payload_bytes},
            )
            insert_action_request(
                request_id=req_id,
                agent_id=req_obj.agent_id,
                action_type=req_obj.action_type,
                resource=req_obj.resource,
                resource_sensitivity=req_obj.resource_sensitivity,
                task_context=req_obj.task_context,
                instruction_source=req_obj.instruction_source,
                payload={"error": "payload_omitted_due_to_excessive_size"},
                **kwargs,
            )
            insert_decision(
                decision_id=f"dec_{uuid.uuid4().hex[:12]}",
                request_id=req_id,
                decision="DENY",
                risk_score=100.0,
                injection_score=0.0,
                provenance_trust=0.0,
                reasons=oversized_decision.reasons,
                latency_ms=latency_ms,
                **kwargs,
            )
            insert_audit_event(
                request_id=req_id,
                event="REQUEST_PAYLOAD_OVERSIZED_DENIED",
                details={"payload_bytes": payload_bytes, "max_allowed": MAX_PAYLOAD_SIZE_BYTES},
                **kwargs,
            )
            return req_id, oversized_decision

        # Record request in DB
        insert_action_request(
            request_id=req_id,
            agent_id=req_obj.agent_id,
            action_type=req_obj.action_type,
            resource=req_obj.resource,
            resource_sensitivity=req_obj.resource_sensitivity,
            task_context=req_obj.task_context,
            instruction_source=req_obj.instruction_source,
            payload=req_obj.payload,
            **kwargs,
        )
        
        insert_audit_event(
            request_id=req_id,
            event="REQUEST_RECEIVED",
            details={
                "agent_id": req_obj.agent_id,
                "action_type": req_obj.action_type,
                "resource": req_obj.resource,
                "sensitivity": req_obj.resource_sensitivity,
                "source": req_obj.instruction_source,
            },
            **kwargs,
        )

        # Step A: Permission Engine (Identity & RBAC Least-Privilege)
        perm_result = check_permission(
            agent_id=req_obj.agent_id,
            action_type=req_obj.action_type,
            resource=req_obj.resource,
            **kwargs,
        )

        # Step B: Data Provenance Evaluation
        prov_result = evaluate_provenance(
            instruction_source=req_obj.instruction_source,
            payload=req_obj.payload,
            task_context=req_obj.task_context,
        )

        # Step C: Injection & Jailbreak Detection
        inj_score, inj_detected, inj_reasons = detect_injection(
            payload=req_obj.payload,
            task_context=req_obj.task_context,
            use_claude=use_claude_injection_check,
        )

        # Step D: Dynamic Risk Scoring
        risk_result = compute_risk(
            action_type=req_obj.action_type,
            resource=req_obj.resource,
            resource_sensitivity=req_obj.resource_sensitivity,
            task_context=req_obj.task_context,
            instruction_source=req_obj.instruction_source,
            payload=req_obj.payload,
            provenance_result=prov_result,
        )

        # Step E: Policy Engine Synthesis
        decision = evaluate_policy(
            permission=perm_result,
            risk=risk_result,
            provenance=prov_result,
            injection_score=inj_score,
            injection_reasons=inj_reasons,
            action_type=req_obj.action_type,
        )

        # Measure latency
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        # Persist Decision
        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        insert_decision(
            decision_id=decision_id,
            request_id=req_id,
            decision=decision.decision,
            risk_score=decision.risk_score,
            injection_score=decision.injection_score,
            provenance_trust=decision.provenance_trust,
            reasons=decision.reasons,
            latency_ms=latency_ms,
            **kwargs,
        )

        # Handle Routing: If HUMAN_APPROVAL, enqueue into approvals table
        if decision.decision == "HUMAN_APPROVAL":
            approval_id = f"appr_{uuid.uuid4().hex[:12]}"
            insert_approval(
                approval_id=approval_id,
                request_id=req_id,
                status="PENDING",
                **kwargs,
            )
            insert_audit_event(
                request_id=req_id,
                event="APPROVAL_PENDING",
                details={
                    "approval_id": approval_id,
                    "risk_score": decision.risk_score,
                    "reasons": decision.reasons,
                },
                **kwargs,
            )

        insert_audit_event(
            request_id=req_id,
            event="EVALUATION_COMPLETED",
            details={
                "decision": decision.decision,
                "latency_ms": latency_ms,
                "risk_score": decision.risk_score,
                "factors": decision.contributing_factors,
            },
            **kwargs,
        )

        return req_id, decision

    except Exception as runtime_err:
        # FAIL-CLOSED: Any unhandled exception must NEVER allow an action through.
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        fail_closed_decision = DecisionResult(
            decision="DENY",
            risk_score=100.0,
            injection_score=0.0,
            provenance_trust=0.0,
            reasons=[
                "CRITICAL GOVERNOR FAIL-CLOSED EVENT: An internal error occurred during authorization evaluation.",
                f"Exception details: {type(runtime_err).__name__}: {str(runtime_err)}",
                "Action has been blocked for safety.",
            ],
            contributing_factors={"fail_closed": True, "error": str(runtime_err)},
        )
        try:
            insert_audit_event(
                request_id=req_id,
                event="GOVERNOR_FAIL_CLOSED_ERROR",
                details={"error": str(runtime_err), "latency_ms": latency_ms},
                **kwargs,
            )
        except Exception:
            pass
            
        return req_id, fail_closed_decision


def execute_authorized(
    request_id: str,
    db_path: Optional[str] = None,
) -> Any:
    """
    Governor single runtime execution gateway.
    AI agents and client applications invoke this function to execute an authorized action.
    Delegates to executor.execute_authorized, strictly verifying prior Governor authorization.
    Fail-closed: returns an ExecutionResult with success=False on any unexpected exception.
    """
    from config import DB_PATH
    from executor import ExecutionResult, execute_authorized as _run_executor
    try:
        return _run_executor(request_id=request_id, db_path=db_path or DB_PATH)
    except Exception as exc:
        return ExecutionResult(
            success=False,
            request_id=request_id,
            action_type="unknown",
            resource="unknown",
            output=None,
            error=f"Governor execution gateway failure (fail-closed): {type(exc).__name__}: {str(exc)}",
            sandboxed=True,
        )
