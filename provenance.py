"""
Data Provenance Engine for Agent Permission Governor.
Tracks origin and trust level of incoming instructions (trusted_user, system, tool_output,
uploaded_file, web_content, unknown) and computes trust scores and taint indicators.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from config import PROVENANCE_TRUST_MAP

@dataclass
class ProvenanceResult:
    """Outcome of provenance evaluation."""
    source: str
    trust_score: float
    is_untrusted: bool
    risk_multiplier: float
    reasons: list[str]

VALID_SOURCES = set(PROVENANCE_TRUST_MAP.keys())

def evaluate_provenance(
    instruction_source: str,
    payload: Any = None,
    task_context: str = "",
) -> ProvenanceResult:
    """
    Evaluate instruction provenance, calculate baseline trust, and detect potential
    untrusted data flow or provenance taint.
    """
    norm_source = instruction_source.strip().lower() if instruction_source else "unknown"
    if norm_source not in VALID_SOURCES:
        norm_source = "unknown"
        
    base_trust = PROVENANCE_TRUST_MAP.get(norm_source, 0.20)
    reasons: list[str] = []
    
    # Analyze provenance risks
    is_untrusted = base_trust < 0.60
    
    if norm_source == "trusted_user":
        reasons.append("Provenance: Direct authenticated user input (high trust).")
        risk_multiplier = 1.0
    elif norm_source == "system":
        reasons.append("Provenance: Internal scheduled or verified system task (high trust).")
        risk_multiplier = 1.0
    elif norm_source == "tool_output":
        reasons.append("Provenance: Derived from intermediate tool execution (moderate trust, check for indirect injection).")
        risk_multiplier = 1.2
    elif norm_source == "uploaded_file":
        reasons.append("Provenance: Extracted from uploaded document/file (low trust, potential poisoned content).")
        risk_multiplier = 1.4
    elif norm_source == "web_content":
        reasons.append("Provenance: Retrieved from external web source (untrusted, high risk of indirect injection).")
        risk_multiplier = 1.5
    else:
        reasons.append(f"Provenance: Unknown or unverified instruction source '{instruction_source}' (untrusted).")
        risk_multiplier = 1.5

    # Secondary check: Taint indicator in payload or context
    # If the payload contains nested references to web/untrusted data, flag taint
    payload_str = str(payload).lower() if payload else ""
    context_str = task_context.lower()
    
    untrusted_indicators = ["scraped_url", "http://", "https://", "untrusted_input", "attachment:", "external_feed"]
    has_taint = any(ind in payload_str or ind in context_str for ind in untrusted_indicators)
    
    if has_taint and norm_source in ("trusted_user", "system"):
        # Source was nominally trusted, but data payload contains untrusted third-party content
        base_trust = max(0.40, base_trust - 0.35)
        is_untrusted = True
        risk_multiplier = max(risk_multiplier, 1.35)
        reasons.append("Provenance Taint Warning: Payload contains external/untrusted data streams; trust adjusted downward.")

    return ProvenanceResult(
        source=norm_source,
        trust_score=round(base_trust, 2),
        is_untrusted=is_untrusted,
        risk_multiplier=risk_multiplier,
        reasons=reasons,
    )
