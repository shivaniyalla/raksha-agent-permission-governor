"""
Permission Engine for Agent Permission Governor.
Enforces strict least-privilege access control (default-deny).
An action is granted only if an active policy explicitly allows the agent's role
for the specified action type and target resource.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional

from db import get_agent, get_policies_for_role

@dataclass
class PermissionResult:
    """Outcome of permission verification."""
    is_allowed: bool
    role: str
    matched_policy: Optional[dict[str, Any]]
    reasons: list[str]

def match_resource(policy_resource: str, request_resource: str) -> bool:
    """
    Check if a requested resource matches a policy resource type.
    Supports exact match, wildcard '*', prefix match (e.g. 'customer_record' matches 'customer_record_123'),
    and substring/path matching.
    """
    p = policy_resource.strip().lower()
    r = request_resource.strip().lower()
    
    if p == "*" or p == r:
        return True
    
    # Prefix or semantic grouping: e.g. policy 'customer_record' matches 'customer_record_001' or 'customer_record/45'
    if r.startswith(p + "_") or r.startswith(p + "/") or r.startswith(p + ":") or r.startswith(p + "-"):
        return True
        
    return False

def check_permission(
    agent_id: str,
    action_type: str,
    resource: str,
    db_path: Optional[str] = None,
) -> PermissionResult:
    """
    Evaluate agent identity and check if least-privilege policy grants the requested action.
    
    Default-deny: Returns is_allowed=False unless explicitly matched.
    """
    kwargs = {"db_path": db_path} if db_path else {}
    
    # 1. Verify Agent Identity
    agent = get_agent(agent_id, **kwargs)
    if not agent:
        return PermissionResult(
            is_allowed=False,
            role="unknown",
            matched_policy=None,
            reasons=[f"Unauthorized agent ID '{agent_id}': Agent identity not registered in directory."]
        )
    
    role = agent["role"]
    action_norm = action_type.strip().lower()
    
    # 2. Retrieve policies for this role
    policies = get_policies_for_role(role, **kwargs)
    if not policies:
        return PermissionResult(
            is_allowed=False,
            role=role,
            matched_policy=None,
            reasons=[f"Default Deny: Role '{role}' has no active access policies configured."]
        )
    
    # 3. Match action and resource against active policies
    for policy in policies:
        p_action = policy["action_type"].strip().lower()
        p_resource = policy["resource_type"]
        
        # Check action match (exact or wildcard)
        if p_action == "*" or p_action == action_norm:
            if match_resource(p_resource, resource):
                return PermissionResult(
                    is_allowed=True,
                    role=role,
                    matched_policy=policy,
                    reasons=[
                        f"Least-privilege permission granted: Role '{role}' is authorized "
                        f"for action '{action_norm}' on resource '{resource}' (matched policy #{policy['id']}: {p_resource})."
                    ]
                )
    
    # 4. If no policy matched -> DEFAULT DENY
    return PermissionResult(
        is_allowed=False,
        role=role,
        matched_policy=None,
        reasons=[
            f"Default Deny: Role '{role}' is NOT authorized to perform '{action_norm}' on resource '{resource}'."
        ]
    )
