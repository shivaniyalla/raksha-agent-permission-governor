"""
Demo AI Agent Module for RAKSHA.
Simulates autonomous AI agents proposing structured action requests.
Uses Claude (if ANTHROPIC_API_KEY is available) or a deterministic offline fallback parser.
Security Principle: This module ONLY generates intended action proposals;
it has NO execution capabilities and CANNOT bypass governor.evaluate().
"""

from __future__ import annotations
import json
import logging
from typing import Any, Optional

from config import ANTHROPIC_API_KEY, CLAUDE_MODEL

logger = logging.getLogger("governor.agent_demo")

# Preset agent identities
PRESET_AGENTS = {
    "support_agent": {
        "id": "support_agent_01",
        "name": "Customer Support Agent",
        "default_resource": "customer_record_101",
        "default_sensitivity": "internal",
    },
    "dev_agent": {
        "id": "dev_agent_01",
        "name": "DevOps Pipeline Bot",
        "default_resource": "dev_sandbox",
        "default_sensitivity": "internal",
    },
    "finance_agent": {
        "id": "finance_agent_01",
        "name": "Financial Assistant",
        "default_resource": "payment_gateway",
        "default_sensitivity": "confidential",
    },
    "security_auditor": {
        "id": "security_agent_01",
        "name": "SecOps Auditor",
        "default_resource": "audit_logs",
        "default_sensitivity": "internal",
    },
}

def generate_action_with_claude(
    user_goal: str,
    agent_role: str = "support_agent",
) -> Optional[dict[str, Any]]:
    """
    Query Anthropic Claude to translate natural language into a structured ActionRequest.
    """
    if not ANTHROPIC_API_KEY:
        return None
        
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        
        agent_info = PRESET_AGENTS.get(agent_role, PRESET_AGENTS["support_agent"])
        
        system_prompt = (
            f"You are {agent_info['name']} (ID: {agent_info['id']}, Role: {agent_role}). "
            "You translate user operational goals into a structured action request JSON object.\n"
            "Respond ONLY with valid JSON having the exact keys:\n"
            "{\n"
            f'  "agent_id": "{agent_info["id"]}",\n'
            '  "action_type": "<read|write_file|call_api|execute_code|delete>",\n'
            '  "resource": "<target resource name>",\n'
            '  "resource_sensitivity": "<public|internal|confidential|pii>",\n'
            '  "task_context": "<brief task description>",\n'
            '  "instruction_source": "<trusted_user|system|tool_output|uploaded_file|web_content|unknown>",\n'
            '  "payload": { ... }\n'
            "}"
        )
        
        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=300,
            temperature=0.0,
            system=system_prompt,
            messages=[{"role": "user", "content": user_goal}],
            timeout=5.0,
        )
        
        raw_text = response.content[0].text.strip()
        # Extract json if enclosed in markdown
        if "```json" in raw_text:
            raw_text = raw_text.split("```json")[1].split("```")[0].strip()
        elif "```" in raw_text:
            raw_text = raw_text.split("```")[1].split("```")[0].strip()
            
        data = json.loads(raw_text)
        return data
    except Exception as exc:
        logger.warning(f"Claude agent prompt generation fallback: {exc}")
        return None

def offline_fallback_intent_parser(
    user_goal: str,
    agent_role: str = "support_agent",
) -> dict[str, Any]:
    """
    Deterministic rule-based intent parser used when running in rules-only mode
    or when no Anthropic API key is configured.
    """
    agent_info = PRESET_AGENTS.get(agent_role, PRESET_AGENTS["support_agent"])
    text_lower = user_goal.lower()
    
    # Action type inference
    if any(k in text_lower for k in ["delete", "remove", "drop", "wipe", "purge"]):
        action_type = "delete"
    elif any(k in text_lower for k in ["execute", "run script", "run code", "bash", "shell"]):
        action_type = "execute_code"
    elif any(k in text_lower for k in ["call api", "webhook", "pay", "charge", "transfer", "gateway"]):
        action_type = "call_api"
    elif any(k in text_lower for k in ["write", "save", "update notes", "create file", "export"]):
        action_type = "write_file"
    else:
        action_type = "read"

    # Resource inference
    if "payment" in text_lower or "pay" in text_lower or "invoice" in text_lower:
        resource = "payment_gateway"
        sensitivity = "confidential"
    elif "customer" in text_lower or "user" in text_lower:
        resource = "customer_record_101"
        sensitivity = "internal"
    elif "code" in text_lower or "script" in text_lower:
        resource = "dev_sandbox"
        sensitivity = "internal"
    elif "audit" in text_lower:
        resource = "audit_logs"
        sensitivity = "internal"
    else:
        resource = agent_info["default_resource"]
        sensitivity = agent_info["default_sensitivity"]

    # Source inference
    if any(k in text_lower for k in ["upload", "file", "document", "pdf", "csv"]):
        source = "uploaded_file"
    elif any(k in text_lower for k in ["web", "scrape", "url", "http"]):
        source = "web_content"
    elif "system" in text_lower or "cron" in text_lower:
        source = "system"
    else:
        source = "trusted_user"

    return {
        "agent_id": agent_info["id"],
        "action_type": action_type,
        "resource": resource,
        "resource_sensitivity": sensitivity,
        "task_context": user_goal,
        "instruction_source": source,
        "payload": {"prompt_excerpt": user_goal[:200]},
    }

def propose_action(
    user_goal: str,
    agent_role: str = "support_agent",
    use_claude: bool = True,
) -> dict[str, Any]:
    """
    Main interface for AI agent action proposal.
    Tries Claude first (if key configured and use_claude=True), otherwise uses offline parser.
    """
    if use_claude and ANTHROPIC_API_KEY:
        claude_action = generate_action_with_claude(user_goal, agent_role)
        if claude_action and "action_type" in claude_action:
            return claude_action
            
    return offline_fallback_intent_parser(user_goal, agent_role)
