"""
Configuration module for the Agent Permission Governor.
Loads configuration from environment variables or Streamlit secrets with safe fallbacks.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "governor.db")

def get_secret_or_env(key: str, default: Any = None) -> Any:
    """
    Retrieve configuration value from Streamlit secrets (if running under Streamlit)
    or standard environment variables, falling back to a default value.
    """
    # Try streamlit secrets if streamlit is imported and initialized
    try:
        import streamlit as st
        if hasattr(st, "secrets") and key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    
    # Fallback to os.environ
    return os.environ.get(key, default)

# Claude Model Configuration
CLAUDE_MODEL: str = str(get_secret_or_env("CLAUDE_MODEL", "claude-sonnet-5-5"))
ANTHROPIC_API_KEY: str | None = get_secret_or_env("ANTHROPIC_API_KEY", None)

# Governor Policy Thresholds
MAX_ALLOWED_RISK_DEFAULT: float = float(get_secret_or_env("MAX_ALLOWED_RISK_DEFAULT", 60.0))
HUMAN_APPROVAL_RISK_THRESHOLD: float = float(get_secret_or_env("HUMAN_APPROVAL_RISK_THRESHOLD", 60.0))
CRITICAL_RISK_THRESHOLD: float = float(get_secret_or_env("CRITICAL_RISK_THRESHOLD", 85.0))
INJECTION_DENY_THRESHOLD: float = float(get_secret_or_env("INJECTION_DENY_THRESHOLD", 60.0))
INJECTION_SUSPICIOUS_THRESHOLD: float = float(get_secret_or_env("INJECTION_SUSPICIOUS_THRESHOLD", 35.0))

# Enterprise Environment & Operational Controls
ENVIRONMENT: str = str(get_secret_or_env("ENVIRONMENT", "development"))
DB_TIMEOUT_SECONDS: float = float(get_secret_or_env("DB_TIMEOUT_SECONDS", 10.0))
MAX_PAYLOAD_SIZE_BYTES: int = int(get_secret_or_env("MAX_PAYLOAD_SIZE_BYTES", 64 * 1024))
ENABLE_WAL_MODE: bool = str(get_secret_or_env("ENABLE_WAL_MODE", "true")).lower() in ("true", "1", "yes")

# Security Monitoring & Alert Thresholds
ALERT_INJECTION_REPEAT_THRESHOLD: int = int(get_secret_or_env("ALERT_INJECTION_REPEAT_THRESHOLD", 2))
ALERT_DENY_REPEAT_THRESHOLD: int = int(get_secret_or_env("ALERT_DENY_REPEAT_THRESHOLD", 3))
POLICY_CACHE_ENABLED: bool = str(get_secret_or_env("POLICY_CACHE_ENABLED", "true")).lower() in ("true", "1", "yes")

# Provenance Trust Baselines
PROVENANCE_TRUST_MAP: dict[str, float] = {
    "trusted_user": 1.0,
    "system": 0.95,
    "tool_output": 0.70,
    "uploaded_file": 0.40,
    "web_content": 0.30,
    "unknown": 0.20,
}
