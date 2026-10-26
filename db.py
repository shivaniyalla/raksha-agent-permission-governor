"""
Database module for Agent Permission Governor.
Provides SQLite initialization, context managers, and persistence helpers.
"""

from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from config import DB_PATH, DB_TIMEOUT_SECONDS, ENABLE_WAL_MODE, POLICY_CACHE_ENABLED

# In-memory caches for static policy and agent definitions (avoids repeated disk I/O)
# Note: Dynamic authorization decisions are NEVER cached.
_AGENT_CACHE: dict[tuple[str, str], dict[str, Any] | None] = {}
_POLICY_CACHE: dict[tuple[str, str], list[dict[str, Any]]] = {}

def clear_db_cache() -> None:
    """Clear in-memory policy and agent caches."""
    _AGENT_CACHE.clear()
    _POLICY_CACHE.clear()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    action_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    max_risk INTEGER NOT NULL DEFAULT 50,
    requires_approval INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS action_requests (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    resource TEXT NOT NULL,
    resource_sensitivity TEXT NOT NULL,
    task_context TEXT NOT NULL,
    instruction_source TEXT NOT NULL,
    payload TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score REAL NOT NULL,
    injection_score REAL NOT NULL,
    provenance_trust REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(request_id) REFERENCES action_requests(id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reviewer TEXT,
    decided_at TEXT,
    FOREIGN KEY(request_id) REFERENCES action_requests(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    event TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id TEXT,
    request_id TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_req ON decisions(request_id);
CREATE INDEX IF NOT EXISTS idx_approvals_req ON approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_policies_role ON policies(role);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
"""

DEFAULT_AGENTS = [
    ("support_agent_01", "Customer Support Bot", "support_agent"),
    ("dev_agent_01", "CI/CD Pipeline Agent", "dev_agent"),
    ("finance_agent_01", "Accounts Payable Assistant", "finance_agent"),
    ("security_agent_01", "SecOps Compliance Bot", "security_auditor"),
]

DEFAULT_POLICIES = [
    # support_agent policies
    ("support_agent", "read", "customer_record", 40, 0),
    ("support_agent", "read", "knowledge_base", 30, 0),
    ("support_agent", "write_file", "ticket_notes", 45, 0),
    ("support_agent", "call_api", "crm_lookup", 40, 0),
    
    # dev_agent policies
    ("dev_agent", "read", "codebase", 40, 0),
    ("dev_agent", "write_file", "dev_sandbox", 65, 0),
    ("dev_agent", "execute_code", "dev_sandbox", 75, 0),
    ("dev_agent", "call_api", "ci_webhook", 60, 0),
    ("dev_agent", "delete", "temporary_build_artifacts", 50, 0),
    ("dev_agent", "delete", "production_records", 50, 1),  # Sensitive production mutation requiring human sign-off
    
    # finance_agent policies
    ("finance_agent", "read", "invoices", 50, 0),
    ("finance_agent", "write_file", "financial_report", 55, 0),
    ("finance_agent", "call_api", "payment_gateway", 70, 1),  # Requires explicit human approval
    
    # security_auditor policies
    ("security_auditor", "read", "audit_logs", 30, 0),
    ("security_auditor", "read", "system_config", 40, 0),
    ("security_auditor", "call_api", "siem_export", 50, 0),
]

def utc_now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def get_db(db_path: str = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database connection with row factory and WAL mode."""
    conn = sqlite3.connect(db_path, timeout=DB_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    try:
        if ENABLE_WAL_MODE and not db_path.startswith(":memory:") and not db_path.endswith(".tmp"):
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            except Exception:
                pass
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db(db_path: str = DB_PATH, seed: bool = True) -> None:
    """Initialize database tables and seed baseline agents and policies."""
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        
        # Ensure backwards-compatible column migration for security_alerts table
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(security_alerts)")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if existing_cols:
            if "created_at" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN created_at TEXT")
                if "timestamp" in existing_cols:
                    conn.execute("UPDATE security_alerts SET created_at = timestamp WHERE created_at IS NULL")
            if "timestamp" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN timestamp TEXT")
                if "created_at" in existing_cols:
                    conn.execute("UPDATE security_alerts SET timestamp = created_at WHERE timestamp IS NULL")
            if "resolved_at" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN resolved_at TEXT")
        
        if seed:
            cursor = conn.cursor()
            # Seed agents if empty
            cursor.execute("SELECT COUNT(*) AS count FROM agents")
            if cursor.fetchone()["count"] == 0:
                cursor.executemany(
                    "INSERT INTO agents (id, name, role) VALUES (?, ?, ?)",
                    DEFAULT_AGENTS
                )
            
            # Seed policies if empty
            cursor.execute("SELECT COUNT(*) AS count FROM policies")
            if cursor.fetchone()["count"] == 0:
                cursor.executemany(
                    "INSERT INTO policies (role, action_type, resource_type, max_risk, requires_approval) VALUES (?, ?, ?, ?, ?)",
                    DEFAULT_POLICIES
                )

def reset_db(db_path: str = DB_PATH) -> None:
    """Wipe all data and reinitialize schema and baseline seed records."""
    clear_db_cache()
    with get_db(db_path) as conn:
        tables = ["security_alerts", "audit_log", "approvals", "decisions", "action_requests", "policies", "agents"]
        for table in tables:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
    init_db(db_path=db_path, seed=True)

# Helper Query Functions

def get_agent(agent_id: str, db_path: str = DB_PATH) -> dict[str, Any] | None:
    """Fetch agent by unique identifier (uses memory cache when enabled)."""
    cache_key = (agent_id, db_path)
    if POLICY_CACHE_ENABLED and cache_key in _AGENT_CACHE:
        return _AGENT_CACHE[cache_key]

    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = cursor.fetchone()
        result = dict(row) if row else None
        if POLICY_CACHE_ENABLED:
            _AGENT_CACHE[cache_key] = result
        return result

def get_policies_for_role(role: str, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all policies for a given agent role (uses memory cache when enabled)."""
    cache_key = (role, db_path)
    if POLICY_CACHE_ENABLED and cache_key in _POLICY_CACHE:
        return _POLICY_CACHE[cache_key]

    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policies WHERE role = ?", (role,))
        result = [dict(row) for row in cursor.fetchall()]
        if POLICY_CACHE_ENABLED:
            _POLICY_CACHE[cache_key] = result
        return result

def insert_security_alert(
    alert_id: str,
    severity: str,
    event_type: str,
    reason: str,
    agent_id: str | None = None,
    request_id: str | None = None,
    status: str = "OPEN",
    created_at: str | None = None,
    db_path: str = DB_PATH,
) -> str:
    """Insert a security alert record into the database."""
    now = created_at or utc_now_iso()
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(security_alerts)")
        cols = {row["name"] for row in cursor.fetchall()}
        
        if "created_at" in cols and "timestamp" in cols:
            conn.execute(
                """
                INSERT INTO security_alerts (id, created_at, timestamp, severity, event_type, agent_id, request_id, reason, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, now, now, severity, event_type, agent_id, request_id, reason, status)
            )
        elif "created_at" in cols:
            conn.execute(
                """
                INSERT INTO security_alerts (id, created_at, severity, event_type, agent_id, request_id, reason, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, now, severity, event_type, agent_id, request_id, reason, status)
            )
        else:
            conn.execute(
                """
                INSERT INTO security_alerts (id, timestamp, severity, event_type, agent_id, request_id, reason, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, now, severity, event_type, agent_id, request_id, reason, status)
            )
    return alert_id

def get_security_alerts(
    status: str | None = None,
    limit: int = 50,
    db_path: str = DB_PATH,
) -> list[dict[str, Any]]:
    """Fetch security alerts with optional status filtering."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(security_alerts)")
        cols = {row["name"] for row in cursor.fetchall()}
        order_col = "created_at" if "created_at" in cols else "timestamp"
        
        query = "SELECT * FROM security_alerts"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += f" ORDER BY {order_col} DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            ts = d.get("created_at") or d.get("timestamp") or utc_now_iso()
            d["created_at"] = ts
            d["timestamp"] = ts
            if "resolved_at" not in d:
                d["resolved_at"] = None
            rows.append(d)
        return rows

def resolve_security_alert(alert_id: str, db_path: str = DB_PATH) -> bool:
    """Mark a security alert as RESOLVED and record timestamp."""
    now = utc_now_iso()
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(security_alerts)")
        cols = {row["name"] for row in cursor.fetchall()}
        if "resolved_at" in cols:
            cursor.execute(
                "UPDATE security_alerts SET status = 'RESOLVED', resolved_at = ? WHERE id = ?",
                (now, alert_id)
            )
        else:
            cursor.execute(
                "UPDATE security_alerts SET status = 'RESOLVED' WHERE id = ?",
                (alert_id,)
            )
        return cursor.rowcount > 0

def get_all_policies(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Fetch all configured policies."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM policies ORDER BY role, action_type")
        return [dict(row) for row in cursor.fetchall()]

def get_all_agents(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    """Fetch all registered agents."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

def insert_action_request(
    request_id: str,
    agent_id: str,
    action_type: str,
    resource: str,
    resource_sensitivity: str,
    task_context: str,
    instruction_source: str,
    payload: Any,
    db_path: str = DB_PATH,
) -> str:
    """Insert an intercepted action request into the database."""
    payload_str = json.dumps(payload) if payload is not None else ""
    now = utc_now_iso()
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO action_requests (
                id, agent_id, action_type, resource, resource_sensitivity,
                task_context, instruction_source, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id, agent_id, action_type, resource,
                resource_sensitivity, task_context, instruction_source,
                payload_str, now
            )
        )
    return request_id

def insert_decision(
    decision_id: str,
    request_id: str,
    decision: str,
    risk_score: float,
    injection_score: float,
    provenance_trust: float,
    reasons: list[str],
    latency_ms: float,
    db_path: str = DB_PATH,
) -> str:
    """Persist a Governor authorization decision."""
    now = utc_now_iso()
    reasons_str = json.dumps(reasons)
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO decisions (
                id, request_id, decision, risk_score, injection_score,
                provenance_trust, reasons_json, latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_id, request_id, decision, risk_score,
                injection_score, provenance_trust, reasons_str,
                latency_ms, now
            )
        )
    return decision_id

def insert_approval(
    approval_id: str,
    request_id: str,
    status: str = "PENDING",
    reviewer: str | None = None,
    decided_at: str | None = None,
    db_path: str = DB_PATH,
) -> str:
    """Insert an approval request entry."""
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO approvals (id, request_id, status, reviewer, decided_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (approval_id, request_id, status, reviewer, decided_at)
        )
    return approval_id

def update_approval_status(
    request_id: str,
    status: str,
    reviewer: str,
    db_path: str = DB_PATH,
) -> bool:
    """Update approval status (APPROVED / REJECTED) with reviewer identity."""
    now = utc_now_iso()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            UPDATE approvals
            SET status = ?, reviewer = ?, decided_at = ?
            WHERE request_id = ?
            """,
            (status, reviewer, now, request_id)
        )
        return cursor.rowcount > 0

def insert_audit_event(
    request_id: str | None,
    event: str,
    details: dict[str, Any],
    db_path: str = DB_PATH,
) -> int:
    """Append an event to the immutable audit log."""
    now = utc_now_iso()
    details_str = json.dumps(details)
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO audit_log (request_id, event, details_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (request_id, event, details_str, now)
        )
        return cursor.lastrowid or 0
