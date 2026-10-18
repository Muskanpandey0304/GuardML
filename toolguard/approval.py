"""
Step 7: Approval flow with full state machine.
States: pending → approved | denied | expired → executed

Bypass defenses:
- call_hash = sha256(session_id + env + tool_name + canonical_json(args))
  Locks args — any change after approval is detected and rejected.
- Single-use: 'executed' status prevents re-use of the same approval.
- Re-check: full guard.check() re-run at execution time (policy may have changed).
- TTL: expired approvals are rejected.
- No tool exposes an approve endpoint — the LLM cannot self-approve.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .masking import mask_value

logger = logging.getLogger(__name__)

DB_PATH = Path(os.getenv("GUARDML_DB", "./guardml.db"))


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables() -> None:
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS approvals (
            id               TEXT PRIMARY KEY,
            session_id       TEXT NOT NULL,
            tool_name        TEXT NOT NULL,
            canonical_args   TEXT NOT NULL,
            call_hash        TEXT NOT NULL,
            risk_score       INTEGER,
            risk_label       TEXT,
            reasons          TEXT,
            llm_reason       TEXT,
            env              TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'pending',
            snapshot_ref     TEXT,
            created_at       REAL NOT NULL,
            expires_at       REAL NOT NULL,
            resolved_at      REAL,
            resolved_by      TEXT,
            executed_at      REAL
        )
    """)
    conn.commit()
    conn.close()


try:
    ensure_tables()
except Exception as e:
    logger.warning("[Approval] Could not create approval tables: %s", e)


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------
def _canonical_json(args: Dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, default=str)


def _compute_call_hash(
    session_id: str, env: str, tool_name: str, args: Dict[str, Any]
) -> str:
    payload = session_id + env + tool_name + _canonical_json(args)
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# ApprovalGate
# ---------------------------------------------------------------------------
class ApprovalGate:
    def __init__(self, ttl_seconds: Optional[float] = None):
        self.ttl_seconds = ttl_seconds or float(
            os.getenv("GUARDML_APPROVAL_TIMEOUT", "600")
        )

    def create_request(
        self,
        session_id: str,
        tool_name: str,
        args: Dict[str, Any],
        risk_score: int,
        risk_label: str,
        reasons: Optional[List[str]] = None,
        env: str = "staging",
        llm_reason: str = "",
        snapshot_ref: str = "",
        matched_rules: Optional[List[str]] = None,
        **kwargs,
    ) -> str:
        """
        Create approval request. Returns approval_id.
        call_hash locks args — changing them after approval will be detected.
        """
        reasons = reasons or matched_rules or []

        approval_id = str(uuid.uuid4())
        now = time.time()
        # Hash the RAW args (so a later execute() with the same args matches), but
        # persist only the masked copy so secrets never land in the approvals table.
        call_hash = _compute_call_hash(session_id, env, tool_name, args)
        stored_args = _canonical_json(mask_value(args))
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO approvals
            (id, session_id, tool_name, canonical_args, call_hash, risk_score,
             risk_label, reasons, llm_reason, env, status, snapshot_ref, created_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                approval_id, session_id, tool_name, stored_args,
                call_hash, risk_score, risk_label, json.dumps(reasons),
                llm_reason, env, "pending", snapshot_ref, now, now + self.ttl_seconds,
            ),
        )
        conn.commit()
        conn.close()
        logger.info(
            "[Approval] Created %s tool=%s session=%s hash=%.12s",
            approval_id, tool_name, session_id, call_hash,
        )
        return approval_id

    def get(self, approval_id: str) -> Optional[Dict]:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def resolve(self, approval_id: str, action: str, resolved_by: str = "ui") -> bool:
        """
        action: 'approved' or 'denied'
        resolved_by: human identity — never the agent.
        The agent has no tool to call this endpoint.
        """
        assert action in ("approved", "denied")
        conn = _get_conn()
        conn.execute(
            "UPDATE approvals SET status=?, resolved_at=?, resolved_by=? "
            "WHERE id=? AND status='pending'",
            (action, time.time(), resolved_by, approval_id),
        )
        conn.commit()
        conn.close()
        logger.info("[Approval] %s resolved=%s by=%s", approval_id, action, resolved_by)
        return True

    def validate_for_execution(
        self,
        approval_id: str,
        tool_name: str,
        args: Dict[str, Any],
        env: str,
        session_id: str,
    ) -> Dict:
        """
        Called by executor before running an approved tool.
        Checks: status==approved, not expired, not already executed, hash matches.
        """
        row = self.get(approval_id)
        if row is None:
            return {"ok": False, "reason": "Approval not found"}

        # Expiry check
        if time.time() > row["expires_at"] or row["status"] == "expired":
            self._expire(approval_id)
            return {"ok": False, "reason": "Approval has expired"}

        if row["status"] == "denied":
            return {"ok": False, "reason": "Approval was denied"}

        if row["status"] == "executed":
            return {"ok": False, "reason": "Approval already used (single-use only)"}

        if row["status"] != "approved":
            return {
                "ok": False,
                "reason": f"Approval status is {row['status']!r} — must be 'approved'",
            }

        # Hash check — args cannot change after approval was created
        expected_hash = _compute_call_hash(session_id, env, tool_name, args)
        if expected_hash != row["call_hash"]:
            logger.warning(
                "[Approval] HASH MISMATCH for %s — args changed after approval!", approval_id
            )
            return {
                "ok": False,
                "reason": "Approval hash mismatch — arguments changed after approval was granted",
            }

        # Tool and env must match exactly
        if row["tool_name"] != tool_name:
            return {"ok": False, "reason": "Tool name mismatch with approval"}
        if row["env"] != env:
            return {"ok": False, "reason": "Environment mismatch with approval"}

        return {"ok": True, "snapshot_ref": row.get("snapshot_ref", "")}

    def mark_executed(self, approval_id: str) -> None:
        """Mark single-use — prevents any re-use of this approval."""
        conn = _get_conn()
        conn.execute(
            "UPDATE approvals SET status='executed', executed_at=? WHERE id=?",
            (time.time(), approval_id),
        )
        conn.commit()
        conn.close()

    def poll_until_resolved(
        self, approval_id: str, poll_interval: float = 1.0
    ) -> str:
        """Block until resolved or expired. Returns 'approved', 'denied', or 'expired'."""
        while True:
            row = self.get(approval_id)
            if row is None:
                return "denied"
            if time.time() > row["expires_at"] and row["status"] == "pending":
                self._expire(approval_id)
                return "expired"
            if row["status"] != "pending":
                return row["status"]
            time.sleep(poll_interval)

    def list_pending(self, session_id: str = "") -> List[Dict]:
        conn = _get_conn()
        if session_id:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='pending' AND session_id=? "
                "ORDER BY created_at DESC",
                (session_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='pending' ORDER BY created_at DESC"
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def _expire(self, approval_id: str) -> None:
        conn = _get_conn()
        conn.execute(
            "UPDATE approvals SET status='expired' WHERE id=? AND status='pending'",
            (approval_id,),
        )
        conn.commit()
        conn.close()
