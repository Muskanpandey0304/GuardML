"""
Hash-chained audit log (Phase 6).
Each entry stores: timestamp, session_id, tool, masked_args, verdict,
risk_score, approved_by, result_summary, prev_hash, hash.
"""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(os.getenv('GUARDML_DB', './guardml.db'))


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _compute_hash(entry: Dict, prev_hash: str) -> str:
    payload = json.dumps(entry, sort_keys=True, default=str) + prev_hash
    return hashlib.sha256(payload.encode()).hexdigest()


def ensure_tables():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            seq INTEGER,
            timestamp REAL NOT NULL,
            session_id TEXT,
            tool TEXT NOT NULL,
            args TEXT,
            verdict TEXT,
            risk_score INTEGER,
            risk_label TEXT,
            approved_by TEXT,
            result_summary TEXT,
            prev_hash TEXT,
            entry_hash TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON audit_log(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)")
    try:
        # A second writer reusing a seq would fork the chain; make that impossible.
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_seq_unique ON audit_log(seq)")
    except sqlite3.IntegrityError:
        pass  # legacy DB that already contains duplicate seqs; verify_chain() will flag it
    conn.commit()
    conn.close()


ensure_tables()


class AuditLog:
    def log_event(
        self,
        session_id: str,
        tool: str,
        args: Any,
        verdict: str,
        risk_score: int = 0,
        risk_label: str = 'low',
        result_summary: str = '',
        approved_by: str = '',
    ) -> str:
        """Log an event. Returns entry id."""
        entry_id = str(uuid.uuid4())
        now = time.time()

        conn = _get_conn()
        # Manual transaction control: BEGIN IMMEDIATE takes the write lock *before*
        # reading the chain tail, so concurrent sessions cannot read the same
        # prev_hash/seq and fork the chain.
        conn.isolation_level = None
        conn.execute('BEGIN IMMEDIATE')
        try:
            return self._append(conn, entry_id, now, session_id, tool, args,
                                verdict, risk_score, risk_label, approved_by,
                                result_summary)
        except BaseException:
            conn.execute('ROLLBACK')
            raise
        finally:
            conn.close()

    def _append(
        self, conn, entry_id, now, session_id, tool, args, verdict,
        risk_score, risk_label, approved_by, result_summary,
    ) -> str:
        last = conn.execute(
            'SELECT entry_hash, seq FROM audit_log ORDER BY seq DESC LIMIT 1'
        ).fetchone()
        prev_hash = last['entry_hash'] if last else '0' * 64
        seq = (last['seq'] + 1) if last else 0

        entry_dict = {
            'id': entry_id,
            'seq': seq,
            'timestamp': now,
            'session_id': session_id,
            'tool': tool,
            'args': json.dumps(args, default=str),
            'verdict': verdict,
            'risk_score': risk_score,
            'risk_label': risk_label,
            'approved_by': approved_by,
            'result_summary': result_summary,
        }
        entry_hash = _compute_hash(entry_dict, prev_hash)

        conn.execute(
            """
            INSERT INTO audit_log
            (id, seq, timestamp, session_id, tool, args, verdict, risk_score,
             risk_label, approved_by, result_summary, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id, seq, now, session_id, tool,
                json.dumps(args, default=str), verdict,
                risk_score, risk_label, approved_by, result_summary,
                prev_hash, entry_hash,
            ),
        )
        conn.execute('COMMIT')
        return entry_id

    def get_session(self, session_id: str) -> List[Dict]:
        conn = _get_conn()
        rows = conn.execute(
            'SELECT * FROM audit_log WHERE session_id=? ORDER BY seq ASC',
            (session_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_all(self, limit: int = 200) -> List[Dict]:
        conn = _get_conn()
        rows = conn.execute(
            'SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?', (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def verify_chain(self) -> Dict:
        """
        Walk the chain and verify hashes.
        Returns {'ok': bool, 'first_tampered_seq': int|None, 'checked': int}
        """
        conn = _get_conn()
        rows = conn.execute('SELECT * FROM audit_log ORDER BY seq ASC').fetchall()
        conn.close()

        if not rows:
            return {'ok': True, 'first_tampered_seq': None, 'checked': 0}

        prev_hash = '0' * 64
        for row in rows:
            entry_dict = {
                'id': row['id'],
                'seq': row['seq'],
                'timestamp': row['timestamp'],
                'session_id': row['session_id'],
                'tool': row['tool'],
                'args': row['args'],
                'verdict': row['verdict'],
                'risk_score': row['risk_score'],
                'risk_label': row['risk_label'],
                'approved_by': row['approved_by'],
                'result_summary': row['result_summary'],
            }
            expected_hash = _compute_hash(entry_dict, prev_hash)
            if expected_hash != row['entry_hash']:
                return {
                    'ok': False,
                    'first_tampered_seq': row['seq'],
                    'entry_id': row['id'],
                    'checked': row['seq'],
                }
            prev_hash = row['entry_hash']

        return {'ok': True, 'first_tampered_seq': None, 'checked': len(rows)}
