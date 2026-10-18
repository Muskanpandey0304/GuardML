"""
Snapshot system (Phase 4).
Records current state before any write tool runs.
For model aliases: stores current version number.
For containers: stores image and config.
"""
from __future__ import annotations
import json
import time
import uuid
import sqlite3
import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(os.getenv('GUARDML_DB', './guardml.db'))


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            target_type TEXT NOT NULL,
            target_name TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at REAL,
            restored BOOLEAN DEFAULT 0,
            restored_at REAL
        )
    """)
    conn.commit()
    conn.close()


ensure_tables()


class SnapshotManager:
    def create(
        self,
        target_type: str,
        target_name: str,
        state: Dict[str, Any],
        session_id: str = '',
    ) -> str:
        """
        Create a snapshot. Returns snapshot_id.
        target_type: 'model_alias' | 'container' | 'generic'
        state: arbitrary dict capturing current state
        """
        snap_id = str(uuid.uuid4())
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO snapshots (id, session_id, target_type, target_name, state, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (snap_id, session_id, target_type, target_name, json.dumps(state), time.time()),
        )
        conn.commit()
        conn.close()
        logger.info('Snapshot created: %s for %s/%s', snap_id, target_type, target_name)
        return snap_id

    def get(self, snapshot_id: str) -> Optional[Dict]:
        conn = _get_conn()
        row = conn.execute('SELECT * FROM snapshots WHERE id = ?', (snapshot_id,)).fetchone()
        conn.close()
        if row is None:
            return None
        d = dict(row)
        d['state'] = json.loads(d['state'])
        return d

    def latest_for(
        self, target_type: str, target_name: str, session_id: str = ''
    ) -> Optional[Dict]:
        conn = _get_conn()
        if session_id:
            row = conn.execute(
                """
                SELECT * FROM snapshots WHERE target_type=? AND target_name=? AND session_id=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (target_type, target_name, session_id),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT * FROM snapshots WHERE target_type=? AND target_name=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (target_type, target_name),
            ).fetchone()
        conn.close()
        if row is None:
            return None
        d = dict(row)
        d['state'] = json.loads(d['state'])
        return d

    def mark_restored(self, snapshot_id: str):
        conn = _get_conn()
        conn.execute(
            'UPDATE snapshots SET restored=1, restored_at=? WHERE id=?',
            (time.time(), snapshot_id),
        )
        conn.commit()
        conn.close()

    def snapshot_model_alias(
        self,
        model_name: str,
        alias: str,
        session_id: str = '',
    ) -> str:
        """Snapshot the current version a model alias points to."""
        import mlflow
        import os
        tracking_uri = os.getenv('MLFLOW_TRACKING_URI', 'sqlite:///./demo/mlruns.db')
        client = mlflow.MlflowClient(tracking_uri=tracking_uri)
        try:
            mv = client.get_model_version_by_alias(model_name, alias)
            state = {
                'model_name': model_name,
                'alias': alias,
                'version': mv.version,
                'run_id': mv.run_id,
            }
        except Exception as e:
            state = {'model_name': model_name, 'alias': alias, 'version': None, 'error': str(e)}
        return self.create(
            target_type='model_alias',
            target_name=f'{model_name}@{alias}',
            state=state,
            session_id=session_id,
        )
