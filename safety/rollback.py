"""
Auto-rollback after failed verify step (Phase 4).
"""
from __future__ import annotations
import logging
import os
from typing import Any, Dict, Optional

from .snapshots import SnapshotManager

logger = logging.getLogger(__name__)


class RollbackManager:
    def __init__(self):
        self.snapshots = SnapshotManager()

    def rollback_model_alias(
        self,
        snapshot_id: str,
        audit_log=None,
        session_id: str = '',
    ) -> Dict:
        """
        Restore a model alias to its snapshotted version.
        Returns {'ok': bool, 'message': str, 'snapshot': dict}
        """
        snap = self.snapshots.get(snapshot_id)
        if snap is None:
            return {'ok': False, 'message': f'Snapshot {snapshot_id!r} not found.'}

        state = snap['state']
        model_name = state.get('model_name')
        alias = state.get('alias')
        version = state.get('version')

        if not all([model_name, alias, version]):
            return {
                'ok': False,
                'message': f'Incomplete snapshot state: {state}',
                'snapshot': snap,
            }

        import mlflow
        tracking_uri = os.getenv('MLFLOW_TRACKING_URI', 'sqlite:///./demo/mlruns.db')
        client = mlflow.MlflowClient(tracking_uri=tracking_uri)

        try:
            client.set_registered_model_alias(model_name, alias, str(version))
            self.snapshots.mark_restored(snapshot_id)
            msg = f'Rolled back {model_name}@{alias} to version {version}'
            logger.warning('ROLLBACK: %s', msg)
            if audit_log is not None:
                audit_log.log_event(
                    session_id=session_id,
                    tool='rollback',
                    args={'snapshot_id': snapshot_id, 'model_name': model_name, 'alias': alias, 'version': version},
                    verdict='ROLLBACK',
                    risk_score=80,
                    risk_label='high',
                    result_summary=msg,
                    approved_by='system_auto_rollback',
                )
            return {'ok': True, 'message': msg, 'snapshot': snap}
        except Exception as e:
            return {'ok': False, 'message': f'Rollback failed: {e}', 'snapshot': snap}

    def auto_rollback_after_verify(
        self,
        verify_result: Dict,
        snapshot_id: str,
        session_id: str = '',
        audit_log=None,
    ) -> Optional[Dict]:
        """
        If verify_result indicates failure, trigger rollback.
        Returns rollback result or None if verify passed.
        """
        healthy = verify_result.get('healthy', True)
        ok = verify_result.get('ok', True)
        if healthy and ok:
            logger.info('Verify passed - no rollback needed.')
            return None

        logger.warning('Verify failed (healthy=%s, ok=%s) - triggering auto-rollback!', healthy, ok)
        snap = self.snapshots.get(snapshot_id)
        if snap is None:
            return {'ok': False, 'message': 'Cannot rollback: snapshot not found.'}

        if snap['target_type'] == 'model_alias':
            return self.rollback_model_alias(snapshot_id, audit_log=audit_log, session_id=session_id)

        return {'ok': False, 'message': f'No rollback handler for target_type={snap["target_type"]!r}'}
