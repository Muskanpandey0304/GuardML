"""
Session replay (Phase 6).
Prints or yields session steps from the audit log.
"""
from __future__ import annotations
import json
from typing import Generator, Dict

from .log import AuditLog


class SessionReplay:
    def __init__(self):
        self.audit = AuditLog()

    def replay(
        self, session_id: str
    ) -> Generator[Dict, None, None]:
        """
        Yield each step in order.
        Each step is a dict from the audit log.
        """
        steps = self.audit.get_session(session_id)
        for step in steps:
            yield step

    def replay_text(self, session_id: str) -> str:
        """Return a human-readable replay of the session."""
        lines = [f'=== Session Replay: {session_id} ===']
        for step in self.replay(session_id):
            import datetime
            ts = datetime.datetime.fromtimestamp(step['timestamp']).strftime('%H:%M:%S')
            verdict = step.get('verdict', '?')
            tool = step.get('tool', '?')
            risk = step.get('risk_label', '?')
            result = step.get('result_summary', '')[:120]
            lines.append(
                f'[{ts}] {tool:30s} | verdict={verdict:20s} | risk={risk:6s} | {result}'
            )
        return '\n'.join(lines)
