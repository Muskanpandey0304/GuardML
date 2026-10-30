"""
Post-mortem report generator (Phase 7).
Facts come only from the audit log and the final diagnosis.
The LLM is given a fixed template and must not add facts from its training data.
"""
from __future__ import annotations
import os
import json
import time
import datetime
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
# Load .env relative to this file so it works from any working directory
load_dotenv(Path(__file__).parent.parent / '.env')
load_dotenv()  # also try cwd

try:
    from guardml.audit.log import AuditLog
    from guardml.agent.llm import select_provider
except ImportError:
    try:
        from audit.log import AuditLog
        from agent.llm import select_provider
    except ImportError:
        from ..audit.log import AuditLog
        from ..agent.llm import select_provider


REPORTS_DIR = Path(os.getenv('GUARDML_REPORTS_DIR', './reports'))
REPORTS_DIR.mkdir(exist_ok=True)

POSTMORTEM_TEMPLATE = """
You are writing a technical post-mortem report. You MUST only use facts from the provided
audit log and diagnosis text. Do NOT add any facts from your training data.

Fill in this exact structure:

# Incident Post-Mortem: {title}
**Date**: {date}
**Session ID**: {session_id}

## Timeline
(List events in chronological order, with timestamps, based ONLY on the audit log below)

## Impact
(What was affected? Based ONLY on the evidence in the diagnosis and audit log)

## Root Cause
(1-2 sentence technical explanation, based ONLY on the evidence provided)

## Fix Applied
(What action was taken, based ONLY on the audit log)

## Prevention Steps
(3-5 concrete steps to prevent recurrence, grounded in the evidence found)

---
## Audit Log (facts you may use):
{audit_log}

## Diagnosis:
{diagnosis}

IMPORTANT: Do not include ANY information not present in the Audit Log or Diagnosis sections above.
"""


class PostMortemGenerator:
    def __init__(self):
        self.audit = AuditLog()
        # Same provider the agent uses (Ollama, Gemini or Anthropic, chosen via GUARDML_LLM_PROVIDER).
        self.provider = select_provider()
        if self.provider is None:
            raise ValueError('No LLM provider configured: set GUARDML_LLM_PROVIDER=ollama, '
                             'or GEMINI_API_KEY / ANTHROPIC_API_KEY')

    def generate(
        self,
        session_id: str,
        diagnosis: str,
        title: str = 'Model Performance Incident',
    ) -> str:
        """
        Generate a post-mortem report. Returns Markdown string.
        Facts come ONLY from the audit log + diagnosis.
        """
        steps = self.audit.get_session(session_id)
        audit_log_text = self._format_audit_log(steps)

        date_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')
        prompt = POSTMORTEM_TEMPLATE.format(
            title=title,
            date=date_str,
            session_id=session_id,
            audit_log=audit_log_text,
            diagnosis=diagnosis,
        )

        response = self.provider.generate(
            'You write factual incident post-mortems from the evidence given, nothing else.',
            [{'role': 'user', 'content': prompt}],
            [],
        )
        if response is None or not response.text:
            raise RuntimeError(f'{self.provider.name}/{self.provider.model} returned no post-mortem text')
        report = response.text

        # Save to file
        filename = REPORTS_DIR / f'postmortem_{session_id[:8]}_{int(time.time())}.md'
        filename.write_text(report, encoding='utf-8')
        return report

    def _format_audit_log(self, steps: List[Dict]) -> str:
        lines = []
        for step in steps:
            ts = datetime.datetime.fromtimestamp(step['timestamp']).strftime('%H:%M:%S')
            lines.append(
                f"[{ts}] tool={step['tool']} verdict={step['verdict']} "
                f"risk={step['risk_label']} result={step.get('result_summary', '')[:200]}"
            )
        return '\n'.join(lines)


def generate_postmortem(session_id: str, diagnosis: str, title: str = 'Model Performance Incident') -> str:
    """Convenience function to generate a post-mortem report."""
    generator = PostMortemGenerator()
    return generator.generate(session_id=session_id, diagnosis=diagnosis, title=title)
