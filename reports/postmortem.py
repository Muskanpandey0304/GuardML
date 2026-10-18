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

from google import genai
from google.genai import types as genai_types
from dotenv import load_dotenv
# Load .env relative to this file so it works from any working directory
load_dotenv(Path(__file__).parent.parent / '.env')
load_dotenv()  # also try cwd

try:
    from guardml.audit.log import AuditLog
except ImportError:
    try:
        from audit.log import AuditLog
    except ImportError:
        from ..audit.log import AuditLog


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
        api_key = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY') or ''
        if not api_key:
            raise ValueError('GEMINI_API_KEY not set in environment or .env file')
        self.client = genai.Client(api_key=api_key)
        self.model_name = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')

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

        # Try models in order — fallback if overloaded or deprecated
        models_to_try = [
            self.model_name,
            'gemini-1.5-flash',
            'gemini-3.5-flash',
            'gemini-3.5-flash-lite',
        ]
        last_error = None
        for model in models_to_try:
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=prompt,
                )
                report = response.text
                break
            except Exception as e:
                last_error = e
                continue
        else:
            raise last_error

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
