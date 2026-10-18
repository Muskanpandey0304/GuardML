"""
GuardML agent loop.

The LLM only PROPOSES tool calls. Every call is executed through
GuardedExecutor, the single choke point that runs ToolGuard, the approval gate,
snapshot -> execute -> verify -> rollback, output masking/sanitising, taint
tracking and the audit log. This module never calls tool.run() itself.
"""
from __future__ import annotations
import os
import re
import json
import uuid
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

from .prompts import SYSTEM_PROMPT
from .schemas import get_tool_schemas
from .llm import LLMProvider, select_provider, make_completer

try:
    from guardml.toolguard.schemas import ToolCall, Decision
    from guardml.toolguard.guard import ToolGuard
    from guardml.toolguard.executor import GuardedExecutor
    from guardml.toolguard.intent import IntentJudge
    from guardml.toolguard.validation import coerce_identifier_args
    from guardml.toolguard.masking import mask_value
    from guardml.toolguard.approval import ApprovalGate
    from guardml.tools.registry import get_registry
    from guardml.audit.log import AuditLog
    from guardml.safety.snapshots import SnapshotManager
    from guardml.safety.rollback import RollbackManager
except ImportError:
    try:
        from toolguard.schemas import ToolCall, Decision
        from toolguard.guard import ToolGuard
        from toolguard.executor import GuardedExecutor
        from toolguard.intent import IntentJudge
        from toolguard.validation import coerce_identifier_args
        from toolguard.masking import mask_value
        from toolguard.approval import ApprovalGate
        from tools.registry import get_registry
        from audit.log import AuditLog
        from safety.snapshots import SnapshotManager
        from safety.rollback import RollbackManager
    except ImportError:
        from ..toolguard.schemas import ToolCall, Decision
        from ..toolguard.guard import ToolGuard
        from ..toolguard.executor import GuardedExecutor
        from ..toolguard.intent import IntentJudge
        from ..toolguard.validation import coerce_identifier_args
        from ..toolguard.masking import mask_value
        from ..toolguard.approval import ApprovalGate
        from ..tools.registry import get_registry
        from ..audit.log import AuditLog
        from ..safety.snapshots import SnapshotManager
        from ..safety.rollback import RollbackManager


logger = logging.getLogger(__name__)

MAX_TOOL_CALLS = int(os.getenv('GUARDML_MAX_TOOL_CALLS', '10'))
MAX_REASON_CHARS = 500
# Demo-mode only: a destructive REQUEST, not just a word ("accuracy drop" is not one).
_DESTRUCTIVE_RE = re.compile(
    r'\b(delete|remove|rm\s+-rf|drop\s+(table|database|the|model)|truncate|exec)\b'
)


class AgentLoop:
    def __init__(
        self,
        environment: str = 'staging',
        policy_path: Optional[str] = None,
        model: Optional[str] = None,
        on_step: Optional[Callable] = None,
        provider: Optional[LLMProvider] = None,
        demo_mode: bool = False,
        registry=None,
        audit=None,
        approval_gate=None,
        snapshots=None,
        rollback=None,
        intent_check: Optional[bool] = None,
        system_prompt: Optional[str] = None,
    ):
        self.environment = environment
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        # None => follow GUARDML_INTENT_CHECK (default on). Needs a real LLM to run.
        self.intent_check = (
            os.getenv('GUARDML_INTENT_CHECK', '1').strip().lower() not in ('0', 'off', 'false', 'no')
            if intent_check is None else intent_check
        )
        self.model = model  # optional model override for whichever provider is selected
        self.provider = provider
        self.demo_mode = demo_mode
        self.on_step = on_step  # callback(step_dict) for streaming to the UI

        self.registry = registry or get_registry()
        self.audit = audit or AuditLog()
        self.snapshots = snapshots or SnapshotManager()
        self.rollback = rollback or RollbackManager()
        self.approval_gate = approval_gate or ApprovalGate(
            ttl_seconds=float(os.getenv('GUARDML_APPROVAL_TIMEOUT', '300'))
        )
        self.executor = GuardedExecutor(
            guard=ToolGuard(policy_path, registry=self.registry, environment=environment),
            approval_gate=self.approval_gate,
            audit_log=self.audit,
            registry=self.registry,
            snapshots=self.snapshots,
            rollback=self.rollback,
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def run(self, user_message: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Run the agent for one user message. Returns the final response dict."""
        session_id = session_id or str(uuid.uuid4())

        # The user's own words are the only trusted source of argument values.
        self.executor.register_user_message(session_id, self.environment, user_message)

        provider = None if self.demo_mode else (self.provider or select_provider())
        if provider is None:
            return self._run_demo_mode(user_message, session_id)
        if self.model:
            provider.model = self.model
        if self.intent_check and self.executor.guard.intent_judge is None:
            self.executor.guard.intent_judge = IntentJudge(
                make_completer(provider, os.getenv('GUARDML_JUDGE_MODEL') or None)
            )

        messages: List[Dict[str, Any]] = [{'role': 'user', 'content': user_message}]
        tool_schemas = get_tool_schemas(self.registry)
        tool_calls_made = 0
        steps: List[Dict[str, Any]] = []
        llm_failed = False

        while tool_calls_made < MAX_TOOL_CALLS:
            response = provider.generate(self.system_prompt, messages, tool_schemas)
            if response is None:
                llm_failed = True
                break

            if not response.tool_calls:
                steps.append({'type': 'final_answer', 'text': response.text})
                self._emit(steps[-1])
                return {
                    'session_id': session_id,
                    'answer': response.text,
                    'steps': steps,
                    'tool_calls': tool_calls_made,
                    'complete': True,
                }

            messages.append({
                'role': 'assistant',
                'text': response.text,
                'tool_calls': response.tool_calls,
                'raw': response.raw,
            })

            results = []
            for tc in response.tool_calls:
                step, content = self._handle_tool_call(tc.name, tc.input, session_id)
                tool_calls_made += 1
                results.append({'id': tc.id, 'name': tc.name, 'content': content})
                steps.append(step)
                self._emit(step)
            messages.append({'role': 'tool', 'results': results})

        if llm_failed and not steps:
            # Do NOT fall back to canned output: the user asked a real model.
            return {
                'session_id': session_id,
                'answer': ('⚠️ The LLM provider did not respond (see server logs). '
                           'No tools were run and no conclusions were drawn.'),
                'steps': steps,
                'tool_calls': 0,
                'complete': False,
                'llm_failed': True,
            }

        suffix = ('the LLM provider stopped responding' if llm_failed
                  else f'the tool-call budget ({MAX_TOOL_CALLS}) was reached')
        return {
            'session_id': session_id,
            'answer': (f'🔍 **Partial investigation** ({suffix}): completed {len(steps)} step(s). '
                       'See the steps panel for the tool findings.'),
            'steps': steps,
            'tool_calls': tool_calls_made,
            'complete': True,
            'llm_failed': llm_failed,
        }

    # ------------------------------------------------------------------
    # One tool call, end to end, through the executor
    # ------------------------------------------------------------------
    def _handle_tool_call(
        self, tool_name: str, tool_args: Any, session_id: str
    ) -> Tuple[Dict[str, Any], str]:
        """
        Returns (step_for_ui, content_for_llm).
        step['outcome'] is one of: allowed, blocked, approved_executed,
        approval_denied, approval_expired.
        """
        args = dict(tool_args) if isinstance(tool_args, dict) else {}
        tool = self.registry.get(tool_name)
        if tool is not None:  # whole numbers for string identifiers (version=1) -> '1'
            args = coerce_identifier_args(args, getattr(tool, 'parameters_schema', None) or {})
        reason = args.pop('reason', None)  # a note for humans, never a tool argument
        if reason is not None:
            reason = str(reason)[:MAX_REASON_CHARS]

        step: Dict[str, Any] = {
            'type': 'tool_call',
            'tool': tool_name,
            'args': mask_value(args),
            'verdict': None,
            'risk_score': 0,
            'risk_label': 'low',
            'result': None,
            'outcome': 'allowed',
        }
        if reason:
            step['reason'] = mask_value(reason)

        call = ToolCall(
            session_id=session_id, tool_name=tool_name, args=args,
            reason=reason, env=self.environment,
        )
        result = self.executor.execute(call)
        verdict = result.verdict
        step.update(
            verdict=verdict.decision.value,
            risk_score=verdict.risk_score,
            risk_label=verdict.risk_label,
            reasons=list(verdict.reasons),
            matched_rules=list(verdict.matched_rules),
        )

        if verdict.decision == Decision.BLOCK:
            step['outcome'] = 'blocked'

        elif verdict.decision == Decision.NEEDS_APPROVAL and verdict.approval_id:
            approval_id = verdict.approval_id
            step['approval_id'] = approval_id
            self._emit({**step, 'type': 'needs_approval'})

            status = self.approval_gate.poll_until_resolved(approval_id)
            step['approval_status'] = status
            if status == 'approved':
                # Re-validated by the executor: hash, TTL, single use, fresh guard check.
                result = self.executor.execute(call, approval_id=approval_id)
                step['outcome'] = 'approved_executed'
            else:
                step['outcome'] = f'approval_{status}'
                step['result'] = {'ok': False, 'error': f'Approval {status}'}
                self.audit.log_event(
                    session_id=session_id, tool=tool_name, args=mask_value(args),
                    verdict=f'APPROVAL_{status.upper()}',
                    risk_score=verdict.risk_score, risk_label=verdict.risk_label,
                    result_summary=f'Approval {status}',
                )
                content = json.dumps({'ok': False, 'error': f'Action {tool_name!r} was {status}.'})
                return step, f'<tool_output tool="{tool_name}" untrusted="true">\n{content}\n</tool_output>'

        step['result'] = self._parse_output(result.output)
        verification = result.verification
        content = result.for_llm()
        if verification is not None:
            step['verification'] = verification
            if verification['action'] == 'rolled_back':
                step['rollback'] = verification.get('rollback')
                self._emit({'type': 'auto_rollback', 'result': step['rollback']})
            # Tell the model what happened after its change, so it can't claim success blindly.
            content += '\n<verification>' + json.dumps(verification, default=str) + '</verification>'
        return step, content

    @staticmethod
    def _parse_output(output: str) -> Any:
        try:
            return json.loads(output)
        except (TypeError, ValueError):
            return {'raw': output}

    # ------------------------------------------------------------------
    # Deterministic demo mode (no LLM key): scripted tool plans, real guard
    # ------------------------------------------------------------------
    def _run_demo_mode(self, user_message: str, session_id: str) -> Dict[str, Any]:
        """
        No LLM is involved. A fixed tool plan is chosen from keywords and every call
        still goes through the real ToolGuard / executor / approval flow.
        """
        msg = user_message.lower()
        steps: List[Dict[str, Any]] = []

        if 'roll back' in msg or 'rollback' in msg:
            plan = [('mlflow_set_alias',
                     {'model_name': 'fraud_classifier', 'alias': 'production', 'version': '1',
                      'reason': 'User asked to roll production back to version 1.'})]
        elif _DESTRUCTIVE_RE.search(msg):
            plan = [('mlflow_delete_model', {'model_name': 'fraud_classifier'})]
        else:
            plan = [
                ('mlflow_get_production_model', {'model_name': 'fraud_classifier'}),
                ('mlflow_list_runs', {'experiment_name': 'fraud_detection'}),
                ('drift_report', {'current_path': 'demo/data/current.csv',
                                  'reference_path': 'demo/data/reference.csv'}),
                ('data_quality_check', {'data_path': 'demo/data/current.csv'}),
            ]

        def done(answer: str) -> Dict[str, Any]:
            return {'session_id': session_id, 'answer': answer, 'steps': steps,
                    'tool_calls': len(steps), 'complete': True}

        for tool_name, tool_args in plan:
            step, _ = self._handle_tool_call(tool_name, tool_args, session_id)
            steps.append(step)
            self._emit(step)
            outcome = step['outcome']

            if outcome == 'blocked':
                err = (step.get('result') or {}).get('error', 'Blocked by safety policy')
                return done(f'🛑 **BLOCKED BY TOOLGUARD**: `{tool_name}` was not run.\n\n**Reason**: {err}')
            if outcome in ('approval_denied', 'approval_expired'):
                return done(f'Action `{tool_name}` was {outcome.split("_")[1]}. No changes were made.')
            if outcome == 'approved_executed':
                ver = step.get('verification') or {}
                if ver.get('action') == 'kept_unverified':
                    return done(f'✅ `{tool_name}` was approved and executed. ⚠️ **Not verified**: '
                                f'the health check at {ver.get("url")} could not be reached '
                                f'({ver.get("detail")}). The change was kept because the '
                                f'{self.environment!r} policy is "warn"; check the service manually.')
                if step.get('rollback'):
                    return done(f'↩️ `{tool_name}` was approved and executed, but the post-change '
                                f'health check failed, so it was **automatically rolled back**: '
                                f'{step["rollback"].get("message", "")}')
                ok = (step.get('result') or {}).get('ok', False)
                return done(f'✅ **APPROVED & EXECUTED**: `{tool_name}` ran successfully.' if ok
                            else f'⚠️ `{tool_name}` was approved but failed. See the steps panel.')

        return done(
            '🔍 **Demo mode** (no LLM API key configured): a scripted investigation ran four '
            'read-only tools through ToolGuard. Open each step in the panel for the real tool '
            'output. Configure GEMINI_API_KEY or ANTHROPIC_API_KEY for an LLM-written diagnosis.'
        )

    def _emit(self, step: Dict[str, Any]) -> None:
        if self.on_step:
            try:
                self.on_step(step)
            except Exception:
                logger.debug('on_step callback failed', exc_info=True)
