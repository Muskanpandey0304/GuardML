"""
Step 3: The check pipeline — guard.check().
Runs checks in strict order. Any check can raise severity. BLOCK stops immediately.

Order:
  1. Registered? → BLOCK if unknown
  2. Blocked tool? → BLOCK if on list
  3. Session limits (call_count, locked) → BLOCK
  4. Argument validation → BLOCK on failure
  5. Blocked patterns (all string args, normalized) → BLOCK on match
  6. Risk scoring
  7. Policy decision → ALLOW / NEEDS_APPROVAL / BLOCK
  8. Risk escalation: score≥70 → NEEDS_APPROVAL; medium without reason → ask for reason
"""
from __future__ import annotations

import logging
from typing import Optional

from .schemas import Decision, SessionState, ToolCall, Verdict
from .policy import PolicyLoader
from .risk import ToolRiskMeta, compute_risk
from .provenance import find_untrusted_args, describe as describe_provenance
from .validation import (
    scan_args_for_patterns, ValidationError, SchemaContext, validate_against_schema,
    validate_identifier, validate_path, validate_string_max,
)
from . import session as session_store

logger = logging.getLogger(__name__)


class ToolGuard:
    def __init__(
        self,
        policy_path: Optional[str] = None,
        registry=None,
        environment: str = 'staging',
        session_call_count: int = 0,
        intent_judge=None,
        **kwargs,
    ):
        self.policy = PolicyLoader(policy_path)
        self._registry = registry
        self.environment = environment
        self.session_call_count = session_call_count
        # Optional IntentJudge (toolguard/intent.py). None => the intent check is inactive.
        self.intent_judge = intent_judge

    def _get_registry(self):
        if self._registry is not None:
            return self._registry
        try:
            from guardml.tools.registry import get_registry
        except ImportError:
            try:
                from tools.registry import get_registry
            except ImportError:
                from ..tools.registry import get_registry
        return get_registry()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def check(self, call: ToolCall | str, args: Optional[dict] = None, **kwargs) -> Verdict:
        """
        Run the 8-step check pipeline.
        Severity can only increase — never decrease.
        """
        if isinstance(call, str):
            tool_name = call
            call_args = args if args is not None else {}
            session_id = kwargs.get('session_id', 'test_session')
            env = kwargs.get('env', self.environment)
            call = ToolCall(session_id=session_id, tool_name=tool_name, args=call_args, env=env)

        # recheck=True: the executor re-runs the guard when an APPROVED call is about to execute.
        # That is the same call, not a new one, so it must not use up the call budget or trigger
        # the repeat-write penalty (which would make the executed risk differ from the approved one).
        recheck = bool(kwargs.get('recheck', False))
        session = session_store.get_or_create(call.session_id, call.env)
        if self.session_call_count:
            session.call_count = max(session.call_count, self.session_call_count)

        registry = self._get_registry()

        # ── Step 1: Is the tool registered? ──────────────────────────────────
        tool = registry.get(call.tool_name)
        if tool is None:
            v = Verdict.block(
                reason=f"Unknown tool: {call.tool_name!r}",
                rule="unregistered_tool",
            )
            self._finalize(session, call, v, recheck)
            return v

        # ── Step 2: Blocked tool list ─────────────────────────────────────────
        if call.tool_name in self.policy.blocked_tools:
            v = Verdict.block(
                reason=f"{call.tool_name!r} is on the blocked_tools list (never runs)",
                rule="blocked_tool",
            )
            self._finalize(session, call, v, recheck)
            return v

        # ── Step 3: Session limits ────────────────────────────────────────────
        limits = self.policy.limits
        if session.locked:
            v = Verdict.block(
                reason=f"Session is locked after {session.blocked_count} blocked calls",
                rule="session_locked",
            )
            return v  # do not update locked session

        if session.call_count >= limits.max_calls_per_session:
            v = Verdict.block(
                reason=f"Session call limit ({limits.max_calls_per_session}) reached",
                rule="call_limit",
            )
            self._finalize(session, call, v, recheck)
            return v

        # ── Step 4: Argument validation ───────────────────────────────────────
        try:
            self._validate_args(call, tool)
        except ValidationError as e:
            v = Verdict.block(
                reason=f"Argument validation failed: {e}",
                rule="arg_validation",
            )
            self._finalize(session, call, v, recheck)
            return v

        # ── Step 5: Blocked patterns ──────────────────────────────────────────
        matched = scan_args_for_patterns(
            call.args, self.policy.matches_blocked_pattern
        )
        if matched:
            v = Verdict.block(
                reason=f"Blocked pattern in arguments: {matched!r}",
                rule=f"blocked_pattern:{matched}",
            )
            self._finalize(session, call, v, recheck)
            return v

        # ── Step 6: Risk scoring ──────────────────────────────────────────────
        tool_class = getattr(tool, "risk_level", None)
        tool_class_str = tool_class.value if tool_class else "read"

        base = self.policy.base_risk(tool_class_str)
        env_bonus = self.policy.env_risk_bonus(call.env)
        reversibility, blast = ToolRiskMeta.get(call.tool_name)
        protected = self.policy.any_arg_protected(call.args)
        tainted = session.tainted and tool_class_str != "read"
        repeat = (
            (call.tool_name in session.write_tools_used and not recheck)
            or session.blocked_count > 0
        )

        # Provenance: did a write argument come from tool output rather than the user?
        prov_hits = []
        prov_cfg = self.policy.provenance
        if prov_cfg.enabled and tool_class_str in prov_cfg.classes:
            prov_hits = find_untrusted_args(
                call.args, session.trusted_tokens,
                session.untrusted_tokens, session.untrusted_overflow,
            )

        risk = compute_risk(
            base_risk=base,
            env_bonus=env_bonus,
            reversibility=reversibility,
            blast_radius=blast,
            protected_target=protected,
            tainted_session=tainted,
            repeat_penalty=repeat,
            untrusted_provenance=bool(prov_hits),
        )

        # ── Step 7: Policy decision ───────────────────────────────────────────
        policy_dec = self.policy.policy_decision(tool_class_str, call.env)

        if policy_dec == "block":
            v = Verdict(
                decision=Decision.BLOCK,
                risk_score=risk.score,
                risk_label=risk.label,
                reasons=[
                    f"{call.tool_name!r} (class={tool_class_str}) not allowed "
                    f"in environment {call.env!r}"
                ],
                matched_rules=["policy_block"],
                tool_name=call.tool_name,
                session_id=call.session_id,
            )
            self._finalize(session, call, v, recheck)
            return v

        # Start with ALLOW, then escalate
        v = Verdict(
            decision=Decision.ALLOW,
            risk_score=risk.score,
            risk_label=risk.label,
            reasons=list(risk.factors),
            tool_name=call.tool_name,
            session_id=call.session_id,
        )

        if policy_dec == "approval":
            v = v.escalate(
                Decision.NEEDS_APPROVAL,
                reason=f"{call.tool_name!r} requires approval in {call.env!r} (policy)",
                rule="policy_approval",
            )

        # ── Step 7b: Provenance ───────────────────────────────────────────────
        if prov_hits:
            v = v.escalate(
                Decision.NEEDS_APPROVAL,
                reason=describe_provenance(prov_hits),
                rule="untrusted_provenance",
            )

        # ── Step 7c: Intent check (isolated judge; can only escalate) ─────────
        intent_cfg = self.policy.intent_check
        if (
            self.intent_judge is not None
            and intent_cfg.enabled
            and tool_class_str in intent_cfg.classes
        ):
            intent = self.intent_judge.check(session.user_requests, call.tool_name, call.args)
            if intent.aligned:
                v = v.model_copy(update={
                    "reasons": v.reasons + [f"intent check passed: {intent.rationale}"]
                })
            else:
                v = v.escalate(
                    Decision.NEEDS_APPROVAL,
                    reason=f"Intent check: {intent.rationale}",
                    rule="intent_error" if intent.error else "intent_misaligned",
                )

        # ── Step 8: Risk escalation ───────────────────────────────────────────
        if risk.score >= 70:
            v = v.escalate(
                Decision.NEEDS_APPROVAL,
                reason=f"Risk score {risk.score} >= 70 forces NEEDS_APPROVAL",
                rule="risk_escalation_high",
            )
        elif risk.score >= 31 and not call.reason:
            if limits.require_reason_for in ("medium", "low"):
                # Non-executing verdict asking for a reason (not counted as a call)
                return v.escalate(
                    Decision.NEEDS_APPROVAL,
                    reason=(
                        f"Risk score {risk.score} is {risk.label} — "
                        "please supply a 'reason' field explaining this call"
                    ),
                    rule="reason_required",
                ).model_copy(update={"tool_name": call.tool_name, "session_id": call.session_id})

        v = v.model_copy(
            update={"tool_name": call.tool_name, "session_id": call.session_id}
        )
        self._finalize(session, call, v, recheck)
        return v

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _validate_args(self, call: ToolCall, tool) -> None:
        """
        1. A tool with its own validate_args() validates itself.
        2. A tool that declares properties in parameters_schema is validated by the
           types it declares (type + x-guard kind); unknown arguments are rejected.
        3. Only tools that declare NO properties (legacy / test doubles) fall back to
           guessing from argument names.
        """
        if hasattr(tool, "validate_args"):
            tool.validate_args(call.args)
            return

        schema = getattr(tool, "parameters_schema", None) or {}
        if schema.get("properties"):
            validate_against_schema(
                call.args,
                schema,
                SchemaContext(
                    allowed_file_roots=self.policy.allowed_file_roots,
                    allowed_repo_roots=self.policy.allowed_repo_roots,
                    allowed_health_hosts=self.policy.allowed_health_hosts,
                    allowed_namespaces=self.policy.allowed_k8s_namespaces,
                    allowed_log_containers=self.policy.allowed_log_containers,
                ),
            )
            return

        _IDENTIFIER_FIELDS = {
            "container", "model_name", "alias", "experiment_name",
            "run_id", "pod", "service", "namespace", "version",
        }
        _PATH_FIELDS = {"path", "current_path", "reference_path", "file_path", "filepath", "output"}
        for key, val in call.args.items():
            if key in _IDENTIFIER_FIELDS and isinstance(val, str):
                validate_identifier(val, key)
            elif key in _PATH_FIELDS and isinstance(val, str):
                validate_path(val, key, self.policy.allowed_file_roots)
            elif isinstance(val, str):
                validate_string_max(val, key, max_len=512)

    def _finalize(
        self, session: SessionState, call: ToolCall, verdict: Verdict, recheck: bool = False
    ) -> None:
        """Update session state after every verdict (including blocks)."""
        if recheck and verdict.decision != Decision.BLOCK:
            return  # an approval re-check is not a new call
        updated = session.increment_call()
        if verdict.decision == Decision.BLOCK:
            updated = updated.increment_blocked()
        # Track write tools for repeat penalty calculation
        tool = self._get_registry().get(call.tool_name)
        if tool is not None:
            tc = getattr(tool, "risk_level", None)
            if tc and tc.value in ("write_low", "write_high"):
                updated = updated.add_write(call.tool_name)
        session_store.update(updated)
