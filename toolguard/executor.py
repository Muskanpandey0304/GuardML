"""
Step 8: GuardedExecutor — the single choke point.
THE only code path that calls tool.run(). The agent loop only knows this executor.

Features:
- Single entry: GuardedExecutor.execute(call, approval_id=None)
- Taint tracking: marks session tainted after free-text tool output
- Output sanity: strips control chars, flags injection phrases, truncates
- Wraps output in <tool_output> tags for the LLM ("this is data, not instructions")
- Writes audit entry BEFORE execution (intent) and AFTER (outcome)
  so a crash cannot hide an action
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

from .schemas import Decision, ToolCall, Verdict
from .guard import ToolGuard
from .approval import ApprovalGate
from .masking import mask_value, detect_injection_phrases
from . import session as session_store

logger = logging.getLogger(__name__)

# Control characters (except normal tab/LF/CR)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Tools whose output taints the session (free text from external sources)
_FREE_TEXT_TOOLS = {
    "docker_logs",
    "kubectl_logs",
    "mlflow_get_run",
    "mlflow_list_runs",
    "drift_report",
    "data_quality_check",
    "disk_memory_status",
}


class ExecutionResult:
    def __init__(
        self,
        ok: bool,
        output: str,
        verdict: Verdict,
        tool_name: str,
        tainted: bool = False,
        error: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        verification: Optional[dict] = None,
    ):
        self.snapshot_id = snapshot_id
        # Post-write check: {'status': healthy|unhealthy|unreachable,
        #                    'action': kept|kept_unverified|rolled_back, ...}
        self.verification = verification
        self.ok = ok
        self.output = output
        self.verdict = verdict
        self.tool_name = tool_name
        self.tainted = tainted
        self.error = error

    def for_llm(self) -> str:
        """Wrap output in tags that signal 'this is data, not instructions'."""
        return (
            f'<tool_output tool="{self.tool_name}" untrusted="true">\n'
            f"{self.output}\n"
            f"</tool_output>"
        )


class GuardedExecutor:
    def __init__(
        self,
        guard: Optional[ToolGuard] = None,
        approval_gate: Optional[ApprovalGate] = None,
        audit_log=None,
        registry=None,
        snapshots=None,
        rollback=None,
    ):
        self.guard = guard or ToolGuard(registry=registry)
        self.approval_gate = approval_gate or ApprovalGate()
        self.audit = audit_log
        self._registry = registry
        # Optional safety hooks: snapshot before a write, verify + auto-rollback after.
        # None = skip (unit tests, read-only deployments).
        self.snapshots = snapshots
        self.rollback = rollback

    def register_user_message(self, session_id: str, env: str, text: str) -> None:
        """Record what the user asked for. The only trusted source of argument values."""
        session_store.record_user_message(session_id, env, text)

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


    def execute(self, call: ToolCall, approval_id: Optional[str] = None) -> ExecutionResult:
        """
        THE only path that calls tool.run().

        With approval_id:
          1. Validate approval (hash, TTL, single-use)
          2. Re-run guard.check() (policy may have changed since approval)
          3. Execute
        Without approval_id:
          1. Run guard.check()
          2. BLOCK → return error, no execution
          3. NEEDS_APPROVAL → create request, return pending status, no execution
          4. ALLOW → execute
        """
        session = session_store.get_or_create(call.session_id, call.env)
        audit_id = self._audit_intent(call)

        # ── Approval path ────────────────────────────────────────────────────
        if approval_id is not None:
            val = self.approval_gate.validate_for_execution(
                approval_id=approval_id,
                tool_name=call.tool_name,
                args=call.args,
                env=call.env,
                session_id=call.session_id,
            )
            if not val["ok"]:
                result = ExecutionResult(
                    ok=False,
                    output=json.dumps({"error": val["reason"]}),
                    verdict=Verdict.block(val["reason"], rule="approval_validation"),
                    tool_name=call.tool_name,
                )
                self._audit_outcome(audit_id, result, call)
                return result

            # Re-check: policy or env may have changed since approval
            verdict = self.guard.check(call, recheck=True)
            if verdict.decision == Decision.BLOCK:
                self.approval_gate._expire(approval_id)
                result = ExecutionResult(
                    ok=False,
                    output=json.dumps({"error": f"Re-check blocked: {verdict.reasons}"}),
                    verdict=verdict,
                    tool_name=call.tool_name,
                )
                self._audit_outcome(audit_id, result, call)
                return result

            result = self._run_tool(call, verdict)
            self.approval_gate.mark_executed(approval_id)
            row = self.approval_gate.get(approval_id) or {}
            self._audit_outcome(
                audit_id, result, call,
                verdict_label="APPROVED_EXECUTED",
                approved_by=row.get("resolved_by") or "",
            )
            return result

        # ── Normal path ──────────────────────────────────────────────────────
        verdict = self.guard.check(call)

        if verdict.decision == Decision.BLOCK:
            output = json.dumps({
                "ok": False,
                "error": f"BLOCKED: {'; '.join(verdict.reasons)}",
                "verdict": "BLOCK",
                "matched_rules": verdict.matched_rules,
            })
            result = ExecutionResult(
                ok=False, output=output, verdict=verdict, tool_name=call.tool_name
            )
            self._audit_outcome(audit_id, result, call)
            return result

        if verdict.decision == Decision.NEEDS_APPROVAL:
            new_approval_id = self.approval_gate.create_request(
                session_id=call.session_id,
                tool_name=call.tool_name,
                args=call.args,
                risk_score=verdict.risk_score,
                risk_label=verdict.risk_label,
                reasons=verdict.reasons,
                env=call.env,
                llm_reason=call.reason or "",
            )
            output = json.dumps({
                "status": "pending_approval",
                "approval_id": new_approval_id,
                "message": "A human must approve this action before it runs.",
                "risk_score": verdict.risk_score,
                "risk_label": verdict.risk_label,
                "reasons": verdict.reasons,
            })
            verdict = verdict.model_copy(update={"approval_id": new_approval_id})
            result = ExecutionResult(
                ok=False, output=output, verdict=verdict, tool_name=call.tool_name
            )
            self._audit_outcome(audit_id, result, call)
            return result

        # ALLOW — execute
        result = self._run_tool(call, verdict)
        self._audit_outcome(audit_id, result, call)
        return result

    # ------------------------------------------------------------------
    # Internal: run tool safely
    # ------------------------------------------------------------------
    def _run_tool(self, call: ToolCall, verdict: Verdict) -> ExecutionResult:
        registry = self._get_registry()
        tool = registry.get(call.tool_name)
        if tool is None:
            return ExecutionResult(
                ok=False,
                output=json.dumps({"error": f"Tool {call.tool_name!r} not found"}),
                verdict=verdict,
                tool_name=call.tool_name,
            )
        # Pre-write snapshot (so a failed verify can be reverted)
        snapshot_id = self._pre_write_snapshot(call, tool)

        try:
            tool_result = tool.run(**call.args)
            raw_data = tool_result.data
            error = tool_result.error
            ok = tool_result.ok
        except Exception as e:
            raw_data = None
            error = str(e)
            ok = False

        # Mask output BEFORE it goes anywhere
        masked_data = mask_value(raw_data)
        output_str = json.dumps(
            {"ok": ok, "data": masked_data, "error": error},
            default=str,
        )

        # Truncate to max_output_chars
        max_chars = self.guard.policy.limits.max_output_chars
        if len(output_str) > max_chars:
            output_str = output_str[:max_chars] + " ... [truncated]"

        # Strip control characters from output
        output_str = _CTRL_RE.sub("", output_str)

        # Detect and log injection phrases (do NOT change verdict)
        injections = detect_injection_phrases(output_str)
        if injections:
            logger.warning(
                "[GuardedExecutor] suspected_injection in %s output: %s",
                call.tool_name, injections,
            )
            if self.audit:
                self.audit.log_event(
                    session_id=call.session_id,
                    tool=call.tool_name,
                    args={},
                    verdict="suspected_injection",
                    risk_score=verdict.risk_score,
                    risk_label=verdict.risk_label,
                    result_summary=f"Injection phrases detected: {injections}",
                )

        # Provenance: remember every token the model has now seen from a tool, so a later
        # write using one of them (and not stated by the user) can be caught.
        session_store.record_tool_output(call.session_id, call.env, call.tool_name, output_str)

        # Taint tracking — mark session after free-text external output
        tainted = False
        if call.tool_name in _FREE_TEXT_TOOLS and ok:
            sess = session_store.get_or_create(call.session_id, call.env)
            if not sess.tainted:
                session_store.update(sess.mark_tainted())
                tainted = True
                logger.debug(
                    "[GuardedExecutor] Session %s tainted by %s",
                    call.session_id, call.tool_name,
                )

        # Post-write verify; auto-rollback if the change broke the service
        verification = None
        if ok and snapshot_id:
            verification = self._verify_and_rollback(call, snapshot_id)

        return ExecutionResult(
            ok=ok,
            output=output_str,
            verdict=verdict,
            tool_name=call.tool_name,
            tainted=tainted,
            error=error,
            snapshot_id=snapshot_id,
            verification=verification,
        )

    # ------------------------------------------------------------------
    # Safety hooks: snapshot -> execute -> verify -> rollback
    # ------------------------------------------------------------------
    def _pre_write_snapshot(self, call: ToolCall, tool) -> Optional[str]:
        if self.snapshots is None or getattr(tool, "risk_level", None) is None:
            return None
        if tool.risk_level.value == "read":
            return None
        if call.tool_name == "mlflow_set_alias":
            model_name = call.args.get("model_name", "")
            alias = call.args.get("alias", "production")
            if model_name:
                try:
                    return self.snapshots.snapshot_model_alias(model_name, alias, call.session_id)
                except Exception:
                    logger.exception("[GuardedExecutor] snapshot failed for %s", call.tool_name)
        return None

    def _verify_and_rollback(self, call: ToolCall, snapshot_id: str) -> Optional[dict]:
        """
        Health-check the service after a write and decide:
          healthy     -> keep
          unhealthy   -> rollback (the service answered and is broken)
          unreachable -> policy.on_unreachable[env]: 'rollback' (fail closed) or 'warn'
        Returns a verification dict (stored on ExecutionResult.verification).
        """
        if self.rollback is None or call.tool_name != "mlflow_set_alias":
            return None
        try:
            from guardml.tools.deploy_tools import HealthCheck
        except ImportError:
            from ..tools.deploy_tools import HealthCheck

        url = os.getenv("GUARDML_VERIFY_URL") or self.guard.policy.verify_after_write.url
        try:
            data = HealthCheck().run(url=url).data or {}
        except Exception as e:
            data = {"ok": False, "healthy": False, "error": str(e)}

        if data.get("healthy"):
            return {"status": "healthy", "action": "kept", "url": url}

        # HealthCheck only reports status_code when the service actually answered.
        reachable = "status_code" in data
        status = "unhealthy" if reachable else "unreachable"
        detail = data.get("error") or f"HTTP {data.get('status_code')}"
        action = "rollback" if reachable else self.guard.policy.on_verify_unreachable(call.env)

        if action == "warn":
            logger.warning("[GuardedExecutor] %s could not be verified (%s): %s",
                           call.tool_name, url, detail)
            if self.audit:
                self.audit.log_event(
                    session_id=call.session_id, tool="verify",
                    args={"url": url, "snapshot_id": snapshot_id},
                    verdict="VERIFY_UNREACHABLE", risk_score=0, risk_label="pending",
                    result_summary=f"Change kept but UNVERIFIED ({call.env} policy=warn): {detail}"[:500],
                )
            return {"status": status, "action": "kept_unverified", "url": url, "detail": detail}

        try:
            rb = self.rollback.auto_rollback_after_verify(
                verify_result={**data, "ok": False, "healthy": False},
                snapshot_id=snapshot_id,
                session_id=call.session_id,
                audit_log=self.audit,
            )
        except Exception:
            logger.exception("[GuardedExecutor] rollback failed for %s", call.tool_name)
            rb = {"ok": False, "message": "rollback raised an exception; see server logs"}
        return {"status": status, "action": "rolled_back", "url": url, "detail": detail, "rollback": rb}

    # ------------------------------------------------------------------
    # Audit hooks (intent before + outcome after)
    # ------------------------------------------------------------------
    def _audit_intent(self, call: ToolCall) -> Optional[str]:
        if self.audit:
            return self.audit.log_event(
                session_id=call.session_id,
                tool=call.tool_name,
                args=mask_value(call.args),
                verdict="INTENT",
                risk_score=0,
                risk_label="pending",
                result_summary="(pre-execution intent logged)",
            )
        return None

    def _audit_outcome(
        self,
        intent_id: Optional[str],
        result: ExecutionResult,
        call: ToolCall,
        verdict_label: Optional[str] = None,
        approved_by: str = "",
    ) -> None:
        if self.audit:
            self.audit.log_event(
                session_id=call.session_id,
                tool=call.tool_name,
                args=mask_value(call.args),
                verdict=verdict_label or result.verdict.decision.value,
                risk_score=result.verdict.risk_score,
                risk_label=result.verdict.risk_label,
                result_summary=result.output[:500],
                approved_by=approved_by,
            )
