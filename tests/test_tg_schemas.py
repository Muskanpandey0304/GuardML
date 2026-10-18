"""
Step 1 tests: Core data structures.
Key invariant: severity can ONLY go up, never down.
"""
import pytest
from guardml.toolguard.schemas import Decision, Verdict, ToolCall, SessionState


class TestDecisionOrdering:
    def test_allow_lt_needs_approval(self):
        assert Decision.ALLOW < Decision.NEEDS_APPROVAL

    def test_needs_approval_lt_block(self):
        assert Decision.NEEDS_APPROVAL < Decision.BLOCK

    def test_allow_lt_block(self):
        assert Decision.ALLOW < Decision.BLOCK

    def test_block_not_lt_allow(self):
        assert not (Decision.BLOCK < Decision.ALLOW)

    def test_max_returns_higher(self):
        assert Decision.ALLOW.max(Decision.BLOCK) == Decision.BLOCK
        assert Decision.BLOCK.max(Decision.ALLOW) == Decision.BLOCK
        assert Decision.NEEDS_APPROVAL.max(Decision.ALLOW) == Decision.NEEDS_APPROVAL
        assert Decision.ALLOW.max(Decision.ALLOW) == Decision.ALLOW


class TestVerdictEscalation:
    def test_allow_escalates_to_needs_approval(self):
        v = Verdict.allow()
        v2 = v.escalate(Decision.NEEDS_APPROVAL, "some reason")
        assert v2.decision == Decision.NEEDS_APPROVAL

    def test_allow_escalates_to_block(self):
        v = Verdict.allow()
        v2 = v.escalate(Decision.BLOCK, "blocked reason")
        assert v2.decision == Decision.BLOCK

    def test_block_cannot_be_lowered_to_allow(self):
        v = Verdict.block("already blocked")
        v2 = v.escalate(Decision.ALLOW, "try to lower")
        assert v2.decision == Decision.BLOCK  # must not decrease

    def test_block_cannot_be_lowered_to_needs_approval(self):
        v = Verdict.block("already blocked")
        v2 = v.escalate(Decision.NEEDS_APPROVAL, "try to lower")
        assert v2.decision == Decision.BLOCK

    def test_needs_approval_cannot_be_lowered_to_allow(self):
        v = Verdict.needs_approval(50, "medium", "needs approval")
        v2 = v.escalate(Decision.ALLOW, "try to lower")
        assert v2.decision == Decision.NEEDS_APPROVAL

    def test_reasons_accumulate(self):
        v = Verdict.allow()
        v2 = v.escalate(Decision.NEEDS_APPROVAL, "reason1")
        v3 = v2.escalate(Decision.BLOCK, "reason2")
        assert "reason1" in v3.reasons
        assert "reason2" in v3.reasons

    def test_matched_rules_accumulate(self):
        v = Verdict.allow()
        v2 = v.escalate(Decision.BLOCK, "r", rule="rule_A")
        assert "rule_A" in v2.matched_rules

    def test_original_verdict_immutable(self):
        v = Verdict.allow()
        v.escalate(Decision.BLOCK, "change it")
        assert v.decision == Decision.ALLOW  # pydantic model_copy is immutable


class TestSessionState:
    def test_increment_call(self):
        s = SessionState(session_id="s1", env="staging")
        s2 = s.increment_call()
        assert s2.call_count == 1
        assert s.call_count == 0  # original unchanged

    def test_lock_at_exactly_3_blocked(self):
        s = SessionState(session_id="s1", env="staging")
        s = s.increment_blocked()
        assert not s.locked
        s = s.increment_blocked()
        assert not s.locked
        s = s.increment_blocked()  # 3rd
        assert s.locked

    def test_taint(self):
        s = SessionState(session_id="s1", env="staging")
        assert not s.tainted
        s2 = s.mark_tainted()
        assert s2.tainted
        assert not s.tainted  # original unchanged

    def test_add_write(self):
        s = SessionState(session_id="s1", env="staging")
        s2 = s.add_write("mlflow_set_alias")
        assert "mlflow_set_alias" in s2.write_tools_used
        assert s.write_tools_used == []


class TestToolCall:
    def test_valid_call(self):
        call = ToolCall(
            session_id="abc",
            tool_name="mlflow_list_runs",
            args={"experiment_name": "fraud"},
            env="staging",
        )
        assert call.tool_name == "mlflow_list_runs"

    def test_rejects_extra_fields(self):
        with pytest.raises(Exception):
            ToolCall(
                session_id="abc",
                tool_name="mlflow_list_runs",
                args={},
                env="staging",
                unknown_field="bad",  # extra="forbid"
            )

    def test_has_call_id_and_timestamp(self):
        call = ToolCall(
            session_id="abc", tool_name="tool", args={}, env="staging"
        )
        assert call.call_id
        assert call.timestamp > 0
