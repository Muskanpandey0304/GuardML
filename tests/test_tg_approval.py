"""
Step 7 tests: Approval flow and bypass defenses.
Tests every bypass in the checklist: reuse, changed args, expired, self-approval path.
"""
import time
import pytest

from guardml.toolguard.approval import ApprovalGate, ensure_tables


DEFAULT_ARGS = {
    "model_name": "fraud_classifier",
    "alias": "production",
    "version": "1",
}


@pytest.fixture
def gate(tmp_path, monkeypatch):
    db = tmp_path / "test_approval.db"
    monkeypatch.setenv("GUARDML_DB", str(db))
    import importlib
    import guardml.toolguard.approval as apmod
    importlib.reload(apmod)
    apmod.ensure_tables()
    return apmod.ApprovalGate(ttl_seconds=60)


class TestApprovalFlow:
    def test_create_returns_id(self, gate):
        aid = gate.create_request(
            session_id="s1", tool_name="mlflow_set_alias",
            args=DEFAULT_ARGS, risk_score=80, risk_label="high",
            reasons=["high risk"], env="production",
        )
        assert aid
        row = gate.get(aid)
        assert row["status"] == "pending"

    def test_approve(self, gate):
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "approved", resolved_by="operator")
        assert gate.get(aid)["status"] == "approved"
        assert gate.get(aid)["resolved_by"] == "operator"

    def test_deny(self, gate):
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "denied", resolved_by="operator")
        assert gate.get(aid)["status"] == "denied"

    def test_approved_runs_once(self, gate):
        """Single-use: second validate_for_execution must fail."""
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "approved", resolved_by="human")
        # First validation succeeds
        r1 = gate.validate_for_execution(aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1")
        assert r1["ok"]
        gate.mark_executed(aid)
        # Second attempt must fail — single-use
        r2 = gate.validate_for_execution(aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1")
        assert not r2["ok"]
        assert "single-use" in r2["reason"].lower() or "already" in r2["reason"].lower()

    def test_changed_args_fails_hash_check(self, gate):
        """Changing any arg after approval is detected by hash mismatch."""
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "approved", resolved_by="human")
        bad_args = {**DEFAULT_ARGS, "version": "999"}
        result = gate.validate_for_execution(
            aid, "mlflow_set_alias", bad_args, "production", "s1"
        )
        assert not result["ok"]
        assert "hash" in result["reason"].lower() or "mismatch" in result["reason"].lower()

    def test_expired_approval_fails(self, tmp_path, monkeypatch):
        """TTL expired → execution rejected."""
        db = tmp_path / "exp_test.db"
        monkeypatch.setenv("GUARDML_DB", str(db))
        import importlib
        import guardml.toolguard.approval as apmod
        importlib.reload(apmod)
        apmod.ensure_tables()
        short_gate = apmod.ApprovalGate(ttl_seconds=0.01)
        aid = short_gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        short_gate.resolve(aid, "approved", resolved_by="human")
        time.sleep(0.05)  # let it expire
        result = short_gate.validate_for_execution(
            aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1"
        )
        assert not result["ok"]
        assert "expir" in result["reason"].lower()

    def test_pending_not_executable(self, gate):
        """Pending (not yet resolved) cannot be executed."""
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        result = gate.validate_for_execution(
            aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1"
        )
        assert not result["ok"]

    def test_denied_not_executable(self, gate):
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "denied", resolved_by="human")
        result = gate.validate_for_execution(
            aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1"
        )
        assert not result["ok"]
        assert "denied" in result["reason"].lower()

    def test_nonexistent_approval_fails(self, gate):
        result = gate.validate_for_execution(
            "nonexistent-id-xyz", "mlflow_set_alias", DEFAULT_ARGS, "production", "s1"
        )
        assert not result["ok"]

    def test_tool_name_mismatch_fails(self, gate):
        """Approval for tool A cannot be used to run tool B."""
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production"
        )
        gate.resolve(aid, "approved", resolved_by="human")
        result = gate.validate_for_execution(
            aid, "docker_restart",  # different tool!
            DEFAULT_ARGS, "production", "s1"
        )
        assert not result["ok"]

    def test_env_mismatch_fails(self, gate):
        """Approval granted for staging cannot run in production."""
        aid = gate.create_request(
            "s1", "mlflow_set_alias", DEFAULT_ARGS, 50, "medium", [], "staging"
        )
        gate.resolve(aid, "approved", resolved_by="human")
        result = gate.validate_for_execution(
            aid, "mlflow_set_alias", DEFAULT_ARGS, "production", "s1"  # wrong env!
        )
        assert not result["ok"]

    def test_list_pending(self, gate):
        gate.create_request("s1", "mlflow_set_alias", DEFAULT_ARGS, 80, "high", [], "production")
        gate.create_request("s1", "docker_restart", {"container": "model-api"}, 50, "medium", [], "production")
        pending = gate.list_pending(session_id="s1")
        assert len(pending) == 2

    def test_no_tool_exposes_approve_endpoint(self):
        """Verify no tool object has an 'approve' or 'resolve' method (LLM self-approval prevention)."""
        from guardml.tests.conftest import _MOCK_REGISTRY
        for tool in _MOCK_REGISTRY.all_tools():
            assert not hasattr(tool, "approve"), f"{tool.name} exposes 'approve'"
            assert not hasattr(tool, "resolve"), f"{tool.name} exposes 'resolve'"

