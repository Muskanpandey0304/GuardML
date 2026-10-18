"""
conftest.py for ToolGuard tests.
Provides a minimal mock tool registry so pipeline/guard tests work
without requiring mlflow, evidently, or other heavy optional dependencies.
"""
import sys
import types
from unittest.mock import MagicMock
import pytest

# Import only base (no mlflow dependency) — not the full tools package
from guardml.tools.base import BaseTool, RiskLevel, ToolResult
from guardml.toolguard import session as session_store


# ---------------------------------------------------------------------------
# Minimal mock tools covering all test scenarios
# ---------------------------------------------------------------------------
class _MockTool(BaseTool):
    def __init__(self, name: str, risk_level: RiskLevel):
        self.name = name
        self.description = f"Mock {risk_level.value} tool: {name}"
        self.risk_level = risk_level
        self.parameters_schema = {"type": "object", "properties": {}}

    def _execute(self, **kwargs):
        return {"ok": True, "mock": True}


_MOCK_TOOLS_LIST = [
    # Read tools
    _MockTool("mlflow_list_runs", RiskLevel.READ),
    _MockTool("mlflow_get_run", RiskLevel.READ),
    _MockTool("mlflow_compare_runs", RiskLevel.READ),
    _MockTool("mlflow_list_model_versions", RiskLevel.READ),
    _MockTool("mlflow_get_production_model", RiskLevel.READ),
    _MockTool("drift_report", RiskLevel.READ),
    _MockTool("data_quality_check", RiskLevel.READ),
    _MockTool("dvc_status", RiskLevel.READ),
    _MockTool("dvc_diff", RiskLevel.READ),
    _MockTool("gpu_status", RiskLevel.READ),
    _MockTool("disk_memory_status", RiskLevel.READ),
    _MockTool("docker_ps", RiskLevel.READ),
    _MockTool("docker_logs", RiskLevel.READ),
    _MockTool("docker_stats", RiskLevel.READ),
    _MockTool("kubectl_get_pods", RiskLevel.READ),
    _MockTool("kubectl_logs", RiskLevel.READ),
    _MockTool("health_check", RiskLevel.READ),
    # Write low
    _MockTool("docker_restart", RiskLevel.WRITE_LOW),
    # Write high
    _MockTool("mlflow_set_alias", RiskLevel.WRITE_HIGH),
    _MockTool("trigger_retrain", RiskLevel.WRITE_HIGH),
]


class _MockRegistry:
    def __init__(self):
        self._tools = {t.name: t for t in _MOCK_TOOLS_LIST}

    def get(self, name: str):
        return self._tools.get(name)

    def all_tools(self):
        return list(self._tools.values())

    def all_schemas(self):
        return [t.to_schema() for t in self._tools.values()]

    def names(self):
        return list(self._tools.keys())


_MOCK_REGISTRY = _MockRegistry()


# ---------------------------------------------------------------------------
# Patch guard.py's _get_registry to return the mock registry.
# We patch at class level so it applies to all ToolGuard instances.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def patch_registry(monkeypatch):
    import guardml.toolguard.guard as guard_mod

    def _mock_get_registry(self):
        return _MOCK_REGISTRY

    monkeypatch.setattr(guard_mod.ToolGuard, "_get_registry", _mock_get_registry)
    yield


@pytest.fixture(autouse=True)
def reset_sessions():
    session_store.reset_all()
    yield
    session_store.reset_all()


@pytest.fixture
def mock_registry():
    """The shared mock tool registry (no mlflow / docker needed)."""
    return _MOCK_REGISTRY
