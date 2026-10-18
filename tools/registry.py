"""
Tool registry: registers all tools and provides lookup.
"""
from __future__ import annotations
from typing import Dict, List, Optional

from .base import BaseTool
from .mlflow_tools import (
    MlflowListRuns, MlflowGetRun, MlflowCompareRuns,
    MlflowListModelVersions, MlflowGetProductionModel, MlflowSetAlias,
)
from .drift_tools import DriftReport
from .quality_tools import DataQualityCheck
from .data_tools import DvcStatus, DvcDiff
from .system_tools import GpuStatus, DiskMemoryStatus
from .deploy_tools import (
    DockerPs, DockerLogs, DockerStats, DockerRestart,
    HealthCheck, KubectlGetPods, KubectlLogs,
)

_ALL_TOOLS: List[BaseTool] = [
    MlflowListRuns(),
    MlflowGetRun(),
    MlflowCompareRuns(),
    MlflowListModelVersions(),
    MlflowGetProductionModel(),
    MlflowSetAlias(),
    DriftReport(),
    DataQualityCheck(),
    DvcStatus(),
    DvcDiff(),
    GpuStatus(),
    DiskMemoryStatus(),
    DockerPs(),
    DockerLogs(),
    DockerStats(),
    DockerRestart(),
    HealthCheck(),
    KubectlGetPods(),
    KubectlLogs(),
]


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {t.name: t for t in _ALL_TOOLS}

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def all_tools(self) -> List[BaseTool]:
        return list(self._tools.values())

    def all_schemas(self) -> List[dict]:
        return [t.to_schema() for t in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools.keys())


_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
