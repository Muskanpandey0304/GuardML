"""
MLflow tool wrappers (Phase 2).
All tools are read-only except mlflow_set_alias which is write_high.
"""
from __future__ import annotations
import os
import json
from typing import Any, Dict, List, Optional
import mlflow
from mlflow import MlflowClient

from .base import BaseTool, RiskLevel

DEFAULT_TRACKING_URI = os.getenv('MLFLOW_TRACKING_URI', 'sqlite:///./demo/mlruns.db')


def _get_client() -> MlflowClient:
    return MlflowClient(tracking_uri=DEFAULT_TRACKING_URI)


class MlflowListRuns(BaseTool):
    name = 'mlflow_list_runs'
    description = 'List MLflow experiment runs. Returns run_id, status, metrics, params.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'experiment_name': {'type': 'string', 'x-guard': 'identifier', 'description': 'Experiment name'},
            'max_results': {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 10, 'description': 'Max runs to return (1-50)'},
        },
        'required': ['experiment_name'],
    }

    def _execute(self, experiment_name: str, max_results: int = 10, **_) -> List[Dict]:
        max_results = min(max(1, int(max_results)), 50)
        client = _get_client()
        mlflow.set_tracking_uri(DEFAULT_TRACKING_URI)
        exp = mlflow.get_experiment_by_name(experiment_name)
        if exp is None:
            return []
        runs = client.search_runs(
            experiment_ids=[exp.experiment_id],
            max_results=max_results,
            order_by=['start_time DESC'],
        )
        return [
            {
                'run_id': r.info.run_id,
                'run_name': r.info.run_name,
                'status': r.info.status,
                'start_time': r.info.start_time,
                'metrics': dict(r.data.metrics),
                'params': dict(r.data.params),
                'tags': {k: v for k, v in r.data.tags.items() if not k.startswith('mlflow.')},
            }
            for r in runs
        ]


class MlflowGetRun(BaseTool):
    name = 'mlflow_get_run'
    description = 'Get details of a specific MLflow run by run_id.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'run_id': {'type': 'string', 'x-guard': 'identifier', 'description': 'MLflow run ID'},
        },
        'required': ['run_id'],
    }

    def _execute(self, run_id: str, **_) -> Dict:
        client = _get_client()
        run = client.get_run(run_id)
        return {
            'run_id': run.info.run_id,
            'run_name': run.info.run_name,
            'status': run.info.status,
            'start_time': run.info.start_time,
            'end_time': run.info.end_time,
            'artifact_uri': run.info.artifact_uri,
            'metrics': dict(run.data.metrics),
            'params': dict(run.data.params),
        }


class MlflowCompareRuns(BaseTool):
    name = 'mlflow_compare_runs'
    description = 'Compare two MLflow runs side by side, returning metric and param diffs.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'run_id_a': {'type': 'string', 'x-guard': 'identifier', 'description': 'First run ID'},
            'run_id_b': {'type': 'string', 'x-guard': 'identifier', 'description': 'Second run ID'},
        },
        'required': ['run_id_a', 'run_id_b'],
    }

    def _execute(self, run_id_a: str, run_id_b: str, **_) -> Dict:
        client = _get_client()
        a = client.get_run(run_id_a)
        b = client.get_run(run_id_b)

        metric_keys = set(a.data.metrics) | set(b.data.metrics)
        metric_diff = {}
        for k in metric_keys:
            va = a.data.metrics.get(k)
            vb = b.data.metrics.get(k)
            delta = None
            if va is not None and vb is not None:
                delta = round(vb - va, 6)
            metric_diff[k] = {'run_a': va, 'run_b': vb, 'delta': delta}

        return {
            'run_a': {'id': run_id_a, 'name': a.info.run_name},
            'run_b': {'id': run_id_b, 'name': b.info.run_name},
            'metric_comparison': metric_diff,
            'param_comparison': {
                k: {'run_a': a.data.params.get(k), 'run_b': b.data.params.get(k)}
                for k in set(a.data.params) | set(b.data.params)
            },
        }


class MlflowListModelVersions(BaseTool):
    name = 'mlflow_list_model_versions'
    description = 'List all versions of a registered MLflow model.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'model_name': {'type': 'string', 'x-guard': 'identifier', 'description': 'Registered model name'},
        },
        'required': ['model_name'],
    }

    def _execute(self, model_name: str, **_) -> List[Dict]:
        client = _get_client()
        versions = client.search_model_versions(f"name='{model_name}'")
        return [
            {
                'version': v.version,
                'run_id': v.run_id,
                'status': v.status,
                'creation_timestamp': v.creation_timestamp,
                'last_updated_timestamp': v.last_updated_timestamp,
                'aliases': list(v.aliases) if hasattr(v, 'aliases') else [],
                'tags': dict(v.tags) if v.tags else {},
            }
            for v in sorted(versions, key=lambda x: int(x.version))
        ]


class MlflowGetProductionModel(BaseTool):
    name = 'mlflow_get_production_model'
    description = 'Get the current production model version and its run metrics.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'model_name': {'type': 'string', 'x-guard': 'identifier', 'description': 'Registered model name'},
            'alias': {'type': 'string', 'x-guard': 'identifier', 'default': 'production', 'description': 'Model alias'},
        },
        'required': ['model_name'],
    }

    def _execute(self, model_name: str, alias: str = 'production', **_) -> Dict:
        client = _get_client()
        try:
            mv = client.get_model_version_by_alias(model_name, alias)
            run = client.get_run(mv.run_id)
            return {
                'model_name': model_name,
                'alias': alias,
                'version': mv.version,
                'run_id': mv.run_id,
                'status': mv.status,
                'metrics': dict(run.data.metrics),
                'params': dict(run.data.params),
                'creation_timestamp': mv.creation_timestamp,
            }
        except Exception as e:
            return {'error': str(e), 'model_name': model_name, 'alias': alias}


class MlflowSetAlias(BaseTool):
    name = 'mlflow_set_alias'
    description = 'Set a model alias (e.g. promote or rollback). WRITE operation - requires approval in production.'
    risk_level = RiskLevel.WRITE_HIGH
    parameters_schema = {
        'type': 'object',
        'properties': {
            'model_name': {'type': 'string', 'x-guard': 'identifier', 'description': 'Registered model name'},
            'alias': {'type': 'string', 'x-guard': 'identifier', 'description': 'Alias to set (e.g. production, champion)'},
            'version': {'type': 'string', 'x-guard': 'identifier', 'description': 'Model version number to point alias to'},
        },
        'required': ['model_name', 'alias', 'version'],
    }

    def _execute(self, model_name: str, alias: str, version: str, **_) -> Dict:
        client = _get_client()
        client.set_registered_model_alias(model_name, alias, version)
        return {
            'ok': True,
            'model_name': model_name,
            'alias': alias,
            'version': version,
            'message': f'Alias {alias!r} now points to version {version}',
        }
