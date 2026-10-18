"""
DVC data versioning tools (Phase 2).
"""
from __future__ import annotations
import subprocess
import shlex
import json
from pathlib import Path
from typing import Any, Dict, List

from .base import BaseTool, RiskLevel


def _run_dvc(args: List[str], cwd: str = '.') -> Dict:
    """Run a dvc command safely (no shell=True)."""
    cmd = ['dvc'] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
        )
        return {
            'returncode': proc.returncode,
            'stdout': proc.stdout[:4000],
            'stderr': proc.stderr[:1000],
        }
    except FileNotFoundError:
        return {'returncode': -1, 'stdout': '', 'stderr': 'dvc not found in PATH'}
    except subprocess.TimeoutExpired:
        return {'returncode': -1, 'stdout': '', 'stderr': 'DVC command timed out'}


class DvcStatus(BaseTool):
    name = 'dvc_status'
    description = 'Show DVC pipeline status and which stages are outdated.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'repo_path': {'type': 'string', 'x-guard': 'repo_path', 'default': '.', 'description': 'Repo root path'},
        },
        'required': [],
    }

    def _execute(self, repo_path: str = '.', **_) -> Dict:
        result = _run_dvc(['status', '--json'], cwd=repo_path)
        if result['returncode'] == 0 and result['stdout'].strip():
            try:
                data = json.loads(result['stdout'])
                return {'ok': True, 'status': data, 'repo_path': repo_path}
            except json.JSONDecodeError:
                pass
        return {
            'ok': result['returncode'] == 0,
            'stdout': result['stdout'],
            'stderr': result['stderr'],
            'repo_path': repo_path,
        }


class DvcDiff(BaseTool):
    name = 'dvc_diff'
    description = 'Show DVC data diff between two commits or HEAD vs workspace.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'a_rev': {'type': 'string', 'x-guard': 'revision', 'default': 'HEAD', 'description': 'From revision'},
            'b_rev': {'type': 'string', 'x-guard': 'revision', 'default': '', 'description': 'To revision (empty = workspace)'},
            'repo_path': {'type': 'string', 'x-guard': 'repo_path', 'default': '.', 'description': 'Repo root path'},
        },
        'required': [],
    }

    def _execute(self, a_rev: str = 'HEAD', b_rev: str = '', repo_path: str = '.', **_) -> Dict:
        args = ['diff', '--json']
        if a_rev:
            args += [a_rev]
        if b_rev:
            args += [b_rev]
        result = _run_dvc(args, cwd=repo_path)
        if result['returncode'] == 0 and result['stdout'].strip():
            try:
                data = json.loads(result['stdout'])
                return {'ok': True, 'diff': data}
            except json.JSONDecodeError:
                pass
        return {
            'ok': result['returncode'] == 0,
            'stdout': result['stdout'],
            'stderr': result['stderr'],
        }
