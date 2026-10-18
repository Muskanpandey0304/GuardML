"""
System monitoring tools: nvidia-smi, disk, memory (Phase 2).
"""
from __future__ import annotations
import subprocess
import platform
import json
from typing import Any, Dict, List

from .base import BaseTool, RiskLevel


def _run(cmd: List[str], timeout: int = 15) -> Dict:
    """Run a command safely, no shell=True."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {'returncode': proc.returncode, 'stdout': proc.stdout[:4000], 'stderr': proc.stderr[:500]}
    except FileNotFoundError:
        return {'returncode': -1, 'stdout': '', 'stderr': f'{cmd[0]!r} not found'}
    except subprocess.TimeoutExpired:
        return {'returncode': -1, 'stdout': '', 'stderr': 'Command timed out'}


class GpuStatus(BaseTool):
    name = 'gpu_status'
    description = 'Get GPU status using nvidia-smi: memory, utilization, temperature.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {},
        'required': [],
    }

    def _execute(self, **_) -> Dict:
        result = _run([
            'nvidia-smi',
            '--query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu',
            '--format=csv,noheader,nounits',
        ])
        if result['returncode'] != 0:
            return {'ok': False, 'error': result['stderr'] or 'nvidia-smi failed or not available'}
        lines = [l.strip() for l in result['stdout'].strip().splitlines() if l.strip()]
        gpus = []
        for i, line in enumerate(lines):
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 5:
                try:
                    gpus.append({
                        'index': i,
                        'name': parts[0],
                        'memory_used_mb': float(parts[1]),
                        'memory_total_mb': float(parts[2]),
                        'memory_used_pct': round(float(parts[1]) / max(float(parts[2]), 1) * 100, 1),
                        'gpu_utilization_pct': float(parts[3]),
                        'temperature_c': float(parts[4]),
                    })
                except ValueError:
                    gpus.append({'index': i, 'raw': line})
        return {'ok': True, 'gpus': gpus, 'count': len(gpus)}


class DiskMemoryStatus(BaseTool):
    name = 'disk_memory_status'
    description = 'Get disk usage and memory stats for the current system.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'path': {'type': 'string', 'x-guard': 'path', 'default': './demo/data', 'description': 'Disk path to check (must be inside the allowed data roots)'},
        },
        'required': [],
    }

    def _execute(self, path: str = './demo', **_) -> Dict:
        import shutil
        import psutil

        # Disk
        try:
            disk = shutil.disk_usage(path)
            disk_info = {
                'path': path,
                'total_gb': round(disk.total / 1e9, 2),
                'used_gb': round(disk.used / 1e9, 2),
                'free_gb': round(disk.free / 1e9, 2),
                'used_pct': round(disk.used / disk.total * 100, 1),
            }
        except Exception as e:
            disk_info = {'error': str(e)}

        # Memory
        try:
            mem = psutil.virtual_memory()
            mem_info = {
                'total_gb': round(mem.total / 1e9, 2),
                'used_gb': round(mem.used / 1e9, 2),
                'available_gb': round(mem.available / 1e9, 2),
                'used_pct': round(mem.percent, 1),
            }
        except Exception as e:
            mem_info = {'error': str(e)}

        return {'ok': True, 'disk': disk_info, 'memory': mem_info}
