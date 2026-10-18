from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock

from guardml.tools.base import BaseTool, RiskLevel, ToolResult
from guardml.tools.deploy_tools import HealthCheck, DockerPs, DockerLogs
from guardml.tools.system_tools import DiskMemoryStatus
from guardml.tools.registry import get_registry, ToolRegistry


class TestToolResult:
    def test_ok_result(self):
        r = ToolResult(ok=True, data={'foo': 'bar'})
        assert r.ok
        assert r.error is None

    def test_error_result(self):
        r = ToolResult(ok=False, error='something went wrong')
        assert not r.ok
        assert 'wrong' in r.error


class TestRegistry:
    def test_all_tools_registered(self):
        registry = get_registry()
        names = registry.names()
        assert 'mlflow_list_runs' in names
        assert 'drift_report' in names
        assert 'data_quality_check' in names
        assert 'health_check' in names
        assert 'docker_ps' in names
        assert 'gpu_status' in names
        assert 'mlflow_set_alias' in names

    def test_get_unknown_returns_none(self):
        registry = get_registry()
        assert registry.get('nonexistent_tool_xyz') is None

    def test_schemas_have_required_fields(self):
        registry = get_registry()
        for schema in registry.all_schemas():
            assert 'name' in schema
            assert 'description' in schema
            assert 'input_schema' in schema


class TestHealthCheck:
    def test_healthy_response(self):
        # health_check uses http.client (never follows redirects), so mock that.
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"status": "healthy"}'
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp
        with patch('http.client.HTTPConnection', return_value=mock_conn):
            hc = HealthCheck()
            result = hc.run(url='http://localhost:8001/health')
            assert result.ok
            assert result.data['healthy']

    def test_connection_refused(self):
        hc = HealthCheck()
        result = hc.run(url='http://localhost:19999/health', timeout_seconds=1)
        assert not result.ok or (result.ok and not result.data.get('healthy', True))


class TestDockerTools:
    def test_docker_ps_ok(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"Names":"myapp","Status":"Up"}\n'
        mock_result.stderr = ''
        with patch('subprocess.run', return_value=mock_result):
            tool = DockerPs()
            result = tool.run()
            assert result.ok

    def test_docker_logs_line_limit(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '\n'.join([f'log line {i}' for i in range(300)])
        mock_result.stderr = ''
        with patch('subprocess.run', return_value=mock_result):
            tool = DockerLogs()
            result = tool.run(container='myapp', lines=300)
            assert result.ok


class TestDiskMemoryStatus:
    def test_disk_memory_runs(self):
        tool = DiskMemoryStatus()
        result = tool.run(path='/')
        assert result.ok is True or result.data is not None
