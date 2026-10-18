"""
Docker and kubectl deployment tools (Phase 2).
"""
from __future__ import annotations
import http.client
import ipaddress
import json
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .base import BaseTool, RiskLevel


def _run(cmd: List[str], timeout: int = 30) -> Dict:
    """Run safely, no shell=True."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {'returncode': proc.returncode, 'stdout': proc.stdout[:4000], 'stderr': proc.stderr[:1000]}
    except FileNotFoundError:
        return {'returncode': -1, 'stdout': '', 'stderr': f'{cmd[0]!r} not found'}
    except subprocess.TimeoutExpired:
        return {'returncode': -1, 'stdout': '', 'stderr': 'Timed out'}


# --------------------------------------------------------------------------
# health_check hardening (SSRF defense)
# --------------------------------------------------------------------------
# Only these exact paths may be requested. No query strings, no fragments.
ALLOWED_HEALTH_PATHS = frozenset({'/health', '/ready'})
MAX_HEALTH_BODY_BYTES = 4000
MAX_HEALTH_TIMEOUT = 10
# Fail-closed fallback if policy.yaml cannot be read. guardml-api is NOT here.
_DEFAULT_HEALTH_HOSTS = frozenset({'localhost', '127.0.0.1', 'model-api'})
_LOOPBACK_NAMES = frozenset({'localhost', '127.0.0.1', '::1'})
_POLICY_PATH = Path(__file__).resolve().parent.parent / 'toolguard' / 'policy.yaml'


def _allowed_health_hosts() -> Set[str]:
    """Read allowed_health_hosts from policy.yaml (single source of truth)."""
    try:
        import yaml
        data = yaml.safe_load(_POLICY_PATH.read_text(encoding='utf-8')) or {}
        hosts = data.get('allowed_health_hosts')
        if isinstance(hosts, list) and hosts and all(isinstance(h, str) for h in hosts):
            return {h.strip().lower() for h in hosts}
    except Exception:
        pass
    return set(_DEFAULT_HEALTH_HOSTS)


def _validate_health_url(url: str, allowed_hosts: Set[str]) -> Tuple[str, int, str]:
    """Return (host, port, path) or raise ValueError. Strict, exact-match rules."""
    if not isinstance(url, str) or not url or len(url) > 512:
        raise ValueError('invalid url')
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('control characters or whitespace in url')
    if '?' in url or '#' in url:
        raise ValueError('query strings and fragments are not allowed')
    parts = urlsplit(url)
    if parts.scheme != 'http':
        raise ValueError('only http:// is allowed')
    if parts.username is not None or parts.password is not None or '@' in parts.netloc:
        raise ValueError('credentials in url are not allowed')
    host = (parts.hostname or '').lower()
    if not host or host not in allowed_hosts:
        raise ValueError(f'host {host!r} is not in allowed_health_hosts')
    if parts.path not in ALLOWED_HEALTH_PATHS:
        raise ValueError('path must be exactly /health or /ready')
    try:
        port = parts.port or 80
    except ValueError:
        raise ValueError('invalid port')
    return host, port, parts.path


def _resolve_safe_ip(host: str) -> str:
    """Resolve DNS and make sure EVERY resulting IP is acceptable.

    - localhost / 127.0.0.1 must resolve to loopback only.
    - other allowed hosts (e.g. docker service name 'model-api') may be
      private/loopback, but never link-local (cloud metadata 169.254.x),
      multicast, reserved or unspecified addresses.
    Returns the IP to connect to (pinned, so DNS cannot change afterwards).
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f'DNS resolution failed: {e}')
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        # Loopback is checked first: Python flags ::1 as is_reserved, which would
        # wrongly reject 'localhost' on hosts that resolve it to IPv6 (e.g. Windows).
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or (
            ip.is_reserved and not ip.is_loopback
        ):
            raise ValueError(f'resolved IP {ip} is not allowed')
        if host in _LOOPBACK_NAMES:
            if not ip.is_loopback:
                raise ValueError(f'{host} resolved to non-loopback IP {ip}')
        elif not (ip.is_private or ip.is_loopback):
            raise ValueError(f'resolved IP {ip} is not a private/internal address')
        ips.append(str(ip))
    if not ips:
        raise ValueError('no IP addresses resolved')
    return ips[0]


class DockerPs(BaseTool):
    name = 'docker_ps'
    description = 'List running Docker containers.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'all': {'type': 'boolean', 'default': False, 'description': 'Show all containers (including stopped)'},
        },
        'required': [],
    }

    def _execute(self, all: bool = False, **_) -> Dict:
        cmd = ['docker', 'ps', '--format', 'json']
        if all:
            cmd.append('-a')
        result = _run(cmd)
        containers = []
        if result['returncode'] == 0:
            for line in result['stdout'].strip().splitlines():
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    containers.append({'raw': line})
        return {
            'ok': result['returncode'] == 0,
            'containers': containers,
            'error': result['stderr'] if result['returncode'] != 0 else None,
        }


class DockerLogs(BaseTool):
    name = 'docker_logs'
    description = 'Get Docker container logs (last N lines).'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'container': {'type': 'string', 'x-guard': 'container_read', 'description': 'Container name or ID'},
            'lines': {'type': 'integer', 'minimum': 1, 'maximum': 200, 'default': 50, 'description': 'Number of log lines (max 200)'},
            'since': {'type': 'string', 'x-guard': 'duration', 'default': '', 'description': 'Since timestamp (e.g. 1h, 10m)'},
        },
        'required': ['container'],
    }

    def _execute(self, container: str, lines: int = 50, since: str = '', **_) -> Dict:
        lines = min(max(1, int(lines)), 200)
        cmd = ['docker', 'logs', '--tail', str(lines)]
        if since:
            cmd += ['--since', since]
        cmd.append(container)
        result = _run(cmd)
        return {
            'ok': result['returncode'] == 0,
            'container': container,
            'logs': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None,
        }


class DockerStats(BaseTool):
    name = 'docker_stats'
    description = 'Get Docker container resource usage stats (one snapshot).'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'container': {'type': 'string', 'x-guard': 'identifier', 'default': '', 'description': 'Container name or ID (empty=all)'},
        },
        'required': [],
    }

    def _execute(self, container: str = '', **_) -> Dict:
        cmd = ['docker', 'stats', '--no-stream', '--format', 'json']
        if container:
            cmd.append(container)
        result = _run(cmd)
        stats = []
        if result['returncode'] == 0:
            for line in result['stdout'].strip().splitlines():
                try:
                    stats.append(json.loads(line))
                except json.JSONDecodeError:
                    stats.append({'raw': line})
        return {
            'ok': result['returncode'] == 0,
            'stats': stats,
            'error': result['stderr'] if result['returncode'] != 0 else None,
        }


class DockerRestart(BaseTool):
    name = 'docker_restart'
    description = 'Restart a Docker container. WRITE operation.'
    risk_level = RiskLevel.WRITE_LOW
    parameters_schema = {
        'type': 'object',
        'properties': {
            'container': {'type': 'string', 'x-guard': 'identifier', 'description': 'Container name or ID'},
        },
        'required': ['container'],
    }

    def _execute(self, container: str, **_) -> Dict:
        result = _run(['docker', 'restart', container])
        return {
            'ok': result['returncode'] == 0,
            'container': container,
            'message': 'Restart initiated' if result['returncode'] == 0 else result['stderr'],
        }


class HealthCheck(BaseTool):
    name = 'health_check'
    description = 'HTTP GET health check against a model API endpoint (/health or /ready only).'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'url': {
                'type': 'string',
                'x-guard': 'url',
                'default': 'http://localhost:8001/health',
                'description': 'Health endpoint URL (path must be exactly /health or /ready, no query string)',
            },
            'timeout_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 10, 'default': 10},
        },
        'required': [],
    }

    def _execute(self, url: str = 'http://localhost:8001/health', timeout_seconds: int = 10, **_) -> Dict:
        try:
            timeout = min(max(1, int(timeout_seconds)), MAX_HEALTH_TIMEOUT)
        except (TypeError, ValueError):
            timeout = MAX_HEALTH_TIMEOUT

        # 1) Strict URL validation (scheme, host allowlist, exact path, no query)
        try:
            host, port, path = _validate_health_url(url, _allowed_health_hosts())
            # 2) DNS resolution + IP check; connect to the pinned IP below
            ip = _resolve_safe_ip(host)
        except ValueError as e:
            return {'ok': False, 'url': url, 'error': f'blocked: {e}', 'healthy': False}

        conn = None
        try:
            # Connect to the validated IP directly (prevents DNS rebinding);
            # http.client never follows redirects (follow_redirects=False).
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            host_header = host if port == 80 else f'{host}:{port}'
            conn.request('GET', path, headers={'Host': host_header, 'Accept': 'application/json'})
            resp = conn.getresponse()

            if 300 <= resp.status < 400:
                return {
                    'ok': False, 'status_code': resp.status, 'url': url, 'healthy': False,
                    'error': 'blocked: redirects are not followed',
                }

            # 3) Cap bytes read
            body = resp.read(MAX_HEALTH_BODY_BYTES).decode('utf-8', errors='replace')
            try:
                data = json.loads(body)
            except Exception:
                data = {'raw': body}
            return {
                'ok': True,
                'status_code': resp.status,
                'url': url,
                'response': data,
                'healthy': resp.status == 200,
            }
        except Exception as e:
            return {'ok': False, 'url': url, 'error': str(e), 'healthy': False}
        finally:
            if conn is not None:
                conn.close()


class KubectlGetPods(BaseTool):
    name = 'kubectl_get_pods'
    description = 'List Kubernetes pods in a namespace.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'namespace': {'type': 'string', 'x-guard': 'namespace', 'default': 'default', 'description': 'Kubernetes namespace'},
            'label_selector': {'type': 'string', 'x-guard': 'selector', 'default': '', 'description': 'Label selector filter'},
        },
        'required': [],
    }

    def _execute(self, namespace: str = 'default', label_selector: str = '', **_) -> Dict:
        cmd = ['kubectl', 'get', 'pods', '-n', namespace, '-o', 'json']
        if label_selector:
            cmd += ['-l', label_selector]
        result = _run(cmd)
        if result['returncode'] == 0:
            try:
                data = json.loads(result['stdout'])
                items = data.get('items', [])
                pods = [
                    {
                        'name': p['metadata']['name'],
                        'namespace': p['metadata']['namespace'],
                        'status': p['status'].get('phase', ''),
                        'ready': all(
                            c.get('ready', False)
                            for c in p['status'].get('conditions', [])
                            if c.get('type') == 'Ready'
                        ),
                        'restarts': sum(
                            cs.get('restartCount', 0)
                            for cs in p['status'].get('containerStatuses', [])
                        ),
                    }
                    for p in items
                ]
                return {'ok': True, 'pods': pods, 'namespace': namespace}
            except Exception as e:
                pass
        return {
            'ok': result['returncode'] == 0,
            'stdout': result['stdout'],
            'stderr': result['stderr'],
        }


class KubectlLogs(BaseTool):
    name = 'kubectl_logs'
    description = 'Get Kubernetes pod logs.'
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'pod': {'type': 'string', 'x-guard': 'identifier', 'description': 'Pod name'},
            'namespace': {'type': 'string', 'x-guard': 'namespace', 'default': 'default'},
            'lines': {'type': 'integer', 'minimum': 1, 'maximum': 200, 'default': 50, 'description': 'Max log lines (max 200)'},
            'since': {'type': 'string', 'x-guard': 'duration', 'default': '', 'description': 'Since duration (e.g. 1h)'},
        },
        'required': ['pod'],
    }

    def _execute(self, pod: str, namespace: str = 'default', lines: int = 50, since: str = '', **_) -> Dict:
        lines = min(max(1, int(lines)), 200)
        cmd = ['kubectl', 'logs', pod, '-n', namespace, '--tail', str(lines)]
        if since:
            cmd += ['--since', since]
        result = _run(cmd)
        return {
            'ok': result['returncode'] == 0,
            'pod': pod,
            'logs': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None,
        }
