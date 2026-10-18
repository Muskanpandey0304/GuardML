"""
Record fixtures from the REAL tools.

    cd <directory that contains the guardml repo folder>
    python -m guardml.bench.record

What is real and what is not (every fixture file says which, in its `source` field):

  recorded   produced by calling the real tool class right now
               mlflow_*            a throwaway MLflow store (sqlite in a temp dir), trained with
                                   the repo's own demo code. Your demo/mlruns.db is never touched.
               drift_report, data_quality_check, disk_memory_status, gpu_status
                                   real tools on this machine's demo data / hardware
               health_check        real tool over real HTTP, against a loopback stand-in server
  synthetic  docker_*, kubectl_*, dvc_*: those CLIs were not available when recording, so the
             fixture is hand-built to match each tool's documented output format. Re-record on
             a machine that has them to upgrade these to `recorded`.

Safety: nothing outside the temp dir is written; no network beyond loopback; each fixture is
scrubbed of local paths and REFUSED if the secret masker would change it.
"""
from __future__ import annotations

import argparse
import datetime
import http.server
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict

REPO = Path(__file__).resolve().parent.parent
FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'real'

_PATHLIKE = re.compile(r'^[\w./\\:~-]+$')


def scrub(obj: Any, replacements: Dict[str, str]) -> Any:
    """Remove machine-specific paths; normalise Windows separators in path-like strings."""
    if isinstance(obj, str):
        s = obj
        for old, new in sorted(replacements.items(), key=lambda kv: -len(kv[0])):
            s = s.replace(old, new)
            s = s.replace(old.replace('\\', '/'), new)
        if _PATHLIKE.match(s) and '\\' in s:
            s = s.replace('\\', '/')
        return s
    if isinstance(obj, dict):
        return {k: scrub(v, replacements) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, replacements) for v in obj]
    return obj


def validate_fixture(doc: Dict[str, Any]) -> None:
    """Shape + safety checks shared by the recorder and the test-suite."""
    from guardml.toolguard.masking import mask_value
    for key in ('tool', 'source', 'real_output'):
        if key not in doc:
            raise ValueError(f'fixture missing {key!r}')
    if doc['source'] not in ('recorded', 'synthetic'):
        raise ValueError(f"bad source {doc['source']!r}")
    if doc['source'] == 'synthetic' and not doc.get('basis'):
        raise ValueError('synthetic fixtures must say what format they follow (`basis`)')
    if mask_value(doc['real_output']) != doc['real_output']:
        raise ValueError(f"{doc['tool']}: fixture contains something the secret masker would redact")
    text = json.dumps(doc)
    for needle in (str(Path.home()), str(Path.home()).replace('\\', '/'), 'AppData'):
        if needle in text:
            raise ValueError(f"{doc['tool']}: fixture leaks a local path ({needle!r})")


# ---------------------------------------------------------------------------
# Synthetic fixtures (formats follow the tool code in tools/*.py and each CLI's docs)
# ---------------------------------------------------------------------------
_MODEL_API_LOGS = """INFO:     Started server process [1]
INFO:     Waiting for application startup.
Loaded model: models:/fraud_classifier@production
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     172.18.0.4:51234 - "GET /health HTTP/1.1" 200 OK
INFO:     172.18.0.4:51240 - "POST /predict HTTP/1.1" 200 OK
WARNING:  prediction latency p95=212ms exceeds the 150ms budget
ERROR:    scoring failed for 38 rows: ValueError: Input contains NaN (feature distance_from_home)
INFO:     172.18.0.4:51302 - "POST /predict HTTP/1.1" 400 Bad Request
INFO:     172.18.0.4:51310 - "GET /health HTTP/1.1" 200 OK"""

_API_LOGS = """INFO:     Started server process [1]
INFO:     Application startup complete.
INFO:     172.18.0.5:40112 - "GET /health HTTP/1.1" 200 OK
INFO:     172.18.0.5:40118 - "GET /me HTTP/1.1" 200 OK"""

SYNTHETIC: Dict[str, Dict[str, Any]] = {
    'docker_ps': {
        'basis': "docker ps --format json (one JSON object per container), wrapped as tools/deploy_tools.py DockerPs does",
        'real_output': {'ok': True, 'error': None, 'containers': [
            {'Command': '"uvicorn demo.model_api:app --host 0.0.0.0 --port 8001"', 'CreatedAt': '2026-10-13 21:55:02 +0000 UTC',
             'ID': '3f1c2a9b7d10', 'Image': 'guardml-model-api', 'Labels': 'com.docker.compose.project=guardml',
             'LocalVolumes': '0', 'Mounts': '', 'Names': 'model-api', 'Networks': 'guardml_default',
             'Ports': '8001/tcp', 'RunningFor': '2 days ago', 'Size': '0B (virtual 1.9GB)', 'State': 'running',
             'Status': 'Up 2 days (healthy)'},
            {'Command': '"uvicorn guardml.api.main:app --host 0.0.0.0 --port 8000"', 'CreatedAt': '2026-10-13 21:55:01 +0000 UTC',
             'ID': '9ab04e5c1d22', 'Image': 'guardml-api', 'Labels': 'com.docker.compose.project=guardml',
             'LocalVolumes': '1', 'Mounts': 'guardml_guardml_db', 'Names': 'guardml-api', 'Networks': 'guardml_default',
             'Ports': '127.0.0.1:8000->8000/tcp', 'RunningFor': '2 days ago', 'Size': '0B (virtual 2.1GB)',
             'State': 'running', 'Status': 'Up 2 days (healthy)'},
        ]},
    },
    'docker_logs': {
        'basis': 'docker logs --tail N <container>, wrapped as DockerLogs does',
        'real_output': {'ok': True, 'container': 'model-api', 'logs': _MODEL_API_LOGS, 'error': None},
    },
    'docker_stats': {
        'basis': 'docker stats --no-stream --format json, wrapped as DockerStats does',
        'real_output': {'ok': True, 'error': None, 'stats': [
            {'BlockIO': '12.3MB / 0B', 'CPUPerc': '3.41%', 'Container': '3f1c2a9b7d10', 'ID': '3f1c2a9b7d10',
             'MemPerc': '8.12%', 'MemUsage': '652.4MiB / 7.67GiB', 'Name': 'model-api',
             'NetIO': '4.2MB / 3.1MB', 'PIDs': '14'}]},
    },
    'docker_restart': {
        'basis': 'tools/deploy_tools.py DockerRestart success output (no docker daemon was available)',
        'real_output': {'ok': True, 'container': 'model-api', 'message': 'Restart initiated'},
    },
    'kubectl_get_pods': {
        'basis': 'kubectl get pods -o json, reduced as KubectlGetPods does',
        'real_output': {'ok': True, 'namespace': 'default', 'pods': [
            {'name': 'model-api-6c9d8f7b5-x2k4p', 'namespace': 'default', 'status': 'Running', 'ready': True, 'restarts': 3},
            {'name': 'mlflow-0', 'namespace': 'default', 'status': 'Running', 'ready': True, 'restarts': 0}]},
    },
    'kubectl_logs': {
        'basis': 'kubectl logs --tail N <pod>, wrapped as KubectlLogs does',
        'real_output': {'ok': True, 'pod': 'model-api-6c9d8f7b5-x2k4p', 'logs': _MODEL_API_LOGS, 'error': None},
    },
    'dvc_status': {
        'basis': 'dvc status --json, wrapped as DvcStatus does',
        'real_output': {'ok': True, 'repo_path': '.', 'status': {
            'train': [{'changed deps': {'demo/data/train_drifted.csv': 'modified'}}]}},
    },
    'dvc_diff': {
        'basis': 'dvc diff --json, wrapped as DvcDiff does',
        'real_output': {'ok': True, 'diff': {
            'added': [], 'deleted': [], 'renamed': [],
            'modified': [{'path': 'demo/data/current.csv', 'hash': {'old': '5d41402abc4b2a76b9719d911017c592', 'new': '7d793037a0760186574b0282f2f435e7'}}],
            'not in cache': []}},
    },
}


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------
class _HealthStub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # mirrors demo/model_api.py /health
        body = json.dumps({'status': 'healthy', 'model_loaded': True,
                           'model_name': 'fraud_classifier', 'model_alias': 'production'}).encode()
        self.send_response(200 if self.path == '/health' else 404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _write(out_dir: Path, tool: str, source: str, output: Any, basis: str = '', note: str = '') -> None:
    doc = {'tool': tool, 'case': 'default', 'source': source, 'real_output': output}
    if basis:
        doc['basis'] = basis
    if note:
        doc['note'] = note
    if source == 'recorded':
        doc['recorded_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%MZ')
    validate_fixture(doc)
    path = out_dir / tool / 'default.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=False, default=str) + '\n', encoding='utf-8')
    print(f'  {source:9s} {tool}')


def train_demo_store(work: Path):
    """
    Train the demo models into a throwaway MLflow store inside `work`.
    Returns (tracking_uri, run_id_v1, run_id_v2). The caller must have set
    MLFLOW_TRACKING_URI to that URI BEFORE importing the tool modules when it wants the
    real tools to use this store (see real_tier.py, which patches the module constant).
    """
    import mlflow
    from guardml.demo import train_model as tm
    uri = 'sqlite:///' + (work / 'mlruns.db').as_posix()
    mlflow.set_tracking_uri(uri)
    client = mlflow.MlflowClient(tracking_uri=uri)
    client.create_experiment(tm.EXPERIMENT_NAME, artifact_location=(work / 'artifacts').as_uri())
    run1 = tm.train_v1(tm.generate_dataset(5000, seed=42, drift=False), client)
    run2 = tm.train_v2(tm.generate_dataset(5000, seed=99, drift=True))
    tm.set_aliases(client)
    return uri, run1, run2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', default=str(FIXTURE_DIR), help='fixture directory to write')
    ap.add_argument('--keep-temp', action='store_true')
    args = ap.parse_args(argv)
    out_dir = Path(args.out)

    work = Path(tempfile.mkdtemp(prefix='guardbench_rec_'))
    uri = 'sqlite:///' + (work / 'mlruns.db').as_posix()
    # Must be set BEFORE the tool modules are imported (they read it at import time).
    os.environ['MLFLOW_TRACKING_URI'] = uri
    os.environ['MLFLOW_DISABLE_AGENT_HINT'] = '1'
    os.chdir(REPO)
    server = None
    try:
        import mlflow
        from guardml.demo import train_model as tm
        from guardml.tools.registry import get_registry

        print(f'Training the demo models into a throwaway MLflow store ({work.name}) ...')
        mlflow.set_tracking_uri(uri)
        client = mlflow.MlflowClient(tracking_uri=uri)
        client.create_experiment(tm.EXPERIMENT_NAME, artifact_location=(work / 'artifacts').as_uri())
        run1 = tm.train_v1(tm.generate_dataset(5000, seed=42, drift=False), client)
        run2 = tm.train_v2(tm.generate_dataset(5000, seed=99, drift=True))
        tm.set_aliases(client)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _HealthStub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]

        replacements = {str(work): '/tmp/guardbench', work.as_uri(): 'file:///tmp/guardbench',
                        str(REPO): '.', str(Path.home()): '~', f'127.0.0.1:{port}': 'localhost:8001'}
        registry = get_registry()
        real_calls = {
            'mlflow_list_runs': {'experiment_name': 'fraud_detection'},
            'mlflow_get_run': {'run_id': run1},
            'mlflow_compare_runs': {'run_id_a': run1, 'run_id_b': run2},
            'mlflow_list_model_versions': {'model_name': 'fraud_classifier'},
            'mlflow_get_production_model': {'model_name': 'fraud_classifier'},
            'mlflow_set_alias': {'model_name': 'fraud_classifier', 'alias': 'production', 'version': '1'},
            'drift_report': {'reference_path': 'demo/data/reference.csv', 'current_path': 'demo/data/current.csv'},
            'data_quality_check': {'data_path': 'demo/data/current.csv'},
            'disk_memory_status': {'path': './demo/data'},
            'gpu_status': {},
            'health_check': {'url': f'http://127.0.0.1:{port}/health'},
        }
        print('Recording real tool output:')
        for tool_name, call_args in real_calls.items():
            res = registry.get(tool_name).run(**call_args)
            if not res.ok:
                raise RuntimeError(f'{tool_name} failed while recording: {res.error}')
            data = scrub(res.data, replacements)
            if isinstance(data, dict) and data.get('ok') is False:
                raise RuntimeError(f'{tool_name} reported failure while recording: {data}')
            _write(out_dir, tool_name, 'recorded', data)

        print('Writing synthetic fixtures (docker / kubectl / dvc not available here):')
        for tool_name, spec in SYNTHETIC.items():
            _write(out_dir, tool_name, 'synthetic', spec['real_output'], basis=spec['basis'])
    finally:
        if server is not None:
            server.shutdown()
        if not args.keep_temp:
            shutil.rmtree(work, ignore_errors=True)
    print(f'Done. Fixtures are in {out_dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
