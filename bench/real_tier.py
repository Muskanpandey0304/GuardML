"""
GuardBench, real-infrastructure tier.

    python -m guardml.bench.run --tier real

Answers one question: do the fixture-tier results hold up against REAL systems? Here the MLflow
tools, the snapshot/rollback manager and the data tools are real, and "did the attack work?" is
read from the real MLflow store, not from a model of it.

Safety rules, enforced in code (the tier refuses to start if any is violated):
  * the MLflow store, the audit/approval/snapshot DB and the artifacts live in a fresh temp dir;
    your demo/mlruns.db and guardml.db are never opened
  * the environment must be `staging`; scenarios in other environments are skipped
  * configs without a guard (a_no_guard, b_prompt_only) are REFUSED: unguarded destructive calls
    never touch real infrastructure, even throwaway infrastructure
  * only an explicit allow-list of tools is real (MLflow, drift, data quality, health). Anything else
    (docker_restart, kubectl, dvc ...) is served from fixtures, so no real container is ever touched
  * the real data tools are jailed to demo/data, and the real health tool can only reach the
    loopback stand-in server, even if the guard under test were to let a bad call through
  * the model-api health endpoint is a loopback stand-in (healthy / unhealthy / down), because no
    container runtime is assumed
"""
from __future__ import annotations

import copy
import http.server
import importlib
import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardml.tools.base import BaseTool

from .configs import CONFIGS, Config
from .metrics import summarize
from .report import write_results
from .runner import TierHooks, BenchEnv, run_scenario
from .scenarios import Scenario, load_real
from .world import FixtureTool, World, _ExtraTool, _EXTRA_SPECS, _initial_aliases, apply_injection

REPO = Path(__file__).resolve().parent.parent
DEMO_DATA = (REPO / 'demo' / 'data').resolve()
MODEL = 'fraud_classifier'
KEEP_ALIASES = ('production', 'champion')

# Tools allowed to be REAL in this tier. Everything else is served from fixtures.
REAL_TOOLS = {
    'mlflow_list_runs', 'mlflow_get_run', 'mlflow_compare_runs', 'mlflow_list_model_versions',
    'mlflow_get_production_model', 'mlflow_set_alias',
    'drift_report', 'data_quality_check', 'health_check',
}
_PATH_ARGS = {'drift_report': ('reference_path', 'current_path'), 'data_quality_check': ('data_path',)}
_MODEL_API_ADDR = 'http://localhost:8001/'


class SandboxViolation(SystemExit):
    pass


# ---------------------------------------------------------------------------
# Loopback stand-in for model-api (/health)
# ---------------------------------------------------------------------------
class HealthStub:
    def __init__(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                healthy = outer.mode == 'healthy' and self.path == '/health'
                body = ('{"status": "healthy", "model_loaded": true}' if healthy
                        else '{"status": "degraded", "model_loaded": false}').encode()
                self.send_response(200 if healthy else 503)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.mode = 'healthy'
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f'http://127.0.0.1:{self.port}/health'

    def close(self) -> None:
        self.server.shutdown()


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]  # released on exit: nothing listens there


# ---------------------------------------------------------------------------
# Real tools, jailed, with injections applied to their real output
# ---------------------------------------------------------------------------
class RealWorld(World):
    """Ground truth comes from the real MLflow store (filled in after each run)."""

    def __init__(self):
        super().__init__()
        self.aliases = {}

    def apply(self, tool: str, args: Dict[str, Any]) -> None:
        if tool != 'mlflow_set_alias':  # the real tool does that one; fixture-served tools record here
            super().apply(tool, args)


class JailedRealTool(BaseTool):
    def __init__(self, real: BaseTool, world: World, injections, health_url: str):
        self.name, self.description = real.name, real.description
        self.parameters_schema, self.risk_level = real.parameters_schema, real.risk_level
        self.timeout_seconds = getattr(real, 'timeout_seconds', 30.0)
        self._real, self._world, self._inj, self._health_url = real, world, list(injections), health_url

    def _jail(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        for arg in _PATH_ARGS.get(self.name, ()):
            val = kwargs.get(arg)
            if val:
                resolved = Path(os.path.realpath(val))
                if DEMO_DATA != resolved and DEMO_DATA not in resolved.parents:
                    raise RuntimeError(f'bench jail: {arg}={val!r} is outside demo/data (the guard let it through)')
        if self.name == 'health_check':
            url = kwargs.get('url') or _MODEL_API_ADDR + 'health'
            if url.startswith(_MODEL_API_ADDR):          # the model-api address maps to the stand-in
                return dict(kwargs, url=self._health_url)
            if url != self._health_url:
                raise RuntimeError(f'bench jail: health_check may only reach the loopback stand-in, not {url!r}')
        return kwargs

    def _execute(self, **kwargs) -> Any:
        self._world.record(self.name, kwargs)
        res = self._real.run(**self._jail(kwargs))
        if not res.ok:
            raise RuntimeError(res.error)
        data = copy.deepcopy(res.data)
        for inj in self._inj:
            apply_injection(data, inj)
        return data


class RealRegistry:
    def __init__(self, world: World, injections, health_url: str):
        from guardml.tools.registry import get_registry
        injections = list(injections)
        self._tools: Dict[str, BaseTool] = {}
        for t in get_registry().all_tools():
            mine = [i for i in injections if i.tool == t.name]
            self._tools[t.name] = (JailedRealTool(t, world, mine, health_url) if t.name in REAL_TOOLS
                                   else FixtureTool(t, world, mine))
        for name, desc, props in _EXTRA_SPECS:
            self._tools[name] = _ExtraTool(name, desc, props, world)

    def get(self, name):
        return self._tools.get(name)

    def all_tools(self):
        return list(self._tools.values())

    def all_schemas(self):
        return [t.to_schema() for t in self._tools.values()]

    def names(self):
        return list(self._tools)


# ---------------------------------------------------------------------------
# Real store helpers
# ---------------------------------------------------------------------------
def real_aliases(client) -> Dict[str, str]:
    rm = client.get_registered_model(MODEL)
    return {f'{MODEL}@{a}': str(v) for a, v in rm.aliases.items()}


def reset_store(client) -> None:
    """Back to the demo starting state: v2 (bad) = production, v1 (good) = champion, no other aliases."""
    for alias in list(client.get_registered_model(MODEL).aliases):
        if alias not in KEEP_ALIASES:
            client.delete_registered_model_alias(MODEL, alias)
    client.set_registered_model_alias(MODEL, 'production', '2')
    client.set_registered_model_alias(MODEL, 'champion', '1')


def assert_sandboxed(work: Path, uri: str) -> None:
    """Refuse to run unless every state-changing path is inside this tier's temp dir."""
    tmp_root = Path(tempfile.gettempdir()).resolve()
    if not uri.startswith('sqlite:///'):
        raise SandboxViolation(f'refusing: MLflow URI must be a local sqlite file, got {uri!r}')
    db = Path(uri[len('sqlite:///'):]).resolve()
    if work.resolve() not in db.parents or tmp_root not in db.parents:
        raise SandboxViolation(f'refusing: MLflow store {db} is not inside the temp sandbox {work}')
    from guardml.tools import mlflow_tools
    if mlflow_tools.DEFAULT_TRACKING_URI != uri or os.environ.get('MLFLOW_TRACKING_URI') != uri:
        raise SandboxViolation('refusing: the real MLflow tools are not pointed at the sandbox store')
    if os.environ.get('GUARDML_ENVIRONMENT', 'staging').strip().lower() != 'staging':
        raise SandboxViolation('refusing: GUARDML_ENVIRONMENT must be staging for the real tier')
    for p in (db, Path(os.environ.get('GUARDML_DB', ''))):
        if str(p) and str(p.resolve()) in {str((REPO / 'demo' / 'mlruns.db').resolve()), str((REPO / 'guardml.db').resolve())}:
            raise SandboxViolation(f'refusing: {p} is one of your real databases')


def refuse_unguarded(configs: List[Config]) -> None:
    bad = [c.name for c in configs if not c.guarded]
    if bad:
        raise SandboxViolation(
            f'refusing to run {bad} on real infrastructure: unguarded destructive calls never touch real '
            'systems, even throwaway ones. Use the fixture tier for the no-guard baseline.')


# ---------------------------------------------------------------------------
# Sandbox: everything the tier needs, torn down afterwards
# ---------------------------------------------------------------------------
class RealSandbox:
    def __init__(self, scenarios_hint: int = 0):
        self.work = Path(tempfile.mkdtemp(prefix='guardbench_real_'))
        self.stub: Optional[HealthStub] = None
        self._saved_env: Dict[str, Optional[str]] = {}

    def start(self) -> None:
        os.environ['MLFLOW_DISABLE_AGENT_HINT'] = '1'
        os.environ['GUARDML_ENVIRONMENT'] = 'staging'
        # Tools and the guard resolve relative paths (demo/data/...) from the working directory,
        # exactly as in the product, so run from the repo root and restore afterwards.
        self._cwd = os.getcwd()
        os.chdir(REPO)
        from .record import train_demo_store
        print(f'Training the demo models into a sandbox MLflow store ({self.work.name}) ...')
        self.uri, self.run1, self.run2 = train_demo_store(self.work)

        # Point the real tools at the sandbox. mlflow_tools reads its URI constant at call time;
        # snapshots / rollback read the environment variable at call time.
        os.environ['MLFLOW_TRACKING_URI'] = self.uri
        from guardml.tools import mlflow_tools
        mlflow_tools.DEFAULT_TRACKING_URI = self.uri

        self.env = BenchEnv(self.work)  # temp audit/approval DB (sets GUARDML_DB)
        import guardml.safety.snapshots as snapmod
        import guardml.safety.rollback as rbmod
        importlib.reload(snapmod)       # DB_PATH is read at import
        importlib.reload(rbmod)
        self.snapshots, self.rollback = snapmod.SnapshotManager(), rbmod.RollbackManager()

        assert_sandboxed(self.work, self.uri)
        import mlflow
        self.client = mlflow.MlflowClient(tracking_uri=self.uri)
        self.stub = HealthStub()
        self.down_port = _closed_port()

    def hooks(self) -> TierHooks:
        def before(sc: Scenario) -> None:
            reset_store(self.client)
            self.stub.mode = 'unhealthy' if sc.health == 'unhealthy' else 'healthy'
            port = self.down_port if sc.health == 'down' else self.stub.port
            os.environ['GUARDML_VERIFY_URL'] = f'http://127.0.0.1:{port}/health'

        def make_world(sc: Scenario):
            world = RealWorld()
            return RealRegistry(world, sc.injections, self.stub.url), world

        def after(sc: Scenario, world: World) -> None:
            world.aliases = real_aliases(self.client)

        return TierHooks(make_world=make_world, snapshots=self.snapshots, rollback=self.rollback,
                         before=before, after=after)

    def close(self) -> None:
        if self.stub:
            self.stub.close()
        os.environ.pop('GUARDML_VERIFY_URL', None)
        if getattr(self, '_cwd', None):
            os.chdir(self._cwd)
        shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI entry (called from run.py)
# ---------------------------------------------------------------------------
def main_real(args) -> int:
    from .run import CountingProvider, _select
    from guardml.agent.llm import make_completer, select_provider
    from guardml.toolguard.intent import IntentJudge
    from .configs import JUDGE_RECORDING, ReplayCompleter, RecordingCompleter, resolve_configs

    live = args.mode == 'live'
    spec = args.configs if args.configs != 'all' else ('c_toolguard,d_provenance,e_full' if live
                                                       else 'c_toolguard,d_provenance')
    configs = resolve_configs(spec)
    refuse_unguarded(configs)

    scenarios = [s for s in _select(load_real(), 'all', args.only, args.limit, args.category) if s.env == 'staging']
    if not scenarios:
        print('No real-tier scenarios selected.')
        return 2

    inner = select_provider() if live else None
    if live and inner is None:
        print('Live mode needs GEMINI_API_KEY or ANTHROPIC_API_KEY.')
        return 2
    if live and not args.yes:
        print(f'Live real-tier run on {inner.name}/{inner.model}. Re-run with --yes to spend API quota.')
        return 2
    replay = None
    runnable: List[Config] = []
    for cfg in configs:
        if cfg.intent and not live:
            replay = ReplayCompleter(JUDGE_RECORDING)
            if not replay.replies:
                print(f'skip {cfg.name}: no recorded judge replies (run live with --record-judge first)')
                continue
        runnable.append(cfg)
    if not runnable:
        return 2

    approvers = [a.strip() for a in args.approvers.split(',')]
    box = RealSandbox()
    records: List[Dict[str, Any]] = []
    recorder = None
    try:
        box.start()

        def judge_factory() -> IntentJudge:
            nonlocal recorder
            if live:
                recorder = recorder or RecordingCompleter(make_completer(inner, args.judge_model))
                return IntentJudge(recorder)
            return IntentJudge(replay)

        hooks = box.hooks()
        for cfg in runnable:
            print(f'\n[{cfg.name}] ', end='', flush=True)
            for sc in scenarios:
                for approver in approvers:
                    rec = run_scenario(box.env, sc, cfg, approver, hooks=hooks, judge_factory=judge_factory,
                                       provider_factory=(lambda s: CountingProvider(inner)) if live else None,
                                       mode=args.mode)
                    records.append(rec)
                    print('E' if rec.get('error') else '.', end='', flush=True)
            print()
    finally:
        box.close()

    if recorder is not None and args.record_judge:
        recorder.save(JUDGE_RECORDING)
    summary = summarize(records)
    attacks = [s for s in scenarios if s.is_attack]
    tag = args.tag or f'real-{args.mode}'
    meta = {'title': tag, 'tier': 'real', 'mode': args.mode, 'split': 'real',
            'model': f'{inner.name}/{inner.model}' if inner else None,
            'n_scenarios': len(scenarios), 'n_attack': len(attacks), 'n_benign': len(scenarios) - len(attacks),
            'configs': [c.name for c in runnable]}
    paths = write_results(Path(args.out), tag, meta, summary, records)
    print(f"\nWrote {paths['markdown']}\n      {paths['json']}")
    errored = [r for r in records if r.get('error')]
    if errored:
        print(f'WARNING: {len(errored)} runs errored (first: {errored[0]["scenario"]}: {errored[0]["error"]})')
        return 1
    return 0
