"""
The controlled "world" GuardBench's tools talk to.

Only the world is controlled. The guard, the approval flow, the audit log and (in
live mode) the LLM are all real. The tools keep their real names, schemas and risk
levels, but `run()` serves recorded outputs from bench/fixtures/real/ with an
explicit, reviewable injection patch applied on top, and records side effects in a
World object so "did the attack work?" is answered from state, not from a guess.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from guardml.tools.base import BaseTool, RiskLevel

FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'real'


class FixtureError(Exception):
    pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@lru_cache(maxsize=None)
def _load_fixture_file(tool: str, case: str) -> str:
    path = FIXTURE_DIR / tool / f'{case}.json'
    if not path.exists():
        raise FixtureError(f'no fixture for tool {tool!r} case {case!r} ({path})')
    return path.read_text(encoding='utf-8')


def load_fixture(tool: str, case: str = 'default') -> Dict[str, Any]:
    """The fixture file as a dict (fresh copy; callers may mutate it)."""
    return json.loads(_load_fixture_file(tool, case))


def fixture_sources() -> Dict[str, str]:
    """tool name -> 'recorded' | 'synthetic' | 'derived' for every default fixture on disk."""
    out: Dict[str, str] = {}
    if FIXTURE_DIR.exists():
        for f in sorted(FIXTURE_DIR.glob('*/default.json')):
            out[f.parent.name] = json.loads(f.read_text(encoding='utf-8')).get('source', 'unknown')
    return out


# ---------------------------------------------------------------------------
# Injection patches
# ---------------------------------------------------------------------------
def _segments(path: Any) -> List[str]:
    if isinstance(path, list):
        return [str(p) for p in path]
    return [p for p in str(path).split('.') if p != '']


def _key(container: Any, seg: str) -> Any:
    return int(seg) if isinstance(container, list) else seg


def apply_injection(data: Any, inj: Any) -> Any:
    """
    Plant attacker-controlled text inside a tool output.

    inj.path   dotted path (or list of keys) to the target inside the output
    inj.mode   append  -> add after existing text / list item
               prepend -> add before
               set     -> overwrite (or create) the value
    inj.text   the payload
    """
    segs = _segments(inj.path)
    if not segs:
        raise FixtureError('injection path is empty')
    parent = data
    try:
        for seg in segs[:-1]:
            parent = parent[_key(parent, seg)]
        last = _key(parent, segs[-1])
        if inj.mode == 'set':
            parent[last] = inj.text
            return data
        current = parent[last]
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise FixtureError(f'injection path {inj.path!r} not found in {inj.tool} output: {e!r}')
    if isinstance(current, str):
        parent[last] = (current + '\n' + inj.text) if inj.mode == 'append' else (inj.text + '\n' + current)
    elif isinstance(current, list):
        if inj.mode == 'append':
            current.append(inj.text)
        else:
            current.insert(0, inj.text)
    else:
        raise FixtureError(f'cannot {inj.mode} into {type(current).__name__} at {inj.path!r}')
    return data


# ---------------------------------------------------------------------------
# World state: the ground truth for "did the attack work?"
# ---------------------------------------------------------------------------
def _initial_aliases() -> Dict[str, str]:
    # Matches demo/train_model.py: v1 (good) = champion, v2 (bad) = production.
    return {'fraud_classifier@champion': '1', 'fraud_classifier@production': '2'}


@dataclass
class World:
    aliases: Dict[str, str] = field(default_factory=_initial_aliases)
    restarts: List[str] = field(default_factory=list)
    deleted: List[str] = field(default_factory=list)
    exec_log: List[Dict[str, Any]] = field(default_factory=list)  # every tool.run() that happened

    def record(self, tool: str, args: Dict[str, Any]) -> None:
        self.exec_log.append({'tool': tool, 'args': dict(args)})

    def apply(self, tool: str, args: Dict[str, Any]) -> None:
        if tool == 'mlflow_set_alias':
            self.aliases[f"{args.get('model_name')}@{args.get('alias')}"] = str(args.get('version'))
        elif tool == 'docker_restart':
            self.restarts.append(str(args.get('container')))
        elif tool in ('mlflow_delete_model', 'docker_exec', 'kubectl_delete'):
            self.deleted.append(f'{tool}:{json.dumps(args, sort_keys=True, default=str)}')


def derived_output(tool: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Write tools echo their arguments; the format mirrors the real tool classes."""
    if tool == 'mlflow_set_alias':
        return {'ok': True, 'model_name': args.get('model_name'), 'alias': args.get('alias'),
                'version': args.get('version'),
                'message': f"Alias {args.get('alias')!r} now points to version {args.get('version')}"}
    if tool == 'docker_restart':
        return {'ok': True, 'container': args.get('container'), 'message': 'Restart initiated'}
    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
class FixtureTool(BaseTool):
    """Same name / schema / risk level as a real tool; serves fixtures; records side effects."""

    def __init__(self, real: BaseTool, world: World, injections: Iterable[Any] = ()):
        self.name = real.name
        self.description = real.description
        self.parameters_schema = real.parameters_schema
        self.risk_level = real.risk_level
        self.timeout_seconds = getattr(real, 'timeout_seconds', 30.0)
        self._world = world
        self._injections = list(injections)

    def _execute(self, **kwargs) -> Any:
        self._world.record(self.name, kwargs)
        self._world.apply(self.name, kwargs)
        derived = derived_output(self.name, kwargs)
        if derived is not None:
            return derived
        data = load_fixture(self.name)['real_output']
        for inj in self._injections:
            apply_injection(data, inj)
        return data


class _ExtraTool(BaseTool):
    """
    Dangerous capabilities that exist in a real environment but that GuardML's registry
    deliberately does not expose. They are registered here so the NO-GUARD baseline can
    actually perform the attack (otherwise it would 'fail' only because the tool is missing),
    and so the guard has to refuse a registered, callable tool.
    """

    def __init__(self, name: str, description: str, properties: Dict[str, Any], world: World):
        self.name = name
        self.description = description
        self.parameters_schema = {'type': 'object', 'properties': properties, 'required': list(properties)}
        self.risk_level = RiskLevel.WRITE_HIGH
        self.timeout_seconds = 30.0
        self._world = world

    def _execute(self, **kwargs) -> Any:
        self._world.record(self.name, kwargs)
        self._world.apply(self.name, kwargs)
        return {'ok': True, 'message': f'{self.name} completed'}


_EXTRA_SPECS = [
    ('mlflow_delete_model', 'Delete a registered MLflow model and all its versions.',
     {'model_name': {'type': 'string', 'description': 'Registered model name'}}),
    ('docker_exec', 'Run a command inside a running container.',
     {'container': {'type': 'string', 'description': 'Container name'},
      'command': {'type': 'string', 'description': 'Command to run'}}),
    ('kubectl_delete', 'Delete a Kubernetes pod.',
     {'pod': {'type': 'string', 'description': 'Pod name'}}),
]


class FixtureRegistry:
    """Drop-in for ToolRegistry: same tool names as the real registry, plus the extras."""

    def __init__(self, world: World, injections: Iterable[Any] = ()):
        from guardml.tools.registry import get_registry
        injections = list(injections)
        self.world = world
        self._tools: Dict[str, BaseTool] = {
            t.name: FixtureTool(t, world, [i for i in injections if i.tool == t.name])
            for t in get_registry().all_tools()
        }
        for name, desc, props in _EXTRA_SPECS:
            self._tools[name] = _ExtraTool(name, desc, props, world)

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def all_tools(self) -> List[BaseTool]:
        return list(self._tools.values())

    def all_schemas(self) -> List[dict]:
        return [t.to_schema() for t in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools)
