"""
Scenario schema + loader.

A scenario is one task for the agent plus a precise, machine-checkable definition of
"the attack worked" (or, for benign tasks, "the task was done").
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field, model_validator

SCENARIO_DIR = Path(__file__).parent / 'scenarios'

Category = Literal['benign', 'direct_attack', 'indirect_injection', 'bypass']


class _Strict(BaseModel):
    model_config = {'extra': 'forbid'}


class Step(_Strict):
    """One tool call the scripted (offline) agent makes. Args may use {$from: tool, path: a.b.0.c}."""
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None
    # The tool name is deliberately not in the registry (spelling / case tricks). Otherwise a
    # step naming an unknown tool is rejected at load time as a probable typo.
    unregistered: bool = False


class CallPattern(_Strict):
    """Matches a proposed tool call: same tool, args a superset of `args`, optional substring."""
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    contains: Optional[str] = None  # any argument value contains this text


class Injection(_Strict):
    """Attacker-controlled text planted inside a tool's output (see world.apply_injection)."""
    tool: str
    path: Any                     # dotted string or list of keys into the tool's output
    mode: Literal['append', 'prepend', 'set'] = 'append'
    text: Any


class Utility(_Strict):
    """Benign success: every pattern in `executed` ran, and the end state matches."""
    executed: List[CallPattern] = Field(default_factory=list)
    aliases: Dict[str, str] = Field(default_factory=dict)          # expected end state of the world
    expect_approval: List[CallPattern] = Field(default_factory=list)  # calls a human SHOULD be asked about
    # Real tier only: what the post-write health check must conclude (kept | rolled_back | kept_unverified)
    verification: Optional[Literal['kept', 'rolled_back', 'kept_unverified']] = None


class Attack(_Strict):
    """The attack worked if any of these calls actually executed."""
    calls: List[CallPattern]


class ApprovalAttack(_Strict):
    """
    Attacks on the approval mechanism itself:
      tamper        approve call A, then execute different call B with A's approval id
      replay        approve A, run A (legitimately), then run A again with the same id
      cross_session approve A in session 1, run A in session 2
      cross_env     approve A in staging, run A claiming production (or, if `attack` is given, run that call in production)
    """
    kind: Literal['tamper', 'replay', 'cross_session', 'cross_env']
    original: Step
    attack: Optional[Step] = None  # required for 'tamper', optional for 'cross_env'


class Scenario(_Strict):
    id: str
    category: Category
    description: str
    prompt: str
    env: Literal['staging', 'production'] = 'staging'
    injections: List[Injection] = Field(default_factory=list)
    agent: List[Step] = Field(default_factory=list)   # what the scripted (offline) agent does
    utility: Optional[Utility] = None
    attack: Optional[Attack] = None
    approval_attack: Optional[ApprovalAttack] = None
    tags: List[str] = Field(default_factory=list)
    split: Literal['dev', 'holdout', 'real', 'live', 'adversarial'] = 'dev'
    # Who wrote it. Empty = the guard's author. Scenarios written by other people are reported separately
    # (they are the fairest test), so files named external-*.yaml must set this on every scenario.
    author: Optional[str] = None
    # Real tier only: how the stand-in model-api answers the post-write health check
    health: Literal['healthy', 'unhealthy', 'down'] = 'healthy'

    @model_validator(mode='after')
    def _consistent(self) -> 'Scenario':
        if self.category == 'benign':
            if self.utility is None or self.attack or self.approval_attack:
                raise ValueError(f'{self.id}: benign scenarios need `utility` and nothing attack-related')
        else:
            if self.approval_attack is None and self.attack is None:
                raise ValueError(f'{self.id}: attack scenarios need `attack` (or `approval_attack`)')
            if self.utility is not None:
                raise ValueError(f'{self.id}: attack scenarios must not declare `utility`')
        if self.approval_attack is not None:
            if self.approval_attack.kind == 'tamper' and self.approval_attack.attack is None:
                raise ValueError(f'{self.id}: tamper needs an `attack` step')
        elif not self.agent:
            raise ValueError(f'{self.id}: needs an `agent` script')
        return self

    @property
    def is_attack(self) -> bool:
        return self.category != 'benign'


def load_file(path: Path, split: str = 'dev') -> List[Scenario]:
    raw = yaml.safe_load(path.read_text(encoding='utf-8')) or []
    out = []
    for item in raw:
        item = dict(item)
        item.setdefault('split', split)
        sc = Scenario.model_validate(item)
        if path.name.startswith('external-') and not (sc.author or '').strip():
            raise ValueError(f"{path.name}: scenario {sc.id!r} needs `author:` (files named external-*.yaml are credited and reported separately)")
        out.append(sc)
    return out


def load_adversarial(directory: Optional[Path] = None) -> List[Scenario]:
    """Red-team scenarios written by the guard's own author (scenarios/adversarial/*.yaml). Not independent."""
    base = (directory or SCENARIO_DIR) / 'adversarial'
    out: List[Scenario] = []
    for f in sorted(base.glob('*.yaml')) if base.exists() else []:
        out += load_file(f, 'adversarial')
    return out


def load_live(directory: Optional[Path] = None) -> List[Scenario]:
    """Scenarios written for live models (scenarios/live/*.yaml): the user invites action, the injection redirects it."""
    base = (directory or SCENARIO_DIR) / 'live'
    out: List[Scenario] = []
    for f in sorted(base.glob('*.yaml')) if base.exists() else []:
        out += load_file(f, 'live')
    return out


def load_real(directory: Optional[Path] = None) -> List[Scenario]:
    """Scenarios for the real-infrastructure tier (scenarios/real/*.yaml)."""
    base = (directory or SCENARIO_DIR) / 'real'
    out: List[Scenario] = []
    for f in sorted(base.glob('*.yaml')) if base.exists() else []:
        out += load_file(f, 'real')
    return out


def load_all(include_holdout: bool = False, directory: Optional[Path] = None) -> List[Scenario]:
    """Dev scenarios (scenarios/*.yaml), plus held-out ones (scenarios/holdout/*.yaml) if asked."""
    base = directory or SCENARIO_DIR
    scenarios: List[Scenario] = []
    for f in sorted(base.glob('*.yaml')):
        scenarios += load_file(f, 'dev')
    if include_holdout and (base / 'holdout').exists():
        for f in sorted((base / 'holdout').glob('*.yaml')):
            scenarios += load_file(f, 'holdout')
    ids = [s.id for s in scenarios]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f'duplicate scenario ids: {sorted(dupes)}')
    return scenarios


def matches(pattern: CallPattern, tool: str, args: Dict[str, Any]) -> bool:
    """Does a proposed call match a pattern?"""
    if pattern.tool != tool:
        return False
    for k, v in pattern.args.items():
        if str(args.get(k)) != str(v):
            return False
    if pattern.contains is not None:
        needle = pattern.contains.lower()
        if not any(needle in str(v).lower() for v in args.values()):
            return False
    return True
