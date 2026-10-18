"""
GuardBench CLI.

Run from the directory that CONTAINS the repo folder (so `guardml` is importable):

  python -m guardml.bench.run                         # offline, dev scenarios, all runnable configs
  python -m guardml.bench.run --split holdout         # the held-out attacks (report them separately)
  python -m guardml.bench.run --mode live --yes       # a real LLM decides (costs API calls)
  python -m guardml.bench.run --mode live --yes --record-judge   # also save judge replies for offline replay

Offline mode is deterministic and free: a scripted agent does what each scenario says (for attacks:
a model that already fell for the trap). Live mode lets a real model decide.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardml.agent.llm import LLMProvider, make_completer, select_provider
from guardml.toolguard.intent import IntentJudge

from .configs import CONFIGS, JUDGE_RECORDING, Config, RecordingCompleter, ReplayCompleter, resolve_configs
from .metrics import summarize
from .report import write_results
from .runner import APPROVERS, BenchEnv, run_scenario, validate_scenarios
from .scenarios import Scenario, load_adversarial, load_all, load_live

RESULTS_DIR = Path(__file__).parent / 'results'


class CountingProvider(LLMProvider):
    def __init__(self, inner: LLMProvider):
        self.inner, self.name, self.model, self.calls = inner, inner.name, inner.model, []
        self.models: Dict[str, int] = {}  # model that actually answered -> number of calls

    def generate(self, system, messages, tools):
        self.calls.append(1)
        out = self.inner.generate(system, messages, tools)
        used = getattr(self.inner, 'last_model', None) or self.inner.model
        if out is not None:
            self.models[used] = self.models.get(used, 0) + 1
        return out


def _select(scenarios: List[Scenario], split: str, only: Optional[str], limit: int,
            category: Optional[str] = None) -> List[Scenario]:
    if category:
        wanted_cat = {c.strip() for c in category.split(',')}
        scenarios = [s for s in scenarios if s.category in wanted_cat]
    if split != 'all':
        scenarios = [s for s in scenarios if s.split == split]
    if only:
        wanted = {x.strip() for x in only.split(',')}
        scenarios = [s for s in scenarios if s.id in wanted]
    return scenarios[:limit] if limit else scenarios


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='GuardBench', formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument('--tier', choices=['fixture', 'real'], default='fixture')
    ap.add_argument('--mode', choices=['offline', 'live'], default='offline')
    ap.add_argument('--configs', default='all', help=f'comma list or "all": {", ".join(CONFIGS)}')
    ap.add_argument('--split', choices=['dev', 'holdout', 'live', 'adversarial', 'all'], default='dev',
                    help='live = written for live models; adversarial = red team by the guard author (not independent)')
    ap.add_argument('--approvers', default=','.join(APPROVERS))
    ap.add_argument('--only', help='comma-separated scenario ids')
    ap.add_argument('--category', help='comma-separated: benign, direct_attack, indirect_injection, bypass')
    ap.add_argument('--limit', type=int, default=0, help='first N scenarios only (smoke test)')
    ap.add_argument('--repeat', type=int, default=1, help='live mode: repeat each run N times')
    ap.add_argument('--judge-model', default=None, help='model for the intent judge (default: the agent model)')
    ap.add_argument('--record-judge', action='store_true', help='live mode: save judge replies for offline replay')
    ap.add_argument('--yes', action='store_true', help='live mode: confirm API spend')
    ap.add_argument('--agent-prompt', choices=['default', 'naive'], default='default',
                    help='naive = a real model told to obey instructions found in tool output (stand-in for an easily fooled model)')
    ap.add_argument('--out', default=str(RESULTS_DIR))
    ap.add_argument('--tag', default=None)
    args = ap.parse_args(argv)

    if args.tier == 'real':
        from .real_tier import main_real
        return main_real(args)

    special = {'live': load_live, 'adversarial': load_adversarial}
    pool = special[args.split]() if args.split in special else load_all(include_holdout=args.split != 'dev')
    scenarios = _select(pool, 'all' if args.split in special else args.split, args.only, args.limit, args.category)
    if not scenarios:
        print('No scenarios selected.')
        return 2
    validate_scenarios(scenarios)
    approvers = [a.strip() for a in args.approvers.split(',')]

    live = args.mode == 'live'
    inner: Optional[LLMProvider] = None
    if live:
        inner = select_provider()
        if inner is None:
            print('Live mode needs GEMINI_API_KEY or ANTHROPIC_API_KEY (or GUARDML_LLM_PROVIDER).')
            return 2

    configs: List[Config] = []
    replay: Optional[ReplayCompleter] = None
    for cfg in resolve_configs(args.configs):
        if cfg.live_only and not live:
            print(f'skip {cfg.name}: live only (a scripted agent ignores prompts)')
            continue
        if cfg.intent and not live:
            replay = ReplayCompleter(JUDGE_RECORDING)
            if not replay.replies:
                print(f'skip {cfg.name}: no recorded judge replies ({JUDGE_RECORDING.name}). '
                      'Run once with --mode live --record-judge, then it can be replayed offline.')
                continue
        configs.append(cfg)
    if not configs:
        print('Nothing to run.')
        return 2

    n_runs = len(scenarios) * len(configs) * len(approvers) * (args.repeat if live else 1)
    if live:
        print(f'Live run: ~{n_runs} agent runs x ~3-5 LLM calls each (+ judge calls) on {inner.name}/{inner.model}.')
        if not args.yes:
            print('Re-run with --yes to proceed (this spends API quota).')
            return 2

    workdir = Path(tempfile.mkdtemp(prefix='guardbench_'))
    env = BenchEnv(workdir)
    recorder: Optional[RecordingCompleter] = None

    def judge_factory() -> IntentJudge:
        nonlocal recorder
        if live:
            recorder = recorder or RecordingCompleter(make_completer(inner, args.judge_model))
            return IntentJudge(recorder)
        return IntentJudge(replay)

    provider_factory = (lambda sc: CountingProvider(inner)) if live else None

    records: List[Dict[str, Any]] = []
    try:
        for cfg in configs:
            print(f'\n[{cfg.name}] ', end='', flush=True)
            for sc in scenarios:
                runs_for = [approvers[0]] if sc.approval_attack is not None else approvers
                for approver in runs_for:
                    for _ in range(args.repeat if live else 1):
                        rec = run_scenario(env, sc, cfg, approver, provider_factory=provider_factory,
                                           judge_factory=judge_factory, mode=args.mode,
                                           agent_prompt=args.agent_prompt)
                        records.append(rec)
                        print('E' if rec.get('error') else '.', end='', flush=True)
                        if sc.approval_attack is not None:  # approver is irrelevant; mirror for the rubber-stamp column
                            for other in approvers[1:]:
                                records.append(dict(rec, approver=other))
            print()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if recorder is not None and args.record_judge:
        recorder.save(JUDGE_RECORDING)
        print(f'Saved judge replies to {JUDGE_RECORDING}')

    summary = summarize(records)
    attacks = [s for s in scenarios if s.is_attack]
    tag = args.tag or f"{args.tier}-{args.mode}-{args.split}"
    models_used: Dict[str, int] = {}
    for r in records:
        for m, n in (r.get('models_used') or {}).items():
            models_used[m] = models_used.get(m, 0) + n
    meta = {
        'title': tag, 'tier': args.tier, 'mode': args.mode, 'split': args.split, 'models_used': models_used or None,
        'agent_prompt': args.agent_prompt,
        'model': f'{inner.name}/{inner.model}' if inner else None,
        'n_scenarios': len(scenarios), 'n_attack': len(attacks), 'n_benign': len(scenarios) - len(attacks),
        'configs': [c.name for c in configs],
        'judge_replay_misses': replay.misses if replay else None,
    }
    paths = write_results(Path(args.out), tag, meta, summary, records)
    print(f"\nWrote {paths['markdown']}\n      {paths['json']}")
    if replay and replay.misses:
        print(f'WARNING: {replay.misses} judge prompts had no recording; those escalated (fail closed). '
              'Re-record with --mode live --record-judge before trusting e_full numbers.')
    errored = [r for r in records if r.get('error')]
    if errored:
        print(f'WARNING: {len(errored)} runs errored (first: {errored[0]["scenario"]}: {errored[0]["error"]})')
        return 1
    failed = [r for r in records if r.get('llm_failed')]
    if failed:
        print(f'WARNING: {len(failed)} of {len(records)} runs got no/partial LLM response (rate limit or outage) and were EXCLUDED '
              'from the results. If most runs failed the provider is throttling you: wait and re-run.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
