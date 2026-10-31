"""
Run GuardML's guard on AgentDojo. Needs `pip install agentdojo` and, for live runs, Ollama.

  # free, no model: how many of AgentDojo's ground-truth legitimate calls would the provenance guard block?
  python -m guardml.benchmarks.agentdojo.run --offline-utility --suite banking,slack,travel,workspace

  # live: a local model on Ollama, 4 user tasks x 2 injection tasks, with and without the guard
  python -m guardml.benchmarks.agentdojo.run --suite banking --defence none,full --limit-user 4 --limit-injection 2

Run from the directory that CONTAINS the repo folder (so `guardml` is importable). Results go to
benchmarks/agentdojo/results/<tag>.{json,md}; AgentDojo's own per-task logs go to runs/ and make a re-run resume.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites

from .guard import CONFIGS, WRITE_TOOLS, ToolCallGuard

HERE = Path(__file__).parent
RESULTS_DIR, RUNS_DIR = HERE / 'results', HERE / 'runs'


def _mean(xs) -> Optional[float]:
    xs = list(xs)
    return round(sum(xs) / len(xs), 4) if xs else None


# ---------------------------------------------------------------------------
# Offline: the guard against AgentDojo's own ground-truth solutions (no model)
# ---------------------------------------------------------------------------
def offline_utility(suites: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replays each user task's ground-truth calls through the provenance guard. Every call is legitimate by
    construction, so any block is a false positive: this is a lower bound on the utility cost (the intent
    judge needs a model and is not included).
    """
    guard = ToolCallGuard(provenance=True, intent=False)
    out: Dict[str, Any] = {}
    for name, suite in suites.items():
        rows = []
        for tid, task in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            runtime = FunctionsRuntime(suite.tools)
            history, blocked, writes = [], [], 0
            try:
                calls = task.ground_truth(env)
                for call in calls:
                    writes += call.function in WRITE_TOOLS
                    d = guard.check(task.PROMPT, history, call.function, dict(call.args))
                    if not d.allowed:
                        blocked.append({'tool': call.function, 'rule': d.rule, 'reason': d.reason})
                    result, _ = runtime.run_function(env, call.function, call.args, raise_on_error=True)
                    history.append((call.function, tool_result_to_str(result)))
            except Exception as e:  # a ground truth that cannot be replayed is reported, not hidden
                rows.append({'task': tid, 'error': f'{type(e).__name__}: {e}'[:200]})
                continue
            rows.append({'task': tid, 'calls': len(calls), 'write_calls': writes, 'blocked': blocked})
        ok = [r for r in rows if 'error' not in r]
        with_writes = [r for r in ok if r['write_calls']]
        out[name] = {
            'user_tasks': len(rows), 'replayed': len(ok), 'replay_errors': len(rows) - len(ok),
            'tasks_with_a_write_call': len(with_writes),
            'tasks_blocked': sum(1 for r in ok if r['blocked']),
            'blocked_share_of_tasks_with_writes': _mean(1 if r['blocked'] else 0 for r in with_writes),
            'rows': rows,
        }
    return out


# ---------------------------------------------------------------------------
# Live
# ---------------------------------------------------------------------------
def context_model_name(model: str, num_ctx: int) -> str:
    return model if num_ctx <= 0 else f"{model.replace(':', '-')}-ctx{num_ctx}"


def guard_activity(pipeline_name: str, suite: str, attack: str) -> Dict[str, Any]:
    """
    What the guard blocked, read from AgentDojo's per-task logs (a blocked call is a tool message whose error starts
    with "BLOCKED by ToolGuard (<rule>)"). Reading the logs instead of counting in memory keeps the numbers right when
    a run is resumed or rebuilt: tasks loaded from earlier logs never pass through the guard again.
    """
    by_rule: Counter = Counter()
    pairs = set()
    base = RUNS_DIR / pipeline_name / suite
    for f in sorted(base.rglob('*.json')) if base.exists() else []:
        d = json.loads(f.read_text(encoding='utf-8'))
        for m in d.get('messages', []):
            err = (m.get('error') or '') if m.get('role') == 'tool' else ''
            if err.startswith('BLOCKED by ToolGuard ('):
                by_rule[err.split('(', 1)[1].split(')', 1)[0]] += 1
                if d.get('attack_type') == attack:
                    pairs.add((d['user_task_id'], d['injection_task_id']))
    return {'blocked_calls': sum(by_rule.values()), 'blocked_by_rule': dict(by_rule),
            'attack_pairs_with_a_block': sorted(f'{u}/{i}' for u, i in pairs)}


def ensure_context_model(model: str, num_ctx: int) -> str:
    """Ollama silently truncates prompts beyond its default context window, which would cut AgentDojo's tool
    definitions. Make (once) a copy of the model with a larger window and return its name."""
    name = context_model_name(model, num_ctx)
    if name == model:
        return model
    have = subprocess.run(['ollama', 'list'], capture_output=True, text=True).stdout
    if name not in have:
        with tempfile.TemporaryDirectory() as d:
            mf = Path(d) / 'Modelfile'
            mf.write_text(f'FROM {model}\nPARAMETER num_ctx {num_ctx}\n', encoding='utf-8')
            subprocess.run(['ollama', 'create', name, '-f', str(mf)], check=True)
    return name


def pick(ids: List[str], explicit: Optional[str], limit: int) -> Optional[List[str]]:
    if explicit:
        return [x.strip() for x in explicit.split(',')]
    return ids[:limit] if limit else None


def run_live(args: argparse.Namespace, suites: Dict[str, Any]) -> Dict[str, Any]:
    from guardml.bench.cloud import ensure_ollama   # starts `ollama serve` if it is down, pulls the model if missing
    from .pipeline import build_pipeline            # imports openai; only needed for live runs

    if args.report_only:   # rebuild the report from saved logs: no Ollama, no model
        model = context_model_name(args.model, args.num_ctx)
    else:
        ensure_ollama(args.model)
        model = ensure_context_model(args.model, args.num_ctx)
    summary: Dict[str, Any] = {}
    succeeded_unguarded: Dict[str, set] = {}   # suite -> attack pairs that worked with no guard
    for defence in [d.strip() for d in args.defence.split(',')]:
        pipeline = build_pipeline(model, defence, base_url=args.base_url, ollama_host=args.ollama_host)
        per_suite: Dict[str, Any] = {}
        for name, suite in suites.items():
            uts = pick(list(suite.user_tasks), args.user_tasks, args.limit_user)
            its = pick(list(suite.injection_tasks), args.injection_tasks, args.limit_injection)
            t0 = time.time()
            clean = benchmark_suite_without_injections(
                pipeline, suite, RUNS_DIR, args.force_rerun, uts, args.benchmark_version)
            row = {'utility': _mean(clean['utility_results'].values()), 'n_clean': len(clean['utility_results'])}
            if args.attack != 'none':
                attack = load_attack(args.attack, suite, pipeline)
                atk = benchmark_suite_with_injections(
                    pipeline, suite, attack, RUNS_DIR, args.force_rerun, uts, its, False, args.benchmark_version)
                if defence == 'none':
                    succeeded_unguarded[name] = {f'{u}/{i}' for (u, i), hit in atk['security_results'].items() if hit}
                row.update({
                    'attack': args.attack, 'n_attack': len(atk['security_results']),
                    'utility_under_attack': _mean(atk['utility_results'].values()),
                    # AgentDojo: security == True means the injection's goal WAS achieved
                    'attack_success_rate': _mean(atk['security_results'].values()),
                })
            row['seconds'] = round(time.time() - t0)
            per_suite[name] = row
        activity = {n: guard_activity(pipeline.name, n, args.attack) for n in suites} if defence != 'none' else {}
        for n, a in activity.items():
            worked = succeeded_unguarded.get(n, set())
            a['attack_pairs_that_worked_unguarded'] = len(worked)
            a['of_those_the_guard_blocked_a_call_in'] = len(worked & set(a['attack_pairs_with_a_block']))
        summary[defence] = {'suites': per_suite, 'guard_activity_from_logs': activity,
                            'blocked_calls': sum(a['blocked_calls'] for a in activity.values()),
                            'decisions_this_process': getattr(pipeline.executor, 'decisions', [])}
    return summary


def write_report(tag: str, meta: Dict[str, Any], body: Dict[str, Any], live: bool) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f'{tag}.json').write_text(json.dumps({'meta': meta, 'results': body}, indent=1), encoding='utf-8')
    L = [f'# AgentDojo: {tag}', '', f"- **Run**: {meta['when']} | **AgentDojo**: {meta['agentdojo']} "
         f"| **benchmark**: {meta['benchmark_version']} | **mode**: {meta['mode']}"]
    if live:
        L += [f"- **Model**: {meta['model']} (Ollama) | **attack**: {meta['attack']}"]
        if meta.get('args', {}).get('report_only'):
            L.append('- **Rebuilt from the saved task logs** (no task was re-run), so the run date above is the rebuild time.')
        L += ['',
              '| Defence | Suite | Utility (no attack) | Utility under attack | Attack success | Runs (clean / attack) |',
              '|---|---|---|---|---|---|']
        pct = lambda v: 'n/a' if v is None else f'{v * 100:.0f}%'
        for defence, d in body.items():
            for suite, r in d['suites'].items():
                L.append(f"| {defence} | {suite} | {pct(r['utility'])} | {pct(r.get('utility_under_attack'))} "
                         f"| **{pct(r.get('attack_success_rate'))}** | {r['n_clean']} / {r.get('n_attack', 0)} |")
        L += ['', "Attack success = the injection's goal was achieved (lower is better).", '']
        for defence, d in body.items():
            for suite, a in d.get('guard_activity_from_logs', {}).items():
                L.append(f"- **{defence} / {suite}, from the saved task logs**: {a['blocked_calls']} blocked calls "
                         f"{a['blocked_by_rule'] or ''}; the guard blocked at least one call in "
                         f"{len(a['attack_pairs_with_a_block'])} attack pairs. Of the "
                         f"{a['attack_pairs_that_worked_unguarded']} pairs where the attack worked with no guard, it "
                         f"blocked a call in {a['of_those_the_guard_blocked_a_call_in']}.")
    else:
        L += ['', 'Ground-truth legitimate calls replayed through the provenance guard (no model). '
                  'Every block is a false positive; the intent judge is not included.', '',
              '| Suite | User tasks | With a write call | Tasks blocked | Blocked share of write tasks | Replay errors |',
              '|---|---|---|---|---|---|']
        for suite, r in body.items():
            share = r['blocked_share_of_tasks_with_writes']
            L.append(f"| {suite} | {r['user_tasks']} | {r['tasks_with_a_write_call']} | {r['tasks_blocked']} "
                     f"| {'n/a' if share is None else f'{share * 100:.0f}%'} | {r['replay_errors']} |")
    path = RESULTS_DIR / f'{tag}.md'
    path.write_text('\n'.join(L) + '\n', encoding='utf-8')
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='GuardML on AgentDojo')
    ap.add_argument('--suite', default='banking', help='comma list of: banking, slack, travel, workspace')
    ap.add_argument('--benchmark-version', default='v1.2.2')
    ap.add_argument('--offline-utility', action='store_true', help='no model: replay ground-truth calls through the guard')
    ap.add_argument('--defence', default='none,full', help=f'comma list of: {", ".join(CONFIGS)}')
    ap.add_argument('--attack', default='important_instructions', help='AgentDojo attack name, or "none"')
    ap.add_argument('--model', default='qwen2.5:7b')
    ap.add_argument('--num-ctx', type=int, default=16384, help='context window for the Ollama model (0 = leave as is)')
    ap.add_argument('--base-url', default='http://localhost:11434/v1')
    ap.add_argument('--ollama-host', default='localhost:11434')
    ap.add_argument('--user-tasks', help='comma-separated user task ids')
    ap.add_argument('--injection-tasks', help='comma-separated injection task ids')
    ap.add_argument('--limit-user', type=int, default=0, help='first N user tasks per suite')
    ap.add_argument('--limit-injection', type=int, default=0, help='first N injection tasks per suite')
    ap.add_argument('--force-rerun', action='store_true', help='ignore AgentDojo logs from earlier runs')
    ap.add_argument('--report-only', action='store_true',
                    help='rebuild the report from the saved logs in runs/ (no Ollama, no model; every task must be logged)')
    ap.add_argument('--tag', default=None)
    args = ap.parse_args(argv)

    import importlib.metadata as md
    names = [s.strip() for s in args.suite.split(',')]
    all_suites = get_suites(args.benchmark_version)
    bad = [n for n in names if n not in all_suites]
    if bad:
        raise SystemExit(f'unknown suite(s) {bad}; choose from {list(all_suites)}')
    suites = {n: all_suites[n] for n in names}

    live = not args.offline_utility
    tag = args.tag or (f"offline-utility-{'-'.join(names)}" if not live
                       else f"{args.model.replace(':', '-')}-{'-'.join(names)}-{time.strftime('%Y%m%d-%H%M')}")
    if live:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        with OutputLogger(str(RUNS_DIR)):   # AgentDojo's benchmark functions log through this global context
            body = run_live(args, suites)
    else:
        body = offline_utility(suites)
    meta = {'when': time.strftime('%Y-%m-%d %H:%M'), 'agentdojo': md.version('agentdojo'),
            'benchmark_version': args.benchmark_version, 'mode': 'live' if live else 'offline-utility',
            'model': args.model, 'attack': args.attack, 'num_ctx': args.num_ctx, 'args': vars(args)}
    path = write_report(tag, meta, body, live)
    print(f'Wrote {path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
