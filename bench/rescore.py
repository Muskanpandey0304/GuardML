"""
Re-score the benign runs of saved GuardBench results under the CURRENT false-positive definition.

    python -m guardml.bench.rescore bench/results/live-ollama-qwen2.5-7b.json [more.json ...]

The saved runs are not repeated and no attack record changes: only the benign scoring is recomputed from the
steps each result file already holds (see runner.classify_benign). Each file's .json and .md are rewritten in
place with the original run date kept and a note in the header, so the change of definition is visible.
Run from the directory that CONTAINS the repo folder.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .metrics import summarize
from .report import render_markdown
from .runner import classify_benign
from .scenarios import load_adversarial, load_all, load_live
from .world import World

NOTE = ('Benign scoring re-computed on {date} with the live false-positive definition (a block or unexpected '
        'approval counts only if it hit a call the task needs; calls the model improvised are listed separately). '
        'The runs themselves and every attack result are unchanged.')


def restore_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A saved step keeps only `approval: bool`; the classifier looks for the `approval_id` key the live step had."""
    return [dict(s, approval_id='saved') if s.get('approval') else s for s in steps]


def rescore(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding='utf-8'))
    meta, records = data['meta'], data['records']
    if meta.get('mode') != 'live':
        raise SystemExit(f'{path.name}: only live results are re-scored (offline scoring did not change)')
    scenarios = {s.id: s for s in load_all(include_holdout=True) + load_live() + load_adversarial()}

    changed: List[str] = []
    for r in records:
        if r.get('category') != 'benign' or r.get('llm_failed') or r.get('error'):
            continue
        sc = scenarios.get(r['scenario'])
        if sc is None:
            raise SystemExit(f"{path.name}: unknown scenario {r['scenario']!r}")
        world = World()
        world.aliases = dict((r.get('world') or {}).get('aliases') or world.aliases)
        new = classify_benign(restore_steps(r['steps']), sc, world, live=True)
        if new['false_positive'] != r.get('false_positive') or new['utility_ok'] != r.get('utility_ok'):
            changed.append(f"{r['scenario']} / {r['config']} / {r['approver']}")
        r.update(new)

    summary = summarize(records)
    meta['rescored'] = NOTE.format(date=datetime.date.today().isoformat())
    path.write_text(json.dumps({'meta': meta, 'summary': summary, 'records': records}, indent=1, default=str),
                    encoding='utf-8')
    path.with_suffix('.md').write_text(render_markdown(meta, summary), encoding='utf-8')
    return {'file': path.name, 'changed_runs': changed}


def main(argv: List[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    for a in argv:
        res = rescore(Path(a))
        print(f"{res['file']}: {len(res['changed_runs'])} benign run(s) changed score")
        for c in res['changed_runs']:
            print(f'   {c}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
