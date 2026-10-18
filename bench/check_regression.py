"""
CI gate: fail if a fresh GuardBench run is worse than the committed baseline.

    python -m guardml.bench.run --out new --tag ci-dev
    python -m guardml.bench.check_regression new/ci-dev.json

For every guarded config it requires: attack success (no human, and rubber-stamp) not higher,
benign completion not lower, benign false positives not higher, and no errored runs.
The no-guard baseline is ignored. If the scenario set changed (different counts), the rates are
not comparable: regenerate and commit the baseline instead of editing this check:

    python -m guardml.bench.run --out guardml/bench/results --tag fixture-offline-dev
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

BASELINE = Path(__file__).parent / 'results' / 'fixture-offline-dev.json'
EPS = 1e-9


def compare(new: Dict[str, Any], base: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    for cfg, b in base['summary'].items():
        if cfg == 'a_no_guard':
            continue
        n = new['summary'].get(cfg)
        if n is None:
            problems.append(f'{cfg}: missing from the new run')
            continue
        if (n['attack']['n'], n['benign']['n']) != (b['attack']['n'], b['benign']['n']):
            problems.append(f"{cfg}: scenario counts changed ({b['attack']['n']}+{b['benign']['n']} -> "
                            f"{n['attack']['n']}+{n['benign']['n']}); regenerate and commit the baseline")
            continue
        for key, label in (('asr_unattended', 'attack success (no human)'),
                           ('asr_rubber_stamp', 'attack success (rubber-stamp human)')):
            if n['attack'][key] > b['attack'][key] + EPS:
                newly = sorted(set(n['attack'].get('succeeded_unattended', [])) - set(b['attack'].get('succeeded_unattended', [])))
                problems.append(f"{cfg}: {label} rose {b['attack'][key]:.0%} -> {n['attack'][key]:.0%}"
                                + (f" (newly succeeding: {', '.join(newly)})" if newly and key == 'asr_unattended' else ''))
        if n['benign']['utility'] < b['benign']['utility'] - EPS:
            problems.append(f"{cfg}: benign completion fell {b['benign']['utility']:.0%} -> {n['benign']['utility']:.0%} "
                            f"(not completed: {', '.join(n['benign']['failed_tasks'])})")
        if n['benign']['false_positive_rate'] > b['benign']['false_positive_rate'] + EPS:
            problems.append(f"{cfg}: benign false positives rose "
                            f"{b['benign']['false_positive_rate']:.0%} -> {n['benign']['false_positive_rate']:.0%}")
        if n['errors']:
            problems.append(f"{cfg}: {len(n['errors'])} run(s) errored: {n['errors'][0]}")
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    new = json.loads(Path(argv[0]).read_text(encoding='utf-8'))
    base_path = Path(argv[1]) if len(argv) > 1 else BASELINE
    base = json.loads(base_path.read_text(encoding='utf-8'))
    problems = compare(new, base)
    if problems:
        print('GuardBench REGRESSION against', base_path.name)
        for p in problems:
            print('  -', p)
        return 1
    guarded = [c for c in base['summary'] if c != 'a_no_guard']
    print(f'GuardBench OK: no regression against {base_path.name} ({", ".join(guarded)})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
