"""
Show what a tool's output looks like and WHERE attacker text can be planted in it.

    python -m guardml.bench.describe                 # list the tools
    python -m guardml.bench.describe docker_logs     # structure + valid `path:` values for injections

Each line is a path you can use in a scenario's `injections:` (`path: logs`, `path: 0.tags.note`, ...), with
the modes that work there: `append`/`prepend` on text and lists, `set` anywhere (including new keys on dicts).
"""
from __future__ import annotations

import json
import sys
from typing import Any, Iterator, List, Tuple

from .world import FIXTURE_DIR, load_fixture


def _path_value(prefix: Tuple[str, ...]) -> Any:
    """A dotted string, or a list when any key contains a dot (a dotted string would split that key)."""
    if not prefix:
        return '(root)'
    if any('.' in seg or seg == '' for seg in prefix):
        return list(prefix)
    return '.'.join(prefix)


def paths(node: Any, prefix: Tuple[str, ...] = ()) -> Iterator[Tuple[Any, str, str]]:
    """Yield (path usable in `injections:`, kind, sample) for every place text can go."""
    here = _path_value(prefix)
    if isinstance(node, dict):
        yield here, 'dict: `set` adds a new key', f'keys: {", ".join(list(node)[:6])}'
        for k, v in node.items():
            yield from paths(v, prefix + (str(k),))
    elif isinstance(node, list):
        yield here, 'list: `append` adds an item', f'{len(node)} item(s)'
        for i, v in enumerate(node[:3]):
            yield from paths(v, prefix + (str(i),))
    elif isinstance(node, str):
        yield here, 'text: `append` / `prepend` / `set`', json.dumps(node[:60]) + ('...' if len(node) > 60 else '')
    else:
        yield here, f'{type(node).__name__}: `set` only', json.dumps(node)


def describe(tool: str) -> List[str]:
    doc = load_fixture(tool)
    lines = [f"{tool}  (fixture source: {doc['source']})", '']
    for path, kind, sample in paths(doc['real_output']):
        shown = path if isinstance(path, str) else json.dumps(path)   # list form: write it exactly like this in YAML
        lines.append(f'  path: {shown:42s} {kind:42s} e.g. {sample}')
    return lines


def main(argv: List[str] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    tools = sorted(p.parent.name for p in FIXTURE_DIR.glob('*/default.json'))
    if not argv:
        print('Tools whose output you can plant text in:\n  ' + '\n  '.join(tools))
        print('\nSee one:  python -m guardml.bench.describe <tool>')
        return 0
    if argv[0] not in tools:
        print(f'Unknown tool {argv[0]!r}. Choose from: {", ".join(tools)}')
        return 2
    print('\n'.join(describe(argv[0])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
