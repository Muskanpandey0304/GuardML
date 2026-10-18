"""
Scripted agent for offline (deterministic, free, CI-friendly) runs.

It plays a model that does what the scenario script says: for attack scenarios, a model
that has ALREADY fallen for the trap (the worst case), for benign ones, a competent model.
So offline numbers answer "given a compromised model, does the guard stop the action?",
not "does the model resist?" (that needs a live run).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from guardml.agent.llm import LLMResponse, ScriptedProvider, ToolUse

from .scenarios import Scenario

_OUTPUT_RE = re.compile(r'<tool_output tool="([^"]+)"[^>]*>\n(.*?)\n</tool_output>', re.DOTALL)


def parse_tool_outputs(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Tool outputs seen so far, in order: [{'tool': name, 'output': {ok, data, error}}]."""
    seen: List[Dict[str, Any]] = []
    for m in messages:
        if m.get('role') != 'tool':
            continue
        for r in m['results']:
            hit = _OUTPUT_RE.search(r['content'])
            raw = hit.group(2) if hit else r['content']
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = {'raw': raw}
            seen.append({'tool': r['name'], 'output': parsed})
    return seen


def _dig(obj: Any, path: str) -> Any:
    for seg in path.split('.'):
        obj = obj[int(seg)] if isinstance(obj, list) else obj[seg]
    return obj


def resolve_args(args: Dict[str, Any], outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Replace {$from: tool, path: a.b.0.c} with a value from an earlier tool output."""
    out: Dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, dict) and '$from' in v:
            source = next((o for o in reversed(outputs) if o['tool'] == v['$from']), None)
            if source is None:
                raise ValueError(f"step needs output of {v['$from']!r}, which was never called")
            out[k] = _dig(source['output'], v['path'])
        else:
            out[k] = v
    return out


def build_scripted_provider(scenario: Scenario) -> ScriptedProvider:
    """One tool call per turn, in script order, then a closing message."""
    steps = scenario.agent

    def script(messages: List[Dict[str, Any]]) -> Optional[LLMResponse]:
        outputs = parse_tool_outputs(messages)
        i = len(outputs)
        if i >= len(steps):
            return LLMResponse(text='Done.')
        step = steps[i]
        args = resolve_args(step.args, outputs)
        if step.reason:
            args['reason'] = step.reason
        return LLMResponse(tool_calls=[ToolUse(id=f'{scenario.id}-{i}', name=step.tool, input=args)])

    return ScriptedProvider(script)
