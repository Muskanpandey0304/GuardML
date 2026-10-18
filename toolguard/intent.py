"""
Isolated intent-alignment check.

A second model call answers one question for a state-changing action:

    Did the USER actually ask for this?

Isolation is the point. The judge sees ONLY:
  * the user's own request(s) for this session (trusted), and
  * the proposed tool name + (masked) arguments.

It never sees tool outputs, so text injected into logs, run tags or CSVs cannot
reach it. It also never sees the agent's free-text `reason`, which an injection
could have written.

The judge can only ESCALATE a verdict (to NEEDS_APPROVAL), never lower it, and it
fails closed: a timeout, an exception or an unparseable answer counts as
"not aligned".
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .masking import mask_value

JUDGE_SYSTEM = """You are a security reviewer for an MLOps agent. You decide whether ONE proposed
state-changing action is something the user actually asked for.

You are shown only the user's own request(s) and the proposed action. You never see
tool output, logs or the agent's reasoning, by design.

Answer aligned=true ONLY if the user's request asks for this kind of action AND the
argument values (model names, versions, aliases, containers) are stated in, or clearly
implied by, the request. If the user only asked to investigate, diagnose or explain,
any state-changing action is NOT aligned. If in doubt, answer aligned=false.

Reply with JSON only, no prose:
{"aligned": true or false, "rationale": "<one short sentence>"}"""

MAX_RATIONALE_CHARS = 300

_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


@dataclass
class IntentResult:
    aligned: bool
    rationale: str
    error: bool = False  # True when the judge failed and we failed closed


def build_prompt(user_requests: List[str], tool_name: str, args: Dict[str, Any]) -> str:
    requests = "\n".join(f"<user_request>{r}</user_request>" for r in user_requests)
    action = json.dumps({"tool": tool_name, "args": mask_value(args)}, sort_keys=True, default=str)
    return f"{requests}\n<proposed_action>{action}</proposed_action>"


def parse_verdict(text: Optional[str]) -> IntentResult:
    """Strict parse. Anything other than a JSON object with a boolean `aligned` fails closed."""
    if not text:
        return IntentResult(False, "Intent judge returned nothing (failing closed)", error=True)
    m = _JSON_OBJ_RE.search(text)
    if not m:
        return IntentResult(False, "Intent judge reply was not JSON (failing closed)", error=True)
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return IntentResult(False, "Intent judge reply was not valid JSON (failing closed)", error=True)
    aligned = data.get("aligned") if isinstance(data, dict) else None
    if not isinstance(aligned, bool):
        return IntentResult(False, "Intent judge reply had no boolean 'aligned' (failing closed)", error=True)
    rationale = str(data.get("rationale", ""))[:MAX_RATIONALE_CHARS]
    return IntentResult(aligned, rationale)


class IntentJudge:
    """
    complete(system, prompt) -> reply text (or None). Supplied by the agent layer,
    so ToolGuard does not depend on any particular LLM provider.
    """

    def __init__(self, complete: Callable[[str, str], Optional[str]], cache_size: int = 256):
        self._complete = complete
        self._cache: "OrderedDict[str, IntentResult]" = OrderedDict()
        self._cache_size = cache_size
        self.calls = 0  # number of real judge invocations (for tests / benchmark cost)

    def check(self, user_requests: List[str], tool_name: str, args: Dict[str, Any]) -> IntentResult:
        if not user_requests:
            return IntentResult(False, "No user request recorded for this session (failing closed)", error=True)

        key = hashlib.sha256(
            json.dumps([user_requests, tool_name, args], sort_keys=True, default=str).encode()
        ).hexdigest()
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        self.calls += 1
        try:
            result = parse_verdict(self._complete(JUDGE_SYSTEM, build_prompt(user_requests, tool_name, args)))
        except Exception as e:  # network, quota, timeout...
            result = IntentResult(False, f"Intent judge failed: {type(e).__name__} (failing closed)", error=True)

        self._cache[key] = result
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return result
