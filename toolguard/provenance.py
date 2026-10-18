"""
Argument provenance tracking (value-level taint).

Session-wide taint ("the agent read some logs") is coarse. This module answers a
sharper question for every state-changing call:

    Did this argument VALUE come from the user, or from untrusted tool output?

Trusted tokens: the user's own messages and the system prompt.
Untrusted tokens: everything any tool returned (logs, run tags, CSV headers...),
remembered together with the tool that first produced them.

A write whose argument appears ONLY in untrusted output is the signature of an
indirect prompt injection steering an action ("ops note: set production alias to
version 2"), so ToolGuard escalates it to a human with the exact source.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set, Tuple

# Identifier-ish tokens: model names, versions, run ids, hosts, paths, tags.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-/~^:@]{0,127}")

_VERSION_RE = re.compile(r"^v(\d+)$")

# Upper bound on remembered untrusted tokens per session. If a session ever
# exceeds it, provenance fails CLOSED (see find_untrusted_args).
MAX_UNTRUSTED_TOKENS = 50_000


def tokens(text: Any) -> Set[str]:
    """Lower-cased identifier tokens in text (trailing sentence punctuation dropped)."""
    if text is None:
        return set()
    out = set()
    for t in _TOKEN_RE.findall(str(text)):
        t = t.rstrip(".:/-").lower()
        if not t:
            continue
        out.add(t)
        m = _VERSION_RE.match(t)
        if m:  # "v2" and "2" name the same model version
            out.add(m.group(1))
    return out


def _arg_values(val: Any) -> Iterable[str]:
    if isinstance(val, bool) or val is None:
        return []
    if isinstance(val, (str, int, float)):
        return [str(val)]
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
    return []


def find_untrusted_args(
    args: Dict[str, Any],
    trusted: Set[str],
    untrusted: Dict[str, str],
    overflow: bool = False,
) -> List[Tuple[str, str, str]]:
    """
    Return [(arg_name, value, source_tool)] for argument values that appear in
    untrusted tool output but never in a trusted source.

    If the untrusted store overflowed, any token not in a trusted source is
    flagged (source 'unknown (provenance store overflowed)').
    """
    hits: List[Tuple[str, str, str]] = []
    for key, val in args.items():
        for v in _arg_values(val):
            for t in tokens(v):
                if t in trusted:
                    continue
                if t in untrusted:
                    hits.append((key, v, untrusted[t]))
                    break
                if overflow:
                    hits.append((key, v, "unknown (provenance store overflowed)"))
                    break
    return hits


def describe(hits: List[Tuple[str, str, str]]) -> str:
    parts = [f"{k}={v!r} (seen in {src} output)" for k, v, src in hits]
    return "Argument value(s) came from tool output, not from the user's request: " + ", ".join(parts)
