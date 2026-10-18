"""
Session state store (in-memory, keyed by session_id).
Thread-safe. Used by guard.check() and GuardedExecutor.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from .schemas import SessionState


_lock = threading.Lock()
_sessions: Dict[str, SessionState] = {}


def get_or_create(session_id: str, env: str = "staging") -> SessionState:
    with _lock:
        if session_id not in _sessions:
            _sessions[session_id] = SessionState(session_id=session_id, env=env)
        return _sessions[session_id]


def update(state: SessionState) -> None:
    with _lock:
        _sessions[state.session_id] = state


def record_user_message(session_id: str, env: str, text: str) -> None:
    """Remember what the USER asked for: the only trusted source of argument values."""
    with _lock:
        state = _sessions.get(session_id) or SessionState(session_id=session_id, env=env)
        _sessions[session_id] = state.add_user_request(text)


def record_tool_output(session_id: str, env: str, tool_name: str, text: str) -> None:
    """Remember tokens a tool returned: untrusted data that must not steer a write."""
    with _lock:
        state = _sessions.get(session_id) or SessionState(session_id=session_id, env=env)
        _sessions[session_id] = state.add_untrusted(tool_name, text)


def get(session_id: str) -> Optional[SessionState]:
    with _lock:
        return _sessions.get(session_id)


def clear(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def reset_all() -> None:
    """For testing only — clears all sessions."""
    with _lock:
        _sessions.clear()
