"""GuardML tool layer."""
# Note: registry import is lazy to avoid loading heavy deps at import time.
# Use get_registry() when you need the full registry.
__all__ = ['ToolRegistry', 'get_registry']


def get_registry():
    from .registry import get_registry as _get
    return _get()


def ToolRegistry():
    from .registry import ToolRegistry as _TR
    return _TR()
