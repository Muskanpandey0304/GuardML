"""
Tool schemas given to the LLM (Phase 5).
Built from the tool registry.

The registry schemas carry guard-only hints ("x-guard") that tell ToolGuard how to
validate each argument. Those are internal, so they are stripped before the
schema is shown to a model, and an optional `reason` field is added to every tool.
"""
from __future__ import annotations
import copy
from typing import List, Dict, Any

try:
    from guardml.tools.registry import get_registry
except ImportError:
    try:
        from tools.registry import get_registry
    except ImportError:
        from ..tools.registry import get_registry


REASON_FIELD = {
    'type': 'string',
    'description': (
        'One sentence explaining why you are making this call. '
        'REQUIRED for any tool that changes state; it is shown to the human approver.'
    ),
}


def _strip_guard_hints(node: Any) -> Any:
    """Recursively drop keys starting with 'x-' (internal guard annotations)."""
    if isinstance(node, dict):
        return {k: _strip_guard_hints(v) for k, v in node.items() if not str(k).startswith('x-')}
    if isinstance(node, list):
        return [_strip_guard_hints(v) for v in node]
    return node


def llm_schema(tool_schema: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one registry schema into the form shown to the model."""
    schema = _strip_guard_hints(copy.deepcopy(tool_schema))
    params = schema.setdefault('input_schema', {'type': 'object', 'properties': {}})
    params.setdefault('properties', {})
    params['properties'].setdefault('reason', dict(REASON_FIELD))
    return schema


def get_tool_schemas(registry=None) -> List[Dict[str, Any]]:
    """Return all registered tool schemas in Anthropic format (LLM-facing)."""
    reg = registry or get_registry()
    return [llm_schema(s) for s in reg.all_schemas()]
