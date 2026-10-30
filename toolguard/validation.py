"""
Step 4: Argument validation and injection defense.
This is where most real bypasses are stopped.

4a. Identifier rule: ^[A-Za-z0-9_.\\-]{1,64}$ kills ; | & $ ` quotes spaces newlines nulls
4b. String max length + control char rejection
4c. Int range validation
4d. Path confinement with realpath + symlink escape detection
4e. URL / SSRF defense for health_check
4f. Recursive arg scanner for pattern checks
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Identifier rule — kills injection chars in one rule
# ---------------------------------------------------------------------------
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}\Z")
# Git/DVC revisions: branch names, tags, HEAD~1, HEAD^, commit SHAs. Never a leading "-".
_REVISION_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/~^]{0,63}\Z")
# Durations for docker/kubectl --since: 30s, 10m, 1h, 2d
_DURATION_RE = re.compile(r"^[0-9]{1,5}[smhd]\Z")
# Kubernetes label selectors: app=model-api,tier!=debug
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/=!, ()]{0,127}\Z")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Forbidden URL schemes
_FORBIDDEN_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}

# Private / link-local / loopback ranges (SSRF defense)
_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def validate_identifier(value: str, field: str) -> None:
    """
    Enforce ^[A-Za-z0-9_.\\-]{1,64}$.
    Kills ; | & $ backtick quotes spaces newlines null bytes in one rule.
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected string, got {type(value).__name__}")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"{field}: contains control characters")
    if not _IDENTIFIER_RE.match(value):
        raise ValidationError(
            f"{field}={value!r} fails identifier rule — shell-injection characters are forbidden"
        )


def validate_string_max(value: str, field: str, max_len: int = 512) -> None:
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected string")
    if len(value) > max_len:
        raise ValidationError(f"{field}: exceeds max length {max_len}")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"{field}: contains control characters")


def validate_int_range(value: Any, field: str, min_val: int, max_val: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{field}: expected integer, got {value!r}")
    if not (min_val <= v <= max_val):
        raise ValidationError(
            f"{field}={v} is out of allowed range [{min_val}, {max_val}]"
        )
    return v


def validate_path(value: str, field: str, allowed_roots: List[str]) -> str:
    """
    Resolve path with realpath and ensure it is inside an allowed root.
    Rejects .., absolute paths outside roots, and symlinks that escape.
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected string")
    # Reject known-sensitive absolute paths immediately
    for sensitive in ("/etc", "/root", "/var", "/proc", "/sys"):
        if value.startswith(sensitive):
            raise ValidationError(
                f"{field}: absolute path to sensitive location is blocked"
            )
    # On POSIX, 'C:/x' would resolve as a relative path inside the repo, so reject Windows drive/UNC forms.
    # (On Windows, realpath handles them correctly and they are legitimate.)
    if os.name != "nt" and re.match(r"^([A-Za-z]:|\\\\|//)", value):
        raise ValidationError(
            f"{field}: Windows drive or UNC paths are not allowed"
        )
    # Reject .. traversal
    parts = Path(value).parts
    if ".." in parts:
        raise ValidationError(f"{field}: path traversal (..) is not allowed")
    resolved = os.path.realpath(value)
    norm_resolved = os.path.normcase(resolved)
    for root in allowed_roots:
        root_resolved = os.path.normcase(os.path.realpath(root))
        if norm_resolved.startswith(root_resolved + os.sep) or norm_resolved == root_resolved:
            return resolved
    raise ValidationError(
        f"{field}={value!r} is outside allowed roots: {allowed_roots}"
    )


def _validate_regex(value: str, field: str, pattern: "re.Pattern", what: str) -> None:
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected string, got {type(value).__name__}")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"{field}: contains control characters")
    if not pattern.match(value):
        raise ValidationError(f"{field}={value!r} is not a valid {what}")


def validate_revision(value: str, field: str) -> None:
    """Git/DVC revision. Must not start with '-' (would be parsed as a CLI flag)."""
    _validate_regex(value, field, _REVISION_RE, "revision")


def validate_duration(value: str, field: str) -> None:
    _validate_regex(value, field, _DURATION_RE, "duration (e.g. 30s, 10m, 1h)")


def validate_selector(value: str, field: str) -> None:
    _validate_regex(value, field, _SELECTOR_RE, "label selector")


def validate_url(value: str, field: str, allowed_hosts: List[str]) -> None:
    """
    SSRF defense for URL arguments.
    - Only http and https allowed
    - Host must be in the allowlist
    - Resolved IP must not be loopback, link-local, or private
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected string")
    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    if scheme in _FORBIDDEN_SCHEMES:
        raise ValidationError(f"{field}: scheme {scheme!r} is not allowed")
    if scheme not in ("http", "https"):
        raise ValidationError(
            f"{field}: only http and https are allowed, got {scheme!r}"
        )
    host = parsed.hostname or ""
    if not host:
        raise ValidationError(f"{field}: URL has no host")
    # Allowlist check
    if allowed_hosts and host not in allowed_hosts:
        raise ValidationError(
            f"{field}: host {host!r} not in allowlist {allowed_hosts}"
        )
    # Resolve and reject private/loopback/link-local IPs.
    # Exception: if the host is explicitly in allowed_hosts, we skip the IP check
    # (spec: "unless explicitly configured"). This allows localhost in the allowlist.
    if host not in allowed_hosts:
        try:
            resolved_ip = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved_ip)
            for net in _BLOCKED_NETS:
                try:
                    if ip in net:
                        raise ValidationError(
                            f"{field}: host {host!r} resolves to blocked address "
                            f"{resolved_ip} (private/loopback/link-local)"
                        )
                except TypeError:
                    pass
        except socket.gaierror:
            pass  # DNS failure — let the tool itself fail


# ---------------------------------------------------------------------------
# Recursive arg scanner
# ---------------------------------------------------------------------------
def scan_args_for_patterns(
    args: Dict[str, Any],
    check_fn: Callable[[str], Optional[str]],
) -> Optional[str]:
    """
    Recursively scan all string values in args through check_fn.
    Returns the first matched pattern string, or None.
    Handles nested dicts and lists — prevents bypass via nested args.
    """
    def _recurse(v: Any) -> Optional[str]:
        if isinstance(v, str):
            return check_fn(v)
        if isinstance(v, dict):
            for vv in v.values():
                r = _recurse(vv)
                if r:
                    return r
        if isinstance(v, (list, tuple)):
            for vv in v:
                r = _recurse(vv)
                if r:
                    return r
        return None

    return _recurse(args)


# ---------------------------------------------------------------------------
# Input normalisation (agent boundary, NOT part of the guard's checks)
# ---------------------------------------------------------------------------
def coerce_identifier_args(args: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Models (and tools) often hand back a whole NUMBER where the schema says string, e.g.
    version=1 or version=1.0 for an identifier field. That is sloppy but harmless, and
    rejecting it only makes legitimate tasks fail. Convert exactly that case, nothing more:
    int / whole float -> str, only for properties declared type=string with x-guard=identifier.
    Bools, non-whole floats, lists, dicts and every other kind are left untouched, so the
    strict validation that follows still rejects them.
    """
    props = schema.get("properties") or {}
    out = dict(args)
    for key, val in args.items():
        spec = props.get(key) or {}
        if spec.get("type") != "string" or spec.get("x-guard") != "identifier":
            continue
        if isinstance(val, bool):
            continue
        if isinstance(val, int):
            out[key] = str(val)
        elif isinstance(val, float) and val.is_integer():
            out[key] = str(int(val))
    return out


# ---------------------------------------------------------------------------
# Schema-driven argument validation
# ---------------------------------------------------------------------------
class SchemaContext:
    """Policy-derived allow-lists the typed validators need."""

    def __init__(
        self,
        allowed_file_roots: Optional[List[str]] = None,
        allowed_repo_roots: Optional[List[str]] = None,
        allowed_health_hosts: Optional[List[str]] = None,
        allowed_namespaces: Optional[List[str]] = None,
        allowed_log_containers: Optional[List[str]] = None,
    ):
        self.allowed_file_roots = allowed_file_roots or []
        self.allowed_repo_roots = allowed_repo_roots or []
        self.allowed_health_hosts = allowed_health_hosts or []
        self.allowed_namespaces = allowed_namespaces if allowed_namespaces is not None else ['default']
        self.allowed_log_containers = allowed_log_containers   # None = unrestricted


_MAX_ARRAY_ITEMS = 50


def _check_json_type(value: Any, expected: str, field: str) -> None:
    ok = {
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": (isinstance(value, int) and not isinstance(value, bool))
        # some LLM APIs return whole numbers as 50.0
        or (isinstance(value, float) and value.is_integer()),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, True)
    if not ok:
        raise ValidationError(f"{field}: expected {expected}, got {type(value).__name__}")


def _validate_typed(value: Any, spec: Dict[str, Any], field: str, ctx: SchemaContext) -> None:
    expected = spec.get("type")
    if expected:
        _check_json_type(value, expected, field)

    if expected in ("integer", "number"):
        lo, hi = spec.get("minimum"), spec.get("maximum")
        if lo is not None and value < lo or hi is not None and value > hi:
            raise ValidationError(f"{field}={value} is out of allowed range [{lo}, {hi}]")
        return
    if expected == "boolean":
        return
    if expected == "array":
        if len(value) > _MAX_ARRAY_ITEMS:
            raise ValidationError(f"{field}: too many items (max {_MAX_ARRAY_ITEMS})")
        item_spec = spec.get("items") or {}
        for i, item in enumerate(value):
            _validate_typed(item, item_spec, f"{field}[{i}]", ctx)
        return
    if expected == "object":
        raise ValidationError(f"{field}: nested objects are not accepted")

    # Strings: dispatch on the tool's declared x-guard kind. Undeclared = free text.
    kind = spec.get("x-guard", "free_text")
    if kind == "identifier":
        validate_identifier(value, field)
    elif kind == "path":
        validate_path(value, field, ctx.allowed_file_roots)
    elif kind == "repo_path":
        validate_path(value, field, ctx.allowed_repo_roots)
    elif kind == "url":
        validate_url(value, field, ctx.allowed_health_hosts)
    elif kind == "container_read":
        validate_identifier(value, field)
        if ctx.allowed_log_containers is not None and value not in ctx.allowed_log_containers:
            raise ValidationError(f"{field}={value!r}: logs of this container may not be read; allowed: {ctx.allowed_log_containers}")
    elif kind == "namespace":
        validate_identifier(value, field)
        if value not in ctx.allowed_namespaces:
            raise ValidationError(f"{field}={value!r} is not an allowed namespace: {ctx.allowed_namespaces}")
    elif kind == "revision":
        validate_revision(value, field)
    elif kind == "duration":
        validate_duration(value, field)
    elif kind == "selector":
        validate_selector(value, field)
    elif kind == "free_text":
        validate_string_max(value, field, max_len=512)
    else:
        raise ValidationError(f"{field}: unknown x-guard kind {kind!r}")  # fail closed


def validate_against_schema(
    args: Dict[str, Any], schema: Dict[str, Any], ctx: SchemaContext
) -> None:
    """
    Validate every argument by the type the TOOL declares in its parameters_schema
    (type + x-guard kind), instead of guessing from argument names.
    Unknown arguments are rejected (fail closed). Raises ValidationError.
    """
    props: Dict[str, Any] = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    for key, val in args.items():
        if key not in props:
            raise ValidationError(f"{key}: unknown argument for this tool")
        # Optional string args may be passed empty to mean "use the default".
        if val == "" and key not in required:
            continue
        _validate_typed(val, props[key], key, ctx)
    missing = [k for k in required if k not in args]
    if missing:
        raise ValidationError(f"missing required argument(s): {', '.join(sorted(missing))}")
