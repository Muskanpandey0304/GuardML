"""
Step 6: Secret masking with typed redaction.
Applied to ALL outputs before they reach the LLM, audit log, or UI.

Key design: MLflow run IDs (32-char hex) and git SHAs (40-char hex) are
legitimate IDs and MUST pass through unmasked. Only mask hex strings when
they follow a secret-looking key name.
"""
from __future__ import annotations

import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Typed secret patterns
# Each entry: (type_name, compiled_pattern, group_to_redact_or_None)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: List[Tuple[str, re.Pattern, Optional[int]]] = [
    # AWS access key
    (
        "aws_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        None,
    ),
    # GitHub tokens
    (
        "github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        None,
    ),
    # Anthropic / OpenAI / Stripe style sk- or sk_ keys
    (
        "sk_key",
        re.compile(r"sk[-_][A-Za-z0-9_\-]{20,}"),
        None,
    ),
    # Private Key blocks
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----|-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
        None,
    ),
    # Bearer tokens
    (
        "bearer_token",
        re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
        None,
    ),
    # JWT tokens
    (
        "jwt",
        re.compile(
            r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
        ),
        None,
    ),
    # Private key blocks
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        None,
    ),
    # Credentials in URL: ://user:password@
    (
        "url_credential",
        re.compile(r"://([^/\s:@]+):([^/\s:@]+)@"),
        2,  # redact group 2 (the password)
    ),
    # Key-value secret patterns (mask the value, not the key name)
    (
        "kv_secret",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|token|api[_\-]?key|access_key|auth)"
            r"[\s]*[=:]\s*(\S+)"
        ),
        2,  # redact group 2 (the value)
    ),
]

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


# Pure hex strings: MLflow run IDs (32 chars) and git SHAs (40 chars)
_PURE_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)


def _is_legitimate_id(s: str) -> bool:
    """True if s looks like a MLflow run ID (32 hex) or git SHA (40 hex)."""
    return len(s) in (32, 40) and bool(_PURE_HEX_RE.match(s))


def _high_entropy_in_context(text: str, min_len: int = 32, threshold: float = 4.0) -> str:
    """
    Mask high-entropy tokens ONLY when they follow a secret-looking key name.
    MLflow run IDs and git SHAs are explicitly excluded.
    """
    pattern = re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_\-]?key|access_key|auth|credential)"
        r"[\s]*[=:]\s*([A-Za-z0-9+/=_\-\.]{" + str(min_len) + r",})"
    )

    def replacer(m: re.Match) -> str:
        val = m.group(2)
        if _is_legitimate_id(val):
            return m.group(0)  # leave MLflow IDs and git SHAs untouched
        if _shannon_entropy(val) >= threshold:
            return m.group(0).replace(val, "[REDACTED:high_entropy]")
        return m.group(0)

    return pattern.sub(replacer, text)


# ---------------------------------------------------------------------------
# Env-var exact-match redaction
# ---------------------------------------------------------------------------
_SECRET_ENV_SUFFIXES = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "PWD", "CREDENTIAL", "AUTH"
)


def _collect_env_secrets() -> List[str]:
    secrets = []
    for key, val in os.environ.items():
        if any(key.upper().endswith(s) for s in _SECRET_ENV_SUFFIXES):
            if val and len(val) >= 8:
                secrets.append(val)
    return secrets


_ENV_SECRETS: List[str] = _collect_env_secrets()


# ---------------------------------------------------------------------------
# Main masking functions
# ---------------------------------------------------------------------------
def mask_text(text: str) -> str:
    """
    Apply all masking passes to a plain string.
    Applied to: tool output, audit log entries, UI output, error messages, user messages.
    """
    if not isinstance(text, str):
        text = str(text)

    # 1. Typed pattern masking (most specific patterns first)
    for type_name, pattern, group in _SECRET_PATTERNS:
        if group is None:
            text = pattern.sub("[REDACTED]", text)
        else:
            def _replacer(m: re.Match, g: int = group, t: str = type_name) -> str:
                val = m.group(g)
                return m.group(0).replace(val, "[REDACTED]", 1)
            text = pattern.sub(_replacer, text)

    # 2. High-entropy token masking (only in secret key context)
    text = _high_entropy_in_context(text)

    # 3. Env-var exact-match redaction
    for secret in _ENV_SECRETS:
        if secret in text:
            text = text.replace(secret, "[REDACTED]")

    return text


def mask_value(val: Any) -> Any:
    """Recursively mask secrets in dicts, lists, or strings."""
    if isinstance(val, str):
        return mask_text(val)
    if isinstance(val, dict):
        return {k: mask_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        masked = [mask_value(v) for v in val]
        return type(val)(masked)
    return val


# ---------------------------------------------------------------------------
# Injection phrase detector (for audit logging, not for blocking)
# ---------------------------------------------------------------------------
_INJECTION_PHRASES = [
    "ignore previous",
    "system prompt",
    "you are now",
    "new instructions",
    "disregard all",
    "override instructions",
    "forget your instructions",
    "your new task is",
]


def detect_injection_phrases(text: str) -> List[str]:
    """Return list of injection phrases found in text (for audit logging only)."""
    lower = text.lower()
    return [p for p in _INJECTION_PHRASES if p in lower]
