"""
Step 1: Core data structures for ToolGuard.
Severity ordering: ALLOW < NEEDS_APPROVAL < BLOCK.
Any check can raise severity; NO check can ever lower it.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Set

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Decision enum — ordered so higher value = higher severity
# ---------------------------------------------------------------------------
class Decision(str, Enum):
    ALLOW = "ALLOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    BLOCK = "BLOCK"

    def __lt__(self, other: "Decision") -> bool:  # type: ignore[override]
        _order = {"ALLOW": 0, "NEEDS_APPROVAL": 1, "BLOCK": 2}
        return _order[self.value] < _order[other.value]

    def __le__(self, other: "Decision") -> bool:
        return self == other or self < other

    def max(self, other: "Decision") -> "Decision":
        """Return the higher-severity decision. Severity NEVER decreases."""
        _order = {"ALLOW": 0, "NEEDS_APPROVAL": 1, "BLOCK": 2}
        return self if _order[self.value] >= _order[other.value] else other


# ---------------------------------------------------------------------------
# ToolCall
# ---------------------------------------------------------------------------
class ToolCall(BaseModel):
    session_id: str = Field(..., description="Session identifier")
    tool_name: str = Field(..., description="Registered tool name")
    args: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    reason: Optional[str] = Field(None, description="LLM-supplied reason for the call")
    env: str = Field(..., description="Environment: staging or production")
    timestamp: float = Field(default_factory=time.time)
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
class Verdict(BaseModel):
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    risk_label: str  # low | medium | high
    reasons: List[str] = Field(default_factory=list)
    matched_rules: List[str] = Field(default_factory=list)
    approval_id: Optional[str] = None
    tool_name: str = ""
    session_id: str = ""

    def escalate(
        self,
        decision: Decision,
        reason: str,
        rule: Optional[str] = None,
    ) -> "Verdict":
        """Return a new Verdict with severity >= current. CANNOT lower severity."""
        new_decision = self.decision.max(decision)
        new_reasons = self.reasons + [reason]
        new_rules = self.matched_rules + ([rule] if rule else [])
        return self.model_copy(
            update={
                "decision": new_decision,
                "reasons": new_reasons,
                "matched_rules": new_rules,
            }
        )

    ALLOW: ClassVar[Decision] = Decision.ALLOW
    NEEDS_APPROVAL: ClassVar[Decision] = Decision.NEEDS_APPROVAL
    BLOCK: ClassVar[Decision] = Decision.BLOCK

    @property
    def verdict(self) -> Decision:
        return self.decision

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else ""

    @staticmethod
    def block(reason: str, rule: str = "", score: int = 100) -> "Verdict":
        return Verdict(
            decision=Decision.BLOCK,
            risk_score=score,
            risk_label="high",
            reasons=[reason],
            matched_rules=[rule] if rule else [],
        )

    @staticmethod
    def allow(score: int = 0, label: str = "low") -> "Verdict":
        return Verdict(
            decision=Decision.ALLOW,
            risk_score=score,
            risk_label=label,
            reasons=[],
        )


    @staticmethod
    def needs_approval(score: int, label: str, reason: str) -> "Verdict":
        return Verdict(
            decision=Decision.NEEDS_APPROVAL,
            risk_score=score,
            risk_label=label,
            reasons=[reason],
        )


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------
class SessionState(BaseModel):
    session_id: str
    env: str = "staging"
    call_count: int = 0
    blocked_count: int = 0
    tainted: bool = False  # True after reading untrusted free text
    write_tools_used: List[str] = Field(default_factory=list)
    locked: bool = False  # True after blocked_count >= 3
    # Value-level provenance (see toolguard/provenance.py)
    user_requests: List[str] = Field(default_factory=list)       # trusted: what the user typed
    trusted_tokens: Set[str] = Field(default_factory=set)         # tokens of the user's requests
    untrusted_tokens: Dict[str, str] = Field(default_factory=dict)  # token -> first tool that returned it
    untrusted_overflow: bool = False  # store hit its cap -> provenance fails closed

    def increment_call(self) -> "SessionState":
        return self.model_copy(update={"call_count": self.call_count + 1})

    def increment_blocked(self) -> "SessionState":
        blocked = self.blocked_count + 1
        locked = blocked >= 3
        return self.model_copy(update={"blocked_count": blocked, "locked": locked})

    def mark_tainted(self) -> "SessionState":
        return self.model_copy(update={"tainted": True})

    def add_user_request(self, text: str) -> "SessionState":
        from .provenance import tokens
        return self.model_copy(update={
            "user_requests": (self.user_requests + [text[:2000]])[-5:],
            "trusted_tokens": self.trusted_tokens | tokens(text),
        })

    def add_untrusted(self, tool_name: str, text: str) -> "SessionState":
        from .provenance import tokens, MAX_UNTRUSTED_TOKENS
        known = dict(self.untrusted_tokens)
        overflow = self.untrusted_overflow
        for t in tokens(text):
            if t in known:
                continue
            if len(known) >= MAX_UNTRUSTED_TOKENS:
                overflow = True
                break
            known[t] = tool_name
        return self.model_copy(update={"untrusted_tokens": known, "untrusted_overflow": overflow})

    def add_write(self, tool_name: str) -> "SessionState":
        return self.model_copy(
            update={"write_tools_used": self.write_tools_used + [tool_name]}
        )
