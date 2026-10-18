"""
Step 2: Policy loader.
- Validates against schema on startup (fail closed on unknown keys or bad values)
- Computes and logs a SHA-256 hash of the policy file
- Compiles all regexes once, case-insensitive
- Normalizes inputs before pattern matching
"""
from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Schema models — extra="forbid" rejects unknown keys
# ---------------------------------------------------------------------------
class ToolClassConfig(BaseModel):
    base_risk: int
    model_config = {"extra": "forbid"}


class EnvironmentConfig(BaseModel):
    allow: List[str] = Field(default_factory=list)
    approval: List[str] = Field(default_factory=list)
    risk_bonus: int = 0
    model_config = {"extra": "forbid"}


class ProtectedResources(BaseModel):
    model_aliases: List[str] = Field(default_factory=list)
    containers: List[str] = Field(default_factory=list)
    model_config = {"extra": "forbid"}


class Limits(BaseModel):
    max_calls_per_session: int = 20
    max_blocked_per_session: int = 3
    max_output_chars: int = 8000
    approval_ttl_seconds: int = 600
    require_reason_for: str = "medium"
    tool_timeout_seconds: int = 15
    model_config = {"extra": "forbid"}


class ProvenanceConfig(BaseModel):
    enabled: bool = True
    classes: List[str] = Field(default_factory=lambda: ["write_low", "write_high"])
    model_config = {"extra": "forbid"}


class IntentCheckConfig(BaseModel):
    enabled: bool = True
    classes: List[str] = Field(default_factory=lambda: ["write_low", "write_high"])
    model_config = {"extra": "forbid"}


class VerifyConfig(BaseModel):
    url: str = "http://localhost:8001/health"
    on_unreachable: Dict[str, Literal["warn", "rollback"]] = Field(default_factory=dict)
    model_config = {"extra": "forbid"}


class PolicySchema(BaseModel):
    version: int
    default_decision: str
    tool_classes: Dict[str, ToolClassConfig]
    environments: Dict[str, EnvironmentConfig]
    blocked_tools: List[str] = Field(default_factory=list)
    protected_resources: ProtectedResources = Field(default_factory=ProtectedResources)
    blocked_patterns: List[str] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    allowed_health_hosts: List[str] = Field(default_factory=list)
    allowed_file_roots: List[str] = Field(default_factory=list)
    allowed_repo_roots: List[str] = Field(default_factory=list)
    allowed_k8s_namespaces: List[str] = Field(default_factory=lambda: ['default'])
    allowed_log_containers: Optional[List[str]] = None   # None = no restriction
    verify_after_write: VerifyConfig = Field(default_factory=VerifyConfig)
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    intent_check: IntentCheckConfig = Field(default_factory=IntentCheckConfig)
    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# PolicyLoader
# ---------------------------------------------------------------------------
class PolicyLoader:
    def __init__(self, policy_path: Optional[str] = None):
        path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        raw = path.read_text(encoding="utf-8")

        # Compute and log policy hash at startup
        self.policy_hash = hashlib.sha256(raw.encode()).hexdigest()
        logger.info(
            "[ToolGuard] Policy loaded from %s sha256=%s", path, self.policy_hash
        )

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise RuntimeError(f"[ToolGuard] Policy YAML parse error: {e}") from e

        # Validate against schema — fail closed on any error
        try:
            self._schema = PolicySchema.model_validate(data)
        except ValidationError as e:
            raise RuntimeError(
                f"[ToolGuard] Invalid policy file {path}:\n{e}"
            ) from e

        # Compile regexes once, case-insensitive
        self._compiled_patterns: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in self._schema.blocked_patterns
        ]
        logger.info(
            "[ToolGuard] Compiled %d blocked patterns", len(self._compiled_patterns)
        )

    # -- Accessors -----------------------------------------------------------

    @property
    def default_decision(self) -> str:
        return self._schema.default_decision

    @property
    def blocked_tools(self) -> List[str]:
        return self._schema.blocked_tools

    @property
    def limits(self) -> Limits:
        return self._schema.limits

    @property
    def protected_resources(self) -> ProtectedResources:
        return self._schema.protected_resources

    @property
    def allowed_health_hosts(self) -> List[str]:
        return self._schema.allowed_health_hosts

    @property
    def allowed_file_roots(self) -> List[str]:
        return self._schema.allowed_file_roots

    @property
    def allowed_repo_roots(self) -> List[str]:
        return self._schema.allowed_repo_roots

    @property
    def allowed_log_containers(self) -> Optional[List[str]]:
        return self._schema.allowed_log_containers

    @property
    def allowed_k8s_namespaces(self) -> List[str]:
        return self._schema.allowed_k8s_namespaces

    @property
    def provenance(self) -> ProvenanceConfig:
        return self._schema.provenance

    @property
    def intent_check(self) -> IntentCheckConfig:
        return self._schema.intent_check

    @property
    def verify_after_write(self) -> VerifyConfig:
        return self._schema.verify_after_write

    def on_verify_unreachable(self, env: str) -> str:
        """'warn' or 'rollback'. Unlisted environments fail closed (rollback)."""
        return self._schema.verify_after_write.on_unreachable.get(env, "rollback")

    def get_env(self, env: str) -> EnvironmentConfig:
        envs = self._schema.environments
        if env not in envs:
            return EnvironmentConfig()  # empty → deny all
        return envs[env]

    def get_tool_class_config(self, tool_class: str) -> Optional[ToolClassConfig]:
        return self._schema.tool_classes.get(tool_class)

    def policy_decision(self, tool_class: str, env: str) -> str:
        """Returns 'allow', 'approval', or 'block'."""
        env_cfg = self.get_env(env)
        if tool_class in env_cfg.allow:
            return "allow"
        if tool_class in env_cfg.approval:
            return "approval"
        return "block"

    def env_risk_bonus(self, env: str) -> int:
        return self.get_env(env).risk_bonus

    def base_risk(self, tool_class: str) -> int:
        cfg = self.get_tool_class_config(tool_class)
        return cfg.base_risk if cfg else 50

    # -- Normalization and pattern matching ----------------------------------

    def normalize(self, text: str) -> str:
        """Unicode NFKC, lowercase, collapse whitespace, URL-decode once."""
        text = unicodedata.normalize("NFKC", text)
        text = urllib.parse.unquote(text)  # URL-decode once
        text = text.lower()
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def matches_blocked_pattern(self, text: str) -> Optional[str]:
        """
        Returns the matching pattern string if any blocked pattern matches
        the normalized input, else None.
        """
        normalized = self.normalize(text)
        for pat in self._compiled_patterns:
            if pat.search(normalized):
                return pat.pattern
        return None

    def is_protected_resource(self, value: str) -> bool:
        v = value.lower()
        for alias in self._schema.protected_resources.model_aliases:
            if alias.lower() == v:
                return True
        for container in self._schema.protected_resources.containers:
            if container.lower() == v:
                return True
        return False

    def any_arg_protected(self, args: dict) -> bool:
        """Recursively check if any string arg value is a protected resource."""
        def _check(v: Any) -> bool:
            if isinstance(v, str):
                return self.is_protected_resource(v)
            if isinstance(v, dict):
                return any(_check(vv) for vv in v.values())
            if isinstance(v, list):
                return any(_check(vv) for vv in v)
            return False
        return _check(args)
