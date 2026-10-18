"""
Step 2 tests: Policy loader.
- Valid policy loads with correct hash
- Unknown keys cause startup failure (fail closed)
- Pattern matching with normalization (URL-encoded, case variations)
- Environment policy decisions
"""
import hashlib
import pytest
from pathlib import Path

from guardml.toolguard.policy import PolicyLoader


VALID_POLICY = """
version: 1
default_decision: BLOCK
tool_classes:
  read:       { base_risk: 5 }
  write_low:  { base_risk: 25 }
  write_high: { base_risk: 45 }
environments:
  staging:
    allow:      [read, write_low]
    approval:   [write_high]
    risk_bonus: 0
  production:
    allow:      [read]
    approval:   [write_low, write_high]
    risk_bonus: 20
blocked_tools:
  - docker_rm
protected_resources:
  model_aliases: [production]
  containers:    [model-api]
blocked_patterns:
  - 'rm\\s+-rf'
  - '--force'
limits:
  max_calls_per_session: 20
  max_blocked_per_session: 3
  max_output_chars: 8000
  approval_ttl_seconds: 600
  require_reason_for: medium
  tool_timeout_seconds: 15
allowed_health_hosts:
  - localhost
allowed_file_roots:
  - ./demo/data
"""

INVALID_UNKNOWN_KEY = VALID_POLICY + "\nunknown_extra_key: bad_value\n"


@pytest.fixture
def valid_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(VALID_POLICY)
    return str(p)


@pytest.fixture
def loader(valid_file):
    return PolicyLoader(valid_file)


class TestPolicyLoader:
    def test_loads_successfully(self, loader):
        assert loader is not None

    def test_hash_is_sha256_of_file(self, valid_file):
        content = Path(valid_file).read_text()
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert PolicyLoader(valid_file).policy_hash == expected

    def test_hash_length_is_64(self, loader):
        assert len(loader.policy_hash) == 64

    def test_blocked_tools(self, loader):
        assert "docker_rm" in loader.blocked_tools

    def test_staging_allows_read(self, loader):
        assert loader.policy_decision("read", "staging") == "allow"

    def test_staging_allows_write_low(self, loader):
        assert loader.policy_decision("write_low", "staging") == "allow"

    def test_staging_approves_write_high(self, loader):
        assert loader.policy_decision("write_high", "staging") == "approval"

    def test_production_allows_read(self, loader):
        assert loader.policy_decision("read", "production") == "allow"

    def test_production_approves_write_low(self, loader):
        assert loader.policy_decision("write_low", "production") == "approval"

    def test_production_approves_write_high(self, loader):
        assert loader.policy_decision("write_high", "production") == "approval"

    def test_unknown_env_blocks(self, loader):
        assert loader.policy_decision("read", "unknown_env") == "block"

    def test_pattern_rm_rf(self, loader):
        assert loader.matches_blocked_pattern("rm -rf /") is not None

    def test_pattern_rm_rf_url_encoded(self, loader):
        # URL-encoded + uppercase → normalized → should still match
        assert loader.matches_blocked_pattern("RM%20-RF") is not None

    def test_pattern_force_flag(self, loader):
        assert loader.matches_blocked_pattern("--force") is not None

    def test_clean_string_not_matched(self, loader):
        assert loader.matches_blocked_pattern("fraud_detection_v2") is None

    def test_protected_production(self, loader):
        assert loader.is_protected_resource("production")

    def test_protected_model_api(self, loader):
        assert loader.is_protected_resource("model-api")

    def test_not_protected_staging(self, loader):
        assert not loader.is_protected_resource("staging")

    def test_any_arg_protected_dict(self, loader):
        args = {"model_name": "fraud_classifier", "alias": "production"}
        assert loader.any_arg_protected(args)

    def test_any_arg_protected_nested(self, loader):
        args = {"outer": {"alias": "production"}}
        assert loader.any_arg_protected(args)

    def test_any_arg_not_protected(self, loader):
        args = {"model_name": "fraud_classifier", "alias": "staging_v2"}
        assert not loader.any_arg_protected(args)


class TestFailClosed:
    def test_unknown_key_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(INVALID_UNKNOWN_KEY)
        with pytest.raises(RuntimeError, match="Invalid policy"):
            PolicyLoader(str(p))

    def test_missing_file_raises(self):
        with pytest.raises(Exception):
            PolicyLoader("/nonexistent/path/to/policy.yaml")
