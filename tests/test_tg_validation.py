"""
Step 4 tests: Argument validation and injection defense.
Covers the test checklist items for argument injection and path/URL attacks.
"""
import pytest
from guardml.toolguard.validation import (
    validate_identifier,
    validate_string_max,
    validate_int_range,
    validate_path,
    validate_url,
    ValidationError,
)


class TestIdentifierRule:
    """^[A-Za-z0-9_.\\-]{1,64}$ kills injection chars in one rule."""

    def test_valid_simple(self):
        validate_identifier("fraud_classifier", "model_name")  # no raise

    def test_valid_with_dot(self):
        validate_identifier("model.v2", "model_name")

    def test_valid_with_dash(self):
        validate_identifier("model-api-v2", "container")

    def test_semicolon_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api; rm -rf /", "container")

    def test_pipe_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api|whoami", "container")

    def test_dollar_paren_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api$(whoami)", "container")

    def test_backtick_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api`id`", "container")

    def test_newline_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api\nrm -rf", "container")

    def test_null_byte_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api\x00bad", "container")

    def test_space_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("my container", "container")

    def test_ampersand_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("api&&id", "container")

    def test_too_long_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("a" * 65, "container")

    def test_single_char_valid(self):
        validate_identifier("a", "container")

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            validate_identifier("", "container")


class TestStringMax:
    def test_valid(self):
        validate_string_max("fraud_detection", "experiment_name", 128)

    def test_too_long(self):
        with pytest.raises(ValidationError):
            validate_string_max("x" * 513, "field", 512)

    def test_control_char_rejected(self):
        with pytest.raises(ValidationError):
            validate_string_max("hello\x00world", "field")


class TestIntRange:
    def test_valid(self):
        assert validate_int_range(50, "lines", 1, 500) == 50

    def test_boundary_min(self):
        assert validate_int_range(1, "lines", 1, 500) == 1

    def test_boundary_max(self):
        assert validate_int_range(500, "lines", 1, 500) == 500

    def test_too_large_rejected(self):
        with pytest.raises(ValidationError):
            validate_int_range(100000, "lines", 1, 500)

    def test_zero_rejected_when_min_1(self):
        with pytest.raises(ValidationError):
            validate_int_range(0, "lines", 1, 500)

    def test_non_int_rejected(self):
        with pytest.raises(ValidationError):
            validate_int_range("abc", "lines", 1, 500)

    def test_negative_rejected(self):
        with pytest.raises(ValidationError):
            validate_int_range(-1, "lines", 1, 500)


class TestPathConfinement:
    def test_valid_path_inside_root(self, tmp_path):
        allowed = str(tmp_path)
        target = tmp_path / "data.csv"
        target.touch()
        result = validate_path(str(target), "data_path", [allowed])
        assert "data.csv" in result

    def test_dotdot_rejected(self, tmp_path):
        allowed = str(tmp_path / "data")
        with pytest.raises(ValidationError, match="traversal"):
            validate_path("../../etc/passwd", "data_path", [allowed])

    def test_etc_passwd_rejected(self):
        with pytest.raises(ValidationError):
            validate_path("/etc/passwd", "data_path", ["/safe"])

    def test_etc_shadow_rejected(self):
        with pytest.raises(ValidationError):
            validate_path("/etc/shadow", "data_path", ["/safe"])

    def test_outside_root_rejected(self, tmp_path):
        allowed = str(tmp_path / "data")
        with pytest.raises(ValidationError):
            validate_path("/tmp/evil.csv", "data_path", [allowed])

    def test_proc_rejected(self):
        with pytest.raises(ValidationError):
            validate_path("/proc/self/environ", "data_path", ["/safe"])


class TestURLValidation:
    def test_valid_http_localhost(self):
        # No raise expected
        validate_url("http://localhost:8001/health", "url", ["localhost"])

    def test_valid_https(self):
        validate_url("https://localhost:8001/health", "url", ["localhost"])

    def test_file_scheme_rejected(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("file:///etc/passwd", "url", [])

    def test_ftp_rejected(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("ftp://example.com/file", "url", [])

    def test_javascript_rejected(self):
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("javascript:alert(1)", "url", [])

    def test_host_not_in_allowlist(self):
        with pytest.raises(ValidationError, match="allowlist"):
            validate_url("http://evil.com/health", "url", ["localhost"])

    def test_no_host_rejected(self):
        with pytest.raises(ValidationError):
            validate_url("http:///health", "url", [])

    def test_link_local_blocked(self):
        """169.254.169.254 (AWS metadata) is blocked when not in the allowlist."""
        with pytest.raises((ValidationError, Exception)):
            validate_url(
                "http://169.254.169.254/latest/meta-data",
                "url",
                [],  # empty allowlist — host not explicitly allowed
            )
