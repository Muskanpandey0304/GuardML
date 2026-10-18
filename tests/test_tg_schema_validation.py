from pathlib import Path
"""
Day 2 tests: schema-driven argument validation.

Arguments are validated by the type each TOOL declares (type + x-guard kind),
not by guessing from argument names. Unknown arguments are rejected.
"""
import json

import pytest

from guardml.toolguard.guard import ToolGuard
from guardml.toolguard.schemas import Decision
from guardml.toolguard.validation import (
    SchemaContext, ValidationError, validate_against_schema,
    validate_identifier, validate_revision, coerce_identifier_args,
)
from guardml.tools.registry import get_registry

CTX = SchemaContext(
    allowed_file_roots=['./demo/data', './reports'],
    allowed_namespaces=['default'],
    allowed_repo_roots=['.'],
    allowed_health_hosts=['localhost', '127.0.0.1', 'model-api'],
)


def _schema(**props):
    required = props.pop('_required', [])
    return {'type': 'object', 'properties': props, 'required': required}


# ── Unit: validate_against_schema ────────────────────────────────────────────
class TestSchemaValidator:
    def test_unknown_argument_rejected(self):
        with pytest.raises(ValidationError, match='unknown argument'):
            validate_against_schema({'dataset_path': 'x'}, _schema(data_path={'type': 'string'}), CTX)

    def test_missing_required_rejected(self):
        with pytest.raises(ValidationError, match='missing required'):
            validate_against_schema({}, _schema(container={'type': 'string'}, _required=['container']), CTX)

    def test_wrong_type_rejected(self):
        with pytest.raises(ValidationError):
            validate_against_schema({'lines': 'fifty'}, _schema(lines={'type': 'integer'}), CTX)

    def test_bool_is_not_an_integer(self):
        with pytest.raises(ValidationError):
            validate_against_schema({'lines': True}, _schema(lines={'type': 'integer'}), CTX)

    def test_whole_float_accepted_as_integer(self):
        validate_against_schema({'lines': 50.0}, _schema(lines={'type': 'integer', 'minimum': 1, 'maximum': 200}), CTX)

    def test_range_enforced(self):
        spec = _schema(lines={'type': 'integer', 'minimum': 1, 'maximum': 200})
        with pytest.raises(ValidationError, match='out of allowed range'):
            validate_against_schema({'lines': 201}, spec, CTX)
        with pytest.raises(ValidationError, match='out of allowed range'):
            validate_against_schema({'lines': 0}, spec, CTX)

    def test_optional_empty_string_means_default(self):
        validate_against_schema({'since': ''}, _schema(since={'type': 'string', 'x-guard': 'duration'}), CTX)

    def test_required_empty_string_still_validated(self):
        with pytest.raises(ValidationError):
            validate_against_schema(
                {'container': ''},
                _schema(container={'type': 'string', 'x-guard': 'identifier'}, _required=['container']),
                CTX,
            )

    def test_array_items_validated(self):
        spec = _schema(columns={'type': 'array', 'items': {'type': 'string', 'x-guard': 'identifier'}})
        validate_against_schema({'columns': ['amount', 'credit_score']}, spec, CTX)
        with pytest.raises(ValidationError):
            validate_against_schema({'columns': ['amount', 'x; rm -rf /']}, spec, CTX)

    def test_nested_object_rejected(self):
        with pytest.raises(ValidationError):
            validate_against_schema({'x': {'a': 1}}, _schema(x={'type': 'object'}), CTX)

    def test_unknown_guard_kind_fails_closed(self):
        with pytest.raises(ValidationError, match='unknown x-guard kind'):
            validate_against_schema({'x': 'a'}, _schema(x={'type': 'string', 'x-guard': 'banana'}), CTX)

    def test_undeclared_string_is_length_limited_free_text(self):
        validate_against_schema({'x': 'a' * 512}, _schema(x={'type': 'string'}), CTX)
        with pytest.raises(ValidationError):
            validate_against_schema({'x': 'a' * 513}, _schema(x={'type': 'string'}), CTX)


# ── Unit: identifier / revision hardening ────────────────────────────────────
class TestFlagAndNewlineInjection:
    @pytest.mark.parametrize('value', ['-f', '--help', '-rf', '--tail=0'])
    def test_identifier_cannot_look_like_a_flag(self, value):
        with pytest.raises(ValidationError):
            validate_identifier(value, 'container')

    @pytest.mark.parametrize('value', ['model-api\n', 'model-api\n\n'])
    def test_identifier_rejects_trailing_newline(self, value):
        with pytest.raises(ValidationError):
            validate_identifier(value, 'container')

    @pytest.mark.parametrize('value', ['--no-pager', '-h', '--output=x', 'HEAD;id', 'a b', 'HEAD\n'])
    def test_revision_rejects_flags_and_metachars(self, value):
        with pytest.raises(ValidationError):
            validate_revision(value, 'a_rev')

    @pytest.mark.parametrize('value', ['HEAD', 'HEAD~1', 'HEAD^', 'main', 'v1.2.3', 'feature/x', 'a1b2c3d'])
    def test_revision_accepts_normal_revs(self, value):
        validate_revision(value, 'a_rev')


# ── Integration: the REAL tool registry through ToolGuard ────────────────────
@pytest.fixture
def real_guard():
    g = ToolGuard()
    reg = get_registry()
    g._get_registry = lambda: reg  # conftest patches the class; override on the instance
    return g


CASES = [
    # (tool, args, expected decision)
    ('data_quality_check', {'data_path': 'demo/data/current.csv'}, Decision.ALLOW),
    ('data_quality_check', {'data_path': '../.env'}, Decision.BLOCK),
    ('data_quality_check', {'data_path': 'C:/Windows/win.ini'}, Decision.BLOCK),
    ('data_quality_check', {'dataset_path': 'demo/data/current.csv'}, Decision.BLOCK),  # unknown arg
    ('data_quality_check', {'null_threshold': 5}, Decision.BLOCK),
    ('drift_report', {'reference_path': 'demo/data/reference.csv', 'current_path': 'demo/data/current.csv'}, Decision.ALLOW),
    ('drift_report', {'current_path': '../../secrets.csv'}, Decision.BLOCK),
    ('drift_report', {'columns': ['amount; id']}, Decision.BLOCK),
    ('dvc_status', {'repo_path': '.'}, Decision.ALLOW),
    ('dvc_status', {'repo_path': 'C:/Windows'}, Decision.BLOCK),
    ('dvc_status', {'repo_path': '/etc'}, Decision.BLOCK),
    ('dvc_diff', {'a_rev': 'HEAD~1'}, Decision.ALLOW),
    ('dvc_diff', {'a_rev': '--no-pager'}, Decision.BLOCK),
    ('dvc_diff', {'b_rev': '-h'}, Decision.BLOCK),
    ('docker_logs', {'container': 'model-api', 'lines': 50, 'since': '10m'}, Decision.ALLOW),
    ('docker_logs', {'container': '-f'}, Decision.BLOCK),
    ('docker_logs', {'container': 'model-api', 'lines': 9999}, Decision.BLOCK),
    ('docker_logs', {'container': 'model-api', 'since': '--follow'}, Decision.BLOCK),
    ('kubectl_get_pods', {'namespace': 'default', 'label_selector': 'app=model-api'}, Decision.ALLOW),
    ('kubectl_get_pods', {'namespace': '--all-namespaces'}, Decision.BLOCK),
    ('kubectl_get_pods', {'label_selector': '-o=yaml'}, Decision.BLOCK),
    ('kubectl_logs', {'pod': 'model-api-0', 'lines': 20}, Decision.ALLOW),
    ('kubectl_logs', {'pod': '--help'}, Decision.BLOCK),
    ('health_check', {'url': 'http://localhost:8001/health'}, Decision.ALLOW),
    ('health_check', {'url': 'http://169.254.169.254/latest/meta-data/'}, Decision.BLOCK),
    ('health_check', {'url': 'file:///etc/passwd'}, Decision.BLOCK),
    ('disk_memory_status', {}, Decision.ALLOW),
    ('disk_memory_status', {'path': '/'}, Decision.BLOCK),
    ('mlflow_get_production_model', {'model_name': 'fraud_classifier'}, Decision.ALLOW),
    ('mlflow_get_production_model', {"model_name": "x' OR name LIKE '%"}, Decision.BLOCK),
    ('mlflow_list_runs', {'experiment_name': 'fraud_detection', 'max_results': 500}, Decision.BLOCK),
    ('mlflow_list_runs', {'experiment_name': 'fraud_detection', 'max_results': 10}, Decision.ALLOW),
]


@pytest.mark.parametrize('tool,args,expected', CASES, ids=[f'{t}-{i}' for i, (t, _, _) in enumerate(CASES)])
def test_real_tools_validated_by_declared_types(real_guard, tool, args, expected):
    v = real_guard.check(tool, args, session_id=f'sv-{tool}-{abs(hash(json.dumps(args, sort_keys=True)))}', env='staging')
    assert v.decision == expected, f'{tool}{args}: expected {expected}, got {v.decision} ({v.reasons})'


# ── Guard rail: a new tool cannot forget to declare its argument kinds ───────
def _string_specs(props):
    for name, spec in props.items():
        t = spec.get('type')
        if t == 'string':
            yield name, spec
        elif t == 'array':
            yield from ((f'{name}[]', s) for _, s in _string_specs({'item': spec.get('items') or {}}))


def test_every_string_argument_declares_an_x_guard_kind():
    missing = []
    for schema in get_registry().all_schemas():
        for name, spec in _string_specs(schema['input_schema'].get('properties', {})):
            if 'x-guard' not in spec:
                missing.append(f"{schema['name']}.{name}")
    assert not missing, f'string arguments without an x-guard kind: {missing}'


# ── Boundary normalisation: numbers for string identifiers (found by GuardBench ben-12) ──
class TestCoerceIdentifierArgs:
    SCHEMA = {'properties': {
        'version': {'type': 'string', 'x-guard': 'identifier'},
        'path': {'type': 'string', 'x-guard': 'path'},
        'lines': {'type': 'integer'},
        'free': {'type': 'string'},
    }}

    def test_int_and_whole_float_become_strings(self):
        assert coerce_identifier_args({'version': 1}, self.SCHEMA) == {'version': '1'}
        assert coerce_identifier_args({'version': 2.0}, self.SCHEMA) == {'version': '2'}

    def test_only_identifier_fields_are_touched(self):
        args = {'path': 5, 'free': 7, 'lines': 9, 'unknown': 3}
        assert coerce_identifier_args(args, self.SCHEMA) == args

    @pytest.mark.parametrize('val', [True, False, 1.5, [1], {'a': 1}, None, 'x'])
    def test_bools_fractions_containers_are_left_for_strict_validation(self, val):
        assert coerce_identifier_args({'version': val}, self.SCHEMA) == {'version': val}

    def test_coerced_value_still_passes_strict_validation_and_garbage_still_fails(self):
        schema = {'type': 'object', 'required': ['version'], 'properties': self.SCHEMA['properties']}
        validate_against_schema(coerce_identifier_args({'version': 3}, self.SCHEMA), schema, CTX)
        with pytest.raises(ValidationError):
            validate_against_schema(coerce_identifier_args({'version': 1.5}, self.SCHEMA), schema, CTX)


# ── v2: read-side confinement found by the adversarial set ──────────────────
class TestReadSideConfinementV2:
    def test_source_code_under_demo_is_no_longer_readable(self):
        from guardml.toolguard.validation import validate_path, ValidationError
        with pytest.raises(ValidationError):
            validate_path('demo/train_model.py', 'data_path', CTX.allowed_file_roots)
        validate_path('demo/data/current.csv', 'data_path', CTX.allowed_file_roots)

    def test_only_allow_listed_namespaces_are_readable(self):
        from guardml.toolguard.validation import validate_against_schema, ValidationError
        schema = get_registry().get('kubectl_get_pods').parameters_schema
        validate_against_schema({'namespace': 'default'}, schema, CTX)
        for ns in ('kube-system', 'production'):
            with pytest.raises(ValidationError, match='not an allowed namespace'):
                validate_against_schema({'namespace': ns}, schema, CTX)


class TestLogContainerAllowList:
    def _ctx(self, allowed):
        return SchemaContext(allowed_file_roots=['./demo/data'], allowed_log_containers=allowed)

    def test_control_plane_logs_are_refused_when_not_listed(self):
        from guardml.toolguard.validation import validate_against_schema, ValidationError
        schema = get_registry().get('docker_logs').parameters_schema
        validate_against_schema({'container': 'model-api'}, schema, self._ctx(['model-api', 'mlflow']))
        with pytest.raises(ValidationError, match='may not be read'):
            validate_against_schema({'container': 'guardml-api'}, schema, self._ctx(['model-api', 'mlflow']))

    def test_unset_list_means_no_restriction(self):
        from guardml.toolguard.validation import validate_against_schema
        schema = get_registry().get('docker_logs').parameters_schema
        validate_against_schema({'container': 'anything'}, schema, self._ctx(None))

    def test_shipped_policy_blocks_the_control_plane(self):
        from guardml.toolguard.policy import PolicyLoader
        import guardml.toolguard.policy as pm
        pol = PolicyLoader(str(Path(pm.__file__).with_name('policy.yaml')))
        assert 'model-api' in pol.allowed_log_containers and 'guardml-api' not in pol.allowed_log_containers
