"""
Day 2 tests: the agent loop runs EVERY tool call through GuardedExecutor, and the
LLM provider layer converts conversations correctly.
"""
import importlib
import json
from pathlib import Path

import pytest

from guardml.agent.llm import (
    AnthropicProvider, LLMResponse, OllamaProvider, ScriptedProvider, ToolUse,
    select_provider,
)
from guardml.agent.loop import AgentLoop
from guardml.agent.schemas import get_tool_schemas, llm_schema
from guardml.toolguard import session as session_store

PKG_ROOT = Path(__file__).resolve().parent.parent


# ── Test doubles ─────────────────────────────────────────────────────────────
class FakeSnapshots:
    def __init__(self):
        self.calls = []

    def snapshot_model_alias(self, model_name, alias, session_id=''):
        self.calls.append((model_name, alias, session_id))
        return 'snap-1'


class FakeRollback:
    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def auto_rollback_after_verify(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


@pytest.fixture
def stack(tmp_path, monkeypatch, mock_registry):
    """Real audit log + approval gate on a temp DB; fake snapshot/rollback."""
    monkeypatch.setenv('GUARDML_DB', str(tmp_path / 'loop.db'))
    import guardml.audit.log as logmod
    import guardml.toolguard.approval as apmod
    importlib.reload(logmod)
    importlib.reload(apmod)
    logmod.ensure_tables()
    apmod.ensure_tables()

    class S:
        audit = logmod.AuditLog()
        gate = apmod.ApprovalGate(ttl_seconds=60)
        snapshots = FakeSnapshots()
        rollback = FakeRollback()

    def make(provider=None, demo_mode=False, environment='staging', intent_check=False):
        return AgentLoop(
            environment=environment, provider=provider, demo_mode=demo_mode,
            intent_check=intent_check,
            registry=mock_registry, audit=S.audit, approval_gate=S.gate,
            snapshots=S.snapshots, rollback=S.rollback,
        )

    S.make = staticmethod(make)

    def auto_resolve(decision, who='tester'):
        def _poll(approval_id, poll_interval=1.0):
            S.gate.resolve(approval_id, decision, resolved_by=who)
            return decision
        monkeypatch.setattr(S.gate, 'poll_until_resolved', _poll)

    S.auto_resolve = staticmethod(auto_resolve)
    return S


def call(name, **args):
    return ToolUse(id=f'id-{name}', name=name, input=args)


def script(*responses):
    return ScriptedProvider(list(responses))


# ── The choke point ──────────────────────────────────────────────────────────
class TestSingleChokePoint:
    def test_only_the_executor_calls_tool_run(self):
        """A real `tool.run(...)` call may only exist in toolguard/executor.py."""
        import ast
        offenders = []
        for path in PKG_ROOT.rglob('*.py'):
            rel = path.relative_to(PKG_ROOT).as_posix()
            if rel.startswith(('tests/', 'tools/', 'myenv/', '.venv/', 'demo/', 'bench/')):
                continue
            if rel == 'toolguard/executor.py':
                continue
            tree = ast.parse(path.read_text(encoding='utf-8', errors='ignore'))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'run'
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == 'tool'):
                    offenders.append(f'{rel}:{node.lineno}')
        assert not offenders, f'tool.run() called outside GuardedExecutor: {offenders}'

    def test_read_tool_runs_and_output_is_wrapped_untrusted(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_list_runs', experiment_name='fraud_detection')]),
            LLMResponse(text='all good'),
        )
        result = stack.make(provider).run('why did accuracy drop?', session_id='s-read')

        assert result['answer'] == 'all good'
        assert result['steps'][0]['outcome'] == 'allowed'
        fed_back = provider.calls[1][-1]['results'][0]['content']
        assert fed_back.startswith('<tool_output tool="mlflow_list_runs" untrusted="true">')

    def test_free_text_tool_output_taints_the_session(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_list_runs', experiment_name='fraud_detection')]),
            LLMResponse(text='done'),
        )
        stack.make(provider).run('x', session_id='s-taint')
        assert session_store.get('s-taint').tainted is True

    def test_blocked_tool_never_runs(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_delete_model', model_name='fraud_classifier')]),
            LLMResponse(text='I cannot do that'),
        )
        result = stack.make(provider).run('delete the model', session_id='s-block')
        step = result['steps'][0]
        assert step['outcome'] == 'blocked' and step['verdict'] == 'BLOCK'
        assert 'BLOCKED' in step['result']['error']
        assert stack.snapshots.calls == []

    def test_argument_injection_is_blocked(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('docker_logs', container='-f')]),
            LLMResponse(text='ok'),
        )
        result = stack.make(provider).run('logs', session_id='s-inj')
        assert result['steps'][0]['outcome'] == 'blocked'

    def test_every_call_leaves_intent_and_outcome_in_audit(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_list_runs', experiment_name='fraud_detection')]),
            LLMResponse(text='ok'),
        )
        stack.make(provider).run('x', session_id='s-audit')
        verdicts = [e['verdict'] for e in stack.audit.get_session('s-audit')]
        assert verdicts == ['INTENT', 'ALLOW']
        assert stack.audit.verify_chain()['ok'] is True


class TestNumericIdentifiers:
    def test_integer_version_from_a_tool_output_is_not_blocked(self, stack):
        """GuardBench ben-12: the real MLflow tool returns version as an int."""
        stack.auto_resolve('approved')
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_set_alias', model_name='fraud_classifier',
                                         alias='production', version=1, reason='rollback')]),
            LLMResponse(text='done'),
        )
        # the conftest mock tools have no schema; give this one a declared identifier type
        tool = stack.make(provider).registry.get('mlflow_set_alias')
        tool.parameters_schema = {'type': 'object', 'properties': {
            'model_name': {'type': 'string', 'x-guard': 'identifier'},
            'alias': {'type': 'string', 'x-guard': 'identifier'},
            'version': {'type': 'string', 'x-guard': 'identifier'}}, 'required': ['model_name', 'alias', 'version']}
        try:
            result = stack.make(provider).run('roll back to version 1', session_id='s-num')
        finally:
            tool.parameters_schema = {'type': 'object', 'properties': {}}
        step = result['steps'][0]
        assert step['args']['version'] == '1' and step['outcome'] == 'approved_executed'


# ── reason field ─────────────────────────────────────────────────────────────
class TestReasonField:
    def test_reason_reaches_the_guard_and_is_not_a_tool_arg(self, stack):
        provider = script(
            LLMResponse(tool_calls=[call('docker_restart', container='model-api',
                                         reason='Container is wedged after the deploy.')]),
            LLMResponse(text='restarted'),
        )
        result = stack.make(provider).run('restart it', session_id='s-reason')
        step = result['steps'][0]
        # medium risk (50) with a reason supplied -> allowed without a human
        assert step['verdict'] == 'ALLOW' and step['outcome'] == 'allowed'
        assert step['reason'] == 'Container is wedged after the deploy.'
        assert 'reason' not in step['args']
        assert 'reason' not in json.loads(stack.audit.get_session('s-reason')[0]['args'])

    def test_medium_risk_without_reason_needs_approval(self, stack):
        stack.auto_resolve('denied')
        provider = script(
            LLMResponse(tool_calls=[call('docker_restart', container='model-api')]),
            LLMResponse(text='ok'),
        )
        result = stack.make(provider).run('restart it', session_id='s-noreason')
        assert result['steps'][0]['verdict'] == 'NEEDS_APPROVAL'


# ── approval flow ────────────────────────────────────────────────────────────
ROLLBACK_CALL = dict(model_name='fraud_classifier', alias='production', version='1',
                     reason='User asked to roll back.')


class TestApprovalFlow:
    def test_approved_call_runs_once_with_snapshot_and_audit(self, stack):
        stack.auto_resolve('approved', who='alice')
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_set_alias', **ROLLBACK_CALL)]),
            LLMResponse(text='rolled back'),
        )
        loop = stack.make(provider)
        result = loop.run('roll back to v1', session_id='s-appr')

        step = result['steps'][0]
        assert step['verdict'] == 'NEEDS_APPROVAL'
        assert step['outcome'] == 'approved_executed'
        assert step['result']['ok'] is True
        assert stack.snapshots.calls == [('fraud_classifier', 'production', 's-appr')]

        final = [e for e in stack.audit.get_session('s-appr') if e['verdict'] == 'APPROVED_EXECUTED']
        assert len(final) == 1 and final[0]['approved_by'] == 'alice'
        assert stack.audit.verify_chain()['ok'] is True

        # single use: replaying the same approval is refused
        from guardml.toolguard.schemas import ToolCall
        args = {k: v for k, v in ROLLBACK_CALL.items() if k != 'reason'}
        replay = loop.executor.execute(
            ToolCall(session_id='s-appr', tool_name='mlflow_set_alias', args=args, env='staging'),
            approval_id=step['approval_id'],
        )
        assert replay.ok is False and 'already used' in replay.output

    def test_denied_call_never_runs(self, stack):
        stack.auto_resolve('denied')
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_set_alias', **ROLLBACK_CALL)]),
            LLMResponse(text='understood'),
        )
        result = stack.make(provider).run('roll back to v1', session_id='s-deny')
        step = result['steps'][0]
        assert step['outcome'] == 'approval_denied'
        assert stack.snapshots.calls == []
        assert 'APPROVAL_DENIED' in [e['verdict'] for e in stack.audit.get_session('s-deny')]



# ── post-write verification: healthy / unhealthy / unreachable ───────────────
def _health(monkeypatch, data, seen=None):
    """Stub the post-write HealthCheck with a fixed response."""
    from guardml.tools import deploy_tools
    from guardml.tools.base import ToolResult

    def fake_run(self, **kwargs):
        if seen is not None:
            seen.append(kwargs.get('url'))
        return ToolResult(ok=True, data=data)

    monkeypatch.setattr(deploy_tools.HealthCheck, 'run', fake_run)


HEALTHY = {'ok': True, 'status_code': 200, 'healthy': True}
UNHEALTHY = {'ok': True, 'status_code': 503, 'healthy': False}
UNREACHABLE = {'ok': False, 'healthy': False, 'error': '[WinError 10061] connection refused'}


class TestPostWriteVerification:
    def _approve_and_run(self, stack, environment='staging', session_id='s-v'):
        stack.auto_resolve('approved')
        provider = script(
            LLMResponse(tool_calls=[call('mlflow_set_alias', **ROLLBACK_CALL)]),
            LLMResponse(text='done'),
        )
        loop = stack.make(provider, environment=environment)
        return loop.run('roll back', session_id=session_id), provider

    def test_healthy_keeps_the_change(self, stack, monkeypatch):
        _health(monkeypatch, HEALTHY)
        result, _ = self._approve_and_run(stack)
        ver = result['steps'][0]['verification']
        assert ver['status'] == 'healthy' and ver['action'] == 'kept'
        assert stack.rollback.calls == []

    def test_unhealthy_rolls_back(self, stack, monkeypatch):
        _health(monkeypatch, UNHEALTHY)
        stack.rollback.result = {'ok': True, 'message': 'Rolled back to version 2'}
        result, provider = self._approve_and_run(stack)
        step = result['steps'][0]
        assert step['verification']['status'] == 'unhealthy'
        assert step['verification']['action'] == 'rolled_back'
        assert step['rollback']['ok'] is True
        assert stack.rollback.calls[0]['snapshot_id'] == 'snap-1'
        # the model is told its change was reverted
        assert '"rolled_back"' in provider.calls[1][-1]['results'][0]['content']

    def test_unreachable_in_staging_keeps_change_but_marks_unverified(self, stack, monkeypatch):
        _health(monkeypatch, UNREACHABLE)
        result, _ = self._approve_and_run(stack, session_id='s-v-stg')
        ver = result['steps'][0]['verification']
        assert ver['status'] == 'unreachable' and ver['action'] == 'kept_unverified'
        assert stack.rollback.calls == []
        verdicts = [e['verdict'] for e in stack.audit.get_session('s-v-stg')]
        assert 'VERIFY_UNREACHABLE' in verdicts

    def test_unreachable_in_production_fails_closed(self, stack, monkeypatch):
        _health(monkeypatch, UNREACHABLE)
        result, _ = self._approve_and_run(stack, environment='production', session_id='s-v-prod')
        ver = result['steps'][0]['verification']
        assert ver['status'] == 'unreachable' and ver['action'] == 'rolled_back'
        assert len(stack.rollback.calls) == 1

    def test_unlisted_environment_fails_closed(self):
        from guardml.toolguard.policy import PolicyLoader
        assert PolicyLoader().on_verify_unreachable('qa') == 'rollback'

    def test_verify_url_env_override(self, stack, monkeypatch):
        seen = []
        _health(monkeypatch, HEALTHY, seen)
        monkeypatch.setenv('GUARDML_VERIFY_URL', 'http://model-api:8001/health')
        self._approve_and_run(stack)
        assert seen == ['http://model-api:8001/health']

    def test_demo_mode_says_unverified_instead_of_claiming_success(self, stack, monkeypatch):
        _health(monkeypatch, UNREACHABLE)
        stack.auto_resolve('approved')
        result = stack.make(demo_mode=True).run('roll back to version 1', session_id='s-v-demo')
        assert 'Not verified' in result['answer']


# ── honesty when the LLM is unavailable ──────────────────────────────────────
class TestLLMFailure:
    def test_no_canned_fallback_when_provider_fails(self, stack):
        result = stack.make(ScriptedProvider([])).run('why?', session_id='s-fail')
        assert result['complete'] is False
        assert result['tool_calls'] == 0
        assert 'did not respond' in result['answer']


# ── demo mode (no LLM) still goes through the real guard ─────────────────────
class TestDemoMode:
    def test_destructive_request_is_blocked(self, stack):
        result = stack.make(demo_mode=True).run('delete the fraud_classifier model', session_id='s-demo')
        assert 'BLOCKED' in result['answer']
        assert result['steps'][0]['outcome'] == 'blocked'

    def test_accuracy_drop_question_is_a_diagnosis_not_an_attack(self, stack):
        # The README's first scenario contains the word "drop"; it must not be read as a DROP TABLE.
        result = stack.make(demo_mode=True).run('Why did my model accuracy drop this week?', session_id='s-demo3')
        assert [s['tool'] for s in result['steps']][0] == 'mlflow_get_production_model'
        assert all(s['outcome'] == 'allowed' for s in result['steps'])

    def test_rollback_request_goes_through_approval(self, stack, monkeypatch):
        _health(monkeypatch, HEALTHY)
        stack.auto_resolve('approved')
        result = stack.make(demo_mode=True).run('please roll back to version 1', session_id='s-demo2')
        assert result['steps'][0]['verdict'] == 'NEEDS_APPROVAL'
        assert 'APPROVED & EXECUTED' in result['answer']


# ── provider layer ───────────────────────────────────────────────────────────
NEUTRAL = [
    {'role': 'user', 'content': 'hello'},
    {'role': 'assistant', 'text': 'checking', 'tool_calls': [ToolUse('t1', 'gpu_status', {})], 'raw': None},
    {'role': 'tool', 'results': [{'id': 't1', 'name': 'gpu_status', 'content': '{"ok": true}'}]},
]


class TestProviders:
    def test_anthropic_tool_result_has_only_valid_keys(self):
        native = AnthropicProvider.to_native(NEUTRAL)
        assert native[1]['content'][1] == {'type': 'tool_use', 'id': 't1', 'name': 'gpu_status', 'input': {}}
        result_block = native[2]['content'][0]
        assert set(result_block) == {'type', 'tool_use_id', 'content'}  # no stray keys

    def test_ollama_conversion(self):
        native = OllamaProvider.to_native('sys', NEUTRAL)
        assert native[0] == {'role': 'system', 'content': 'sys'}
        assert native[2]['tool_calls'] == [{'function': {'name': 'gpu_status', 'arguments': {}}}]
        assert native[3] == {'role': 'tool', 'tool_name': 'gpu_status', 'content': '{"ok": true}'}

    def test_ollama_response_parsing(self):
        data = {'message': {'content': 'looking', 'tool_calls': [
            {'function': {'name': 'docker_ps', 'arguments': {'all': True}}},
            {'function': {'name': 'gpu_status', 'arguments': '{"x": 1}'}},   # some models send a JSON string
        ]}}
        parsed = OllamaProvider.parse(data)
        assert parsed.text == 'looking'
        assert parsed.tool_calls[0].name == 'docker_ps' and parsed.tool_calls[0].input == {'all': True}
        assert parsed.tool_calls[1].input == {'x': 1}
        assert OllamaProvider.parse({}) is None

    def test_ollama_request_shape_and_no_tools_key_when_empty(self):
        sent = {}

        class Resp:
            status_code = 200
            text = ''

            def json(self):
                return {'message': {'content': 'hi'}}

        class Http:
            def post(self, url, json=None, timeout=None):
                sent.clear()
                sent.update(url=url, **json)
                return Resp()

        p = OllamaProvider(model='m', host='localhost:11434', session=Http())
        assert p.generate('sys', NEUTRAL[:1], []).text == 'hi'
        assert sent['url'] == 'http://localhost:11434/api/chat' and sent['model'] == 'm'
        assert sent['stream'] is False and 'tools' not in sent
        p.generate('sys', NEUTRAL[:1], [{'name': 't', 'description': 'd', 'input_schema': {'type': 'object'}}])
        assert sent['tools'][0]['function']['name'] == 't'

    def test_ollama_returns_none_after_repeated_failures(self, monkeypatch):
        from guardml.agent import llm
        monkeypatch.setattr(llm.time, 'sleep', lambda s: None)

        class Resp:
            status_code = 404
            text = 'model not found'

        class Http:
            def post(self, *a, **k):
                return Resp()

        assert OllamaProvider(model='m', session=Http()).generate('s', NEUTRAL[:1], []) is None

    def test_select_provider_respects_override_and_placeholders(self, monkeypatch):
        for k in ('ANTHROPIC_API_KEY', 'GUARDML_LLM_PROVIDER'):
            monkeypatch.delenv(k, raising=False)
        assert select_provider() is None
        monkeypatch.setenv('ANTHROPIC_API_KEY', 'your-key-here')
        assert select_provider() is None  # placeholder is not a key
        monkeypatch.setenv('GUARDML_LLM_PROVIDER', 'ollama')
        assert select_provider().name == 'ollama'
        monkeypatch.setenv('GUARDML_LLM_PROVIDER', 'demo')
        assert select_provider() is None


# ── LLM-facing schemas ───────────────────────────────────────────────────────
class TestLLMSchemas:
    def test_guard_hints_stripped_and_reason_added(self):
        schema = llm_schema({
            'name': 't', 'description': 'd',
            'input_schema': {'type': 'object', 'properties': {
                'p': {'type': 'string', 'x-guard': 'path'},
                'cols': {'type': 'array', 'items': {'type': 'string', 'x-guard': 'identifier'}},
            }},
        })
        dumped = json.dumps(schema)
        assert 'x-guard' not in dumped
        assert schema['input_schema']['properties']['reason']['type'] == 'string'

    def test_real_registry_schemas_are_clean(self):
        from guardml.tools.registry import get_registry
        schemas = get_tool_schemas(get_registry())
        assert len(schemas) == len(get_registry().all_schemas())
        assert 'x-guard' not in json.dumps(schemas)
        assert all('reason' in s['input_schema']['properties'] for s in schemas)
        # the registry's own schemas keep their hints (the guard needs them)
        assert 'x-guard' in json.dumps(get_registry().all_schemas())
