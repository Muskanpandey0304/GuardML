"""
LLM provider layer.

The agent loop talks to a small, provider-neutral interface:

    provider.generate(system, messages, tools) -> LLMResponse | None

Conversation history is kept in a neutral format and converted per provider:

    {'role': 'user',      'content': str}
    {'role': 'assistant', 'text': str, 'tool_calls': [ToolUse], 'raw': <provider blob>}
    {'role': 'tool',      'results': [{'id': str, 'name': str, 'content': str}]}

`raw` lets a provider hand its own response back verbatim next turn (needed for
Gemini thought signatures); other providers ignore it.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

logger = logging.getLogger(__name__)

DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-5-5'
GEMINI_FALLBACK_MODELS = ['gemini-flash-lite-latest', 'gemini-3.5-flash', 'gemini-flash-latest']
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.5


# ---------------------------------------------------------------------------
# Neutral types
# ---------------------------------------------------------------------------
@dataclass
class ToolUse:
    id: str
    name: str
    input: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str = ''
    tool_calls: List[ToolUse] = field(default_factory=list)
    raw: Any = None  # provider-specific blob, echoed back in the next request


class LLMProvider:
    name = 'base'
    model = ''

    def generate(
        self, system: str, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Optional[LLMResponse]:
        raise NotImplementedError


def _real_key(value: Optional[str]) -> str:
    value = (value or '').strip()
    return '' if not value or value.startswith('your-') else value


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
class AnthropicProvider(LLMProvider):
    name = 'anthropic'

    def __init__(self, api_key: str, model: Optional[str] = None, client: Any = None):
        self.model = model or os.getenv('ANTHROPIC_MODEL') or DEFAULT_ANTHROPIC_MODEL
        if client is None:
            import anthropic  # lazy: the package is only needed when this provider is used
            client = anthropic.Anthropic(api_key=api_key)
        self.client = client

    @staticmethod
    def to_native(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in messages:
            role = m['role']
            if role == 'user':
                out.append({'role': 'user', 'content': m['content']})
            elif role == 'assistant':
                if m.get('raw') is not None:
                    content = m['raw']
                else:
                    content = []
                    if m.get('text'):
                        content.append({'type': 'text', 'text': m['text']})
                    for tc in m.get('tool_calls', []):
                        content.append({'type': 'tool_use', 'id': tc.id, 'name': tc.name, 'input': tc.input})
                out.append({'role': 'assistant', 'content': content})
            elif role == 'tool':
                out.append({
                    'role': 'user',
                    'content': [
                        {'type': 'tool_result', 'tool_use_id': r['id'], 'content': r['content']}
                        for r in m['results']
                    ],
                })
        return out

    @staticmethod
    def parse(resp: Any) -> LLMResponse:
        text_parts: List[str] = []
        calls: List[ToolUse] = []
        for block in resp.content:
            btype = getattr(block, 'type', None)
            if btype == 'text':
                text_parts.append(block.text)
            elif btype == 'tool_use':
                calls.append(ToolUse(id=block.id, name=block.name, input=dict(block.input or {})))
        return LLMResponse(text='\n'.join(text_parts).strip(), tool_calls=calls, raw=list(resp.content))

    def generate(self, system, messages, tools):
        for attempt in range(MAX_RETRIES):
            try:
                kwargs = dict(
                    model=self.model,
                    max_tokens=4096,
                    system=system,
                    messages=self.to_native(messages),
                )
                if tools:  # an empty tools list is rejected by the API
                    kwargs['tools'] = tools
                return self.parse(self.client.messages.create(**kwargs))
            except Exception as e:
                wait = RETRY_BACKOFF_BASE ** attempt
                logger.warning('Anthropic call failed (attempt %d): %s. Retrying in %.1fs', attempt + 1, e, wait)
                time.sleep(wait)
        return None


# ---------------------------------------------------------------------------
# Gemini (REST)
# ---------------------------------------------------------------------------
_GEMINI_SCHEMA_KEYS = {'type', 'description', 'properties', 'items', 'required', 'enum'}


def gemini_schema(node: Any) -> Any:
    """Reduce a JSON-schema fragment to the OpenAPI subset Gemini accepts."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == 'properties':
                out[k] = {pk: gemini_schema(pv) for pk, pv in v.items()}
            elif k in _GEMINI_SCHEMA_KEYS:
                out[k] = gemini_schema(v)
        if isinstance(out.get('type'), str):
            out['type'] = out['type'].upper()
        return out
    if isinstance(node, list):
        return [gemini_schema(v) for v in node]
    return node


class GeminiProvider(LLMProvider):
    name = 'gemini'

    def __init__(self, api_key: str, model: Optional[str] = None, session: Any = None):
        self.api_key = api_key
        self.model = model or os.getenv('GEMINI_MODEL') or GEMINI_FALLBACK_MODELS[0]
        if session is None:
            import requests
            session = requests
        self.http = session
        self.last_model: Optional[str] = None  # the model that actually answered the last call

    @staticmethod
    def to_native(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        contents: List[Dict[str, Any]] = []
        for m in messages:
            role = m['role']
            if role == 'user':
                contents.append({'role': 'user', 'parts': [{'text': m['content']}]})
            elif role == 'assistant':
                parts = m.get('raw')
                if not parts:
                    parts = []
                    if m.get('text'):
                        parts.append({'text': m['text']})
                    for tc in m.get('tool_calls', []):
                        parts.append({'functionCall': {'name': tc.name, 'args': tc.input}})
                contents.append({'role': 'model', 'parts': parts})
            elif role == 'tool':
                contents.append({
                    'role': 'user',
                    'parts': [
                        {'functionResponse': {'name': r['name'], 'response': {'result': r['content']}}}
                        for r in m['results']
                    ],
                })
        return contents

    @staticmethod
    def parse(data: Dict[str, Any]) -> Optional[LLMResponse]:
        candidates = data.get('candidates') or []
        if not candidates:
            return None
        parts = (candidates[0].get('content') or {}).get('parts') or []
        texts: List[str] = []
        calls: List[ToolUse] = []
        for part in parts:
            if 'text' in part:
                texts.append(part['text'])
            elif 'functionCall' in part:
                fc = part['functionCall']
                calls.append(ToolUse(
                    id=part.get('id') or str(uuid.uuid4()),
                    name=fc['name'],
                    input=dict(fc.get('args') or {}),
                ))
        return LLMResponse(text='\n'.join(texts).strip(), tool_calls=calls, raw=parts)

    def _candidate_models(self) -> List[str]:
        models = [self.model]
        # GUARDML_GEMINI_NO_FALLBACK=1: never silently switch models (clean attribution for benchmarks).
        if os.getenv('GUARDML_GEMINI_NO_FALLBACK', '').strip().lower() in ('1', 'true', 'yes'):
            return models
        models += [m for m in GEMINI_FALLBACK_MODELS if m not in models]
        return models

    def generate(self, system, messages, tools):
        payload = {
            'systemInstruction': {'parts': [{'text': system}]},
            'contents': self.to_native(messages),
        }
        if tools:
            payload['tools'] = [{
                'functionDeclarations': [
                    {
                        'name': t['name'],
                        'description': t.get('description', ''),
                        'parameters': gemini_schema(t.get('input_schema', {'type': 'object'})),
                    }
                    for t in tools
                ]
            }]
        # Key goes in a header, never in the URL: exception messages and logs include URLs.
        headers = {'x-goog-api-key': self.api_key, 'Content-Type': 'application/json'}
        candidates = self._candidate_models()
        single = len(candidates) == 1
        for model_name in candidates:
            url = f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent'
            for _attempt in range(5 if single else 2):  # single model: back off and retry on rate limits
                try:
                    resp = self.http.post(url, json=payload, headers=headers, timeout=25)
                    if resp.status_code == 200:
                        parsed = self.parse(resp.json())
                        if parsed is None:
                            break
                        self.last_model = model_name
                        return parsed
                    if resp.status_code in (429, 503):
                        logger.warning('Gemini %s returned %d (rate limit / capacity); %s.', model_name,
                                       resp.status_code, 'backing off' if single else 'trying next model')
                        if single:
                            time.sleep(min(2 ** (_attempt + 1), 20))
                            continue
                        break
                    logger.warning('Gemini API error %d on %s: %s', resp.status_code, model_name, resp.text[:200])
                except Exception as e:
                    logger.warning('Gemini call exception on %s: %s', model_name, type(e).__name__)
                time.sleep(1)
        return None


# ---------------------------------------------------------------------------
# Ollama (local models, REST)
# ---------------------------------------------------------------------------
DEFAULT_OLLAMA_MODEL = 'qwen2.5:7b'
DEFAULT_OLLAMA_HOST = 'http://localhost:11434'


class OllamaProvider(LLMProvider):
    """Local model served by Ollama (/api/chat). No API key; the model must already be pulled."""
    name = 'ollama'

    def __init__(self, model: Optional[str] = None, host: Optional[str] = None, session: Any = None):
        self.model = model or os.getenv('OLLAMA_MODEL') or DEFAULT_OLLAMA_MODEL
        self.host = (host or os.getenv('OLLAMA_HOST') or DEFAULT_OLLAMA_HOST).rstrip('/')
        if not self.host.startswith('http'):
            self.host = 'http://' + self.host
        if session is None:
            import requests
            session = requests
        self.http = session
        self.num_ctx = int(os.getenv('OLLAMA_NUM_CTX', '8192'))
        self.timeout = float(os.getenv('OLLAMA_TIMEOUT', '600'))  # CPU/partial-GPU inference is slow

    @staticmethod
    def to_native(system: str, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = [{'role': 'system', 'content': system}]
        for m in messages:
            role = m['role']
            if role == 'user':
                out.append({'role': 'user', 'content': m['content']})
            elif role == 'assistant':
                msg: Dict[str, Any] = {'role': 'assistant', 'content': m.get('text') or ''}
                if m.get('tool_calls'):
                    msg['tool_calls'] = [
                        {'function': {'name': tc.name, 'arguments': tc.input}} for tc in m['tool_calls']
                    ]
                out.append(msg)
            elif role == 'tool':
                for r in m['results']:
                    out.append({'role': 'tool', 'tool_name': r['name'], 'content': r['content']})
        return out

    @staticmethod
    def parse(data: Dict[str, Any]) -> Optional[LLMResponse]:
        msg = data.get('message')
        if not msg:
            return None
        calls: List[ToolUse] = []
        for tc in msg.get('tool_calls') or []:
            fn = tc.get('function') or {}
            args = fn.get('arguments') or {}
            if isinstance(args, str):  # some models return the arguments as a JSON string
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            calls.append(ToolUse(id=str(uuid.uuid4()), name=fn.get('name', ''), input=dict(args)))
        return LLMResponse(text=(msg.get('content') or '').strip(), tool_calls=calls, raw=msg)

    def generate(self, system, messages, tools):
        payload: Dict[str, Any] = {
            'model': self.model,
            'messages': self.to_native(system, messages),
            'stream': False,
            'options': {'temperature': 0, 'num_ctx': self.num_ctx},
        }
        if tools:
            payload['tools'] = [
                {'type': 'function', 'function': {
                    'name': t['name'],
                    'description': t.get('description', ''),
                    'parameters': t.get('input_schema', {'type': 'object', 'properties': {}}),
                }}
                for t in tools
            ]
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.http.post(f'{self.host}/api/chat', json=payload, timeout=self.timeout)
                if resp.status_code == 200:
                    parsed = self.parse(resp.json())
                    if parsed is not None:
                        return parsed
                else:
                    logger.warning('Ollama API error %d on %s: %s', resp.status_code, self.model, resp.text[:200])
            except Exception as e:
                logger.warning('Ollama call exception on %s: %s', self.model, type(e).__name__)
            time.sleep(RETRY_BACKOFF_BASE ** attempt)
        return None


# ---------------------------------------------------------------------------
# Scripted provider: deterministic "LLM" for tests, offline benchmark and CI
# ---------------------------------------------------------------------------
class ScriptedProvider(LLMProvider):
    """Replays a fixed list of responses (or calls a function) instead of a real model."""
    name = 'scripted'
    model = 'scripted'

    def __init__(self, script: Union[Sequence[LLMResponse], Callable[[List[Dict[str, Any]]], Optional[LLMResponse]]]):
        self._script = script
        self._i = 0
        self.calls: List[List[Dict[str, Any]]] = []

    def generate(self, system, messages, tools):
        self.calls.append(list(messages))
        if callable(self._script):
            return self._script(messages)
        if self._i >= len(self._script):
            return None
        resp = self._script[self._i]
        self._i += 1
        return resp


# ---------------------------------------------------------------------------
# Judge completer: one-shot, tool-less call used by the intent check
# ---------------------------------------------------------------------------
def make_completer(provider: LLMProvider, model: Optional[str] = None) -> Callable[[str, str], Optional[str]]:
    """
    complete(system, prompt) -> text, for toolguard.intent.IntentJudge.
    Uses a copy of the provider (shared client/session) so an optional cheaper
    judge model never changes the main agent's model.
    """
    judge = copy.copy(provider)
    if model:
        judge.model = model

    def complete(system: str, prompt: str) -> Optional[str]:
        resp = judge.generate(system, [{'role': 'user', 'content': prompt}], [])
        return resp.text if resp else None

    return complete


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
def select_provider() -> Optional[LLMProvider]:
    """
    Pick a provider from the environment. Returns None => deterministic demo mode.

    GUARDML_LLM_PROVIDER = anthropic | gemini | ollama | demo   (optional override)
    Otherwise: Gemini if GEMINI_API_KEY/GOOGLE_API_KEY is set, else Anthropic if
    ANTHROPIC_API_KEY is set, else demo mode. Ollama is only used when asked for explicitly
    (model via OLLAMA_MODEL, default qwen2.5:7b).
    """
    choice = os.getenv('GUARDML_LLM_PROVIDER', '').strip().lower()
    gemini_key = _real_key(os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY'))
    anthropic_key = _real_key(os.getenv('ANTHROPIC_API_KEY'))

    if choice == 'demo':
        return None
    if choice == 'ollama':
        return OllamaProvider()
    if choice == 'anthropic':
        return AnthropicProvider(anthropic_key) if anthropic_key else None
    if choice == 'gemini':
        return GeminiProvider(gemini_key) if gemini_key else None
    if gemini_key:
        return GeminiProvider(gemini_key)
    if anthropic_key:
        return AnthropicProvider(anthropic_key)
    return None
