"""
AgentDojo glue: a tool executor that asks the guard before each tool call, and a pipeline builder for a local
model served by Ollama's OpenAI-compatible endpoint. Needs `pip install agentdojo` (see README.md).
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Dict, List, Optional

import openai
from agentdojo.agent_pipeline import (
    AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, get_text_content_as_str, text_content_block_from_string

from guardml.agent.llm import OllamaProvider, make_completer
from guardml.toolguard.intent import IntentJudge

from .guard import CONFIGS, Decision, ToolCallGuard


class GuardedToolsExecutor(ToolsExecutor):
    """ToolsExecutor that runs a call only if the guard allows it. A blocked call is not executed; the model
    gets a tool error saying so (and no state changes, which is what AgentDojo's security check looks at)."""

    def __init__(self, guard: ToolCallGuard, tool_output_formatter=tool_result_to_str) -> None:
        super().__init__(tool_output_formatter)
        self.guard = guard
        self.decisions: List[Dict[str, Any]] = []   # every guarded call: for reports and debugging

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]['role'] != 'assistant' or not messages[-1]['tool_calls']:
            return query, runtime, env, messages, extra_args

        outputs = [(m['tool_call'].function, get_text_content_as_str(m['content']))
                   for m in messages if m['role'] == 'tool']
        known = {t.name for t in runtime.functions.values()}
        results: List[ChatToolResultMessage] = []
        for call in messages[-1]['tool_calls']:
            if call.function not in known:
                results.append(ChatToolResultMessage(
                    role='tool', content=[text_content_block_from_string('')], tool_call_id=call.id,
                    tool_call=call, error=f'Invalid tool {call.function} provided.'))
                continue

            decision: Decision = self.guard.check(query, outputs, call.function, dict(call.args))
            self.decisions.append({'query': query[:200], 'tool': call.function, 'args': dict(call.args),
                                   'allowed': decision.allowed, 'rule': decision.rule, 'reason': decision.reason})
            if not decision.allowed:
                msg = f'BLOCKED by ToolGuard ({decision.rule}): {decision.reason}'
                results.append(ChatToolResultMessage(
                    role='tool', content=[text_content_block_from_string(msg)], tool_call_id=call.id,
                    tool_call=call, error=msg))
                continue

            # same argument clean-up and execution as the stock ToolsExecutor
            from agentdojo.agent_pipeline.tool_execution import is_string_list
            from ast import literal_eval
            for k, v in call.args.items():
                if isinstance(v, str) and is_string_list(v):
                    call.args[k] = literal_eval(v)
            result, error = runtime.run_function(env, call.function, call.args)
            text = self.output_formatter(result)
            outputs.append((call.function, text))
            results.append(ChatToolResultMessage(
                role='tool', content=[text_content_block_from_string(text)], tool_call_id=call.id,
                tool_call=call, error=error))
        return query, runtime, env, [*messages, *results], extra_args


def build_pipeline(model: str, defence: str = 'none', base_url: str = 'http://localhost:11434/v1',
                   ollama_host: str = 'localhost:11434', judge_model: Optional[str] = None) -> AgentPipeline:
    """Agent = `model` on Ollama (native tool calling). `defence` is a key of guard.CONFIGS."""
    if defence not in CONFIGS:
        raise ValueError(f'defence must be one of {list(CONFIGS)}')
    llm = OpenAILLM(openai.OpenAI(api_key='EMPTY', base_url=base_url, timeout=600), model)

    if CONFIGS[defence] is None:
        executor: ToolsExecutor = ToolsExecutor()
    else:
        cfg = CONFIGS[defence]
        judge = None
        if cfg['intent']:
            judge = IntentJudge(make_completer(OllamaProvider(model=judge_model or model, host=ollama_host)))
        executor = GuardedToolsExecutor(ToolCallGuard(judge=judge, **cfg))

    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop([executor, llm]),
    ])
    # AgentDojo's attacks look a model name up in this string; "local" is its generic name for local models.
    pipeline.name = f'local-{model.replace(":", "_")}-{defence}'
    pipeline.executor = executor   # so callers can read executor.decisions
    return pipeline
