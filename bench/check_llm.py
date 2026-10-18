"""
One-call sanity check of your LLM setup (costs a single tiny request).

    python -m guardml.bench.check_llm

Loads .env, picks the provider the app would pick, sends "ping", and says whether it answered.
Nothing else is run and no key is printed.
"""
from __future__ import annotations

import sys
import time

from dotenv import load_dotenv

load_dotenv()

from guardml.agent.llm import select_provider  # noqa: E402  (after load_dotenv so .env is honoured)


def main() -> int:
    provider = select_provider()
    if provider is None:
        print('No LLM provider selected: set GEMINI_API_KEY or ANTHROPIC_API_KEY in .env, '
              'and make sure GUARDML_LLM_PROVIDER is not set to "demo".')
        return 2
    print(f'Provider: {provider.name}   model: {provider.model}')
    start = time.perf_counter()
    reply = provider.generate('Answer with the single word OK.', [{'role': 'user', 'content': 'ping'}], [])
    ms = (time.perf_counter() - start) * 1000
    if reply is None:
        print(f'NO RESPONSE after {ms:.0f} ms. Check the key, the quota / rate limit, and the model name in .env.')
        return 1
    print(f'Reply in {ms:.0f} ms: {reply.text!r}')
    print('LLM setup works.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
