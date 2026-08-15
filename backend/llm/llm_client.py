"""LLM client with multi-key rotation/failover.

Provider-agnostic entry point: reads keys from config and calls the LLM
provider SDK. Any provider failure degrades gracefully via fallback.
"""

import os
import time
import itertools
import threading

from groq import Groq
from groq import RateLimitError, APIStatusError

import config


class LLMKeyPool:
    def __init__(self, keys: list[str]):
        if not keys:
            raise ValueError("No LLM API keys configured")
        self._clients = [Groq(api_key=k) for k in keys]
        self._cycle = itertools.cycle(range(len(self._clients)))
        self._current = next(self._cycle)
        self._lock = threading.Lock()

    def _next_client(self):
        with self._lock:
            self._current = next(self._cycle)
            return self._clients[self._current]

    def chat_completion(self, max_attempts: int = None, **kwargs) -> dict:
        max_attempts = max_attempts or len(self._clients) * 2
        last_err = None
        for attempt in range(max_attempts):
            client = self._next_client()
            try:
                return client.chat.completions.create(**kwargs)
            except RateLimitError as e:
                last_err = e
                time.sleep(min(2 ** (attempt % 4), 10))  # light backoff
                continue
            except APIStatusError as e:
                # non-rate-limit API error (bad request, server error, etc.)
                raise
        raise RuntimeError(
            f"All LLM keys exhausted after {max_attempts} attempts"
        ) from last_err


def get_pool() -> LLMKeyPool | None:
    if not config.LLM_API_KEYS:
        return None
    return LLMKeyPool(config.LLM_API_KEYS)


_pool = get_pool()


def triage_findings(findings_json: str, recon_context: str, memory_context: str = "") -> dict:
    """One triage call. Returns parsed JSON dict. Raises if the pool fails."""
    if _pool is None:
        raise RuntimeError("LLM_API_KEYS not configured")
    from llm.prompts import TRIAGE_SYSTEM_PROMPT

    completion = _pool.chat_completion(
        model=config.LLM_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": TRIAGE_SYSTEM_PROMPT + ("\n\n" + memory_context if memory_context else ""),
            },
            {"role": "user", "content": f"RECON:\n{recon_context}\n\nFINDINGS:\n{findings_json}"},
        ],
        temperature=0.2,
    )
    content = completion.choices[0].message.content
    import json

    return json.loads(content)


def available_models() -> list[str]:
    if _pool is None:
        return []
    return [m.id for m in _pool._clients[0].models.list().data]
