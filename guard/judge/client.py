"""Ollama chat client for the judge stage: one bounded call, strict JSON schema, never retried.

The judge stage runs only when Stage 1 could not decide (guard.engine._consult_judge). It is deliberately
not retried here: the kit's own HTTP client retries a *transport* failure against our `/v1/decision` endpoint
up to twice by default, so a judge that retried internally could turn one ambiguous action into several LLM
calls. `ask()` either returns one verdict within `timeout_s` or raises; the caller falls back to a
deterministic default (guard.judge.fallback) instead of calling again.

Requires a running Ollama server (``ollama serve``) with a chat model pulled, and a build recent enough to
support structured outputs (`format` as a JSON schema, not just `"json"`) and, for Qwen3, the `think` field --
both shipped well before this challenge's deadline. If your server predates them, `format` still constrains
to valid JSON and `think` is ignored, which only costs latency and occasional malformed-response fallbacks.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from guard.judge.schema import JudgeVerdict

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:1.7b"
DEFAULT_TIMEOUT_S = 1.5
DEFAULT_NUM_PREDICT = 200


class JudgeUnavailable(RuntimeError):
    """Transport failure, timeout, non-200 status, or a response that does not match JudgeVerdict."""


@dataclass(frozen=True)
class JudgeConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout_s: float = DEFAULT_TIMEOUT_S
    temperature: float = 0.0
    seed: int = 0
    num_predict: int = DEFAULT_NUM_PREDICT

    @classmethod
    def from_env(cls) -> JudgeConfig:
        return cls(
            base_url=os.environ.get("GUARD_JUDGE_URL", DEFAULT_BASE_URL).rstrip("/"),
            model=os.environ.get("GUARD_JUDGE_MODEL", DEFAULT_MODEL),
            timeout_s=float(os.environ.get("GUARD_JUDGE_TIMEOUT_S", DEFAULT_TIMEOUT_S)),
            num_predict=int(os.environ.get("GUARD_JUDGE_NUM_PREDICT", DEFAULT_NUM_PREDICT)),
        )


class Judge(Protocol):
    """What GuardDefense needs from a judge: a model name (for cache keys) and one bounded call.

    JudgeClient below is the real implementation; tests substitute anything with this shape, no network
    involved -- see tests/test_judge.py.
    """

    config: JudgeConfig

    def ask(self, messages: list[dict[str, str]]) -> tuple[JudgeVerdict, float]: ...


class JudgeClient:
    """Talks to one Ollama server's `/api/chat`. `httpx.Client` is safe under concurrent calls, and the
    engine calls `ask()` outside any lock (see engine.GuardDefense.decide), so multiple runs may be in
    flight here at once."""

    def __init__(self, config: JudgeConfig | None = None) -> None:
        self.config = config or JudgeConfig.from_env()
        self._client = httpx.Client(base_url=self.config.base_url, timeout=self.config.timeout_s)
        self._schema = JudgeVerdict.model_json_schema()

    def ask(self, messages: list[dict[str, str]]) -> tuple[JudgeVerdict, float]:
        started = time.perf_counter()
        try:
            response = self._client.post(
                "/api/chat",
                json={
                    "model": self.config.model,
                    "messages": messages,
                    "stream": False,
                    "format": self._schema,
                    "think": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "seed": self.config.seed,
                        "num_predict": self.config.num_predict,
                    },
                },
            )
        except httpx.TransportError as exc:
            raise JudgeUnavailable(f"transport: {type(exc).__name__}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        if response.status_code != 200:
            raise JudgeUnavailable(f"http {response.status_code}: {response.text[:200]}")
        try:
            content = response.json()["message"]["content"]
            verdict = JudgeVerdict.model_validate(json.loads(content))
        except (KeyError, ValueError) as exc:
            raise JudgeUnavailable(f"malformed response: {exc}") from exc
        return verdict, elapsed_ms

    def health(self) -> bool:
        try:
            return self._client.get("/api/tags").status_code == 200
        except httpx.TransportError:
            return False

    def close(self) -> None:
        self._client.close()
