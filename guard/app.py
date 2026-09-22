"""FastAPI service implementing the SENTINEL v1 defense API (fails closed on any internal error)."""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI

from guard.engine import GuardDefense
from guard.judge.client import JudgeClient, JudgeConfig
from guard.models import DefenseDecision, DefenseRequest
from guard.trace import Trace

log = logging.getLogger("guard")


def _judge_from_env() -> JudgeClient | None:
    """Off by default: Stage 2 only calls Ollama when GUARD_JUDGE_ENABLED is truthy, so a plain `uvicorn
    guard.app:app` never makes a network call on its own and every ambiguous case uses guard.judge.fallback."""
    if os.environ.get("GUARD_JUDGE_ENABLED", "").strip().lower() not in {"1", "true", "yes"}:
        return None
    return JudgeClient(JudgeConfig.from_env())


defense = GuardDefense(trace=Trace.from_env(), judge=_judge_from_env())

app = FastAPI(title="agent-tool-call-guard", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    try:
        return defense.decide(request)
    except Exception:  # noqa: BLE001 - the monitor must never fail open
        log.exception("decision failed; blocking")
        return DefenseDecision(decision="block", risk_score=0.99, confidence=0.5,
                               reason_codes=["GUARD_ERROR"], explanation="Internal error; failing closed.")
