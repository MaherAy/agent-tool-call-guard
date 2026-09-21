"""FastAPI service implementing the SENTINEL v1 defense API (fails closed on any internal error)."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from guard.engine import GuardDefense
from guard.models import DefenseDecision, DefenseRequest
from guard.trace import Trace

log = logging.getLogger("guard")

defense = GuardDefense(trace=Trace.from_env())

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
