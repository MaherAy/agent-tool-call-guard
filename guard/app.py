"""FastAPI service implementing the SENTINEL v1 defense API (fails closed on any internal error)."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from guard import telemetry
from guard.engine import GuardDefense
from guard.models import DefenseDecision, DefenseRequest
from guard.trace import Trace

log = logging.getLogger("guard")

# A local, git-ignored .env may hold LANGFUSE_* settings; variables already in the environment win.
telemetry.load_env_file(Path(os.environ.get("GUARD_ENV_FILE", ".env")))
defense = GuardDefense(trace=Trace.from_env(), telemetry=telemetry.from_env())


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    defense.telemetry.close()  # flush buffered Langfuse spans; never on the request path


app = FastAPI(title="agent-tool-call-guard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


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
