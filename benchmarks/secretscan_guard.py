"""Benchmark adapter: a generic secret scanner (Yelp detect-secrets) used as the data-leak layer.

Scans every outbound string of a candidate action (arguments and content) token by token with detect-secrets'
plugins and redacts what it finds. It is a *layer under test*: it has no notion of provenance, sensitivity or
destination, which is exactly what makes it a fair contrast with a provenance-driven leak check.
"""

from __future__ import annotations

import re
import threading

from detect_secrets.core.scan import scan_line
from detect_secrets.settings import default_settings
from fastapi import FastAPI

from guard.models import CandidateAction, DefenseDecision, DefenseRequest

REDACTION = "[redacted]"
_lock = threading.Lock()


def secret_tokens(text: str) -> set[str]:
    found: set[str] = set()
    with default_settings():
        for raw in re.findall(r"\S+", text):
            token = raw.strip(".,:;!?()[]{}<>\"'")
            if len(token) < 8:
                continue
            # Quoted, so the entropy and service-specific detectors apply. A line such as `secret = <word>` would make
            # the keyword detector fire on any word, which would be unfair to the tool.
            if any(True for _ in scan_line(f'"{token}"')):
                found.add(token)
    return found


def scrub(text: str, tokens: set[str]) -> str:
    for token in sorted(tokens, key=len, reverse=True):
        text = text.replace(token, REDACTION)
    return text


def decide(request: DefenseRequest) -> DefenseDecision:
    action = request.candidate_action
    if action.type == "request_confirmation":
        return DefenseDecision(decision="allow", risk_score=0.05, confidence=0.5, reason_codes=["NO_SECRET_FOUND"])
    found: set[str] = set()
    if action.content:
        found |= secret_tokens(action.content)
    for value in action.arguments.values():
        if isinstance(value, str):
            found |= secret_tokens(value)
    if not found:
        return DefenseDecision(decision="allow", risk_score=0.05, confidence=0.5, reason_codes=["NO_SECRET_FOUND"])
    arguments = {k: (scrub(v, found) if isinstance(v, str) else v) for k, v in action.arguments.items()}
    rewritten = CandidateAction(type=action.type, tool=action.tool, arguments=arguments,
                                content=scrub(action.content, found) if action.content else action.content,
                                final=action.final)
    return DefenseDecision(decision="rewrite", risk_score=0.8, confidence=0.6, reason_codes=["SECRET_SCANNER_HIT"],
                           explanation="A generic secret scanner matched a token in the outbound text; it was removed.",
                           rewritten_action=rewritten)


app = FastAPI(title="secretscan-guard", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    with _lock:
        return decide(request)
