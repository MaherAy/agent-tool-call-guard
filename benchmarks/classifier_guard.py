"""Benchmark adapter: an open-source prompt-injection classifier used as a defense layer.

This is how a detector such as LLM Guard's PromptInjection scanner or Meta's Prompt Guard is normally deployed:
score the untrusted text the agent has read and, once something is flagged, stop the agent's side effects. It is a
*layer under test*, not part of agent-tool-call-guard.

    CG_MODEL       Hugging Face model id (default: protectai/deberta-v3-base-prompt-injection-v2, Apache-2.0)
    CG_THRESHOLD   injection score at or above which content is flagged (default 0.5)
    CG_LOG_DIR     if set, every scored untrusted item is appended to <dir>/items.jsonl for content-level analysis

Policy ("quarantine"): after any untrusted item in the run is flagged, block non-read tool calls and memory writes.
Reads and plain responses stay allowed. There is no confirmation logic: a detector alone does not know which
actions are consequential.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from fastapi import FastAPI

from guard.contract import is_read_tool
from guard.models import DefenseDecision, DefenseRequest
from guard.trust import ProvenanceIndex

MODEL = os.environ.get("CG_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
THRESHOLD = float(os.environ.get("CG_THRESHOLD", "0.5"))
LOG_DIR = os.environ.get("CG_LOG_DIR")

_pipe = None
_lock = threading.Lock()
_runs: dict[str, dict] = {}


def injection_score(text: str) -> float:
    global _pipe
    if _pipe is None:
        from transformers import pipeline

        _pipe = pipeline("text-classification", model=MODEL, truncation=True, max_length=512, device=-1)
    result = _pipe(text[:4000])[0]
    injected = result["label"].upper() in {"INJECTION", "LABEL_1", "UNSAFE"}
    return float(result["score"]) if injected else 1.0 - float(result["score"])


def _log(entry: dict) -> None:
    if not LOG_DIR:
        return
    path = Path(LOG_DIR)
    path.mkdir(parents=True, exist_ok=True)
    with (path / "items.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


def _state(request: DefenseRequest) -> dict:
    run = _runs.get(request.run_id)
    if run is None or request.step_id <= 1 or request.step_id < run["last"]:
        run = {"seen": set(), "flagged": False, "last": 0}
        _runs[request.run_id] = run
    run["last"] = request.step_id
    return run


def decide(request: DefenseRequest) -> DefenseDecision:
    state = _state(request)
    index = ProvenanceIndex(request)
    for item in request.conversation:
        if not item.provenance_ids or index.fully_trusted(item):
            continue  # only untrusted or mixed content is scored
        key = hashlib.sha256(item.content.encode()).hexdigest()[:16]
        if key in state["seen"]:
            continue
        state["seen"].add(key)
        score = injection_score(item.content)
        _log({"run_id": request.run_id, "step": request.step_id, "sha": key, "score": round(score, 4),
              "trust": index.item_trust(item), "text": item.content})
        if score >= THRESHOLD:
            state["flagged"] = True

    action = request.candidate_action
    if action.type == "request_confirmation" and action.confirmation_for is not None:
        action = action.confirmation_for
    side_effect = action.type == "memory_write" or (
        action.type == "tool_call" and not is_read_tool(action.tool, set(request.policy_context.get("consequential_tools") or [])))
    if state["flagged"] and side_effect:
        return DefenseDecision(decision="block", risk_score=0.9, confidence=0.7, reason_codes=["INJECTION_DETECTED"],
                               explanation="Untrusted content was classified as a prompt injection; side effects are held.")
    return DefenseDecision(decision="allow", risk_score=0.3 if state["flagged"] else 0.05, confidence=0.6,
                           reason_codes=["NO_DETECTION"] if not state["flagged"] else ["INJECTION_SEEN_READ_ONLY"])


if os.environ.get("CG_EAGER", "1") == "1":
    injection_score("warm up")  # load the model before serving, so the first decision is not a timeout

app = FastAPI(title="classifier-guard", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    with _lock:
        return decide(request)
