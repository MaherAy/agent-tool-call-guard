"""Langfuse export: optional, safe, and shaped as documented. No network is used."""

from __future__ import annotations

import json
from contextlib import contextmanager

import pytest

from guard.engine import Config, GuardDefense
from guard.telemetry import LangfuseTelemetry, Telemetry, from_env, load_env_file
from tests.conftest import request, tool
from tests.test_engine import SECRET, _with_secret

SAMPLE = {
    "run_id": "run-x", "step": 3, "turn": 0, "rule": "R6", "decision": "block", "risk": 0.9, "confidence": 0.8,
    "codes": ["TAINTED_ARGUMENT"], "explanation": "Argument(s) ticket_id are not supported by any trusted source.",
    "evidence": {"arguments": ["ticket_id"]}, "latency_ms": 1.2,
    "action": {"type": "tool_call", "tool": "ticket_update", "args": {"ticket_id": "TCK-9"}, "content_chars": 0},
}


class FakeSpan:
    def __init__(self, kwargs):
        self.kwargs, self.scores, self.ended = kwargs, [], False

    def score_trace(self, **kwargs):
        self.scores.append(kwargs)

    def end(self):
        self.ended = True


class FakeClient:
    def __init__(self, fail=False):
        self.fail, self.spans, self.seeds, self.shutdown_called = fail, [], [], False

    def create_trace_id(self, seed):
        self.seeds.append(seed)
        return "trace-" + seed

    def start_observation(self, **kwargs):
        if self.fail:
            raise RuntimeError("langfuse is down")
        self.spans.append(FakeSpan(kwargs))
        return self.spans[-1]

    def shutdown(self):
        self.shutdown_called = True


class FakePropagate:
    def __init__(self):
        self.calls = []

    @contextmanager
    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        yield


def telemetry(client=None):
    propagate = FakePropagate()
    return LangfuseTelemetry(client or FakeClient(), propagate), propagate


def test_off_by_default(monkeypatch):
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_TRACING_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    t = from_env()
    assert type(t) is Telemetry and not t.enabled
    t.emit(SAMPLE)
    t.close()  # no-ops


def test_can_be_switched_off_even_with_keys(monkeypatch):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setenv("LANGFUSE_TRACING_ENABLED", "false")
    assert not from_env().enabled


def test_one_guardrail_trace_per_decision_with_deterministic_id_and_scores():
    t, propagate = telemetry()
    t.emit(SAMPLE)
    client = t._client
    assert client.seeds == ["guard:run-x:3"]
    span = client.spans[0]
    assert span.kwargs["as_type"] == "guardrail" and span.kwargs["level"] == "WARNING"
    assert span.kwargs["trace_context"] == {"trace_id": "trace-guard:run-x:3"}
    assert span.kwargs["output"]["reason_codes"] == ["TAINTED_ARGUMENT"]
    assert {(s["name"], s["data_type"]) for s in span.scores} == {
        ("risk_score", "NUMERIC"), ("confidence", "NUMERIC"), ("decision", "CATEGORICAL")}
    assert span.ended
    attrs = propagate.calls[0]
    assert attrs["session_id"] == "run-x" and "decision:block" in attrs["tags"] and "rule:R6" in attrs["tags"]


def test_allow_decisions_are_not_warnings():
    t, _ = telemetry()
    t.emit({**SAMPLE, "decision": "allow", "codes": ["USER_GOAL_ALIGNED"], "rule": "R0"})
    assert t._client.spans[0].kwargs["level"] == "DEFAULT"


def test_a_failing_langfuse_never_affects_the_decision():
    t, _ = telemetry(FakeClient(fail=True))
    t.emit(SAMPLE)  # must not raise
    g = GuardDefense(config=Config(), telemetry=t)
    assert g.decide(request("Read the note", tool("unlisted_tool"))).decision == "block"


def test_close_flushes():
    t, _ = telemetry()
    t.close()
    assert t._client.shutdown_called


def test_secret_values_never_leave_the_process():
    t, _ = telemetry()
    g = GuardDefense(config=Config(), telemetry=t)
    goal = "Draft a reply to the vendor at billing@vendor.example"
    d = g.decide(_with_secret(goal, tool("mail_draft", to="billing@vendor.example", subject="s", body=f"ref {SECRET}")))
    assert d.decision == "rewrite"
    sent = json.dumps([s.kwargs for s in t._client.spans], default=str)
    assert "SECRET_TO_SINK" in sent and SECRET not in sent


def test_env_file_is_loaded_without_overriding(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nLANGFUSE_PUBLIC_KEY=pk-file\nLANGFUSE_HOST='http://h'  # trailing\nEMPTY=\n", encoding="utf-8")
    monkeypatch.delenv("LANGFUSE_HOST", raising=False)
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-shell")
    load_env_file(env)
    import os
    assert os.environ["LANGFUSE_PUBLIC_KEY"] == "pk-shell" and os.environ["LANGFUSE_HOST"] == "http://h"
    assert "EMPTY" not in os.environ
    monkeypatch.delenv("LANGFUSE_HOST", raising=False)


def test_matches_the_real_sdk_signatures():
    """Runs only where the langfuse package is installed. Tracing is disabled, so nothing touches the network, but every
    call and keyword is checked against the real client. `_emit` is used because `emit` swallows errors."""
    langfuse = pytest.importorskip("langfuse")
    client = langfuse.Langfuse(public_key="pk-test", secret_key="sk-test", host="http://127.0.0.1:9",
                               tracing_enabled=False)
    LangfuseTelemetry(client, langfuse.propagate_attributes)._emit(SAMPLE)
