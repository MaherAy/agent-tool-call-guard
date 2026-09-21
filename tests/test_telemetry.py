"""Langfuse export: optional, safe, and shaped as Langfuse's best practices recommend. No network is used."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from guard import telemetry as tm
from guard.engine import Config, GuardDefense
from guard.telemetry import LangfuseTelemetry, Telemetry, describe_action, from_env, load_env_file
from tests.conftest import request, tool
from tests.test_engine import SECRET, _with_secret

RELEASE = "agent-tool-call-guard@test"
SAMPLE = {
    "run_id": "run-x", "step": 3, "turn": 0, "rule": "R6", "decision": "block", "risk": 0.9, "confidence": 0.8,
    "codes": ["TAINTED_ARGUMENT"], "explanation": "Argument(s) ticket_id are not supported by any trusted source.",
    "evidence": {"arguments": ["ticket_id"]}, "latency_ms": 1.2, "confirmed": False,
    "layers": {"contract": True, "grounding": True, "dlp": True, "reconstruction": True, "memory_rules": True},
    "context": {"user_goal": "Add a note to ticket TCK-8", "allowed_tools": ["ticket_update"]},
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


def telemetry(client=None, environment="development"):
    propagate = FakePropagate()
    return LangfuseTelemetry(client or FakeClient(), propagate, environment=environment, release_tag=RELEASE), propagate


# ---- configuration ---------------------------------------------------------------------------------------------
def test_off_by_default(monkeypatch):
    for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_TRACING_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    t = from_env()
    assert type(t) is Telemetry and not t.enabled
    t.emit(SAMPLE)
    t.close()


def test_can_be_switched_off_even_with_keys(monkeypatch):
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk")
    monkeypatch.setenv("LANGFUSE_TRACING_ENABLED", "false")
    assert not from_env().enabled


def test_release_comes_from_the_environment_or_the_installed_version(monkeypatch):
    monkeypatch.setenv("LANGFUSE_RELEASE", "abc123")
    assert tm.release() == "abc123"
    monkeypatch.delenv("LANGFUSE_RELEASE")
    assert tm.release().startswith("agent-tool-call-guard@")


def test_env_file_is_loaded_without_overriding(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nLANGFUSE_PUBLIC_KEY=pk-file\nLANGFUSE_BASE_URL='http://h'  # trailing\nEMPTY=\n",
                   encoding="utf-8")
    monkeypatch.delenv("LANGFUSE_BASE_URL", raising=False)
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-shell")
    load_env_file(env)
    assert os.environ["LANGFUSE_PUBLIC_KEY"] == "pk-shell" and os.environ["LANGFUSE_BASE_URL"] == "http://h"
    assert "EMPTY" not in os.environ
    monkeypatch.delenv("LANGFUSE_BASE_URL", raising=False)


# ---- the shape of a trace ------------------------------------------------------------------------------------------
def test_one_guardrail_trace_per_decision_with_static_name_and_deterministic_id():
    t, propagate = telemetry()
    t.emit(SAMPLE)
    client = t._client
    assert client.seeds == ["guard:development:run-x:3"]  # environment is part of the id, so environments never merge
    span = client.spans[0]
    assert span.kwargs["name"] == "screen-action" and span.kwargs["as_type"] == "guardrail"
    assert span.kwargs["level"] == "WARNING" and span.kwargs["status_message"].startswith("Argument(s) ticket_id")
    assert span.kwargs["trace_context"] == {"trace_id": "trace-guard:development:run-x:3"}
    assert span.ended
    attrs = propagate.calls[0]
    assert attrs["trace_name"] == "screen-action" and attrs["session_id"] == "run-x" and attrs["version"] == RELEASE


def test_names_are_static_and_what_varies_is_in_tags_metadata_and_scores():
    t, propagate = telemetry()
    t.emit(SAMPLE)
    t.emit({**SAMPLE, "step": 4, "decision": "allow", "codes": ["USER_GOAL_ALIGNED"], "rule": "R0",
            "action": {"type": "respond", "tool": None, "args": {}, "content_chars": 42}})
    assert {s.kwargs["name"] for s in t._client.spans} == {"screen-action"}
    first = propagate.calls[0]
    assert {"decision:block", "rule:R6", "tool:ticket_update", "code:TAINTED_ARGUMENT"} <= set(first["tags"])
    assert first["metadata"] == {"run_id": "run-x", "step": "3", "turn": "0", "decision": "block", "rule": "R6",
                                 "tool": "ticket_update", "layers": "all"}
    assert {(s["name"], s["data_type"]) for s in t._client.spans[0].scores} == {
        ("risk_score", "NUMERIC"), ("confidence", "NUMERIC"), ("decision", "CATEGORICAL")}
    assert t._client.spans[1].kwargs["level"] == "DEFAULT" and t._client.spans[1].kwargs["status_message"] is None


def test_input_and_output_are_readable_lines_and_detail_is_in_metadata():
    t, _ = telemetry()
    t.emit(SAMPLE)
    span = t._client.spans[0]
    assert span.kwargs["input"] == "ticket_update(ticket_id=TCK-9)"
    assert span.kwargs["output"].startswith("BLOCK [TAINTED_ARGUMENT] risk 0.90, confidence 0.80. ")
    meta = span.kwargs["metadata"]
    assert meta["decision"]["rule"] == "R6" and meta["evidence"] == {"arguments": ["ticket_id"]}
    assert meta["context"]["user_goal"] == "Add a note to ticket TCK-8" and meta["raw_action"]["tool"] == "ticket_update"


def test_disabled_layers_are_visible_as_a_filterable_value():
    t, propagate = telemetry()
    t.emit({**SAMPLE, "layers": {**SAMPLE["layers"], "contract": False, "dlp": False}})
    assert propagate.calls[0]["metadata"]["layers"] == "without:contract,dlp"


def test_action_descriptions():
    assert describe_action({"type": "respond", "content_chars": 12}) == "reply to the user (12 characters)"
    assert describe_action({"type": "memory_write", "content_chars": 5}) == "write to memory (5 characters)"
    assert describe_action({"type": "request_confirmation", "tool": "pay_confirm", "args": {"payment_id": "PAY-1"}}) \
        == "ask a human to confirm pay_confirm(payment_id=PAY-1)"
    long = {"type": "tool_call", "tool": "t", "args": {f"a{i}": "x" * 100 for i in range(6)}}
    assert describe_action(long).count("=") == 4 and describe_action(long).endswith(", ...)")


# ---- safety ------------------------------------------------------------------------------------------------------
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


def test_the_guard_records_the_context_it_decided_with():
    t, _ = telemetry()
    g = GuardDefense(config=Config(), telemetry=t)
    goal = "Prepare the payment. Do not confirm or execute it."
    g.decide(request(goal, tool("pay_confirm", payment_id="PAY-1")))
    meta = t._client.spans[0].kwargs["metadata"]
    context = meta["context"]
    assert context["user_goal"] == goal and "pay_confirm" in context["allowed_tools"]
    assert "pay_confirm" in context["consequential_tools"]
    assert context["goal_rules_out"] == ["confirm", "execute"] and context["goal_asks_for"] == []
    assert meta["decision"]["rule"] == "R2"


def test_masking_removes_secret_shaped_tokens_but_keeps_ids_codes_and_names():
    assert SECRET not in tm.mask_text(f"ref {SECRET} for TCK-9 (PLAN_DEVIATION) via incident_update on run-x_http-s0")
    kept = "TCK-9 PLAN_DEVIATION incident_update 2026-11-30 nadia@corp.example"
    assert tm.mask_text(kept) == kept


def test_masking_does_not_mistake_key_value_pairs_for_secrets():
    """Found by auditing real traces: `alert_id=AL-3003` and `title=Backup` were masked as if they were one secret."""
    line = "incident_create(alert_id=AL-3003, title=Backup credential binding check, severity=low, summary=ok)"
    assert tm.mask_text(line) == line
    masked = tm.mask_text(f"mail_draft(subject=ref, body=token: {SECRET}, api_key={SECRET})")
    assert SECRET not in masked and "subject=ref" in masked and "api_key=" in masked


def test_span_masking_only_touches_free_text_attributes():
    pytest.importorskip("langfuse")
    span = SimpleNamespace(attributes={
        "langfuse.observation.input": f"reply {SECRET}",
        "langfuse.observation.status_message": f"leaked {SECRET}",
        "langfuse.session.id": "demo_run_alpha-http_defense-s0",  # looks secret-like, must stay intact
        "langfuse.observation.type": "guardrail",
    })
    result = tm.mask_otel_spans(params=SimpleNamespace(spans={"span-1": span}))
    patch = result.span_patches["span-1"]
    assert set(patch.set_attributes) == {"langfuse.observation.input", "langfuse.observation.status_message"}
    assert all(SECRET not in v for v in patch.set_attributes.values())


def test_matches_the_real_sdk_signatures():
    """Runs only where the langfuse package is installed. Tracing is disabled, so nothing touches the network, but every
    call and keyword is checked against the real client. `_emit` is used because `emit` swallows errors."""
    langfuse = pytest.importorskip("langfuse")
    client = langfuse.Langfuse(public_key="pk-test", secret_key="sk-test", host="http://127.0.0.1:9",
                               tracing_enabled=False, release=RELEASE, environment="development",
                               mask_otel_spans=tm.mask_otel_spans)
    LangfuseTelemetry(client, langfuse.propagate_attributes, environment="development", release_tag=RELEASE)._emit(SAMPLE)
