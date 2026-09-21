"""Publish a finished evaluation to Langfuse: one trace per scenario, one step per candidate action.

The defense service does not talk to Langfuse. It writes the hash-chained sidecar trace (guard.trace), the kit writes
its event log and summary for every scenario run, and this module joins the two after the run:

    trace "scenario-run"              the scenario: the user's goal, the outcome, the kit's verdict
      +- "screen-action"  (guardrail)   step 1: the candidate action, the decision, risk, confidence, reason codes,
      |    +- "what-happened-next"        the evidence and the context the guard had; then what happened next
      +- "screen-action"                  (executed and what the tool returned / stopped / human approved or denied)
      |    +- "what-happened-next"
      ...

This is what the jury asks to see ("for each candidate action, what it decided, why, and what happened next"), and
"what happened next" comes from the kit's own event log rather than from the defense's guess.

Langfuse best practices applied: static, verb-first names (what varies is in tags, metadata and scores); one trace per
unit of work; the most specific observation types (`agent`, `guardrail`, `tool`); readable input and output lines with
the structured detail in metadata; `environment`, `release` and `version` set; scores for what should be filtered and
charted; secret-shaped tokens masked before anything leaves the process (`mask_otel_spans`, and again when the text is
built); no user id, because the SENTINEL protocol carries none.

    python -m guard.langfuse_export publish RESULTS_DIR --trace RESULTS_DIR/trace/guard-trace.jsonl
    python -m guard.langfuse_export publish RESULTS_DIR --dry-run     # the same tree as plain text, nothing is sent
    python -m guard.langfuse_export check                            # verify the keys

Configure through the environment (a git-ignored `.env` file works; see `.env.example`):
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_BASE_URL, LANGFUSE_TRACING_ENVIRONMENT, LANGFUSE_RELEASE
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

from guard import dlp

log = logging.getLogger("guard.langfuse_export")
SERVICE = "agent-tool-call-guard"
ROOT_NAME = "scenario-run"
STEP_NAME = "screen-action"
NEXT_NAME = "what-happened-next"
_OFF = {"0", "false", "no", "off"}
# `=` and `:` separate a key from its value (`alert_id=AL-3003`), so the key and the value are judged on their own
# instead of being mistaken, together, for one long random-looking secret.
_TOKEN = re.compile(r"[^\s\"',;<>()\[\]{}=:]+")
# Attributes that carry free text. Identifiers that group traces (session id, trace name, tags) are never masked.
_MASKED_ATTRIBUTES = ("input", "output", "status_message")
_RUN_ID = re.compile(r"^(?P<scenario>.+)-[^-]+-s\d+$")  # <scenario>-<defense>-s<n>, the kit's convention
BAD_OUTCOMES = {"attack succeeded"}
WARN_OUTCOMES = {"attack stopped, task not done", "benign task failed"}


# ---- configuration and masking -----------------------------------------------------------------------------------
def release() -> str:
    """The version of the guard that produced a trace, so runs can be compared across versions."""
    explicit = os.environ.get("LANGFUSE_RELEASE")
    if explicit:
        return explicit
    try:
        return f"{SERVICE}@{importlib_metadata.version(SERVICE)}"
    except importlib_metadata.PackageNotFoundError:
        return f"{SERVICE}@dev"


def mask_text(text: str) -> str:
    """Replace secret-shaped tokens (long, mixed character classes, high entropy) with a marker."""
    for raw in set(_TOKEN.findall(text)):
        token = raw.strip(".,:;!?\"'")
        if dlp.secret_like(token):
            text = text.replace(token, dlp.REDACTION)
    return text


def mask_otel_spans(*, params: Any) -> Any:
    """Langfuse's recommended masking hook: patch exported span attributes before they leave the process."""
    from langfuse.types import MaskOtelSpansResult, OtelSpanPatch

    patches = {}
    for identifier, span in params.spans.items():
        replacements = {}
        for key, value in span.attributes.items():
            if isinstance(value, str) and any(part in key for part in _MASKED_ATTRIBUTES):
                masked = mask_text(value)
                if masked != value:
                    replacements[key] = masked
        if replacements:
            patches[identifier] = OtelSpanPatch(set_attributes=replacements)
    return MaskOtelSpansResult(span_patches=patches)


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from a local env file without overriding variables already set. Values are never logged."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)


# ---- one readable line per thing ---------------------------------------------------------------------------------
def scenario_of(run_id: str) -> str:
    """The scenario a run belongs to, from the kit's run id convention; any other run id stands for itself."""
    match = _RUN_ID.match(run_id)
    return match["scenario"] if match else run_id


def outcome_label(summary: dict[str, Any]) -> str:
    """One readable verdict per scenario run, from the kit's own summary."""
    done = bool(summary.get("task_success"))
    if summary.get("attack_present"):
        if summary.get("attack_success"):
            return "attack succeeded"
        return "attack stopped, task done" if done else "attack stopped, task not done"
    return "benign task done" if done else "benign task failed"


def describe_action(action: dict[str, Any]) -> str:
    """The attempted action as one readable line, e.g. `incident_update(incident_id=INC-0101, status=closed)`."""
    kind, tool, args = action["type"], action.get("tool"), action.get("args") or {}

    def call() -> str:
        items = list(args.items())
        shown = ", ".join(f"{key}={str(value)[:40]}" for key, value in items[:4])
        return f"{tool}({shown}{', ...' if len(items) > 4 else ''})"

    if kind == "tool_call":
        return call()
    if kind == "request_confirmation":
        return f"ask a human to confirm {call()}"
    if kind == "respond":
        return f"reply to the user ({action.get('content_chars', 0)} characters)"
    if kind == "memory_write":
        return f"write to memory ({action.get('content_chars', 0)} characters)"
    return str(kind)


def describe_verdict(step: Step) -> str:
    return (f"{step.decision.upper()} [{', '.join(step.codes)}] risk {step.risk:.2f}, confidence {step.confidence:.2f}. "
            f"{step.explanation}")


def describe_result(payload: dict[str, Any]) -> str:
    """What a tool returned, in one line: whether it worked, its effects, and the start of its result."""
    bits = ["succeeded" if payload.get("succeeded", True) and not payload.get("error") else f"failed ({payload.get('error')})"]
    if payload.get("effects"):
        bits.append("effects: " + ", ".join(str(e) for e in payload["effects"]))
    result = payload.get("result")
    if isinstance(result, dict) and result:
        bits.append("result: " + ", ".join(f"{k}={str(v)[:60]}" for k, v in list(result.items())[:4]))
    elif result not in (None, "", {}):
        bits.append(f"result: {str(result)[:120]}")
    return "; ".join(bits)


# ---- the model: what a scenario run looked like ------------------------------------------------------------------
@dataclass
class Step:
    number: int
    decision: str
    risk: float
    confidence: float
    codes: list[str]
    explanation: str
    attempted: str
    tool: str
    rule: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    kit: dict[str, Any] = field(default_factory=dict)
    executed: str | None = None  # the call that actually ran, if any
    happened: str = ""  # what happened next, one line
    happened_level: str = "DEFAULT"
    happened_detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Run:
    run_id: str
    scenario: str
    summary: dict[str, Any]
    goal: str
    verdict: str  # the evaluator's line, e.g. "2/2 success conditions passed"
    steps: list[Step]
    layers: str = "all"

    @property
    def outcome(self) -> str:
        return outcome_label(self.summary)

    def decisions(self) -> Counter:
        return Counter(step.decision for step in self.steps)

    def counts_line(self) -> str:
        counts = self.decisions()
        return ", ".join(f"{counts[name]} {name}" for name in ("allow", "block", "escalate", "rewrite") if counts[name])


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("payload")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return {"text": body}
    return body if isinstance(body, dict) else {}


def _kit_action(action: dict[str, Any]) -> dict[str, Any]:
    """The kit's own record of an action, in the sidecar's shape, with secret-shaped values masked."""
    target = action.get("confirmation_for") or action
    args = {name: mask_text(str(value))[:80] for name, value in (target.get("arguments") or {}).items()}
    return {"type": action.get("type", "tool_call"), "tool": target.get("tool"), "args": args,
            "content_chars": len(target.get("content") or "")}


def _call(tool: str | None, arguments: dict[str, Any]) -> str:
    return mask_text(describe_action({"type": "tool_call", "tool": tool, "args": arguments}))


def load_sidecar(path: Path | None) -> dict[tuple[str, int], dict[str, Any]]:
    """The defense's own records, keyed by (run id, step). A later line for the same key replaces an earlier one."""
    records: dict[tuple[str, int], dict[str, Any]] = {}
    if path is None or not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            records[(record["run_id"], int(record["step"]))] = record
    return records


def _what_happened(decision: str, events: list[dict[str, Any]], approved: bool | None, execution: dict[str, Any] | None
                   ) -> tuple[str | None, str, str, dict[str, Any]]:
    """(the call that ran, one line about what happened next, level, detail) from the events after a decision."""
    requests = [_payload(e) for e in events if e["type"] == "tool_request"]
    results = [_payload(e) for e in events if e["type"] in ("tool_result", "retrieval_result")]
    replies = [_payload(e) for e in events if e["type"] == "model_output"]
    memory = [_payload(e) for e in events if e["type"] in ("memory_write", "memory_read")]
    human = next((_payload(e) for e in events if e["type"] == "human_confirmation"), None)
    if human is not None:
        approved = bool(human.get("approved"))
    prefix = "" if approved is None else ("A human approved it. " if approved else "A human denied it. ")
    detail: dict[str, Any] = {}
    if execution:
        detail = {key: execution[key] for key in ("succeeded", "violated", "legitimate") if key in execution}
    if approved is not None:
        detail["human_approved"] = approved

    if requests:
        request = requests[0]
        call = _call(request.get("tool"), request.get("arguments") or {})
        outcome = mask_text(describe_result(results[0])) if results else "no result recorded"
        lead = {"rewrite": "A safer version was executed instead. ", "allow": ""}.get(decision, "")
        level = "WARNING" if results and (results[0].get("error") or results[0].get("succeeded") is False) else "DEFAULT"
        if detail.get("violated"):
            level = "ERROR"
            outcome += " (the kit counts this execution as a violation)"
        return call, f"{prefix}{lead}Executed {call}: {outcome}", level, detail
    if replies:
        reply = replies[0]
        text = mask_text(str(reply.get("content", "")))
        detail["final"] = bool(reply.get("final"))
        return None, f"{prefix}Reply delivered to the user: {text[:160]}", "DEFAULT", detail
    if memory:
        text = mask_text(json.dumps(memory[0], ensure_ascii=True))
        return None, f"{prefix}Memory access recorded: {text[:160]}", "DEFAULT", detail
    if decision == "block":
        return None, "Not executed. The action was stopped and the agent was told why.", "DEFAULT", detail
    if decision == "escalate":
        return None, f"{prefix or 'A human was asked. '}Nothing was executed.", "DEFAULT", detail
    return None, f"{prefix}Nothing further was recorded for this step.", "DEFAULT", detail


def build_run(summary: dict[str, Any], events: list[dict[str, Any]], sidecar: dict[tuple[str, int], dict[str, Any]]) -> Run:
    run_id = summary["run_id"]
    goal = next((mask_text(str(_payload(e).get("text", ""))) for e in events if e["type"] == "user_message"), "")
    verdict = next((str(_payload(e).get("summary", "")) for e in events if e["type"] == "task_success"), "")
    by_step = {int(d["step_id"]): d for d in summary.get("decisions", [])}
    executions = {int(x["step_id"]): x for x in summary.get("tool_executions", [])}
    groups: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for event in events:
        if event["type"] == "defense_decision":
            groups.append((event, []))
        elif groups and event["actor"] != "evaluator" and event["type"] != "user_message":
            groups[-1][1].append(event)

    steps, layers = [], "all"
    for event, following in groups:
        d = _payload(event)
        number = int(event["step_id"])
        record = sidecar.get((run_id, number))
        action = record["action"] if record else _kit_action(d.get("action") or {})
        tool = str(action.get("tool") or action["type"])
        kit_decision = by_step.get(number, {})
        approved = kit_decision.get("human_approved")
        executed, happened, level, happened_detail = _what_happened(d["decision"], following, approved, executions.get(number))
        detail: dict[str, Any] = {"decision": {"decision": d["decision"], "reason_codes": d.get("reason_codes", []),
                                               "risk_score": d.get("risk_score"), "confidence": d.get("confidence")}}
        if record:
            detail["decision"].update({"rule": record["rule"], "confirmed": record.get("confirmed", False)})
            detail.update({"evidence": record["evidence"], "context": record.get("context", {}),
                           "raw_action": record["action"], "latency_ms": record["latency_ms"]})
            off = sorted(name for name, on in (record.get("layers") or {}).items() if not on)
            layers = "without:" + ",".join(off) if off else layers
        elif kit_decision.get("latency_ms") is not None:
            detail["latency_ms"] = kit_decision["latency_ms"]
        if d.get("rewritten_action"):
            detail["rewritten_to"] = _kit_action(d["rewritten_action"])
        steps.append(Step(
            number=number, decision=d["decision"], risk=float(d.get("risk_score") or 0.0),
            confidence=float(d.get("confidence") or 0.0), codes=list(d.get("reason_codes") or []),
            explanation=str(record["explanation"] if record else d.get("explanation", "")),
            attempted=describe_action(action), tool=tool, rule=record["rule"] if record else None, detail=detail,
            kit={k: kit_decision[k] for k in ("legitimate", "consequential") if k in kit_decision},
            executed=executed, happened=happened, happened_level=level, happened_detail=happened_detail))
    return Run(run_id=run_id, scenario=summary.get("scenario_id") or scenario_of(run_id), summary=summary, goal=goal,
               verdict=verdict, steps=steps, layers=layers)


def load_runs(artifacts: Path, sidecar_path: Path | None = None) -> list[Run]:
    """Every scenario run under `artifacts` (the kit's `<run>.summary.json` and `<run>.jsonl` pairs)."""
    sidecar = load_sidecar(sidecar_path)
    runs = []
    for summary_path in sorted(artifacts.rglob("*.summary.json")):
        events_path = summary_path.with_name(summary_path.name.removesuffix(".summary.json") + ".jsonl")
        if not events_path.is_file():
            continue
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        runs.append(build_run(summary, events, sidecar))
    return runs


# ---- rendering: plain text ---------------------------------------------------------------------------------------
def render_text(run: Run) -> str:
    lines = [f"{run.scenario}  |  {run.outcome}  |  {run.verdict}  |  {run.counts_line()}", f"  goal: {run.goal[:300]}"]
    for step in run.steps:
        flag = "  <- part of the attack" if step.kit.get("legitimate") is False else ""
        lines.append(f"  step {step.number}  {step.decision.upper():<8} risk {step.risk:.2f}  conf {step.confidence:.2f}  "
                     f"{step.attempted}{flag}")
        lines.append(f"          why: [{', '.join(step.codes)}]" + (f" ({step.rule})" if step.rule else "")
                     + f" {step.explanation}")
        lines.append(f"          then: {step.happened}")
    return "\n".join(lines)


# ---- rendering: Langfuse -----------------------------------------------------------------------------------------
def _tags(run: Run) -> list[str]:
    summary = run.summary
    family = summary.get("attack_family") if summary.get("attack_present") else None
    tags = [SERVICE, f"scenario:{run.scenario}", f"outcome:{run.outcome}", f"split:{summary.get('split', '?')}",
            f"domain:{summary.get('domain', '?')}", f"attack:{family or 'none'}"]
    tags += [f"decision:{name}" for name in sorted(run.decisions())]
    tags += sorted({f"rule:{s.rule}" for s in run.steps if s.rule and s.decision != "allow"})
    return [tag[:200] for tag in tags][:30]


def _root_metadata(run: Run) -> dict[str, Any]:
    summary = run.summary
    meta = {key: summary[key] for key in ("scenario_id", "split", "domain", "attack_family", "difficulty",
                                          "hard_negative", "seed", "steps", "termination", "defense") if key in summary}
    meta.update({"outcome": run.outcome, "evaluator": run.verdict, "decisions": dict(run.decisions()), "layers": run.layers})
    if summary.get("findings"):
        meta["findings"] = mask_text(json.dumps(summary["findings"], ensure_ascii=True))[:1000]
    return meta


def publish_run(client: Any, propagate_attributes: Any, run: Run, release_tag: str) -> str:
    summary = run.summary
    trace_id = client.create_trace_id()
    outcome = run.outcome
    level = "ERROR" if outcome in BAD_OUTCOMES else "WARNING" if outcome in WARN_OUTCOMES else "DEFAULT"
    message = None
    if outcome in BAD_OUTCOMES:
        message = "The attack reached its goal. " + mask_text(json.dumps(summary.get("findings") or "", ensure_ascii=True))[:250]
    elif outcome in WARN_OUTCOMES:
        message = f"{outcome}: {run.verdict}"
    family = summary.get("attack_family") if summary.get("attack_present") else "none"
    with propagate_attributes(
        trace_name=ROOT_NAME, session_id=run.run_id[:200], version=release_tag, tags=_tags(run),
        metadata={"scenario": run.scenario[:200], "outcome": outcome[:200], "layers": run.layers[:200]},
    ):
        root = client.start_observation(
            trace_context={"trace_id": trace_id}, name=ROOT_NAME, as_type="agent", input=run.goal,
            output=f"{outcome.capitalize()}. {run.verdict}. {len(run.steps)} actions: {run.counts_line()}.",
            metadata=_root_metadata(run), level=level, status_message=message)
        for step in run.steps:
            observation = root.start_observation(
                name=STEP_NAME, as_type="guardrail", input=f"step {step.number}: {step.attempted}",
                output=describe_verdict(step),
                metadata={"step": str(step.number), "decision": step.decision, "rule": str(step.rule or ""),
                          "tool": step.tool, "layers": run.layers, **step.detail, "kit": step.kit},
                level="DEFAULT" if step.decision == "allow" else "WARNING",
                status_message=None if step.decision == "allow" else step.explanation[:300])
            observation.score(name="risk_score", value=step.risk, data_type="NUMERIC")
            observation.score(name="confidence", value=step.confidence, data_type="NUMERIC")
            observation.score(name="decision", value=step.decision, data_type="CATEGORICAL")
            nxt = observation.start_observation(
                name=NEXT_NAME, as_type="tool" if step.executed else "span", input=step.executed,
                output=step.happened, metadata=step.happened_detail, level=step.happened_level)
            nxt.end()
            observation.end()
            time.sleep(0.003)  # Langfuse orders by start time at millisecond precision: keep the steps in sequence
        root.score_trace(name="outcome", value=outcome, data_type="CATEGORICAL",
                         comment=f"{summary.get('domain', '?')} / {family}, {summary.get('steps', '?')} steps")
        root.score_trace(name="task_success", value=float(bool(summary.get("task_success"))), data_type="BOOLEAN")
        root.score_trace(name="attack_success", value=float(bool(summary.get("attack_success"))), data_type="BOOLEAN")
        root.score_trace(name="attack_family", value=str(family), data_type="CATEGORICAL")
        if summary.get("domain"):
            root.score_trace(name="domain", value=str(summary["domain"]), data_type="CATEGORICAL")
        root.end()
    return trace_id


def make_client() -> tuple[Any, Any, str] | None:
    """(client, propagate_attributes, environment), or None when Langfuse is not configured or switched off."""
    if os.environ.get("LANGFUSE_TRACING_ENABLED", "true").strip().lower() in _OFF:
        return None
    if not (os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")):
        return None
    try:
        from langfuse import Langfuse, propagate_attributes
    except ImportError:
        log.warning("LANGFUSE_* is set but the langfuse package is not installed; run: pip install '.[langfuse]'")
        return None
    environment = os.environ.get("LANGFUSE_TRACING_ENVIRONMENT", "development")
    client = Langfuse(environment=environment, release=release(), mask_otel_spans=mask_otel_spans)
    return client, propagate_attributes, environment


def publish_directory(artifacts: Path, sidecar: Path | None, force: bool = False) -> str:
    """Publish every scenario run under `artifacts`. Returns a one-line report."""
    configured = make_client()
    if configured is None:
        return "Langfuse is not configured (set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY); nothing was published."
    client, propagate, environment = configured
    marker = artifacts / f".langfuse-published-{environment}"
    if marker.exists() and not force:
        return (f"These results were already published to environment '{environment}'. Publishing again would duplicate "
                f"the traces; use another LANGFUSE_TRACING_ENVIRONMENT or pass --force.")
    runs = load_runs(artifacts, sidecar)
    try:
        for run in runs:
            publish_run(client, propagate, run, release())
    finally:
        client.shutdown()  # flushes buffered spans
    marker.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    return f"Published {len(runs)} scenario runs ({sum(len(r.steps) for r in runs)} actions) to environment '{environment}'."


def _check() -> int:
    configured = make_client()
    if configured is None:
        print("Langfuse is not configured: set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_BASE_URL "
              "(and install the extra: pip install '.[langfuse]').")
        return 2
    client, _, environment = configured
    ok = bool(client.auth_check())
    print(f"authentication: {'OK' if ok else 'FAILED (check the keys and LANGFUSE_BASE_URL)'} (environment '{environment}')")
    client.shutdown()
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    load_env_file(Path(os.environ.get("GUARD_ENV_FILE", ".env")))
    parser = argparse.ArgumentParser(prog="python -m guard.langfuse_export", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    publish = sub.add_parser("publish", help="publish a finished evaluation")
    publish.add_argument("artifacts", type=Path, help="a directory holding the kit's <run>.summary.json / <run>.jsonl files")
    publish.add_argument("--trace", type=Path, help="the guard's sidecar trace (guard-trace.jsonl); adds rule, evidence, context")
    publish.add_argument("--dry-run", action="store_true", help="print the tree as text and send nothing")
    publish.add_argument("--force", action="store_true", help="publish even if these results were already published")
    sub.add_parser("check", help="verify the Langfuse keys")
    args = parser.parse_args(argv)
    if args.command == "check":
        return _check()
    if args.dry_run:
        for run in load_runs(args.artifacts, args.trace):
            print(render_text(run) + "\n")
        return 0
    print(publish_directory(args.artifacts, args.trace, force=args.force))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
