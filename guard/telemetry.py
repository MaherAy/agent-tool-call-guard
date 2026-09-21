"""Optional export of decision records to Langfuse, for observability.

The hash-chained sidecar trace (guard.trace) stays the source of truth; this module mirrors each decision to a
Langfuse project so it can be browsed. It follows Langfuse's tracing best practices:

* One trace = one self-contained unit of work: the screening of ONE candidate action. One *session* = one agent run
  (`session_id` = run_id), so the steps of a run are grouped in order. The scenario is read from the run id
  (`<scenario>-<defense>-s<n>`, the kit's convention) and is a tag and a metadata field, so a scenario can be filtered.
* After an evaluation, `record_outcomes` attaches the kit's verdict to each session as scores (outcome, task success,
  attack success, attack family, domain), so the Sessions list reads as one row per scenario with its result.
* Static, verb-first names (`screen-action`), never dynamic values. What varies (decision, rule, tool, reason codes) is
  in tags, filterable metadata and scores, so names stay stable for dashboards, evaluators and saved filters.
* Observation type `guardrail` (the most specific type for a check that can stop an action).
* Readable input/output on the root observation (which populates the trace tables; `set_trace_io` is deprecated):
  the attempted action as a one-line call, and the decision as a one-line verdict.
  The structured detail (raw action, evidence, the context the guard had) lives in metadata.
* Enough context to audit a decision later: the user's goal, the policy (allowed and consequential tools), what the goal
  asked for or ruled out, what trust/sensitivity the run had seen, and which layers were enabled.
* `environment`, `release` and `version` are set, so demo, test and production traces never mix and runs are comparable
  across versions of the guard.
* Sensitive data: protected values are redacted before a record is built, and `mask_otel_spans` masks any secret-shaped
  token in inputs, outputs and status messages again just before export.
* Trace ids are derived from `guard:<environment>:<run_id>:<step>`, so any line of the sidecar trace maps to one
  Langfuse trace.

Operating rules: off unless LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set (and LANGFUSE_TRACING_ENABLED is not
false); never blocks and never raises into the decision path (the SDK exports on a background thread and the service
shuts the client down, which flushes, on exit); no user id is set because the SENTINEL protocol carries no user identity.

Configure through the environment (a git-ignored `.env` file works; see `.env.example`):
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_BASE_URL, LANGFUSE_TRACING_ENVIRONMENT, LANGFUSE_RELEASE

Check a configuration without running the benchmark:
    python -m guard.telemetry check
"""

from __future__ import annotations

import logging
import os
import re
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

from guard import dlp

log = logging.getLogger("guard.telemetry")
_OFF = {"0", "false", "no", "off"}
SERVICE = "agent-tool-call-guard"
SPAN_NAME = "screen-action"
# `=` and `:` separate a key from its value (`alert_id=AL-3003`), so the key and the value are judged on their own
# instead of being mistaken, together, for one long random-looking secret.
_TOKEN = re.compile(r"[^\s\"',;<>()\[\]{}=:]+")
# Attributes that carry free text. Identifiers that group traces (session id, trace name, tags) are never masked.
_MASKED_ATTRIBUTES = ("input", "output", "status_message")
_RUN_ID = re.compile(r"^(?P<scenario>.+)-[^-]+-s\d+$")  # <scenario>-<defense>-s<n>


def release() -> str:
    """The version of the guard that produced a trace, so runs can be compared across versions."""
    explicit = os.environ.get("LANGFUSE_RELEASE")
    if explicit:
        return explicit
    try:
        return f"{SERVICE}@{importlib_metadata.version(SERVICE)}"
    except importlib_metadata.PackageNotFoundError:
        return f"{SERVICE}@dev"


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


def describe_verdict(record: dict[str, Any]) -> str:
    codes = ", ".join(record["codes"])
    return (f"{record['decision'].upper()} [{codes}] risk {record['risk']:.2f}, confidence {record['confidence']:.2f}. "
            f"{record['explanation']}")


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


class Telemetry:
    """No-op base: what the defense uses when Langfuse is not configured."""

    enabled = False

    def emit(self, record: dict[str, Any]) -> None:
        return None

    def record_outcomes(self, summaries: list[dict[str, Any]]) -> None:
        return None

    def close(self) -> None:
        return None


class LangfuseTelemetry(Telemetry):
    enabled = True

    def __init__(self, client: Any, propagate_attributes: Any, environment: str = "development",
                 release_tag: str | None = None) -> None:
        self._client = client
        self._propagate = propagate_attributes
        self._environment = environment
        self._release = release_tag or release()

    def emit(self, record: dict[str, Any]) -> None:
        try:
            self._emit(record)
        except Exception:  # noqa: BLE001 - observability must never affect a decision
            log.debug("langfuse export failed", exc_info=True)

    def _emit(self, record: dict[str, Any]) -> None:
        action = record["action"]
        tool = action.get("tool") or action["type"]
        decision = record["decision"]
        layers = record.get("layers") or {}
        disabled = sorted(name for name, on in layers.items() if not on)
        run_id = str(record["run_id"])
        trace_id = self._client.create_trace_id(seed=f"guard:{self._environment}:{run_id}:{record['step']}")
        scenario = scenario_of(run_id)
        tags = ["agent-tool-call-guard", f"scenario:{scenario}", f"decision:{decision}", f"rule:{record['rule']}",
                f"tool:{tool}", *[f"code:{code}" for code in record["codes"][:8]]]
        filterable = {"scenario": scenario, "run_id": run_id, "step": str(record["step"]), "turn": str(record["turn"]),
                      "decision": decision, "rule": str(record["rule"]), "tool": str(tool),
                      "layers": "without:" + ",".join(disabled) if disabled else "all"}
        attempted, verdict = describe_action(action), describe_verdict(record)
        with self._propagate(
            trace_name=SPAN_NAME,
            session_id=run_id[:200],
            version=self._release,
            tags=[tag[:200] for tag in tags],
            metadata={key: value[:200] for key, value in filterable.items()},
        ):
            span = self._client.start_observation(
                trace_context={"trace_id": trace_id},
                name=SPAN_NAME,
                as_type="guardrail",
                input=attempted,
                output=verdict,
                metadata={
                    "decision": {"decision": decision, "rule": record["rule"], "reason_codes": record["codes"],
                                 "risk_score": record["risk"], "confidence": record["confidence"],
                                 "confirmed": record.get("confirmed", False)},
                    "evidence": record["evidence"],
                    "context": record.get("context", {}),
                    "raw_action": action,
                    "latency_ms": record["latency_ms"],
                },
                level="DEFAULT" if decision == "allow" else "WARNING",
                status_message=None if decision == "allow" else record["explanation"][:300],
            )
            span.score_trace(name="risk_score", value=float(record["risk"]), data_type="NUMERIC")
            span.score_trace(name="confidence", value=float(record["confidence"]), data_type="NUMERIC")
            span.score_trace(name="decision", value=decision, data_type="CATEGORICAL")
            span.end()

    def record_outcomes(self, summaries: list[dict[str, Any]]) -> None:
        """Attach the kit's verdict on each scenario run to its session. `summaries` are the kit's `*.summary.json`."""
        for summary in summaries:
            try:
                self._record_outcome(summary)
            except Exception:  # noqa: BLE001
                log.debug("langfuse outcome export failed", exc_info=True)

    def _record_outcome(self, summary: dict[str, Any]) -> None:
        session = str(summary["run_id"])[:200]
        attack = (summary.get("attack_family") or "unknown") if summary.get("attack_present") else "none"
        detail = {key: summary[key] for key in ("scenario_id", "split", "domain", "attack_family", "difficulty",
                                                "hard_negative", "steps", "termination") if key in summary}
        label = outcome_label(summary)
        score = self._client.create_score
        common = {"session_id": session, "environment": self._environment}
        score(name="outcome", value=label, data_type="CATEGORICAL", metadata=detail,
              comment=f"{summary.get('domain', '?')} / {attack}, {summary.get('steps', '?')} steps", **common)
        score(name="task_success", value=float(bool(summary.get("task_success"))), data_type="BOOLEAN", **common)
        score(name="attack_success", value=float(bool(summary.get("attack_success"))), data_type="BOOLEAN", **common)
        score(name="attack_family", value=str(attack), data_type="CATEGORICAL", **common)
        if summary.get("domain"):
            score(name="domain", value=str(summary["domain"]), data_type="CATEGORICAL", **common)

    def auth_ok(self) -> bool:
        return bool(self._client.auth_check())

    def close(self) -> None:
        try:
            self._client.shutdown()  # flushes buffered spans
        except Exception:  # noqa: BLE001
            log.debug("langfuse shutdown failed", exc_info=True)


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


def from_env() -> Telemetry:
    if os.environ.get("LANGFUSE_TRACING_ENABLED", "true").strip().lower() in _OFF:
        return Telemetry()
    if not (os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")):
        return Telemetry()
    try:
        from langfuse import Langfuse, propagate_attributes
    except ImportError:
        log.warning("LANGFUSE_* is set but the langfuse package is not installed; run: pip install '.[langfuse]'")
        return Telemetry()
    environment = os.environ.get("LANGFUSE_TRACING_ENVIRONMENT", "development")
    tag = release()
    client = Langfuse(environment=environment, release=tag, mask_otel_spans=mask_otel_spans)
    return LangfuseTelemetry(client, propagate_attributes, environment=environment, release_tag=tag)


def _check() -> int:
    load_env_file(Path(os.environ.get("GUARD_ENV_FILE", ".env")))
    telemetry = from_env()
    if not isinstance(telemetry, LangfuseTelemetry):
        print("Langfuse is not configured: set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_BASE_URL "
              "(and install the extra: pip install '.[langfuse]').")
        return 2
    ok = telemetry.auth_ok()
    print(f"authentication: {'OK' if ok else 'FAILED (check the keys and LANGFUSE_BASE_URL)'}")
    if ok:
        telemetry.emit({"run_id": "check-run", "step": 1, "turn": 0, "rule": "R0", "decision": "allow", "risk": 0.05,
                        "confidence": 0.7, "codes": ["USER_GOAL_ALIGNED"], "explanation": "Configuration check.",
                        "evidence": {}, "latency_ms": 0.0,
                        "action": {"type": "tool_call", "tool": "check", "args": {}, "content_chars": 0}})
        print("sample decision sent as session 'check-run'; look for it in your Langfuse project")
    telemetry.close()
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "check":
        raise SystemExit(_check())
    print("usage: python -m guard.telemetry check")
    raise SystemExit(2)
