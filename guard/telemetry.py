"""Optional export of decision records to Langfuse, for observability.

The hash-chained sidecar trace (guard.trace) stays the source of truth; this module mirrors each decision to a
Langfuse project so it can be browsed: one *session* per agent run, one *trace* per decision, with the rule, the
reason codes, the evidence and the latency, plus `risk_score`, `confidence` and `decision` scores for filtering.

Rules this module follows:
* Off unless LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set (and LANGFUSE_TRACING_ENABLED is not false).
* Never blocks and never raises into the decision path: a failure to export is logged at debug level only. Spans are
  exported by the SDK on a background thread.
* Sends only what the sidecar record already contains: secret values are redacted before a record is built, and
  observed text is truncated. All data in this benchmark is synthetic.
* Trace ids are derived from `guard:<run_id>:<step>`, so any line of the sidecar trace maps to one Langfuse trace.

Configure through the environment (a git-ignored `.env` file works; see `.env.example`):
    LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST (or your self-hosted URL), LANGFUSE_TRACING_ENVIRONMENT

Check a configuration without running the benchmark:
    python -m guard.telemetry check
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger("guard.telemetry")
_OFF = {"0", "false", "no", "off"}


class Telemetry:
    """No-op base: what the defense uses when Langfuse is not configured."""

    enabled = False

    def emit(self, record: dict[str, Any]) -> None:
        return None

    def close(self) -> None:
        return None


class LangfuseTelemetry(Telemetry):
    enabled = True

    def __init__(self, client: Any, propagate_attributes: Any) -> None:
        self._client = client
        self._propagate = propagate_attributes

    def emit(self, record: dict[str, Any]) -> None:
        try:
            self._emit(record)
        except Exception:  # noqa: BLE001 - observability must never affect a decision
            log.debug("langfuse export failed", exc_info=True)

    def _emit(self, record: dict[str, Any]) -> None:
        action = record["action"]
        tool = action.get("tool") or action["type"]
        decision = record["decision"]
        trace_id = self._client.create_trace_id(seed=f"guard:{record['run_id']}:{record['step']}")
        tags = ["agent-tool-call-guard", f"decision:{decision}", f"rule:{record['rule']}", f"tool:{tool}",
                *[f"code:{code}" for code in record["codes"][:8]]]
        with self._propagate(
            trace_name=f"guard:{decision}:{tool}",
            session_id=str(record["run_id"])[:200],
            tags=[tag[:200] for tag in tags],
            metadata={"run_id": str(record["run_id"])[:200], "step": str(record["step"]), "turn": str(record["turn"])},
        ):
            span = self._client.start_observation(
                trace_context={"trace_id": trace_id},
                name="guard.decision",
                as_type="guardrail",
                input={"action": action},
                output={"decision": decision, "risk_score": record["risk"], "confidence": record["confidence"],
                        "reason_codes": record["codes"], "rule": record["rule"], "explanation": record["explanation"]},
                metadata={"evidence": record["evidence"], "latency_ms": record["latency_ms"]},
                level="DEFAULT" if decision == "allow" else "WARNING",
            )
            span.score_trace(name="risk_score", value=float(record["risk"]), data_type="NUMERIC")
            span.score_trace(name="confidence", value=float(record["confidence"]), data_type="NUMERIC")
            span.score_trace(name="decision", value=decision, data_type="CATEGORICAL")
            span.end()

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
    client = Langfuse(environment=os.environ.get("LANGFUSE_TRACING_ENVIRONMENT", "development"))
    return LangfuseTelemetry(client, propagate_attributes)


def _check() -> int:
    load_env_file(Path(os.environ.get("GUARD_ENV_FILE", ".env")))
    telemetry = from_env()
    if not isinstance(telemetry, LangfuseTelemetry):
        print("Langfuse is not configured: set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_HOST "
              "(and install the extra: pip install '.[langfuse]').")
        return 2
    ok = telemetry.auth_ok()
    print(f"authentication: {'OK' if ok else 'FAILED (check the keys and LANGFUSE_HOST)'}")
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
