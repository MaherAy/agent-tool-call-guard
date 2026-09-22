"""What Stage 1 does when the judge stage cannot be reached (no client configured, timeout, transport
error, or a malformed response). This is a deterministic decision, not a second network call -- see
client.py's docstring on why the judge stage is never internally retried.

By the time this runs, R1/R2/R5/R6/R7/R8/R9 have already passed: the tool is within policy, any identifier
or external recipient is grounded in trusted evidence, no protected value is going to a disallowed sink, and
either the action is not consequential or it is already confirmed. What is missing is only whether the
user's goal actually asked for this write -- a plausibility question, not a safety one. An unrequested write
to a tool is allowed at low risk; an unrequested memory write is escalated, because memory persists and a
human is cheap to ask once.
"""

from __future__ import annotations

from guard.models import CandidateAction

REASON_CODE = "JUDGE_UNAVAILABLE"
MAX_FALLBACK_RISK = 0.40


def decide(action: CandidateAction, soft_codes: list[str], soft_risk: float) -> tuple[str, float, list[str], str]:
    """Returns (decision, risk, reason_codes, explanation)."""
    codes = [*soft_codes, REASON_CODE]
    if action.type == "memory_write":
        return (
            "escalate",
            max(0.45, soft_risk),
            codes,
            "The judge stage could not be reached; an unrequested memory write needs a human.",
        )
    return (
        "allow",
        min(MAX_FALLBACK_RISK, soft_risk),
        codes,
        "The judge stage could not be reached; only soft, non-conclusive signals remained.",
    )
