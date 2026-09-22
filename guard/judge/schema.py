"""The only shape a judge-stage answer may take. `extra="forbid"` makes any other field a malformed response
(see client.py), so the judge cannot smuggle a new field, an argument, or a value past this contract."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from guard.repairs import RepairId

JudgeReason = Literal[
    "goal_supports_action",       # the action plausibly serves the trusted goal
    "goal_does_not_support_action",  # nothing in the goal asks for this
    "content_looks_planted",      # an excerpt appears to have planted this specific action
    "uncertain",                  # neither is clear; let a human decide
]


class JudgeVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block", "escalate"]
    repair: RepairId | None = None
    reason: JudgeReason
