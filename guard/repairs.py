"""Closed menu of judge-stage repairs.

The judge stage may name one of these; it never writes an argument, a value, or a tool name of its own --
that would turn the second stage into exactly the free-text channel the rest of this defense refuses to
trust. The engine builds the actual action from the name, then re-runs every rule on the result (see
``engine.GuardDefense._consult_judge``) before it is returned, so a repair only ever narrows what the
original action could do.

Honest note on reachability: the judge stage is only ever consulted for a *non-consequential* action
(``engine.py``'s R9 always decides a consequential one first). Both repairs below target verbs
(``*_send``, a closing status update) that the reference policies mark consequential, and ``closes()`` in
contract.py treats a closing status as consequential unconditionally, regardless of policy. So under the
kit's published domains this menu is rarely *offered* in the first place -- Stage 2 mostly answers a plain
allow / block / escalate question. The menu exists for policies where such a tool is not marked
consequential (a low-stakes internal notification, for example), and is exercised end to end by
``tests/test_repairs.py`` and ``tests/test_judge.py`` under a synthetic policy of that shape. This is
disclosed rather than hidden, per the project's own rule against overstating what a layer does.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from guard.models import CandidateAction


class RepairId(StrEnum):
    """The only repair names that exist. Adding one means adding its function to REPAIRS below."""

    SEND_TO_DRAFT = "send_to_draft"
    DROP_CLOSING_STATUS = "drop_closing_status"


Repair = Callable[[CandidateAction], "CandidateAction | None"]


def _send_to_draft(action: CandidateAction) -> CandidateAction | None:
    """A `*_send` tool call becomes the matching `*_draft` call; nothing else about it changes."""
    if action.type != "tool_call" or not (action.tool or "").endswith("_send"):
        return None
    return action.model_copy(update={"tool": action.tool[: -len("_send")] + "_draft"})


def _drop_closing_status(action: CandidateAction) -> CandidateAction | None:
    """Drop a `status: closed|resolved` argument; the rest of the call (e.g. the note text) is kept."""
    if action.type != "tool_call" or "status" not in action.arguments:
        return None
    status = str(action.arguments.get("status", "")).strip().lower()
    if status not in {"closed", "resolved"}:
        return None
    remaining = {k: v for k, v in action.arguments.items() if k != "status"}
    return action.model_copy(update={"arguments": remaining})


REPAIRS: dict[RepairId, Repair] = {
    RepairId.SEND_TO_DRAFT: _send_to_draft,
    RepairId.DROP_CLOSING_STATUS: _drop_closing_status,
}


def applicable(action: CandidateAction, allowed_tools: set[str]) -> list[RepairId]:
    """Repairs that would produce a different, policy-permitted action -- the only ones offered to the judge.

    A repair that would name a tool outside `allowed_tools` is never offered: the judge cannot widen the
    ceiling any more than the goal contract can (see contract.py).
    """
    names: list[RepairId] = []
    for repair_id, fn in REPAIRS.items():
        result = fn(action)
        if result is None or result == action:
            continue
        if result.type == "tool_call" and result.tool not in allowed_tools:
            continue
        names.append(repair_id)
    return names


def apply(repair_id: RepairId | str, action: CandidateAction) -> CandidateAction | None:
    try:
        key = RepairId(repair_id)
    except ValueError:
        return None
    fn = REPAIRS.get(key)
    return fn(action) if fn else None
