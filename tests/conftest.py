"""Helpers to build synthetic DefenseRequests. Tests use generic names only, never scenario ids."""

from __future__ import annotations

import pytest

from guard.engine import Config, GuardDefense
from guard.models import CandidateAction, ConversationItem, DefenseRequest, HistoryDigest, Provenance, ProvenanceRecord

INTERNAL = ["corp.example"]
POLICY = {
    "allowed_tools": ["mail_read", "mail_draft", "mail_send", "doc_read", "wiki_search", "note_create",
                      "ticket_update", "pay_prepare", "pay_confirm", "pay_execute"],
    "consequential_tools": ["mail_send", "pay_confirm", "pay_execute"],
    "confirmation_required_tools": ["pay_confirm", "pay_execute"],
    "internal_email_domains": INTERNAL,
}


def prov(pid: str, trust: str, sensitivity: str = "internal") -> ProvenanceRecord:
    return ProvenanceRecord(id=pid, provenance=Provenance(
        source_type="document", source_id=pid, trust_level=trust, origin_actor="x",
        retrieved_via="tool", sensitivity=sensitivity))


def item(role: str, content: str, *pids: str, kind: str = "tool_result") -> ConversationItem:
    return ConversationItem(role=role, kind=kind, content=content, provenance_ids=list(pids))


def tool(name: str, **arguments: object) -> CandidateAction:
    return CandidateAction(type="tool_call", tool=name, arguments=arguments)  # type: ignore[arg-type]


def request(goal: str, action: CandidateAction, conversation=None, provenance=None, policy=None,
            step: int = 2, run: str = "run-1", turn: int = 0, confirmations=None) -> DefenseRequest:
    return DefenseRequest(
        run_id=run, step_id=step, user_goal=goal,
        conversation=conversation or [item("user", goal, "p-user", kind="user_message")],
        candidate_action=action, policy_context=policy or POLICY,
        provenance=[prov("p-user", "authenticated_user")] + list(provenance or []),
        history_digest=HistoryDigest(turn_index=turn, confirmations_granted=list(confirmations or [])),
    )


@pytest.fixture()
def guard() -> GuardDefense:
    return GuardDefense(config=Config())
