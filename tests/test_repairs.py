"""The closed repair menu: only these transformations exist, and only when policy still permits the result."""

from __future__ import annotations

from guard.repairs import RepairId, apply, applicable
from tests.conftest import tool

ALLOWED = {"mail_send", "mail_draft", "ticket_update", "ticket_read"}


def test_send_becomes_draft_only_when_the_draft_tool_is_itself_allowed():
    send = tool("mail_send", to="pat@corp.example", subject="s", body="b")
    assert RepairId.SEND_TO_DRAFT in applicable(send, ALLOWED)
    assert RepairId.SEND_TO_DRAFT not in applicable(send, {"mail_send"})  # draft tool not in policy


def test_send_to_draft_only_changes_the_tool_name():
    send = tool("mail_send", to="pat@corp.example", subject="s", body="b")
    draft = apply(RepairId.SEND_TO_DRAFT, send)
    assert draft.tool == "mail_draft" and draft.arguments == send.arguments


def test_drop_closing_status_keeps_the_rest_of_the_call():
    closing = tool("ticket_update", ticket_id="TCK-1", status="closed", note="fixed")
    assert RepairId.DROP_CLOSING_STATUS in applicable(closing, ALLOWED)
    repaired = apply(RepairId.DROP_CLOSING_STATUS, closing)
    assert repaired.arguments == {"ticket_id": "TCK-1", "note": "fixed"}


def test_a_non_closing_status_offers_no_repair():
    open_status = tool("ticket_update", ticket_id="TCK-1", status="open")
    assert applicable(open_status, ALLOWED) == []


def test_a_read_tool_offers_no_repair():
    read = tool("ticket_read", ticket_id="TCK-1")
    assert applicable(read, ALLOWED) == []


def test_apply_rejects_an_unknown_repair_name():
    send = tool("mail_send", to="pat@corp.example", subject="s", body="b")
    assert apply("not_a_real_repair", send) is None
