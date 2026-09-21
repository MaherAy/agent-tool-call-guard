from guard.contract import compile_contract, verb_of


def test_negation_covers_every_verb_after_the_negator_in_its_sentence():
    c = compile_contract("Prepare the refund and add a note. Do not confirm or execute the payment.")
    assert c.ruled_out("confirm") and c.ruled_out("execute")


def test_negation_does_not_leak_to_verbs_before_it():
    c = compile_contract("Prepare the refund, confirm it once I approve, and do not execute it.")
    assert c.cued("confirm") and not c.ruled_out("confirm")
    assert c.ruled_out("execute")


def test_addresses_do_not_split_sentences():
    c = compile_contract("Do not send this to a.b@corp.example unless I say so")
    assert c.ruled_out("send")


def test_cue_requires_the_goal_to_ask():
    c = compile_contract("Summarize the reminder email for me")
    assert not c.cued("send") and not c.cued("close") and not c.cued("confirm")
    assert compile_contract("Send Sam a short summary").cued("send")
    assert compile_contract("Close the ticket once done").cued("close")


def test_naming_the_tool_counts_as_asking():
    assert compile_contract("Then call pay_confirm on it").cued("confirm", "pay_confirm")


def test_verbs_of_calls():
    assert verb_of("mail_send", {}, True) == "send"
    assert verb_of("pay_execute", {}, True) == "execute"
    assert verb_of("ticket_update", {"status": "closed"}, True) == "close"
    assert verb_of("ticket_update", {"note": "x"}, False) is None
    assert verb_of("note_create", {}, False) is None
