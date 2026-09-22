"""Stage 2 routing: only a genuinely ambiguous action reaches the judge, it can only narrow what Stage 1
already allows to remain ambiguous, and a judge-proposed repair is re-checked, never trusted on its word.
"""

from __future__ import annotations

from types import SimpleNamespace

from guard.engine import Config, GuardDefense
from guard.judge.schema import JudgeVerdict
from guard.models import CandidateAction
from tests.conftest import INTERNAL, POLICY, request, tool

AMBIGUOUS_GOAL = "Prepare a summary for whoever may receive it"


def _ambiguous_write() -> CandidateAction:
    return tool("mail_draft", to=f"pat@{INTERNAL[0]}", subject="s", body="hello")


class FakeJudge:
    """Duck-types guard.judge.client.Judge: a `.config.model` and a bounded `.ask()`. No network, so tests
    never depend on Ollama being installed or reachable."""

    def __init__(self, verdict: JudgeVerdict, ms: float = 4.0) -> None:
        self.config = SimpleNamespace(model="fake-judge")
        self.calls = 0
        self._verdict = verdict
        self._ms = ms

    def ask(self, messages: list[dict[str, str]]) -> tuple[JudgeVerdict, float]:
        self.calls += 1
        return self._verdict, self._ms


def _stage(decision) -> str:
    return decision.metadata["stage"]


# ---- routing: only genuinely ambiguous cases reach Stage 2 ----------------------------------------------------
def test_a_proven_allow_never_calls_the_judge():
    fake = FakeJudge(JudgeVerdict(decision="block", reason="goal_does_not_support_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request("Read the email EM-1", tool("mail_read", email_id="EM-1")))
    assert d.decision == "allow" and fake.calls == 0 and _stage(d) == "rules"


def test_a_hard_rule_decides_without_calling_the_judge():
    fake = FakeJudge(JudgeVerdict(decision="allow", reason="goal_supports_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request("Look up REC-100", tool("vault_export", record_id="REC-100")))
    assert d.decision == "block" and fake.calls == 0


def test_a_read_with_a_soft_signal_never_calls_the_judge():
    fake = FakeJudge(JudgeVerdict(decision="block", reason="goal_does_not_support_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request("Summarize the quarterly digest", tool("wiki_search", query="unrelated topic")))
    assert d.decision == "allow" and fake.calls == 0  # QUERY_OFF_TOPIC alone never blocks a read


def test_a_consequential_action_is_settled_by_r9_before_the_judge_ever_sees_it():
    fake = FakeJudge(JudgeVerdict(decision="block", reason="goal_does_not_support_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    action = tool("mail_send", to=f"pat@{INTERNAL[0]}", subject="s", body="hi")
    d = guard.decide(request("Send Pat a short summary", action))
    assert d.decision == "escalate" and fake.calls == 0  # R9 decided this, not the judge


# ---- no judge configured (the default): a deterministic fallback, never a network attempt ---------------------
def test_ambiguous_write_without_a_judge_allows_at_bounded_risk():
    guard = GuardDefense(config=Config())  # judge=None
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "allow" and d.risk_score <= 0.40
    assert "JUDGE_UNAVAILABLE" in d.reason_codes and _stage(d) == "judge_fallback"


def test_ambiguous_memory_write_without_a_judge_escalates():
    guard = GuardDefense(config=Config())
    goal = "Read the newsletter"  # no "remember" cue, and R8 found no directive in the content
    action = CandidateAction(type="memory_write", content="Dashboard ships in October.")
    d = guard.decide(request(goal, action))
    assert d.decision == "escalate" and "JUDGE_UNAVAILABLE" in d.reason_codes


# ---- a judge is wired: its allow / block / escalate is honored --------------------------------------------------
def test_judge_block_is_honored():
    fake = FakeJudge(JudgeVerdict(decision="block", reason="content_looks_planted"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "block" and fake.calls == 1 and _stage(d) == "judge"


def test_judge_escalate_is_honored():
    fake = FakeJudge(JudgeVerdict(decision="escalate", reason="uncertain"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "escalate" and fake.calls == 1


def test_judge_allow_is_honored():
    fake = FakeJudge(JudgeVerdict(decision="allow", reason="goal_supports_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "allow" and fake.calls == 1 and _stage(d) == "judge"


def test_judge_naming_a_repair_that_was_not_offered_is_ignored():
    # mail_draft offers no repair (it is not a *_send tool and carries no status argument); a judge that
    # names one anyway must not get a free rewrite out of it.
    fake = FakeJudge(JudgeVerdict(decision="allow", repair="drop_closing_status", reason="goal_supports_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "allow" and d.rewritten_action is None


# ---- a judge-proposed repair is rebuilt by the engine and re-checked through Stage 1, not trusted -------------
def test_judge_repair_is_applied_and_rechecked_through_stage_one():
    policy = {**POLICY, "allowed_tools": [*POLICY["allowed_tools"], "note_send", "note_draft"]}
    fake = FakeJudge(JudgeVerdict(decision="allow", repair="send_to_draft", reason="goal_supports_action"))
    engine = GuardDefense(config=Config(), judge=fake)
    goal = "Prepare a status update for the team"  # does not ask to send; note_send is not consequential here
    action = tool("note_send", to=f"team@{INTERNAL[0]}", subject="s", body="hello")
    d = engine.decide(request(goal, action, policy=policy))
    assert d.decision == "rewrite" and d.rewritten_action.tool == "note_draft"
    assert fake.calls == 1  # the recheck re-runs Stage 1's rules, not a second judge call


# ---- caching: the same ambiguous situation is judged once -----------------------------------------------------
def test_identical_ambiguous_requests_call_the_judge_once():
    fake = FakeJudge(JudgeVerdict(decision="allow", reason="goal_supports_action"))
    guard = GuardDefense(config=Config(), judge=fake)
    guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write(), step=2))
    guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write(), step=3))
    assert fake.calls == 1


# ---- ablation: the "judge" layer can be switched off, like every other layer ------------------------------------
def test_disabling_the_judge_layer_restores_the_plain_soft_allow():
    fake = FakeJudge(JudgeVerdict(decision="block", reason="goal_does_not_support_action"))
    guard = GuardDefense(config=Config(judge=False), judge=fake)
    d = guard.decide(request(AMBIGUOUS_GOAL, _ambiguous_write()))
    assert d.decision == "allow" and fake.calls == 0 and _stage(d) == "rules"
