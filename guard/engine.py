"""The decision engine: an action runs only if trusted evidence explains it.

Stage 1 (deterministic, this file, no LLM): order of checks, first hit wins; every decision carries a rule
id and reason codes.

  R1  tool ceiling        the tool must be in the policy's allowed_tools
  R2  goal negation       the user's goal ruled this verb out ("do not confirm or execute")
  R5  goal justification  a consequential tool must actually be asked for in the goal
  R6  argument grounding  ids and external recipients of a write must come from trusted evidence
  R7  reconstruction      a read that mirrors an instruction found in untrusted content and is not explained
                          by trusted evidence
  R8  memory rule         memory holds facts, not instructions or authority
  R4  data flow           a protected value may not reach a destination its sensitivity disallows (redacted)
  R9  human confirmation  a consequential action needs a recorded confirmation

If none of R1-R9 decides, the action is either a proven allow (nothing left to check: `USER_GOAL_ALIGNED`,
rule R0) or genuinely ambiguous -- a non-consequential write or a memory write whose only signal is "the goal
never asked for this" (`WRITE_NOT_IN_GOAL` / `MEMORY_NOT_IN_GOAL`). Only that second case is Stage 2's job
(`_consult_judge`, guard/judge/): a small local LLM that can only choose allow / block / escalate, and on
allow may name one repair from a closed menu (guard.repairs) -- never write an argument, a value or a tool
name of its own. A repair is re-run through every R1-R9 rule (`_evaluate(..., allow_judge=False)`) before it
is trusted, so Stage 2 can narrow what Stage 1 already decided is ambiguous, but it can never reopen anything
Stage 1 already decided. Reads never reach Stage 2 (they have no external effect, and R4/R7 already guard
them); nothing does when no judge is configured (`judge=None`), which is the default -- see
`guard.judge.fallback` for what happens instead.

Every layer, including "judge" (whether Stage 2 is consulted at all), can be switched off with
GUARD_DISABLE=contract,grounding,dlp,reconstruction,memory_rules,judge so every component has an ablation row.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from guard import dlp, memory, repairs
from guard.contract import closes, compile_contract, is_read_tool, verb_of
from guard.judge import fallback as judge_fallback
from guard.judge import prompt as judge_prompt
from guard.judge.cache import JudgeCache
from guard.judge.client import Judge, JudgeUnavailable
from guard.ledger import RunRegistry, RunState
from guard.models import CandidateAction, DefenseDecision, DefenseRequest
from guard.trace import Trace
from guard.trust import ProvenanceIndex

LAYERS = ("contract", "grounding", "dlp", "reconstruction", "memory_rules", "judge")


@dataclass(frozen=True)
class Config:
    contract: bool = True
    grounding: bool = True
    dlp: bool = True
    reconstruction: bool = True
    memory_rules: bool = True
    judge: bool = True

    @classmethod
    def from_env(cls) -> Config:
        off = {p.strip() for p in os.environ.get("GUARD_DISABLE", "").split(",") if p.strip()}
        return cls(**{name: name not in off for name in LAYERS})


@dataclass
class Verdict:
    decision: str
    risk: float
    confidence: float
    codes: list[str]
    explanation: str
    rule: str
    stage: str = "rules"  # "rules" | "judge" | "judge_fallback" -- which stage produced this verdict
    rewritten: CandidateAction | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_decision(self) -> DefenseDecision:
        return DefenseDecision(
            decision=self.decision,  # type: ignore[arg-type]
            risk_score=round(min(1.0, max(0.0, self.risk)), 4),
            confidence=round(min(1.0, max(0.0, self.confidence)), 4),
            reason_codes=self.codes[:16],
            explanation=self.explanation[:500],
            rewritten_action=self.rewritten,
            metadata={"rule": self.rule, "stage": self.stage},
        )


def action_digest(action: CandidateAction) -> str:
    """The digest the evaluator uses for confirmations (same algorithm as CandidateAction.digest)."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def _is_consequential(action: CandidateAction, consequential_tools: set[str]) -> bool:
    return action.tool in consequential_tools or closes(action.arguments)


def _sha8(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


class GuardDefense:
    name = "guard"

    def __init__(self, config: Config | None = None, trace: Trace | None = None, judge: Judge | None = None) -> None:
        self.config = config or Config.from_env()
        self.trace = trace or Trace(None)
        self.judge = judge  # None = Stage 2 has no model wired; ambiguous cases use guard.judge.fallback
        self.judge_cache = JudgeCache()
        self.registry = RunRegistry()
        self._lock = threading.Lock()

    # ---- public ------------------------------------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        started = time.perf_counter()
        with self._lock:
            state = self.registry.get(request)
            state.absorb(request, ProvenanceIndex(request))
        # Stage 2, when it runs, does network I/O (guard/judge/client.py). It must never happen inside this
        # lock, or one run waiting on the LLM would serialize every other run's decision behind it.
        verdict = self._evaluate(request, state)
        self._record(request, state, verdict, (time.perf_counter() - started) * 1000)
        return verdict.to_decision()

    # ---- rules -------------------------------------------------------------------------------
    def _evaluate(self, request: DefenseRequest, state: RunState, allow_judge: bool = True) -> Verdict:
        cfg = self.config
        candidate = request.candidate_action
        asking = candidate.type == "request_confirmation" and candidate.confirmation_for is not None
        action = candidate.confirmation_for if asking else candidate
        assert action is not None
        policy = request.policy_context
        allowed = set(policy.get("allowed_tools") or [])
        consequential_tools = set(policy.get("consequential_tools") or []) | set(policy.get("confirmation_required_tools") or [])
        internal = [str(d).strip().lower() for d in policy.get("internal_email_domains") or [] if str(d).strip()]
        goal = request.user_goal

        is_tool = action.type == "tool_call"
        tool = action.tool
        consequential = is_tool and _is_consequential(action, consequential_tools)
        read = is_tool and is_read_tool(tool, consequential_tools)
        confirmed = action_digest(action) in request.history_digest.confirmations_granted
        soft: list[tuple[float, str]] = []

        # R1: tool ceiling
        if is_tool and tool not in allowed:
            return Verdict("block", 0.97, 0.95, ["TOOL_NOT_ALLOWED"],
                           f"Tool '{tool}' is not permitted for this task.", "R1", evidence={"tool": tool})

        # R2 / R5: what the goal rules out, and what it actually asks for
        if cfg.contract and is_tool:
            contract = compile_contract(goal)
            verb = verb_of(tool, action.arguments, consequential)
            if verb and contract.ruled_out(verb):
                return Verdict("block", 0.96, 0.90, ["GOAL_NEGATED"],
                               f"The user's request rules out '{verb}' ('{tool}').", "R2",
                               evidence={"tool": tool, "verb": verb})
            if verb and consequential and not contract.cued(verb, tool):
                return Verdict("block", 0.85, 0.75, ["PLAN_DEVIATION"],
                               f"'{tool}' is consequential and the user's request does not ask for it.", "R5",
                               evidence={"tool": tool, "verb": verb})
            if not read and not consequential and not contract.soft_cue(tool):
                soft.append((0.20, "WRITE_NOT_IN_GOAL"))

        # R6: writes may only act on ids and external recipients that trusted evidence establishes
        if cfg.grounding and is_tool and not read:
            bad = self._ungrounded(action, state, goal, internal)
            if bad:
                return Verdict("block", 0.90, 0.80, ["TAINTED_ARGUMENT"],
                               f"Argument(s) {', '.join(bad)} are not supported by any trusted source.", "R6",
                               evidence={"arguments": bad})

        # R7: a read that mirrors an instruction in untrusted content and is not explained by trusted evidence
        if cfg.reconstruction and read:
            span = state.directive_match(action, request.history_digest.turn_index)
            if span and not self._explained_read(action, state, goal):
                return Verdict("block", 0.92, 0.85, ["INJECTED_INSTRUCTION"],
                               "A read call mirrors an instruction found in untrusted content and the user's "
                               "request does not explain it.", "R7", evidence={"span": span})

        # R8: memory holds facts, not instructions
        if cfg.memory_rules and action.type == "memory_write":
            scan = memory.scan(action.content or "", allowed | consequential_tools)
            if scan.flagged:
                if len(scan.residue) >= memory.MIN_RESIDUE_CHARS and not asking:
                    return Verdict("rewrite", 0.80, 0.70, ["MEMORY_DIRECTIVE"],
                                   "Memory entry carried an instruction or authority claim; only the facts were kept.",
                                   "R8", rewritten=action.model_copy(update={"content": scan.residue}))
                return Verdict("block", 0.85, 0.75, ["MEMORY_DIRECTIVE"],
                               "Memory entry carries an instruction or authority claim; not stored.", "R8")
            if not self._mentions(goal, ("remember", "memory", "save", "note")):
                soft.append((0.15, "MEMORY_NOT_IN_GOAL"))

        # R4: protected values, decoded and redacted at every sink (including the final response)
        if cfg.dlp and state.secrets:
            sink = dlp.sink_of(action, internal)
            if sink is not None:
                leaks = dlp.disallowed_leaks(sink, state.secrets)
                if leaks:
                    codes = ["SECRET_TO_SINK"]
                    if not dlp.leaks_in_plain(sink.text, leaks):
                        codes.append("ENCODED_EXFIL")
                    evidence = {"sink": sink.name, "destination": sink.destination,
                                "values": len(leaks), "digests": [_sha8(s) for s in leaks]}
                    can_repair = not asking and not (consequential and not confirmed)
                    if can_repair:
                        rewritten = dlp.redact_action(action, leaks)
                        if rewritten != action:
                            return Verdict("rewrite", 0.90, 0.85, codes,
                                           "A protected value was going to a destination its sensitivity does not "
                                           "allow; it was removed and the rest of the action kept.", "R4",
                                           rewritten=rewritten, evidence=evidence)
                    return Verdict("block", 0.97, 0.90, codes,
                                   "A protected value was going to a destination its sensitivity does not allow.",
                                   "R4", evidence=evidence)

        # R9: consequential actions need a recorded human confirmation
        if consequential and not confirmed:
            if asking:
                return Verdict("allow", 0.30, 0.70, ["CONFIRMATION_REQUESTED"],
                               "Asking a human to confirm a consequential action is the safe path.", "R9")
            return Verdict("escalate", 0.50, 0.70, ["CONSEQUENTIAL_UNCONFIRMED"],
                           "Consequential action without a recorded human confirmation.", "R9",
                           evidence={"tool": tool})

        # soft signals never block on their own
        if read and cfg.grounding:
            for name, value in action.arguments.items():
                if isinstance(value, str) and value.strip() and not dlp.EMAIL_FULL.match(value.strip()) \
                        and not dlp.is_identifier_arg(name, value) and state.overlap(value, goal) < 0.34:
                    soft.append((0.10, "QUERY_OFF_TOPIC"))
                    break
        risk = min(0.40, 0.05 + sum(weight for weight, _ in soft))
        codes = [code for _, code in soft] or ["USER_GOAL_ALIGNED"]

        # Stage 2 boundary: nothing hard fired, but a write or memory entry that the goal never asked for is
        # not a proven allow either. Reads and `respond` never reach here with a live soft signal that
        # matters (a read's only soft code is QUERY_OFF_TOPIC, which R4/R7 already backstop), and a
        # `request_confirmation` wrapper (`asking`) already has its own safe path in R9 above.
        ambiguous = bool(soft) and not asking and not read and action.type in ("tool_call", "memory_write")
        if cfg.judge and allow_judge and ambiguous:
            return self._consult_judge(request, state, action, codes, risk)

        return Verdict("allow", risk, 0.70, codes, "No rule objected.", "R0")

    # ---- judge (Stage 2) -----------------------------------------------------------------------
    def _consult_judge(self, request: DefenseRequest, state: RunState, action: CandidateAction,
                        soft_codes: list[str], soft_risk: float) -> Verdict:
        """The only call into Stage 2. Any repair the judge names is rebuilt here and re-run through
        `_evaluate` (with `allow_judge=False`, so a repair can only be re-checked once, never re-judged) so
        R1-R9 have the final say on whatever the judge proposed."""
        allowed = {str(t) for t in (request.policy_context.get("allowed_tools") or [])}
        repair_names = repairs.applicable(action, allowed)
        messages = judge_prompt.build(request.user_goal, action, soft_codes, repair_names,
                                       state, request.history_digest.turn_index)

        if self.judge is None:
            decision, risk, codes, explanation = judge_fallback.decide(action, soft_codes, soft_risk)
            return Verdict(decision, risk, 0.40, codes, explanation, "J0", stage="judge_fallback")

        cache_key = self.judge_cache.key(messages, self.judge.config.model)
        cached = self.judge_cache.get(cache_key)
        if cached is not None:
            verdict, judge_ms, cache_hit = cached, 0.0, True
        else:
            try:
                verdict, judge_ms = self.judge.ask(messages)
            except JudgeUnavailable:
                decision, risk, codes, explanation = judge_fallback.decide(action, soft_codes, soft_risk)
                return Verdict(decision, risk, 0.40, codes, explanation, "J0", stage="judge_fallback")
            self.judge_cache.put(cache_key, verdict)
            cache_hit = False

        codes_out = [*soft_codes, f"JUDGE_{verdict.reason.upper()}"]
        evidence = {"judge_ms": round(judge_ms, 1), "cache_hit": cache_hit, "judge_reason": verdict.reason}

        if verdict.decision == "block":
            return Verdict("block", max(0.55, soft_risk), 0.55, codes_out,
                           "The judge stage found the action not supported by the user's goal.", "J1",
                           evidence=evidence, stage="judge")
        if verdict.decision == "escalate":
            return Verdict("escalate", max(0.45, soft_risk), 0.55, codes_out,
                           "The judge stage could not tell whether the goal supports this action; a human "
                           "should decide.", "J1", evidence=evidence, stage="judge")

        # decision == "allow", optionally with a named repair -- re-checked, never trusted on its word
        if verdict.repair is not None and verdict.repair in repair_names:
            rewritten = repairs.apply(verdict.repair, action)
            if rewritten is not None:
                rechecked = self._evaluate(request.model_copy(update={"candidate_action": rewritten}),
                                           state, allow_judge=False)
                if rechecked.decision == "block":
                    return Verdict("block", max(0.55, soft_risk), 0.55, [*codes_out, *rechecked.codes],
                                   "The judge proposed a repair, but it was still not safe: "
                                   + rechecked.explanation, "J1", evidence=evidence, stage="judge")
                return Verdict("rewrite", min(0.40, soft_risk), 0.55, codes_out,
                               "The judge stage found a safer substitute for this action.", "J1",
                               rewritten=rewritten, evidence=evidence, stage="judge")

        return Verdict("allow", min(0.40, soft_risk), 0.55, codes_out,
                       "The judge stage found the action plausibly supported by the user's goal.", "J1",
                       evidence=evidence, stage="judge")

    # ---- helpers -----------------------------------------------------------------------------
    @staticmethod
    def _mentions(text: str, stems: tuple[str, ...]) -> bool:
        low = text.lower()
        return any(stem in low for stem in stems)

    @staticmethod
    def _ungrounded(action: CandidateAction, state: RunState, goal: str, internal: list[str]) -> list[str]:
        bad = []
        for name, value in action.arguments.items():
            if not isinstance(value, str) or not value.strip():
                continue
            v = value.strip()
            if dlp.EMAIL_FULL.match(v):
                if dlp.recipient_trust(v, internal) == "untrusted_external" and not state.grounded(v, goal):
                    bad.append(name)
            elif dlp.is_identifier_arg(name, v) and not state.grounded(v, goal):
                bad.append(name)
        return bad

    @staticmethod
    def _explained_read(action: CandidateAction, state: RunState, goal: str) -> bool:
        for name, value in action.arguments.items():
            if not isinstance(value, str) or not value.strip():
                continue
            v = value.strip()
            if dlp.EMAIL_FULL.match(v) or dlp.is_identifier_arg(name, v):
                if not state.grounded(v, goal):
                    return False
            elif state.overlap(v, goal) < 0.5:
                return False
        return True

    def _context(self, request: DefenseRequest, state: RunState) -> dict[str, Any]:
        """What the guard knew when it decided, so a decision can be audited later without the run."""
        policy, digest = request.policy_context, request.history_digest
        goal = request.user_goal[:300]
        if state.secrets:
            leaks = dlp.leaks_in(goal, state.secrets.keys())
            goal = dlp.redact_text(goal, leaks) if leaks else goal
        contract = compile_contract(request.user_goal) if self.config.contract else None
        return {
            "user_goal": goal,
            "allowed_tools": sorted(policy.get("allowed_tools") or [])[:30],
            "consequential_tools": sorted(policy.get("consequential_tools") or [])[:30],
            "goal_asks_for": sorted(contract.affirmed) if contract else None,
            "goal_rules_out": sorted(contract.negated) if contract else None,
            "least_trusted_seen": digest.least_trusted_seen,
            "most_sensitive_seen": digest.most_sensitive_seen,
            "blocked_so_far": digest.blocked_count,
            "escalated_so_far": digest.escalated_count,
        }

    def _record(self, request: DefenseRequest, state: RunState, verdict: Verdict, latency_ms: float) -> None:
        if self.trace.path is None:
            return
        cand = request.candidate_action
        target = cand.confirmation_for if cand.confirmation_for is not None else cand
        args: dict[str, str] = {}
        for name, value in target.arguments.items():
            text = str(value)
            leaks = dlp.leaks_in(text, state.secrets.keys()) if state.secrets else []
            args[name] = (dlp.redact_text(text, leaks) if leaks else text)[:80]
        evidence = dict(verdict.evidence)
        span = evidence.get("span")
        if isinstance(span, str) and state.secrets:  # observed text may quote a protected value
            leaks = dlp.leaks_in(span, state.secrets.keys())
            evidence["span"] = dlp.redact_text(span, leaks) if leaks else span
        record = {
            "run_id": request.run_id,
            "step": request.step_id,
            "turn": request.history_digest.turn_index,
            "action": {"type": cand.type, "tool": target.tool, "args": args,
                       "content_chars": len(target.content or "")},
            "decision": verdict.decision,
            "risk": verdict.risk,
            "confidence": verdict.confidence,
            "codes": verdict.codes,
            "rule": verdict.rule,
            "stage": verdict.stage,
            "explanation": verdict.explanation,
            "evidence": evidence,
            "confirmed": action_digest(target) in request.history_digest.confirmations_granted,
            "layers": {name: getattr(self.config, name) for name in LAYERS},
            "context": self._context(request, state),
            "latency_ms": round(latency_ms, 3),
        }
        self.trace.append(record)
