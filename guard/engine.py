"""The decision engine: an action runs only if trusted evidence explains it.

Order of checks (first hit wins; every decision carries a rule id and reason codes):

  R1  tool ceiling        the tool must be in the policy's allowed_tools
  R2  goal negation       the user's goal ruled this verb out ("do not confirm or execute")
  R5  goal justification  a consequential tool must actually be asked for in the goal
  R6  argument grounding  ids and external recipients of a write must come from trusted evidence
  R7  reconstruction      a read that mirrors an instruction found in untrusted content and is not explained
                          by trusted evidence
  R8  memory rule         memory holds facts, not instructions or authority
  R4  data flow           a protected value may not reach a destination its sensitivity disallows (redacted)
  R9  human confirmation  a consequential action needs a recorded confirmation

Each layer can be switched off with GUARD_DISABLE=contract,grounding,dlp,reconstruction,memory_rules so every
component has an ablation row.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from guard import dlp, memory
from guard.contract import closes, compile_contract, is_read_tool, verb_of
from guard.ledger import RunRegistry, RunState
from guard.models import CandidateAction, DefenseDecision, DefenseRequest
from guard.telemetry import Telemetry
from guard.trace import Trace
from guard.trust import ProvenanceIndex

LAYERS = ("contract", "grounding", "dlp", "reconstruction", "memory_rules")


@dataclass(frozen=True)
class Config:
    contract: bool = True
    grounding: bool = True
    dlp: bool = True
    reconstruction: bool = True
    memory_rules: bool = True

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
            metadata={"rule": self.rule},
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

    def __init__(self, config: Config | None = None, trace: Trace | None = None,
                 telemetry: Telemetry | None = None) -> None:
        self.config = config or Config.from_env()
        self.trace = trace or Trace(None)
        self.telemetry = telemetry or Telemetry()
        self.registry = RunRegistry()
        self._lock = threading.Lock()

    # ---- public ------------------------------------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        started = time.perf_counter()
        with self._lock:
            state = self.registry.get(request)
            state.absorb(request, ProvenanceIndex(request))
            verdict = self._evaluate(request, state)
            self._record(request, state, verdict, (time.perf_counter() - started) * 1000)
        return verdict.to_decision()

    # ---- rules -------------------------------------------------------------------------------
    def _evaluate(self, request: DefenseRequest, state: RunState) -> Verdict:
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
        return Verdict("allow", risk, 0.70, codes, "No rule objected.", "R0")

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
        if self.trace.path is None and not self.telemetry.enabled:
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
            "explanation": verdict.explanation,
            "evidence": evidence,
            "confirmed": action_digest(target) in request.history_digest.confirmations_granted,
            "layers": {name: getattr(self.config, name) for name in LAYERS},
            "context": self._context(request, state),
            "latency_ms": round(latency_ms, 3),
        }
        self.trace.append(record)
        self.telemetry.emit(record)
