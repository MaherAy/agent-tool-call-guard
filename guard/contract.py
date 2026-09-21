"""The authorization contract, compiled from the trusted user goal (and nothing else).

The contract only ever *narrows* what policy allows: `allowed_tools` stays the ceiling, because in a direct
instruction the goal itself is what asks for the forbidden tool. It answers two questions:

* Did the goal rule this verb out ("do not confirm or execute")?
* For a consequential tool, did the goal actually ask for it?

Cue matching is lexical and deliberately small; unusual goal phrasing is a known limitation (see README).
Only consequential tools are hard-gated by a missing cue: an ordinary write without a cue is a soft signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guard.textnorm import clean

NEGATORS = re.compile(r"\b(?:do not|don't|dont|never|without|must not|should not|no need to)\b", re.IGNORECASE)
SENTENCES = re.compile(r"(?<=[.!?;])\s+|\n+")  # not inside addresses or decimals

# Verb -> word stems that express it in a goal.
VERB_STEMS: dict[str, tuple[str, ...]] = {
    "send": ("send", "forward"),
    "confirm": ("confirm",),
    "execute": ("execut",),
    "close": ("clos", "resolv"),
}
# Soft cues for ordinary writes.
WRITE_STEMS: dict[str, tuple[str, ...]] = {
    "draft": ("draft", "reply", "compos", "write"),
    "create": ("creat", "open", "log", "file", "add", "record", "note"),
    "update": ("updat", "set", "add", "chang", "mark", "note"),
    "prepare": ("prepar",),
}
READ_RE = re.compile(r"_(?:read|search|lookup|summary)$")
CLOSING_STATUS = frozenset({"closed", "resolved"})


def is_read_tool(tool: str | None, consequential: set[str]) -> bool:
    return bool(tool) and tool not in consequential and bool(READ_RE.search(tool or ""))


def closes(action_arguments: dict[str, object]) -> bool:
    status = action_arguments.get("status")
    return isinstance(status, str) and status.strip().lower() in CLOSING_STATUS


def verb_of(tool: str | None, arguments: dict[str, object], consequential: bool) -> str | None:
    """The verb a tool call performs, if it is one the goal can rule in or out."""
    if not tool:
        return None
    last = tool.split("_")[-1]
    if last in VERB_STEMS and last != "close":
        return last
    if closes(arguments):
        return "close"
    if consequential:
        return last  # unmapped consequential verb: its own stem is the cue
    return None


def _stems_for(verb: str) -> tuple[str, ...]:
    return VERB_STEMS.get(verb) or (verb[:5],)


@dataclass(frozen=True)
class Contract:
    goal: str
    affirmed: frozenset[str] = field(default_factory=frozenset)
    negated: frozenset[str] = field(default_factory=frozenset)
    _text: str = ""

    def cued(self, verb: str, tool: str | None = None) -> bool:
        """The goal asks for this verb (or names the tool outright) somewhere outside a negation."""
        if verb in self.affirmed:
            return True
        if tool and _unnegated_occurrence(self._text, re.escape(tool.lower())):
            return True
        return bool(_unnegated_occurrence(self._text, "|".join(re.escape(s) + r"\w*" for s in _stems_for(verb))))

    def ruled_out(self, verb: str) -> bool:
        return verb in self.negated and not self.cued(verb)

    def soft_cue(self, tool: str | None) -> bool:
        """Whether the goal plausibly asks for this write (only ever a soft signal)."""
        if not tool:
            return False
        parts = tool.lower().split("_")
        stems: set[str] = set()
        for stem in WRITE_STEMS.get(parts[-1], (parts[-1][:5],)):
            stems.add(stem)
        stems.update(p for p in parts[:-1] if len(p) >= 4 and p != "email")
        text = self._text
        return any(re.search(rf"\b{re.escape(s)}\w*", text) for s in stems)


def _sentences(text: str) -> list[str]:
    return [s for s in SENTENCES.split(text) if s.strip()]


def _unnegated_occurrence(text: str, pattern: str) -> bool:
    """True if `pattern` occurs in a sentence at a position not preceded by a negator in that sentence."""
    for sentence in _sentences(text):
        negator = NEGATORS.search(sentence)
        for match in re.finditer(rf"\b(?:{pattern})", sentence):
            if negator is None or match.start() < negator.start():
                return True
    return False


def _negated_occurrence(text: str, pattern: str) -> bool:
    for sentence in _sentences(text):
        negator = NEGATORS.search(sentence)
        if negator is None:
            continue
        if re.search(rf"\b(?:{pattern})", sentence[negator.start():]):
            return True
    return False


def compile_contract(goal: str) -> Contract:
    text = clean(goal).lower()
    affirmed: set[str] = set()
    negated: set[str] = set()
    for verb, stems in VERB_STEMS.items():
        pattern = "|".join(re.escape(s) + r"\w*" for s in stems)
        if _unnegated_occurrence(text, pattern):
            affirmed.add(verb)
        if _negated_occurrence(text, pattern):
            negated.add(verb)
    return Contract(goal=goal, affirmed=frozenset(affirmed), negated=frozenset(negated), _text=text)
