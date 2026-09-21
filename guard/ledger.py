"""Per-run state.

One `DefenseRequest` carries only the last 12 conversation items, each cut to 2,000 characters, and its
turn-level trust summary resets every turn. The ledger therefore accumulates what the defense has seen for the
whole run: which values trusted sources establish, which secrets were read, and what untrusted content said.

Evidence classes for a conversation item:
* the user            -> trusted (the authenticated user speaking)
* a provenance-free tool item -> trusted (a receipt for a call the monitor already authorized, e.g. an id minted
  by a "prepare" step)
* an item whose provenance ids are ALL trusted -> trusted
* any item with an untrusted or MIXED provenance (e.g. a tool result carrying an untrusted text field, or
  recalled memory with one poisoned entry) -> untrusted as a whole
* agent- or safety-authored text (no provenance) -> ignored: it may paraphrase injected text
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict

from guard import dlp, textnorm
from guard.models import CandidateAction, ConversationItem, DefenseRequest
from guard.trust import GOVERNED, SENSITIVITY_RANK, UNTRUSTED, ProvenanceIndex

ID_SHAPE = re.compile(r"\b[A-Z]{2,6}-\d{2,4}\b")
EMAIL_ANY = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_WORD = re.compile(r"[a-z0-9][a-z0-9\-\.]{2,}")
_PART_MARK = re.compile(r"\[part \d+/\d+\]")
_STOP = frozenset(
    "the and for with from that this your our are was were has have had not but all any can will would "
    "should could about into onto over under than then them they their there here what which who whom whose "
    "when where why how also please just only very more most some such each every other another".split()
)
DIRECTIVE_WINDOW = 500
MAX_RUNS = 64


def atoms_of(text: str) -> set[str]:
    """Identifier-like values in a text: object ids and e-mail addresses (lowercased)."""
    text = textnorm.clean(text)
    return {m.lower() for m in ID_SHAPE.findall(text)} | {m.lower() for m in EMAIL_ANY.findall(text)}


def content_words(text: str) -> set[str]:
    words = set()
    for raw in _WORD.findall(textnorm.clean(text).lower()):
        word = raw.rstrip(".-")
        pieces = {word} | {p for p in re.split(r"[-.]", word) if len(p) >= 3}
        for piece in pieces:
            if piece.endswith("s") and len(piece) > 4:
                piece = piece[:-1]
            if len(piece) >= 3 and piece not in _STOP:
                words.add(piece)
    return words


def fingerprint(item: ConversationItem) -> str:
    """Content plus provenance, so the same item seen as the observation and in the window counts once."""
    digest = hashlib.sha256(item.content.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{digest}|{','.join(item.provenance_ids)}"


class RunState:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.last_step = 0
        self.seen: set[str] = set()
        self.trusted_atoms: set[str] = set()
        self.trusted_words: set[str] = set()
        self.untrusted: list[tuple[int, str, str]] = []  # (turn first seen, role, expanded text)
        self.secrets: dict[str, str] = {}
        self.contaminated_at: int | None = None
        self._corpus_cache: dict[int, str] = {}

    # ---- ingestion --------------------------------------------------------------------------
    def classify(self, item: ConversationItem, index: ProvenanceIndex) -> str:
        if item.role == "user":
            return "trusted"
        if not item.provenance_ids:
            return "trusted" if item.role == "tool" else "ignored"
        return "trusted" if index.fully_trusted(item) else "untrusted"

    def absorb(self, request: DefenseRequest, index: ProvenanceIndex) -> None:
        self._add_trusted(request.user_goal)
        items = list(request.conversation)
        if request.observation is not None:
            items.append(ConversationItem(role="observation", kind=request.observation.kind,
                                          content=request.observation.content,
                                          provenance_ids=request.observation.provenance_ids))
        for item in items:
            key = fingerprint(item)
            if key in self.seen:
                continue
            self.seen.add(key)
            kind = self.classify(item, index) if item.role != "observation" else self._classify_observation(item, index)
            if kind == "ignored":
                continue
            if kind == "trusted":
                self._add_trusted(item.content)
            else:
                self.untrusted.append((request.history_digest.turn_index, item.role, textnorm.expand(item.content)))
                self._corpus_cache.clear()
                if self.contaminated_at is None and any(index.trust.get(p) in UNTRUSTED for p in item.provenance_ids):
                    self.contaminated_at = request.step_id
            sensitivity = index.item_sensitivity(item)
            if sensitivity in GOVERNED:
                for token in dlp.candidate_secrets(item.content):
                    current = self.secrets.get(token)
                    if current is None or SENSITIVITY_RANK[sensitivity] > SENSITIVITY_RANK[current]:
                        self.secrets[token] = sensitivity

    def _classify_observation(self, item: ConversationItem, index: ProvenanceIndex) -> str:
        if not item.provenance_ids:
            return "ignored"  # its role is unknown here; the same text also appears in the conversation window
        return "trusted" if index.fully_trusted(item) else "untrusted"

    def _add_trusted(self, text: str) -> None:
        self.trusted_atoms |= atoms_of(text)
        self.trusted_words |= content_words(text)

    # ---- queries ----------------------------------------------------------------------------
    def grounded(self, value: str, goal: str) -> bool:
        key = value.strip().lower()
        return key in self.trusted_atoms or key in atoms_of(goal)

    def overlap(self, text: str, goal: str) -> float:
        words = content_words(text)
        if not words:
            return 1.0
        known = self.trusted_words | content_words(goal)
        return len(words & known) / len(words)

    def corpus_for(self, turn: int) -> str:
        """Untrusted content that can be steering the agent right now: what it read this turn, plus recalled memory.

        Content read in an earlier turn only matters again through memory, which the memory rule guards; scoping
        the corpus this way keeps an honest call from being mistaken for an old payload that merely names it.
        """
        if turn not in self._corpus_cache:
            texts = [t for seen, role, t in self.untrusted if seen == turn or role == "memory"]
            self._corpus_cache[turn] = textnorm.squash(" ".join(_PART_MARK.sub(" ", t) for t in texts))
        return self._corpus_cache[turn]

    def directive_match(self, action: CandidateAction, turn: int) -> str | None:
        """A span of untrusted content in which this call's tool name and an argument value co-occur."""
        tool = (action.tool or "").lower()
        corpus = self.corpus_for(turn)
        if not tool or not corpus:
            return None
        values = [textnorm.squash(str(v)) for v in action.arguments.values() if isinstance(v, str) and len(v.strip()) >= 4]
        for needle in {tool, tool.replace("_", " ")}:
            start = corpus.find(needle)
            while start != -1:
                window = corpus[start : start + DIRECTIVE_WINDOW]
                if not values or any(v in window for v in values):
                    return window[:160]
                start = corpus.find(needle, start + 1)
        return None


class RunRegistry:
    """Bounded LRU of per-run state. `run_id` is stable across re-runs of a scenario, so state resets whenever
    the step counter restarts."""

    def __init__(self, capacity: int = MAX_RUNS) -> None:
        self._runs: OrderedDict[str, RunState] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    def get(self, request: DefenseRequest) -> RunState:
        with self._lock:
            run = self._runs.get(request.run_id)
            if run is None or request.step_id <= 1 or request.step_id < run.last_step:
                run = RunState(request.run_id)
                self._runs[request.run_id] = run
            self._runs.move_to_end(request.run_id)
            while len(self._runs) > self._capacity:
                self._runs.popitem(last=False)
            run.last_step = request.step_id
            return run

    def clear(self) -> None:
        with self._lock:
            self._runs.clear()
