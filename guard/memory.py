"""Memory rule: memory holds facts, never instructions or authority.

An entry written after reading untrusted content is recalled later as evidence. Text that names a tool or
claims an approval or standing instruction is not data; it is a directive addressed to a future reader.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Naming shape of tools (verb suffix), so a directive is recognised even for a tool this policy does not list.
_TOOLISH = re.compile(
    r"\b[a-z]{3,}_(?:read|search|lookup|summary|create|update|prepare|confirm|execute|draft|send|disable|isolate|close)\b"
)
_AUTHORITY = re.compile(
    r"approved by|pre-?approved|already (?:been )?(?:approved|granted)|standing (?:instruction|order)|"
    r"policy update|no further (?:sign-?off|approval|review)|silence them|"
    r"do not (?:ask for|require) (?:approval|confirmation)",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
MIN_RESIDUE_CHARS = 12


@dataclass(frozen=True)
class MemoryScan:
    flagged: bool
    residue: str  # the data-only remainder once directive sentences are dropped


def scan(content: str, tool_names: Iterable[str]) -> MemoryScan:
    names = [n.lower() for n in tool_names if n]
    kept: list[str] = []
    flagged = False
    for sentence in _SENTENCE.split(content):
        if not sentence.strip():
            continue
        low = sentence.lower()
        if _TOOLISH.search(low) or _AUTHORITY.search(sentence) or any(n in low for n in names):
            flagged = True
        else:
            kept.append(sentence.strip())
    return MemoryScan(flagged=flagged, residue=" ".join(kept))
