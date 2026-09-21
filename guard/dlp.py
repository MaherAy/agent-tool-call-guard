"""Data-flow protection: secret detection, sinks, leak checks and redaction.

A token counts as a secret when it *came from* a confidential or restricted observation **and** reads as a
credential by generic measures (length, character-class mix, entropy). No canary prefix or format is used
anywhere; detection is value-level, not record-level, because a task may legitimately answer from a
restricted record whose only real secret is one field inside it.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass

from guard import textnorm
from guard.models import CandidateAction
from guard.trust import allowed_at

EMAIL_FULL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ID_FULL = re.compile(r"^[A-Z]{2,6}-\d{2,4}$")
_WORD = re.compile(r"[^\s\"',;<>()\[\]{}]+")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([t ]\d{2}:\d{2}(:\d{2})?z?)?$", re.IGNORECASE)

MIN_SECRET_CHARS = 12
MIN_ENTROPY_BITS = 2.5
REDACTION = "[redacted]"


def shannon_bits(token: str) -> float:
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(token)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def secret_like(token: str) -> bool:
    """Generic credential-shape test. Rejects dates, ids, addresses and single-case prose."""
    if len(token) < MIN_SECRET_CHARS or _DATE.match(token) or EMAIL_FULL.match(token) or "://" in token:
        return False
    classes = sum((any(c.isupper() for c in token), any(c.islower() for c in token), any(c.isdigit() for c in token)))
    return classes >= 2 and shannon_bits(token) >= MIN_ENTROPY_BITS


def candidate_secrets(text: str) -> set[str]:
    """Secret-shaped tokens in an observation, including inside base64/hex/URL-encoded blobs."""
    text = textnorm.clean(text)[: textnorm.MAX_SCAN_CHARS]
    readings = [text, textnorm.expand(text, rounds=1)]
    found: set[str] = set()
    for reading in readings:
        for raw in _WORD.findall(reading):
            token = raw.strip(".,:;!?\"'")
            if secret_like(token):
                found.add(token)
    return found


def leaks_in(text: str, secrets: Iterable[str]) -> list[str]:
    """Which of `secrets` appear in `text` under any of the six readings."""
    needles = [(s, textnorm.alnum(s)) for s in secrets]
    needles = [(raw, norm) for raw, norm in needles if norm]
    if not needles:
        return []
    haystacks = [textnorm.alnum(variant) for _, variant in textnorm.variants(text)]
    return [raw for raw, norm in needles if any(norm in hay for hay in haystacks)]


def leaks_in_plain(text: str, leaks: Iterable[str]) -> bool:
    plain = textnorm.alnum(text)
    return any(textnorm.alnum(s) in plain for s in leaks)


def _spaced_pattern(secret: str) -> re.Pattern[str] | None:
    chars = [c for c in secret if c.isalnum()]
    if len(chars) < MIN_SECRET_CHARS - 4:
        return None
    return re.compile(r"[\W_]*".join(re.escape(c) for c in chars), re.IGNORECASE)


def redact_text(text: str, leaks: Iterable[str]) -> str:
    """Remove secret values from outbound text, keeping everything else.

    Plain and spacing/case variants are replaced in place; a base64 or hex blob that decodes to a secret has no
    meaningful partial form, so the whole blob goes. If a value is still detectable afterwards (url, rot13 or
    reversed carriers), the whole string is replaced.
    """
    leaks = sorted(set(leaks), key=len, reverse=True)
    out = text
    for secret in leaks:
        out = out.replace(secret, REDACTION)
        pattern = _spaced_pattern(secret)
        if pattern is not None:
            out = pattern.sub(REDACTION, out)
    needles = [textnorm.alnum(s) for s in leaks if textnorm.alnum(s)]
    for pattern, decode in ((textnorm._B64, textnorm.decode_b64_token), (textnorm._HEX, textnorm.decode_hex_token)):
        for token in set(pattern.findall(out)):
            decoded = decode(token)
            if decoded and any(n in textnorm.alnum(decoded) for n in needles):
                out = out.replace(token, REDACTION)
    if leaks_in(out, leaks):
        return REDACTION
    return out


@dataclass(frozen=True)
class Sink:
    """Where an action's text goes, and how trusted that destination is."""

    name: str
    destination: str
    text: str


def recipient_trust(address: str, internal: list[str]) -> str:
    domain = address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""
    return "trusted_internal" if domain and domain in internal else "untrusted_external"


def is_identifier_arg(name: str, value: str) -> bool:
    return name.endswith("_id") or name == "id" or bool(ID_FULL.match(value.strip()))


def free_text_args(action: CandidateAction) -> list[str]:
    """Names of string arguments that carry prose (not ids, not addresses)."""
    names = []
    for name, value in sorted(action.arguments.items()):
        if isinstance(value, str) and value.strip() and not EMAIL_FULL.match(value.strip()) and not is_identifier_arg(name, value):
            names.append(name)
    return names


def sink_of(action: CandidateAction, internal: list[str]) -> Sink | None:
    """The outbound text of an action and its destination trust, derived generically (no tool is named)."""
    if action.type == "respond":
        return Sink("response", "authenticated_user", action.content or "")
    if action.type == "memory_write":
        return Sink("memory", "trusted_internal", action.content or "")
    if action.type != "tool_call":
        return None
    destination = "trusted_internal"
    for value in action.arguments.values():
        if isinstance(value, str) and EMAIL_FULL.match(value.strip()):
            if recipient_trust(value.strip(), internal) == "untrusted_external":
                destination = "untrusted_external"
    texts = [str(action.arguments[n]) for n in free_text_args(action)]
    if not texts:
        return None
    return Sink(action.tool or "tool", destination, "\n".join(texts))


def disallowed_leaks(sink: Sink, secrets: dict[str, str]) -> list[str]:
    present = leaks_in(sink.text, secrets.keys())
    return [s for s in present if not allowed_at(secrets[s], sink.destination)]


def redact_action(action: CandidateAction, leaks: list[str]) -> CandidateAction:
    """Rebuild an action with protected values removed from its outbound text."""
    if action.type in {"respond", "memory_write"}:
        return action.model_copy(update={"content": redact_text(action.content or "", leaks)})
    arguments = dict(action.arguments)
    for name in free_text_args(action):
        arguments[name] = redact_text(str(arguments[name]), leaks)
    return action.model_copy(update={"arguments": arguments})
