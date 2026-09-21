"""Tamper-evident sidecar trace.

The kit's event log drops `DefenseDecision.metadata`, so the richer record (contract verdict, evidence spans,
which rule fired) is written here, one JSON line per decision keyed by `(run_id, step)`. Each line carries the
hash of the previous line, so editing or deleting a line breaks the chain. Secret values are never written,
only counts; observed text is truncated and must be escaped by whatever renders it.

    python -m guard.trace verify path/to/guard-trace.jsonl
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


class Trace:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._prev = GENESIS
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size:
                last = path.read_text(encoding="utf-8").strip().splitlines()[-1]
                self._prev = json.loads(last)["hash"]

    @classmethod
    def from_env(cls) -> Trace:
        directory = os.environ.get("GUARD_TRACE_DIR")
        return cls(Path(directory) / "guard-trace.jsonl" if directory else None)

    def append(self, record: dict[str, Any]) -> None:
        if self.path is None:
            return
        with self._lock:
            digest = _digest(self._prev, record)
            line = json.dumps({**record, "prev": self._prev, "hash": digest}, sort_keys=True, ensure_ascii=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            self._prev = digest


def verify(path: Path) -> tuple[bool, int, str | None]:
    """Recompute the chain. Returns (ok, lines checked, message about the first problem)."""
    prev = GENESIS
    count = 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        entry = json.loads(line)
        claimed_prev, claimed_hash = entry.pop("prev", None), entry.pop("hash", None)
        if claimed_prev != prev:
            return False, count, f"line {number}: previous hash does not match"
        if _digest(prev, entry) != claimed_hash:
            return False, count, f"line {number}: content was modified"
        prev = claimed_hash
        count += 1
    return True, count, None


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        ok, checked, message = verify(Path(sys.argv[2]))
        print(f"{'OK' if ok else 'BROKEN'}: {checked} record(s) checked" + (f" ({message})" if message else ""))
        raise SystemExit(0 if ok else 1)
    print("usage: python -m guard.trace verify <file>")
    raise SystemExit(2)
