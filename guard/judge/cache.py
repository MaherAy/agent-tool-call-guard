"""In-memory cache for judge-stage answers, keyed by the exact prompt they would produce.

Keeps cost down when the same ambiguous situation recurs across steps of a run (or across runs of the same
scenario while iterating), and keeps a recorded run replayable: the same input always yields the same cached
verdict within one process's lifetime, instead of a fresh sample from the model each time.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict

from guard.judge.schema import JudgeVerdict

MAX_ENTRIES = 4096


class JudgeCache:
    def __init__(self, capacity: int = MAX_ENTRIES) -> None:
        self._store: OrderedDict[str, JudgeVerdict] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    @staticmethod
    def key(messages: list[dict[str, str]], model: str) -> str:
        canonical = json.dumps({"model": model, "messages": messages}, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, key: str) -> JudgeVerdict | None:
        with self._lock:
            verdict = self._store.get(key)
            if verdict is not None:
                self._store.move_to_end(key)
            return verdict

    def put(self, key: str, verdict: JudgeVerdict) -> None:
        with self._lock:
            self._store[key] = verdict
            self._store.move_to_end(key)
            while len(self._store) > self._capacity:
                self._store.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
