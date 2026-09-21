"""The one rule that disqualifies a decision: never decide from a scenario id, filename or canary format.

This turns the promise into a check. It scans the defense source for scenario-id-shaped names and for the
benchmark's seeded-secret formats. (This file itself is excluded because it has to contain the patterns.)
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ID = re.compile(r"\b(?:enterprise|finance|soc)_(?:val_)?[a-z]+(?:_[a-z]+)+\b")
CANARY_FORMATS = re.compile(r"SENTINEL_SECRET|sntl_tok_|SYNTN|CTR-SYN|\{\{canary", re.IGNORECASE)


def _sources():
    for base in ("guard", "tests", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            if path.name != Path(__file__).name:
                yield path


def test_no_scenario_ids_in_source():
    hits = [(p.name, m.group(0)) for p in _sources() for m in SCENARIO_ID.finditer(p.read_text(encoding="utf-8"))]
    assert not hits, f"scenario-id-shaped names found: {hits}"


def test_no_canary_formats_in_source():
    hits = [(p.name, m.group(0)) for p in _sources() for m in CANARY_FORMATS.finditer(p.read_text(encoding="utf-8"))]
    assert not hits, f"benchmark secret formats found: {hits}"
