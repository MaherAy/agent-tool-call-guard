"""Trust and sensitivity lattices, the destination policy, and per-request provenance lookup."""

from __future__ import annotations

from guard.models import ConversationItem, DefenseRequest

TRUST_ORDER: tuple[str, ...] = (
    "adversary_controlled",
    "untrusted_external",
    "untrusted_internal",
    "trusted_internal",
    "authenticated_user",
    "system_policy",
)
TRUST_RANK = {name: i for i, name in enumerate(TRUST_ORDER)}
TRUSTED = frozenset({"system_policy", "authenticated_user", "trusted_internal"})
UNTRUSTED = frozenset({"untrusted_internal", "untrusted_external", "adversary_controlled"})

SENSITIVITY_ORDER: tuple[str, ...] = ("public", "internal", "confidential", "restricted")
SENSITIVITY_RANK = {name: i for i, name in enumerate(SENSITIVITY_ORDER)}
GOVERNED = frozenset({"confidential", "restricted"})

# Where content of a given sensitivity may land. Derived from provenance labels only; no value or format of
# any particular secret is consulted.
DESTINATIONS_ALLOWED: dict[str, frozenset[str]] = {
    "restricted": frozenset(),
    "confidential": frozenset({"authenticated_user", "trusted_internal"}),
    "internal": frozenset({"authenticated_user", "trusted_internal", "untrusted_internal"}),
    "public": frozenset(TRUST_ORDER),
}


def allowed_at(sensitivity: str, destination: str) -> bool:
    return destination in DESTINATIONS_ALLOWED.get(sensitivity, frozenset())


def most_sensitive(levels: list[str]) -> str | None:
    known = [lvl for lvl in levels if lvl in SENSITIVITY_RANK]
    return max(known, key=lambda lvl: SENSITIVITY_RANK[lvl]) if known else None


def least_trusted(levels: list[str]) -> str | None:
    known = [lvl for lvl in levels if lvl in TRUST_RANK]
    return min(known, key=lambda lvl: TRUST_RANK[lvl]) if known else None


class ProvenanceIndex:
    """Trust and sensitivity lookup for one request's provenance records."""

    def __init__(self, request: DefenseRequest) -> None:
        self.trust: dict[str, str] = {}
        self.sensitivity: dict[str, str] = {}
        for record in request.provenance:
            self.trust[record.id] = record.provenance.trust_level
            self.sensitivity[record.id] = record.provenance.sensitivity

    def item_trust(self, item: ConversationItem) -> str | None:
        if not item.provenance_ids:
            return None
        return least_trusted([self.trust[p] for p in item.provenance_ids if p in self.trust])

    def item_sensitivity(self, item: ConversationItem) -> str | None:
        if not item.provenance_ids:
            return None
        return most_sensitive([self.sensitivity[p] for p in item.provenance_ids if p in self.sensitivity])

    def fully_trusted(self, item: ConversationItem) -> bool:
        """True only when every provenance id behind the item is trusted (mixed items are not)."""
        if not item.provenance_ids:
            return False
        return all(self.trust.get(p) in TRUSTED for p in item.provenance_ids)
