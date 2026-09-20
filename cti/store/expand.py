"""From a selector to the indicators that share it, and what that is worth.

`selectors.neighbours` answers "what shares anything with this host".
This answers the question an analyst actually asks next: given a link, is it
strong enough to act on, and why?

## The corroboration rule

A candidate is promoted when either:

* one **identity** selector - a content or key digest, where a shared value
  means the two hosts were configured from the same source; or
* two **independent structural** selectors, independent meaning different
  types. Two SANs off one certificate are one fact, not two.

Behavioural and contextual selectors are recorded on the finding because
they describe it, and never counted toward promotion.

This is the rule the source reporting applied without writing down: a page
hash on 13 hosts was acted on alone, while an nginx version was mentioned
and never used to claim anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import duckdb

from .rarity import assess
from .selectors import (CLASS_ORDER, artefact, normalize, selector_class,
                        sharing)


@dataclass
class Candidate:
    """One indicator linked to the seed, with the evidence for it."""
    indicator: str
    actor: str | None
    promoted: bool
    reason: str
    identity: list[tuple[str, str]] = field(default_factory=list)
    structural: list[tuple[str, str]] = field(default_factory=list)
    corroborating: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"indicator": self.indicator, "actor": self.actor,
                "promoted": self.promoted, "reason": self.reason,
                "identity": self.identity, "structural": self.structural,
                "corroborating": self.corroborating}


def from_selector(con: duckdb.DuckDBPyConnection, selector_type: str,
                  selector_value: Any, *, exclude: str | None = None
                  ) -> list[dict[str, Any]]:
    """Indicators carrying this selector value, with the rarity verdict.

    Local only: this reads the selectors table and contacts nothing. It is
    the cheapest expansion and the one that should always run first.
    """
    verdict = assess(con, selector_type, selector_value)
    hits = [h for h in sharing(con, selector_type, selector_value)
            if h["indicator_value"] != exclude]
    for hit in hits:
        hit["selector_type"] = selector_type
        hit["selector_class"] = selector_class(selector_type)
        hit["usable_as_lead"] = verdict["can_promote"]
        hit["why_not"] = verdict["why_not"]
    return hits


def candidates_for(con: duckdb.DuckDBPyConnection, indicator: str
                   ) -> list[Candidate]:
    """Everything linked to this indicator, judged by the corroboration rule."""
    mine = {(r["selector_type"], r["selector_value"])
            for r in _selectors_of(con, indicator)}

    evidence: dict[str, dict[str, Any]] = {}
    for selector_type, selector_value in mine:
        verdict = assess(con, selector_type, selector_value)
        cls = selector_class(selector_type)
        for hit in sharing(con, selector_type, selector_value):
            other = hit["indicator_value"]
            if other == indicator:
                continue
            slot = evidence.setdefault(
                other, {"actor": hit.get("actor"), "identity": [], "structural": [],
                        "corroborating": []})
            pair = (selector_type, str(selector_value)[:80])
            if not verdict["can_promote"]:
                # Class-limited or provider-scale: it describes the link, it
                # cannot make one.
                slot["corroborating"].append(pair)
            elif cls == "identity":
                slot["identity"].append(pair)
            else:
                slot["structural"].append(pair)

    out = []
    for other, slot in evidence.items():
        # Independence is per artefact, not per type. Two selectors read off
        # one certificate are one fact whether they are two SANs or a hash
        # and a serial - the rule this module already stated for SANs,
        # applied everywhere it holds.
        identity_facts = {artefact(t) for t, _ in slot["identity"]}
        structural_facts = {artefact(t) for t, _ in slot["structural"]}
        # A certificate seen as identity is the same certificate seen as
        # structural, so it must not be counted again on the other side.
        structural_facts -= identity_facts

        if identity_facts:
            promoted, reason = True, (
                f"{len(identity_facts)} identity fact(s) "
                f"({', '.join(sorted(identity_facts))}): "
                f"{', '.join(sorted({t for t, _ in slot['identity']}))}")
        elif len(structural_facts) >= 2:
            promoted, reason = True, (
                f"{len(structural_facts)} independent structural facts: "
                f"{', '.join(sorted(structural_facts))}")
        elif structural_facts:
            only = structural_facts.pop()
            types = sorted({t for t, _ in slot["structural"]
                            if artefact(t) == only})
            promoted, reason = False, (
                f"one structural fact only ({only}"
                + (f", via {', '.join(types)}" if len(types) > 1 else "")
                + "); needs a second independent one, or one identity fact")
        else:
            promoted, reason = False, (
                "corroborating selectors only - nothing that can promote")
        out.append(Candidate(
            indicator=other, actor=slot["actor"], promoted=promoted, reason=reason,
            identity=slot["identity"], structural=slot["structural"],
            corroborating=slot["corroborating"]))

    out.sort(key=lambda c: (not c.promoted, -len(c.identity), -len(c.structural)))
    return out


def _selectors_of(con: duckdb.DuckDBPyConnection, indicator: str) -> list[dict]:
    cur = con.execute(
        "SELECT selector_type, selector_value FROM selectors WHERE indicator_value = ?",
        [indicator])
    return [dict(zip([d[0] for d in cur.description], row)) for row in cur.fetchall()]
