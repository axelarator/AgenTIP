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

The rule is not applied here by counting. `relatedness` scores the evidence,
with weights chosen so that this rule is what an undiscounted score means,
and a link is promoted when that score is in the `strong` band. So a fact
that relatedness discounts - a default certificate, a catch-all address, a
CDN edge, a value two hosts held a year apart, a value half the internet
shares - counts for less here too, and can leave a link held back that the
bare rule would have promoted.

This is the rule the source reporting applied without writing down: a page
hash on 13 hosts was acted on alone, while an nginx version was mentioned
and never used to claim anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import duckdb

from .rarity import assess
from .relatedness import CLASS_WEIGHT, Relatedness, pairs_between
from .selectors import (artefact, selector_class,
                        sharing)


@dataclass
class Candidate:
    """One other indicator, what it shares with the seed, and the verdict."""
    indicator: str
    actor: str | None
    promoted: bool
    reason: str
    identity: list[tuple[str, str]] = field(default_factory=list)
    structural: list[tuple[str, str]] = field(default_factory=list)
    corroborating: list[tuple[str, str]] = field(default_factory=list)
    # None when the pair was not scored: it shares nothing that could
    # promote, so its band could not be the promoting one whatever it is.
    score: float | None = None
    band: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"indicator": self.indicator, "actor": self.actor,
                "promoted": self.promoted, "reason": self.reason,
                "score": None if self.score is None else round(self.score, 4),
                "band": self.band,
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


# The band a link must reach to be promoted. `strong` is where the rule in
# the module docstring lands when nothing discounts the evidence: one
# identity fact scores 0.85, two independent structural facts 0.81, and one
# structural fact 0.56, which is `probable` and is held back.
PROMOTING_BAND = "strong"
_GAP_STEPS = (365, 180, 90, 30)


def _why_held(result: Relatedness, identity: set[str], structural: set[str]) -> str:
    """Why a link was not promoted, in words that group: the digest counts
    held-back links by this text, so it names the kind of shortfall and not
    the particular hosts or an exact number of days."""
    notes = sorted({p.note for p in result.pairs if p.note})
    aged = [p for p in result.pairs
            if p.cls in ("identity", "structural") and (p.gap_days or 0) > 30]
    parts = []
    if aged:
        worst = max(p.gap_days for p in aged)
        step = next(s for s in _GAP_STEPS if worst > s)
        kinds = ", ".join(sorted({p.artefact for p in aged}))
        parts.append(f"{kinds} seen more than {step} days apart")
    parts += notes
    if any(0 < (p.global_count or 0) and p.cls in ("identity", "structural")
           and p.weight < 0.5 * CLASS_WEIGHT[p.cls] and not (p.gap_days or 0) > 30
           for p in result.pairs):
        parts.append("value is common across the internet")
    if parts:
        return f"{result.band} ({result.score:.2f}): " + "; ".join(parts)
    if not identity and len(structural) == 1:
        only = next(iter(structural))
        types = sorted({p.selector_type for p in result.pairs
                        if p.artefact == only and p.cls == "structural"})
        return (f"one structural fact only ({only}"
                + (f", via {', '.join(types)}" if len(types) > 1 else "")
                + "); needs a second independent one, or one identity fact")
    if not identity and not structural:
        return "corroborating selectors only - nothing that can promote"
    return f"{result.band} ({result.score:.2f}): evidence too weak to promote"


def candidates_for(con: duckdb.DuckDBPyConnection, indicator: str
                   ) -> list[Candidate]:
    """Every other indicator sharing a selector with `indicator`, judged.

    The judgement is `relatedness.pairs_between`, the same scoring the
    candidate views use. This function used to apply the corroboration rule
    itself, by counting facts, and knew nothing relatedness knows: that a
    certificate is a server's default, that an address is a catch-all, that
    one end sits behind a CDN, or that the two hosts held the value a year
    apart. The same pair could be "promoted" here and "noise" there. Now
    there is one judge, and this is its promoted / held-back view.
    """
    others: dict[str, str | None] = {}
    promotable: set[str] = set()
    shared: dict[str, list[tuple[str, str]]] = {}
    for row in _selectors_of(con, indicator):
        selector_type, value = row["selector_type"], row["selector_value"]
        counts = (selector_class(selector_type) in ("identity", "structural")
                  and assess(con, selector_type, value)["can_promote"])
        for hit in sharing(con, selector_type, value):
            other = hit["indicator_value"]
            if other == indicator:
                continue
            others.setdefault(other, hit.get("actor"))
            shared.setdefault(other, []).append((selector_type, str(value)[:80]))
            if counts:
                promotable.add(other)

    out = []
    for other, actor in others.items():
        if other not in promotable:
            # Behavioural and contextual values only. Their combined weight
            # is capped below the promoting band, so the verdict is known
            # without scoring - and nine pairs in ten are these.
            out.append(Candidate(
                indicator=other, actor=actor, promoted=False,
                reason="corroborating selectors only - nothing that can promote",
                corroborating=sorted(set(shared[other]))))
            continue
        result = pairs_between(con, indicator, other)
        slots: dict[str, list[tuple[str, str]]] = {
            "identity": [], "structural": [], "corroborating": []}
        for p in result.pairs:
            counted = p.cls in ("identity", "structural") and p.weight > 0
            pair = (p.selector_type, p.selector_value[:80])
            slot = slots[p.cls if counted else "corroborating"]
            if pair not in slot:
                slot.append(pair)
        # One certificate seen through three selector types is one fact.
        identity = {artefact(t) for t, _ in slots["identity"]}
        structural = {artefact(t) for t, _ in slots["structural"]} - identity
        promoted = result.band == PROMOTING_BAND
        if promoted and identity:
            reason = (f"{len(identity)} identity fact(s) ({', '.join(sorted(identity))}): "
                      f"{', '.join(sorted({t for t, _ in slots['identity']}))}")
        elif promoted:
            reason = (f"{len(structural)} independent structural facts: "
                      f"{', '.join(sorted(structural))}")
        else:
            reason = _why_held(result, identity, structural)
        out.append(Candidate(
            indicator=other, actor=actor, promoted=promoted, reason=reason,
            identity=slots["identity"], structural=slots["structural"],
            corroborating=slots["corroborating"],
            score=result.score, band=result.band))

    out.sort(key=lambda c: (not c.promoted, -(c.score or 0.0)))
    return out


def _selectors_of(con: duckdb.DuckDBPyConnection, indicator: str) -> list[dict]:
    cur = con.execute(
        "SELECT selector_type, selector_value FROM selectors WHERE indicator_value = ?",
        [indicator])
    return [dict(zip([d[0] for d in cur.description], row)) for row in cur.fetchall()]
