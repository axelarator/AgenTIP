"""Co-hosted names and historical addresses from passive DNS.

Two questions mnemonic PDNS answers for free, both of which turn up a
tracked host's neighbours:

* given a tracked **domain**, what addresses has it resolved to? Those
  historical IPs are where the operator parked it before, and often still
  run the rest of the kit.
* given a tracked **address**, what names resolved to it? Co-residents on a
  dedicated address are usually the same operator; on shared hosting they
  are strangers, which is why the address has to be dedicated for this to
  mean anything - the expansion's corroboration rule enforces that, and the
  caller skips shared-hosting addresses before asking.

Each answer is returned as a `Candidate`, not filed: the expansion sweeps
it and checks it links back before it becomes anything.
"""
from __future__ import annotations

import logging
from typing import Any

from ...sources import budget, passive
from . import Candidate

log = logging.getLogger(__name__)

# How many PDNS records to consider per host. The newest matter most; an
# address a domain left five years ago is net.historical_ip noise.
PDNS_LIMIT = 100


def host_candidates(indicator: str, kind: str, *, limit: int = PDNS_LIMIT
                    ) -> list[Candidate]:
    """Candidate hosts found through one tracked indicator's PDNS history.

    Costs one mnemonic budget unit per call; an exhausted budget returns
    nothing rather than raising, so a run degrades instead of failing.
    """
    try:
        budget.spend("mnemonic", 1)
    except budget.BudgetExhausted as e:
        log.warning("pdns candidates: %s", e)
        return []
    result = passive.pdns(indicator, limit=limit)
    if not isinstance(result, dict) or result.get("error"):
        return []

    out: list[Candidate] = []
    seen: set[str] = set()
    for rec in result.get("records") or []:
        rrtype = rec.get("rrtype")
        if kind == "domain":
            # The addresses this name resolved to: candidate IPs.
            if rrtype not in ("a", "aaaa"):
                continue
            value, value_kind, via = rec.get("answer"), "ip", "net.historical_ip"
        else:
            # The names that resolved to this address: candidate domains.
            if rrtype not in ("a", "aaaa"):
                continue
            value, value_kind, via = rec.get("query"), "domain", "net.cohosted_domain"
        value = (value or "").strip().lower().rstrip(".")
        if not value or value == indicator.lower() or value in seen:
            continue
        seen.add(value)
        window = ""
        if rec.get("first_seen") and rec.get("last_seen"):
            window = f" (seen {rec['first_seen']}..{rec['last_seen']})"
        out.append(Candidate(
            value=value, kind=value_kind,
            discovered_via=f"{via}:{indicator}",
            discovered_from=indicator,
            reason=f"passive DNS {via.split('.')[-1]} of {indicator}{window}"))
    return out
