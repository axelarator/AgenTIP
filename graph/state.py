"""The state the graph carries.

Only two fields have reducers, and that is the whole concurrency story:
`findings` and `errors` are the only things the parallel specialists
write, so they accumulate with operator.add. Everything else is written
by exactly one node, which is what makes the fan-out safe without a lock.
"""
from __future__ import annotations

import operator
from dataclasses import asdict, dataclass, field
from typing import Annotated, Any, Literal, TypedDict

# The specialist families. The first four own a disjoint set of the digest's
# attribute vocabulary, so a change row is routed to exactly one of them.
Family = Literal["infra_change", "cert_tls", "hosting", "opendir",
                 "infrastructure"]

FAMILY_ATTRIBUTES: dict[Family, tuple[str, ...]] = {
    "infra_change": ("asn", "ports", "ptr", "resolved_ip"),
    "cert_tls": ("cert", "cert_hash", "http"),
    "hosting": ("ip_hostnames", "subdomains", "webamon_fingerprint",
                "infostealer_hits"),
    "opendir": ("opendir_files",),
    # The fifth specialist reads links between indicators rather than
    # changes to one. Every other family answers "what changed here?"; this
    # one answers "who else has this?", which is a different question and
    # needs a different reader. Its attribute is not a digest column - it
    # is a candidate link produced by the corroboration rule.
    "infrastructure": ("selector_link",),
}

ATTRIBUTE_FAMILY: dict[str, Family] = {
    attribute: family
    for family, attributes in FAMILY_ATTRIBUTES.items()
    for attribute in attributes
}


@dataclass
class Item:
    """One digest row, normalized and scored.

    `score` and `suppressed` come from the deterministic ranker, before
    any model sees the row. That ordering is deliberate: the old single
    pass spent its 3-item budget on whatever was at the top of the
    digest, which on a typical day is hundreds of unrelated domains
    hosted on a Cloudflare IP.
    """
    family: Family
    attribute: str
    actor: str | None
    indicator: str
    change_type: str
    confidence: str
    detected_at: str | None = None
    old_value: Any = None
    new_value: Any = None
    score: float = 0.0
    suppressed: str | None = None   # why the ranker dropped it, if it did
    source_section: str = "attribute_changes"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """What a specialist concluded about one or more items."""
    family: Family
    actor: str | None
    headline: str
    detail: str
    indicators: list[str] = field(default_factory=list)
    correlation_type: str | None = None   # None = worth saying, not worth saving
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CTIState(TypedDict, total=False):
    # --- collect (Stage A) ---
    day: str
    skip_enrich: bool
    clusters: list[str]
    sweep_results: Annotated[list[dict[str, Any]], operator.add]
    sections: dict[str, Any]
    digest_path: str

    # --- analyze (Stage B) ---
    digest_md: str
    digest_json: dict[str, Any]
    items: list[Item]
    ranked: dict[str, list[Item]]          # family -> the items it should weigh
    findings: Annotated[list[Finding], operator.add]
    errors: Annotated[list[str], operator.add]
    correlations: list[dict[str, Any]]
    narrative: str
    dry_run: bool
