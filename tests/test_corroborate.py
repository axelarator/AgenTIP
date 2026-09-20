"""The corroborate node, the infrastructure family, and the prompt that
must not drift from the code.

The node itself is exercised against a real DuckDB in a tmp dir - it is
arithmetic over the selectors table, so there is nothing to mock - with the
one network call it makes (global counts) stubbed out.
"""
from __future__ import annotations

import pytest

from cti import store as tracking_store
from cti.store import selectors as S
from graph.nodes import collect, rank
from graph.sdk import load_prompt, selector_taxonomy
from graph.state import FAMILY_ATTRIBUTES


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "tracking.duckdb"))
    # Global counts are the node's only network call; price nothing.
    from cti.sources import webamon
    monkeypatch.setattr(webamon, "global_count",
                        lambda t, v: {"error": "stubbed"})
    yield


def _seed(pairs, day="2026-09-20"):
    """pairs: (indicator, selector_type, selector_value, actor)."""
    with tracking_store.connect(read_only=False) as con:
        for indicator, selector_type, value, actor in pairs:
            S.record(con, indicator_value=indicator, selector_type=selector_type,
                     selector_value=value, observed_at=f"{day} 06:00:00",
                     indicator_type="domain", actor=actor, source="test")


def _run(day="2026-09-20"):
    return collect.corroborate({"day": day, "sections": {}}
                               )["sections"]["infrastructure_links"]


# --------------------------------------------------------------------------- #
# The rule, through the node
# --------------------------------------------------------------------------- #

def test_an_identity_selector_promotes_a_link():
    _seed([("a.example", "tls.cert_sha256", "c" * 64, "Actor"),
           ("b.example", "tls.cert_sha256", "c" * 64, "Actor")])
    out = _run()
    assert out["promoted_total"] == 1
    link = out["promoted"][0]
    assert {link["seed"], link["linked_to"]} == {"a.example", "b.example"}
    assert "tls.cert_sha256" in link["reason"]


def test_a_link_is_reported_once_not_once_from_each_end():
    """Both ends are touched the same day, so without deduplication every
    promotion appears twice with the indicators swapped."""
    _seed([("a.example", "tls.cert_sha256", "c" * 64, "Actor"),
           ("b.example", "tls.cert_sha256", "c" * 64, "Actor")])
    assert _run()["promoted_total"] == 1


def test_the_seed_and_the_other_end_are_both_kept():
    """Candidate.to_dict() has its own "indicator" key; merging it over a
    dict that also used "indicator" silently overwrote the seed, so every
    link pointed at itself."""
    _seed([("a.example", "tls.cert_sha256", "c" * 64, "Actor"),
           ("b.example", "tls.cert_sha256", "c" * 64, "Actor")])
    link = _run()["promoted"][0]
    assert link["seed"] != link["linked_to"]
    assert "indicator" not in link, "the ambiguous key must be gone entirely"


def test_one_structural_selector_is_held_back_with_its_reason():
    _seed([("a.example", "net.resolved_ip", "203.0.113.9", "Actor"),
           ("b.example", "net.resolved_ip", "203.0.113.9", "Actor")])
    out = _run()
    assert out["promoted_total"] == 0
    assert out["held_back_total"] == 1
    reason = next(iter(out["held_back_reasons"]))
    # "address", not "net.resolved_ip": independence is per artefact, and
    # the resolved IP determines the PTR, ASN, prefix and country too.
    assert "address" in reason and "second independent" in reason


def test_two_independent_structural_selectors_promote():
    _seed([("a.example", "net.resolved_ip", "203.0.113.9", "Actor"),
           ("b.example", "net.resolved_ip", "203.0.113.9", "Actor"),
           ("a.example", "tls.serial", "0A:1B", "Actor"),
           ("b.example", "tls.serial", "0A:1B", "Actor")])
    assert _run()["promoted_total"] == 1


def test_contextual_selectors_never_promote_however_many():
    """The Server-header problem, through the whole node."""
    shared = [("a.example", "http.server", "cloudflare", "A"),
              ("b.example", "http.server", "cloudflare", "B"),
              ("a.example", "tls.issuer", "Let's Encrypt", "A"),
              ("b.example", "tls.issuer", "Let's Encrypt", "B"),
              ("a.example", "net.country", "US", "A"),
              ("b.example", "net.country", "US", "B")]
    _seed(shared)
    out = _run()
    assert out["promoted_total"] == 0
    assert out["held_back_total"] == 1


# --------------------------------------------------------------------------- #
# What the node does NOT do
# --------------------------------------------------------------------------- #

def test_only_indicators_seen_today_are_checked():
    """A link between two hosts that neither changed is the link it was
    yesterday, and was reported then."""
    _seed([("old-a.example", "tls.cert_sha256", "d" * 64, "Actor"),
           ("old-b.example", "tls.cert_sha256", "d" * 64, "Actor")],
          day="2026-09-01")
    assert _run(day="2026-09-20")["promoted_total"] == 0
    assert _run(day="2026-09-01")["promoted_total"] == 1


def test_a_failure_is_recorded_and_the_day_continues(monkeypatch):
    """The digest is worth more than this section."""
    from cti.store import rarity
    monkeypatch.setattr(rarity, "refresh",
                        lambda con: (_ for _ in ()).throw(RuntimeError("boom")))
    sections = collect.corroborate({"day": "2026-09-20", "sections": {}})["sections"]
    assert sections["infrastructure_links"] == {}
    assert "boom" in sections["status"]["corroborate"]


def test_the_digest_carries_a_bounded_number_of_links(monkeypatch):
    monkeypatch.setattr(collect, "MAX_DIGEST_LINKS", 2)
    pairs = []
    for n in range(5):
        pairs += [(f"a{n}.example", "tls.cert_sha256", f"{n}" * 64, "Actor"),
                  (f"b{n}.example", "tls.cert_sha256", f"{n}" * 64, "Actor")]
    _seed(pairs)
    out = _run()
    assert out["promoted_total"] == 5, "the count is not truncated"
    assert len(out["promoted"]) == 2, "the list is"


# --------------------------------------------------------------------------- #
# Ranking
# --------------------------------------------------------------------------- #

def _digest(promoted, held=0):
    return {"day": "2026-09-20",
            "infrastructure_links": {"promoted": promoted, "held_back_total": held}}


def test_only_promoted_links_reach_a_specialist():
    """Held-back candidates are in the digest for a human. Handing three
    hundred of them to a model is the mistake the ranker exists to stop."""
    items = rank._items_from_infrastructure_links(_digest([], held=300))
    assert items == []


def test_an_item_carries_how_many_were_held_back():
    items = rank._items_from_infrastructure_links(_digest(
        [{"seed": "a", "linked_to": "b", "actor": "X", "reason": "r",
          "identity": [], "structural": [], "corroborating": []}], held=42))
    assert items[0].old_value == {"held_back": 42}


def test_a_link_outranks_every_change_type():
    """A change says one host moved; a link says two hosts are one
    operation."""
    assert rank.CHANGE_WEIGHT["selector_link"] > max(
        v for k, v in rank.CHANGE_WEIGHT.items() if k != "selector_link")


def test_a_link_is_not_re_suppressed_by_the_shared_hosting_rule():
    """The selector layer already applied a stricter, purpose-built gate.
    Re-running the ASN rule here would drop the promoted pairs this family
    exists to surface."""
    item = rank._items_from_infrastructure_links(_digest(
        [{"seed": "a.example", "linked_to": "b.example", "actor": "X",
          "reason": "1 identity selector(s): tls.cert_sha256",
          "identity": [["tls.cert_sha256", "c"]], "structural": [],
          "corroborating": []}]))[0]
    from cti.tracking.analytics import SHARED_HOSTING_ASNS
    scored = rank.score(item, {"a.example": next(iter(SHARED_HOSTING_ASNS))})
    assert scored.suppressed is None and scored.score > 0


def test_links_reach_the_ranked_output_under_their_own_family():
    state = {"digest_json": _digest(
        [{"seed": "a.example", "linked_to": "b.example", "actor": "X",
          "reason": "1 identity selector(s): tls.cert_sha256",
          "identity": [["tls.cert_sha256", "c"]], "structural": [],
          "corroborating": []}])}
    ranked = rank.rank(state)["ranked"]
    assert [i.indicator for i in ranked["infrastructure"]] == ["a.example"]


# --------------------------------------------------------------------------- #
# The prompt is generated, not copied
# --------------------------------------------------------------------------- #

def test_the_taxonomy_in_the_prompt_comes_from_the_code():
    """whois.registrar was reclassed structural -> behavioural during this
    work. A hand-written table would still call it structural, and the
    model would be arguing with a rule that already ran."""
    taxonomy = selector_taxonomy()
    assert "`whois.registrar`" in taxonomy
    behavioural = taxonomy[taxonomy.index("### behavioural"):]
    assert "`whois.registrar`" in behavioural


def test_every_promoting_type_is_explained_in_the_prompt():
    prompt = load_prompt("infrastructure")
    for name, spec in S.TYPES.items():
        if spec.cls in ("identity", "structural"):
            assert f"`{name}`" in prompt, f"{name} can promote but is unexplained"


def test_the_placeholder_is_always_substituted():
    assert "{{" not in load_prompt("infrastructure")


def test_no_prompt_is_left_holding_an_unfilled_placeholder():
    for family in FAMILY_ATTRIBUTES:
        assert "{{" not in load_prompt(family), family


# --------------------------------------------------------------------------- #
# The digest
# --------------------------------------------------------------------------- #

def _digest_file(tmp_path, sections):
    from datetime import date
    from cti.tracking import digest
    return digest.write(date(2026, 9, 20), sections).read_text()


_ONE_LINK = {"infrastructure_links": {
    "promoted": [{"seed": "a.example", "linked_to": "b.example",
                  "actor": "JadeProx", "reason": "1 identity selector(s): "
                                                 "tls.cert_sha256"}],
    "held_back_total": 206,
    "held_back_reasons": {"corroborating selectors only - nothing "
                          "that can promote": 186}}}


def test_a_link_only_day_is_not_a_quiet_day(tmp_path):
    """A corroborated link is an event. Without this, a day whose only
    finding was "these two hosts are one operation" rendered as no activity
    and never woke Stage B."""
    from cti.tracking.digest import _has_signals
    assert _has_signals(_ONE_LINK) is True
    assert "no" not in _digest_file(tmp_path, _ONE_LINK).lower().split("##")[0][20:]


def test_the_digest_names_both_ends_and_the_reason(tmp_path):
    body = _digest_file(tmp_path, _ONE_LINK)
    assert "a.example" in body and "b.example" in body
    assert "tls.cert_sha256" in body


def test_the_digest_says_how_many_were_held_back(tmp_path):
    """Without it, "1 link today" reads as a thin day rather than a strict
    rule, and nobody can tell which."""
    assert "206 further candidate" in _digest_file(tmp_path, _ONE_LINK)


def test_no_links_renders_no_section(tmp_path):
    sections = {"infrastructure_links": {"promoted": [], "held_back_total": 9}}
    assert "Corroborated infrastructure" not in _digest_file(tmp_path, sections)


# --------------------------------------------------------------------------- #
# Independence is per artefact, not per column
# --------------------------------------------------------------------------- #

def test_three_fields_of_one_certificate_are_not_three_facts():
    """The hole this closes.

    tls.serial, tls.subject_cn and tls.san are three structural TYPES and
    one certificate. Counted by type they cleared the two-independent bar
    on a single observation; counted by artefact they are one fact and the
    candidate is held back until something else corroborates it.
    """
    _seed([("a.example", "tls.serial", "0A:1B", "Actor"),
           ("b.example", "tls.serial", "0A:1B", "Actor"),
           ("a.example", "tls.subject_cn", "shared.example", "Actor"),
           ("b.example", "tls.subject_cn", "shared.example", "Actor"),
           ("a.example", "tls.san", "other.example", "Actor"),
           ("b.example", "tls.san", "other.example", "Actor")])
    out = _run()
    assert out["promoted_total"] == 0
    reason = next(iter(out["held_back_reasons"]))
    assert "one structural fact only (certificate" in reason


def test_a_certificate_plus_a_registration_are_two_facts():
    """Two genuinely separate observations still promote."""
    _seed([("a.example", "tls.serial", "0A:1B", "Actor"),
           ("b.example", "tls.serial", "0A:1B", "Actor"),
           ("a.example", "dns.apex", "shared.example", "Actor"),
           ("b.example", "dns.apex", "shared.example", "Actor")])
    out = _run()
    assert out["promoted_total"] == 1
    assert "2 independent structural facts" in out["promoted"][0]["reason"]
    assert "certificate" in out["promoted"][0]["reason"]
    assert "dns.apex" in out["promoted"][0]["reason"]


def test_an_address_determines_its_own_derived_selectors():
    """Sharing the resolved IP guarantees sharing the PTR, ASN, prefix and
    country, so those cannot corroborate each other."""
    _seed([("a.example", "net.resolved_ip", "203.0.113.9", "Actor"),
           ("b.example", "net.resolved_ip", "203.0.113.9", "Actor"),
           ("a.example", "net.reverse_dns", "host.dedicated.example", "Actor"),
           ("b.example", "net.reverse_dns", "host.dedicated.example", "Actor")])
    out = _run()
    assert out["promoted_total"] == 0
    assert "one structural fact only (address" in next(iter(out["held_back_reasons"]))


def test_a_certificate_counted_as_identity_is_not_counted_again():
    """tls.cert_sha256 is identity and tls.serial is structural, but they
    are one certificate. Counting it on both sides would let a single
    observation satisfy both halves of the rule."""
    _seed([("a.example", "tls.cert_sha256", "c" * 64, "Actor"),
           ("b.example", "tls.cert_sha256", "c" * 64, "Actor"),
           ("a.example", "tls.serial", "0A:1B", "Actor"),
           ("b.example", "tls.serial", "0A:1B", "Actor")])
    link = _run()["promoted"][0]
    assert link["reason"].startswith("1 identity fact(s) (certificate)")


def test_an_ungrouped_selector_is_its_own_artefact():
    """The safe default: grouping two genuinely separate facts would weaken
    a real link, which is the more expensive mistake."""
    from cti.store.selectors import TYPES, artefact
    assert artefact("dns.apex") == "dns.apex"
    assert artefact("whois.registrant_email") == "whois.registrant_email"
    # every type resolves to something, known or itself
    assert all(artefact(t) for t in TYPES)
