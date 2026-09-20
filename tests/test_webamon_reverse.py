"""The Webamon reverse layer: selector value -> indicators that share it.

No network. `_search` is stubbed with documents shaped like the real index -
the shapes here were taken from live responses, including the two that make
the layer necessary: a scan document holds every certificate the page
touched, and text fields are analyzed rather than matched whole.
"""
from __future__ import annotations

import duckdb
import pytest

from cti.sources import webamon as W
from cti.store import rarity, selectors as S


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv(W.WEBAMON_API_KEY_ENV, "test-key")


def _stub(monkeypatch, results, total_hits=None):
    """Stub _search, capturing the query it was given."""
    seen: dict = {}

    def fake(params):
        seen.update(params)
        return {"total_hits": total_hits if total_hits is not None else len(results),
                "results": results}

    monkeypatch.setattr(W, "_search", fake)
    return seen


# --------------------------------------------------------------------------- #
# The map is the contract
# --------------------------------------------------------------------------- #

def test_every_mapped_selector_type_is_in_the_taxonomy():
    """A reverse field for a type nobody classed would produce findings whose
    weight is undefined - and unknown types default to contextual silently."""
    unknown = sorted(t for t in W.REVERSE_FIELDS if t not in S.TYPES)
    assert unknown == []


def test_the_selectors_webamon_cannot_answer_are_absent():
    """Verified against the live index, and worth asserting so a future
    'obvious' addition has to re-verify rather than assume."""
    for selector_type in ("tls.cert_sha256",       # no leaf digest published
                          "whois.registrant_email",  # no registration data
                          "whois.registrar",
                          "net.port_set",          # naabu/nmap's job
                          "dns.ns_set", "dns.apex"):
        assert not W.reversible(selector_type), selector_type


# --------------------------------------------------------------------------- #
# Injection
# --------------------------------------------------------------------------- #

def test_a_selector_value_cannot_inject_a_lucene_clause(monkeypatch):
    seen = _stub(monkeypatch, [])
    W.reverse_selector("http.title", 'x" OR page_title:*')
    # Every reserved character is escaped, so the phrase never ends early and
    # the injected clause stays inside it as literal text.
    assert seen["lucene_query"] == 'page_title:"x\\" OR page_title\\:\\*"'


def test_a_backslash_cannot_escape_the_closing_quote(monkeypatch):
    seen = _stub(monkeypatch, [])
    W.reverse_selector("http.title", "trailing\\")
    assert seen["lucene_query"] == 'page_title:"trailing\\\\"'


def test_a_wildcard_san_is_matched_not_expanded(monkeypatch):
    """The API answers HTTP 400 for an unescaped wildcard even inside quotes,
    so every wildcard SAN in this repo's data failed to price."""
    seen = _stub(monkeypatch, [])
    W.global_count("tls.san", "*.sharepoint.com")
    assert seen["lucene_query"] == 'certificate.san_list:"\\*.sharepoint.com"'


# --------------------------------------------------------------------------- #
# Root scoping - the false-positive guard
# --------------------------------------------------------------------------- #

def _scan(resolved, root_sans, other_sans=()):
    """A scan document: the root domain's own certificate, plus the
    third-party certificates the page's resources were served under."""
    return {
        "resolved_domain": resolved,
        "domain": [
            {"name": resolved, "root": True,
             "certificate": [{"san_list": list(root_sans)}]},
            {"name": "cdn.example.net", "root": False,
             "certificate": [{"san_list": list(other_sans)}]},
        ],
    }


def test_a_third_party_certificate_does_not_make_the_page_a_match(monkeypatch):
    """The case that forced root scoping.

    `certificate.san_list:"www.example.com"` really does match
    kiratlimimarlik.com on the live index - because that page loaded an image
    from a host whose certificate names www.example.com. Its own certificate
    names only itself, so it is not a host sharing the SAN.
    """
    _stub(monkeypatch, [
        _scan("kiratlimimarlik.com", ["kiratlimimarlik.com"], ["www.example.com"]),
        _scan("formthirtythree.com", ["www.example.com", "*.example.com"]),
    ])
    result = W.reverse_selector("tls.san", "www.example.com")
    assert result["indicators"] == ["formthirtythree.com"]
    assert result["rejected"] == 1


def test_a_document_with_no_identifiable_root_is_rejected(monkeypatch):
    """A root-scoped check that cannot find the root must reject, not pass:
    passing would reintroduce exactly the false positive it exists to stop."""
    _stub(monkeypatch, [{"resolved_domain": "x.com",
                         "domain": [{"name": "other.com", "root": False,
                                     "certificate": [{"san_list": ["www.example.com"]}]}]}])
    result = W.reverse_selector("tls.san", "www.example.com")
    assert result["indicators"] == [] and result["rejected"] == 1


def test_the_root_is_found_by_name_when_the_flag_is_missing(monkeypatch):
    _stub(monkeypatch, [{"resolved_domain": "x.com",
                         "domain": [{"name": "x.com",
                                     "certificate": [{"san_list": ["www.example.com"]}]}]}])
    assert W.reverse_selector("tls.san", "www.example.com")["indicators"] == ["x.com"]


def test_a_scan_wide_field_is_not_root_scoped(monkeypatch):
    """A fingerprint describes the scan, so there is no root to scope to -
    and requiring one would reject every result."""
    _stub(monkeypatch, [{"resolved_domain": "a.com", "fingerprint": {"dom": "abc"}},
                        {"resolved_domain": "b.com", "fingerprint": {"dom": "abc"}}])
    result = W.reverse_selector("webamon.fp_dom", "abc")
    assert result["indicators"] == ["a.com", "b.com"] and result["rejected"] == 0


def test_a_file_hash_matches_any_resource_not_just_the_root(monkeypatch):
    """A staged payload is a sub-resource by definition, so file.sha256 is
    deliberately scan-wide where http.body_sha256 is root-scoped."""
    doc = {"resolved_domain": "a.com",
           "domain": [{"name": "a.com", "root": True,
                       "resource": [{"sha256": "rootpage"}]},
                      {"name": "cdn.net", "root": False,
                       "resource": [{"sha256": "payload"}]}]}
    _stub(monkeypatch, [doc])
    assert W.reverse_selector("file.sha256", "payload")["indicators"] == ["a.com"]
    _stub(monkeypatch, [doc])
    assert W.reverse_selector("http.body_sha256", "payload")["indicators"] == []


# --------------------------------------------------------------------------- #
# Counting
# --------------------------------------------------------------------------- #

def test_total_hits_counts_scans_and_indicators_are_counted_separately(monkeypatch):
    """example.com's own DOM digest returns 4388 hits and one indicator,
    because the index has scanned that page 4388 times."""
    _stub(monkeypatch, [{"resolved_domain": "example.com", "fingerprint": {"dom": "d"}}] * 3,
          total_hits=4388)
    result = W.reverse_selector("webamon.fp_dom", "d", size=3)
    assert result["total_hits"] == 4388
    assert result["indicators"] == ["example.com"]
    assert result["capped"] is True


def test_an_analyzed_field_is_flagged_as_an_upper_bound(monkeypatch):
    _stub(monkeypatch, [])
    assert W.reverse_selector("tls.san", "x")["exact"] is False
    _stub(monkeypatch, [])
    assert W.reverse_selector("webamon.fp_dom", "x")["exact"] is True


def test_global_count_asks_for_the_smallest_page(monkeypatch):
    seen = _stub(monkeypatch, [], total_hits=48_843_549)
    result = W.global_count("webamon.fp_cookies", "abc")
    assert seen["size"] == 1, "only the count is wanted"
    assert result == {"field": "fingerprint.cookies", "count": 48_843_549,
                      "source": "webamon", "exact": True}


def test_an_unmapped_selector_type_errors_rather_than_guessing(monkeypatch):
    _stub(monkeypatch, [])
    for fn in (W.reverse_selector, W.global_count):
        assert "error" in fn("tls.cert_sha256", "deadbeef")


# --------------------------------------------------------------------------- #
# Pricing, and what a price does
# --------------------------------------------------------------------------- #

@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    c.execute(S.SCHEMA)
    yield c
    c.close()


def _seed(con, selector_type, value, indicators):
    for i, ind in enumerate(indicators):
        S.record(con, indicator_value=ind, selector_type=selector_type,
                 selector_value=value, observed_at="2026-09-20 00:00:00",
                 indicator_type="domain", actor="A")
    rarity.refresh(con)


def test_pricing_skips_values_that_link_nothing(con):
    """Global counts cost budget; a value held by one indicator links nothing
    and does not need a price."""
    _seed(con, "webamon.fp_dom", "lonely", ["only.com"])
    asked: list = []
    out = rarity.fill_global_counts(
        con, lambda t, v: asked.append((t, v)) or {"count": 1, "source": "x"})
    assert asked == [] and out["priced"] == 0


def test_pricing_skips_types_that_could_never_promote(con):
    _seed(con, "http.server", "nginx", ["a.com", "b.com"])
    asked: list = []
    rarity.fill_global_counts(
        con, lambda t, v: asked.append((t, v)) or {"count": 1, "source": "x"})
    assert asked == [], "a contextual type cannot promote, so its price is moot"


def test_a_globally_common_value_stops_being_a_link(con):
    """The gate no vendored list could provide: nobody knows in advance which
    DOM digest is on millions of sites."""
    _seed(con, "webamon.fp_dom", "everywhere", ["a.com", "b.com"])
    assert S.shared(con) != [], "promotable before pricing"

    out = rarity.fill_global_counts(
        con, lambda t, v: {"count": 17_813_980, "source": "webamon", "exact": True})
    assert out["priced"] == 1

    assert S.shared(con) == [], "provider-scale after pricing"
    verdict = rarity.assess(con, "webamon.fp_dom", "everywhere")
    assert verdict["can_promote"] is False
    assert "17,813,980" in verdict["why_not"]
    assert verdict["global_source"] == "webamon"


def test_a_rare_value_survives_pricing(con):
    _seed(con, "webamon.fp_ssl", "rare", ["a.com", "b.com"])
    rarity.fill_global_counts(con, lambda t, v: {"count": 2, "source": "webamon"})
    verdict = rarity.assess(con, "webamon.fp_ssl", "rare")
    assert verdict["can_promote"] is True and verdict["global_count"] == 2
    assert S.shared(con) != []


def test_an_unpriced_value_is_judged_exactly_as_before(con):
    """Pricing is scarce, so most values never get one. An absent price must
    not read as 'common' - that would silently disable the whole index."""
    _seed(con, "webamon.fp_ssl", "unpriced", ["a.com", "b.com"])
    assert rarity.globally_common(con, "webamon.fp_ssl", "unpriced") is False
    assert rarity.assess(con, "webamon.fp_ssl", "unpriced")["can_promote"] is True


def test_a_counter_error_leaves_the_value_unpriced(con):
    _seed(con, "webamon.fp_ssl", "x", ["a.com", "b.com"])
    out = rarity.fill_global_counts(con, lambda t, v: {"error": "rate limited"})
    assert out["priced"] == 0 and out["errors"]
    assert rarity.assess(con, "webamon.fp_ssl", "x")["global_count"] is None


def test_pricing_does_not_spend_slots_on_types_the_counter_cannot_answer(con):
    """A run spent four of its fifty slots on dns.apex and dns.ns_set, which
    no web-scan index carries, and got an error back every time."""
    _seed(con, "dns.apex", "evil.example", ["a.evil.example", "b.evil.example"])
    _seed(con, "webamon.fp_ssl", "askme", ["a.com", "b.com"])
    asked: list = []
    out = rarity.fill_global_counts(
        con, lambda t, v: asked.append(t) or {"count": 3, "source": "webamon"},
        can_price=W.reversible)
    assert asked == ["webamon.fp_ssl"]
    assert out["candidates"] == 1 and out["errors"] == []
