"""The selector layer: what links two indicators, and what must never.

The tests that matter here are the negative ones. A selector index is easy
to build and easy to drown: backfilling this repo's real data without the
class system and the shared-hosting gates produced 849 "promotable links",
almost all of them Cloudflare tenants and Let's Encrypt issuers. With them
it produces 14, and they are real. Several tests below encode that exact
regression with the actual values from the live store.
"""
from __future__ import annotations

from datetime import datetime

import duckdb
import pytest

from cti.store import cdn, psl
from cti.store import selectors as S
from cti.store.schema import init_schema

DAY = datetime(2026, 9, 19, 6, 0)


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    yield c
    c.close()


def add(con, indicator, selector_type, value, actor=None, when=DAY):
    return S.record(con, indicator_value=indicator, selector_type=selector_type,
                    selector_value=value, observed_at=when, actor=actor,
                    indicator_type="domain", source="test")


# --------------------------------------------------------------------------- #
# The taxonomy is the guard
# --------------------------------------------------------------------------- #

def test_every_declared_type_has_a_known_class():
    for name, spec in S.TYPES.items():
        assert spec.cls in S.CLASS_ORDER, f"{name} has class {spec.cls!r}"


def test_every_type_says_what_a_shared_value_means():
    """A selector nobody can interpret is a selector that gets misread."""
    for name, spec in S.TYPES.items():
        assert len(spec.means) > 20, f"{name} has no usable 'means'"


@pytest.mark.parametrize("selector_type", [
    "http.server", "tls.issuer", "net.asn", "http.tech", "net.country",
])
def test_contextual_selectors_can_never_promote(selector_type):
    """`Server: cloudflare` is shared by 8 indicators across 3 actors in the
    live data, and `Let's Encrypt` by 5 across 3. Neither is a lead, and no
    amount of sharing may make one."""
    assert not S.can_promote(selector_type)


@pytest.mark.parametrize("selector_type", [
    "tls.jarm", "tls.ja4s", "net.port_set", "http.title", "net.cohosted_domain",
])
def test_behavioural_selectors_corroborate_but_do_not_promote(selector_type):
    assert not S.can_promote(selector_type)
    assert S.selector_class(selector_type) == "behavioural"


@pytest.mark.parametrize("selector_type", [
    "tls.cert_sha256", "http.body_sha256", "http.favicon_mmh3", "dns.apex",
    "whois.registrant_email", "tls.san",
])
def test_identity_and_structural_selectors_may_promote(selector_type):
    assert S.can_promote(selector_type)


def test_an_unclassified_type_defaults_to_powerless():
    """Adding a selector type must be a deliberate act. A typo, or a new type
    someone forgot to class, must not silently gain promoting power."""
    assert S.selector_class("something.invented") == "contextual"
    assert not S.can_promote("something.invented")


# --------------------------------------------------------------------------- #
# Normalization - the same fact from two tools must become one selector
# --------------------------------------------------------------------------- #

def test_hashes_match_regardless_of_case():
    assert (S.normalize("tls.cert_sha256", "ABCD1234")
            == S.normalize("tls.cert_sha256", "abcd1234"))


def test_hostnames_match_regardless_of_case_or_trailing_dot():
    assert (S.normalize("dns.apex", "Example.COM.")
            == S.normalize("dns.apex", "example.com"))


def test_a_set_valued_selector_is_order_independent():
    """Ports arrive in whatever order the scanner emitted them."""
    assert (S.normalize("net.port_set", [443, 80, 8443])
            == S.normalize("net.port_set", [8443, 443, 80]))


def test_empty_and_placeholder_values_are_not_selectors():
    for junk in (None, "", "   ", "-", "unknown", "N/A", "null"):
        assert S.normalize("http.server", junk) is None


def test_the_empty_body_hash_is_not_a_link():
    """Every host that answers with no body shares this digest. Recording it
    would link them all to each other."""
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert S.normalize("http.body_sha256", empty) is None
    assert S.normalize("http.body_sha256", "a" * 64) is not None


def test_a_boolean_is_never_a_selector_value():
    assert S.normalize("tls.cert_sha256", True) is None


# --------------------------------------------------------------------------- #
# The query that was impossible
# --------------------------------------------------------------------------- #

def test_sharing_finds_every_indicator_with_a_value(con):
    for host in ("a.example", "b.example", "c.example"):
        add(con, host, "tls.cert_sha256", "DEADBEEF", actor="X")
    hits = S.sharing(con, "tls.cert_sha256", "deadbeef")
    assert {h["indicator_value"] for h in hits} == {"a.example", "b.example", "c.example"}


def test_sharing_is_case_insensitive_on_the_query_too(con):
    add(con, "a.example", "tls.cert_sha256", "abc123")
    assert len(S.sharing(con, "tls.cert_sha256", "ABC123")) == 1


def test_recording_the_same_selector_twice_updates_rather_than_duplicates(con):
    assert add(con, "a.example", "dns.apex", "example.com") is True
    assert add(con, "a.example", "dns.apex", "example.com",
               when=datetime(2026, 9, 20)) is False
    assert len(S.sharing(con, "dns.apex", "example.com")) == 1


def test_shared_hides_the_noise_types_by_default(con):
    """This is the 849-to-14 reduction, in miniature."""
    for host in ("a.example", "b.example"):
        add(con, host, "http.server", "cloudflare")
        add(con, host, "tls.issuer", "C = US, O = Let's Encrypt, CN = YE1")
        add(con, host, "tls.cert_sha256", "realsharedcert")

    promotable = S.shared(con)
    assert [r["selector_type"] for r in promotable] == ["tls.cert_sha256"]

    everything = S.shared(con, promotable_only=False)
    assert len(everything) == 3, "the noise is still recorded, just not surfaced"


def test_a_value_held_by_one_indicator_is_not_a_link(con):
    add(con, "lonely.example", "tls.cert_sha256", "unique")
    assert S.shared(con) == []


def test_neighbours_reports_which_selectors_connect_two_indicators(con):
    add(con, "a.example", "dns.apex", "shared.example")
    add(con, "b.example", "dns.apex", "shared.example")
    add(con, "a.example", "tls.cert_sha256", "samecert")
    add(con, "b.example", "tls.cert_sha256", "samecert")
    add(con, "a.example", "http.server", "nginx")
    add(con, "b.example", "http.server", "nginx")

    [neighbour] = S.neighbours(con, "a.example")
    assert neighbour["indicator_value"] == "b.example"
    assert set(neighbour["via"]) == {"dns.apex", "tls.cert_sha256"}
    assert "http.server" not in neighbour["via"], "contextual links must not be offered"
    assert neighbour["strongest"] == "identity"


def test_a_neighbour_linked_only_by_noise_is_not_a_neighbour(con):
    for host in ("a.example", "b.example"):
        add(con, host, "http.server", "cloudflare")
        add(con, host, "net.asn", "13335")
    assert S.neighbours(con, "a.example") == []


def test_an_indicator_is_never_its_own_neighbour(con):
    add(con, "a.example", "dns.apex", "example.com")
    assert S.neighbours(con, "a.example") == []


# --------------------------------------------------------------------------- #
# Registration links need a real public suffix list
# --------------------------------------------------------------------------- #

def test_the_public_suffix_list_is_vendored():
    assert psl.available(), "the PSL data file is missing"


def test_the_registration_link_from_the_source_reporting():
    """`evo.hoster-kg.com` and `help.hoster-kg.com` were used by different
    malware families and tied together by the shared registration."""
    assert psl.apex_for_selector("evo.hoster-kg.com") == "hoster-kg.com"
    assert psl.apex_for_selector("help.hoster-kg.com") == "hoster-kg.com"
    assert psl.apex_for_selector("mineconom.tdtu.org") == "tdtu.org"


def test_a_public_suffix_is_not_a_registration_link():
    """The first version of this took the last two labels and produced
    `workers.dev` as a four-indicator link across two actors. Anyone can get
    a name under it, so it links nothing."""
    assert psl.apex_for_selector("foo.edu.hk") is None
    # `foo.co.uk` is itself the registered name under the `co.uk` suffix, so
    # there is no parent to link on. (`a.b.co.uk` DOES link to `b.co.uk` -
    # that is a real registration, which is why it is not the example here.)
    assert psl.apex_for_selector("foo.co.uk") is None


def test_a_subdomain_under_a_public_suffix_still_links_to_its_own_apex():
    """`ols-img-12.workers.dev` IS the registered name - two hosts under it
    do share a registration, even though `workers.dev` does not."""
    assert (psl.apex_for_selector("is-01.ols-img-12.workers.dev")
            == "ols-img-12.workers.dev")


def test_a_domain_that_is_already_an_apex_records_nothing():
    """An apex selector linking a name only to itself is not a link."""
    assert psl.apex_for_selector("example.com") is None


def test_multi_label_suffixes_resolve_to_the_registered_name():
    assert psl.apex_for_selector("a.b.example.co.uk") == "example.co.uk"


# --------------------------------------------------------------------------- #
# CDN addresses are not links
# --------------------------------------------------------------------------- #

def test_cdn_ranges_are_vendored():
    assert cdn.available()


@pytest.mark.parametrize("address", [
    "172.67.140.122", "104.21.70.237", "2606:4700:3037::6815:46ed",
])
def test_known_cdn_addresses_are_recognised(address):
    """All three appeared as 'structural' links in the real backfill before
    this gate existed. Two domains behind one Cloudflare edge share a
    provider, not an operator."""
    assert cdn.is_cdn(address)


@pytest.mark.parametrize("address", [
    "192.252.186.62", "37.1.220.158", "193.24.211.221",
])
def test_dedicated_addresses_are_not_suppressed(address):
    """The reverse error is worse: 192.252.186.62 carries six JadeProx
    EDR-impersonation domains, and suppressing it would hide a real
    infrastructure cluster."""
    assert not cdn.is_cdn(address)


def test_a_non_address_is_not_a_cdn():
    assert not cdn.is_cdn("not-an-ip")
    assert not cdn.is_cdn("")


# --------------------------------------------------------------------------- #
# Extraction from an observe pass
# --------------------------------------------------------------------------- #

from cti.sources import observe  # noqa: E402

# A realistic result, shaped like the source reporting's own findings: a
# cloned decoy page, a certificate impersonating a state entity, RDP-over-TLS
# on an unusual high port.
_OBSERVED = {
    "target": "azure.uzrailwaystax.com", "kind": "domain",
    "http": {"status": 200, "title": "RTX Corporation",
             "body_sha256": "b" * 64, "favicon_mmh3": -1234567890,
             "server": "nginx/1.29.3", "tech": ["nginx"], "asn": 12345,
             "jarm": "29d3fd00029d29d00042d43d00041d" + "a" * 32},
    "tls": {"issuer": "CN = TLC DV TLS CA", "subject_cn": "azure.uzrailwaystax.com",
            "subject_dn": "CN = azure.uzrailwaystax.com",
            "sans": ["azure.uzrailwaystax.com", "help.hoster-kg.com"],
            "serial": "0A1B2C", "cert_sha256": "c" * 64, "spki_sha256": "d" * 64,
            "ja3s": "e" * 32, "resolved_ip": "193.29.58.192"},
    "dns": {"a": ["193.29.58.192"], "aaaa": [], "ns": ["ns2.example", "ns1.example"],
            "soa_email": "admin@example.com"},
    "whois": {"registrar": "Example Registrar", "registrant_email": "op@mail.example"},
    "cdn": {"is_cdn": False}, "ports": [443, 64350],
    "errors": {}, "tools_missing": [],
}


def _extracted(result, target=None, kind="domain"):
    return dict(observe.selectors_from(
        result, target=target or result["target"], kind=kind))


def test_the_report_style_pass_yields_the_pivots_that_mattered():
    got = _extracted(_OBSERVED)
    assert got["http.body_sha256"] == "b" * 64      # the 13-host decoy page
    assert got["tls.cert_sha256"] == "c" * 64       # the 8-host certificate
    assert got["net.port_set"] == [443, 64350]      # RDP-over-TLS high port
    assert got["dns.apex"] == "uzrailwaystax.com"   # registration level
    assert got["whois.registrant_email"] == "op@mail.example"


def test_every_emitted_selector_type_is_declared():
    """A typo'd type would silently become class contextual and quietly lose
    its ability to promote anything."""
    for selector_type in _extracted(_OBSERVED):
        assert selector_type in observe.known_types(), selector_type


def test_a_certificate_naming_only_itself_is_not_a_link():
    got = list(observe.selectors_from(
        {"tls": {"sans": ["azure.uzrailwaystax.com"]}},
        target="azure.uzrailwaystax.com", kind="domain"))
    assert not [v for t, v in got if t == "tls.san"]


def test_a_san_naming_another_host_is_a_link():
    assert "help.hoster-kg.com" in [
        v for t, v in observe.selectors_from(_OBSERVED, target=_OBSERVED["target"],
                                             kind="domain") if t == "tls.san"]


def test_resolution_is_not_recorded_on_cdn_infrastructure():
    """Two domains behind one CDN address share a provider, not an operator."""
    behind_cdn = {**_OBSERVED, "cdn": {"is_cdn": True, "provider": "cloudflare"}}
    assert "net.resolved_ip" not in _extracted(behind_cdn)
    assert "net.resolved_ip" in _extracted(_OBSERVED), "and IS recorded otherwise"


def test_a_default_openssl_certificate_subject_is_not_a_selector():
    """Every unconfigured OpenSSL install shares this subject."""
    default = {"tls": {"subject_dn": "O = Internet Widgits Pty Ltd, CN = localhost"}}
    assert "tls.subject_cn" not in _extracted(default, target="x.example")


def test_a_stock_server_landing_page_title_is_not_a_selector():
    for title in ("Welcome to nginx!", "404 Not Found", "It works!"):
        got = _extracted({"http": {"title": title}}, target="x.example")
        assert "http.title" not in got, title


def test_the_nameserver_set_is_one_selector_not_several():
    """One nameserver shared with a mass provider means nothing; the whole
    set is an account."""
    got = _extracted(_OBSERVED)
    assert isinstance(got["dns.ns_set"], list)
    assert S.normalize("dns.ns_set", got["dns.ns_set"]) == "ns1.example,ns2.example"


def test_an_ip_observation_yields_no_registration_selectors():
    got = _extracted({**_OBSERVED, "kind": "ip"}, target="193.29.58.192", kind="ip")
    for registration_only in ("dns.apex", "whois.registrar", "dns.ns_set"):
        assert registration_only not in got


def test_contextual_facts_are_still_recorded_just_powerless():
    """They are needed to describe a finding, they simply cannot make one."""
    got = _extracted(_OBSERVED)
    assert got["http.server"] == "nginx/1.29.3"
    assert not S.can_promote("http.server")


def test_summarize_reports_missing_tools_rather_than_pretending():
    text = observe.summarize({"http": {}, "tls": {}, "tools_missing": ["httpx"]})
    assert "missing" in text and "httpx" in text


# --------------------------------------------------------------------------- #
# The CDN gate must fail closed
# --------------------------------------------------------------------------- #

def test_a_broken_cdn_check_does_not_re_enable_the_noise():
    """Found on the first real observe pass. cdncheck exited 2 on a bad flag,
    is_cdn came back False, and four Cloudflare addresses were recorded as
    structural links for example.com - a broken detector silently undoing the
    gate it was there to enforce."""
    broken = {
        "dns": {"a": ["104.20.23.154", "172.66.147.243"],
                "aaaa": ["2606:4700:10::6814:179a"]},
        "cdn": {}, "errors": {"cdn": "cdncheck exited 2"},
    }
    recorded = [v for t, v in observe.selectors_from(
        broken, target="example.com", kind="domain") if t == "net.resolved_ip"]
    assert recorded == []


def test_a_dedicated_address_is_still_recorded_when_the_check_works():
    """The reverse error would hide real clusters."""
    fine = {"dns": {"a": ["193.29.58.192"]}, "cdn": {"is_cdn": False}, "errors": {}}
    recorded = [v for t, v in observe.selectors_from(
        fine, target="x.example", kind="domain") if t == "net.resolved_ip"]
    assert recorded == ["193.29.58.192"]


def test_a_cdn_address_is_dropped_even_when_cdncheck_says_the_target_is_not():
    """cdncheck reports on the TARGET; the resolved addresses can differ.
    Both have to be checked."""
    mixed = {"dns": {"a": ["104.20.23.154", "193.29.58.192"]},
             "cdn": {"is_cdn": False}, "errors": {}}
    recorded = [v for t, v in observe.selectors_from(
        mixed, target="x.example", kind="domain") if t == "net.resolved_ip"]
    assert recorded == ["193.29.58.192"]


def test_the_tls_handshake_address_goes_through_the_same_gate():
    """It is a second, independent path to net.resolved_ip and was not gated
    at all in the first version."""
    cdn_tls = {"dns": {}, "tls": {"resolved_ip": "172.66.147.243"},
               "cdn": {"is_cdn": False}, "errors": {}}
    recorded = [v for t, v in observe.selectors_from(
        cdn_tls, target="x.example", kind="domain") if t == "net.resolved_ip"]
    assert recorded == []
