"""Tests for cti_tools.pivot. No real network calls (and no real SSH to
the Win11 VM) - _get_json/vm_proxy.http_fetch/vm_proxy.resolve_dns are
monkeypatched everywhere so the suite runs offline."""
from __future__ import annotations

import pytest

from cti_tools import pivot


def test_classify_ip():
    assert pivot.classify("8.8.8.8") == "ip"
    assert pivot.classify("2001:4860:4860::8888") == "ip"


def test_classify_url():
    assert pivot.classify("https://example.com/path") == "url"


def test_classify_hash():
    assert pivot.classify("098f6bcd4621d373cade4e832627b4f6") == "hash"  # md5, 32 hex
    assert pivot.classify("7e6d9dac619c04ae1b3c8c0906123e752ed66d63") == "hash"  # sha1, 40 hex


def test_classify_domain_fallback():
    assert pivot.classify("example.com") == "domain"


def test_rdap_lookup_domain(monkeypatch):
    def fake_get_json(url, headers=None):
        assert "rdap.org/domain/example.com" in url
        return {
            "handle": "EXAMPLE-HANDLE",
            "name": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}],
            "entities": [{"roles": ["registrant"], "handle": "REG-1"}],
            "nameservers": [{"ldhName": "ns1.example.com"}],
        }
    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.rdap_lookup("example.com", "domain")
    assert result["handle"] == "EXAMPLE-HANDLE"
    assert result["nameservers"] == ["ns1.example.com"]
    assert result["events"][0]["action"] == "registration"


def test_rdap_lookup_ip_has_no_nameservers(monkeypatch):
    monkeypatch.setattr(pivot, "_get_json", lambda url, headers=None: {"handle": "IP-HANDLE"})
    result = pivot.rdap_lookup("1.2.3.4", "ip")
    assert result["nameservers"] is None


def test_rdap_lookup_error_is_contained(monkeypatch):
    def raise_error(url, headers=None):
        raise pivot.PivotError("boom")
    monkeypatch.setattr(pivot, "_get_json", raise_error)
    result = pivot.rdap_lookup("example.com", "domain")
    assert "error" in result


def test_get_json_transport_failure_becomes_pivoterror(monkeypatch):
    # http_fetch (proxied through the Win11 VM) raises VMProxyError on any
    # transport failure; _get_json must still surface a PivotError so
    # callers return {"error": ...} rather than letting the exception
    # escape mid-pivot.
    def boom(url, headers=None, method="GET"):
        raise pivot.vm_proxy.VMProxyError("ssh transport failed")
    monkeypatch.setattr(pivot.vm_proxy, "http_fetch", boom)
    with pytest.raises(pivot.PivotError):
        pivot._get_json("https://rdap.org/domain/example.com")


def test_get_json_unparseable_body_becomes_pivoterror(monkeypatch):
    monkeypatch.setattr(pivot.vm_proxy, "http_fetch",
                        lambda url, headers=None, method="GET":
                            {"status": 200, "body": "<html>rate limited</html>", "error": None})
    with pytest.raises(pivot.PivotError):
        pivot._get_json("https://api.certspotter.com/v1/issuances?domain=x")


def test_get_text_http_error_status_becomes_pivoterror(monkeypatch):
    monkeypatch.setattr(pivot.vm_proxy, "http_fetch",
                        lambda url, headers=None, method="GET":
                            {"status": 429, "body": "rate limited", "error": None})
    with pytest.raises(pivot.PivotError):
        pivot._get_text("https://api.hackertarget.com/reverseiplookup/?q=1.2.3.4")


def test_ripestat_lookup_merges_three_calls(monkeypatch):
    calls = []

    def fake_get_json(url, headers=None):
        calls.append(url)
        if "network-info" in url:
            return {"data": {"asns": [12345], "prefix": "1.2.3.0/24"}}
        if "as-overview" in url:
            return {"data": {"holder": "EXAMPLE-AS"}}
        if "geoloc" in url:
            return {"data": {"locations": [{"country": "US"}]}}
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.ripestat_lookup("1.2.3.4")
    assert result["asn"] == [12345]
    assert result["as_holder"] == "EXAMPLE-AS"
    assert result["geolocation"] == {"country": "US"}
    assert len(calls) == 3


def test_ripestat_lookup_skips_as_overview_when_no_asn(monkeypatch):
    def fake_get_json(url, headers=None):
        if "network-info" in url:
            return {"data": {"asns": [], "prefix": None}}
        if "geoloc" in url:
            return {"data": {"locations": []}}
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.ripestat_lookup("1.2.3.4")
    assert "as_holder" not in result
    assert result["geolocation"] is None


def test_ripestat_lookup_partial_failure_still_returns_other_fields(monkeypatch):
    def fake_get_json(url, headers=None):
        if "network-info" in url:
            raise pivot.PivotError("network-info down")
        if "geoloc" in url:
            return {"data": {"locations": [{"country": "DE"}]}}
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.ripestat_lookup("1.2.3.4")
    assert "network_info_error" in result
    assert result["geolocation"] == {"country": "DE"}


def test_virustotal_lookup_domain(monkeypatch):
    def fake_get_json(url, headers=None):
        assert headers == {"x-apikey": "fake-key"}
        if url.endswith("/domains/example.com"):
            return {"data": {"attributes": {
                "reputation": -5, "categories": {"vendor": "phishing"},
                "last_analysis_stats": {"malicious": 3},
            }}}
        if "resolutions" in url:
            return {"data": [{"attributes": {"ip_address": "1.2.3.4", "date": 111}}]}
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.virustotal_lookup("example.com", "domain", "fake-key")
    assert result["reputation"] == -5
    assert result["resolutions"] == [{"ip": "1.2.3.4", "date": 111}]


def test_virustotal_lookup_ip_includes_communicating_and_downloaded_files(monkeypatch):
    def fake_get_json(url, headers=None):
        assert headers == {"x-apikey": "fake-key"}
        if url.endswith("/ip_addresses/1.2.3.4"):
            return {"data": {"attributes": {
                "reputation": -10, "as_owner": "Evil Hosting", "country": "RU",
                "last_analysis_stats": {"malicious": 12},
            }}}
        if "resolutions" in url:
            return {"data": [{"attributes": {"host_name": "evil.example", "date": 111}}]}
        if "communicating_files" in url:
            return {"data": [{
                "id": "a" * 64,
                "attributes": {
                    "names": ["plugx.dll", "svchost.exe"],
                    "popular_threat_classification": {"suggested_threat_label": "backdoor.win32.plugx"},
                    "last_analysis_stats": {"malicious": 40, "undetected": 20},
                    "first_submission_date": 1700000000,
                },
            }]}
        if "downloaded_files" in url:
            return {"data": []}
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.virustotal_lookup("1.2.3.4", "ip", "fake-key")
    assert result["reputation"] == -10
    assert result["resolutions"] == [{"domain": "evil.example", "date": 111}]
    assert len(result["communicating_files"]) == 1
    cf = result["communicating_files"][0]
    assert cf["sha256"] == "a" * 64
    assert cf["suggested_label"] == "backdoor.win32.plugx"
    assert cf["malicious"] == 40
    assert cf["total_engines"] == 60
    assert result["downloaded_files"] == []


def test_virustotal_lookup_ip_tolerates_relationship_failure(monkeypatch):
    def fake_get_json(url, headers=None):
        if url.endswith("/ip_addresses/1.2.3.4"):
            return {"data": {"attributes": {}}}
        if "resolutions" in url:
            return {"data": []}
        raise pivot.PivotError("rate limited")

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.virustotal_lookup("1.2.3.4", "ip", "fake-key")
    assert result["communicating_files"] == []
    assert result["downloaded_files"] == []


def test_virustotal_lookup_hash(monkeypatch):
    def fake_get_json(url, headers=None):
        return {"data": {"attributes": {
            "names": ["evil.exe"], "type_description": "PE32",
            "last_analysis_stats": {"malicious": 40},
            "popular_threat_classification": {"suggested_threat_label": "trojan"},
        }}}

    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.virustotal_lookup("098f6bcd4621d373cade4e832627b4f6", "hash", "fake-key")
    assert result["names"] == ["evil.exe"]
    assert result["popular_threat_classification"]["suggested_threat_label"] == "trojan"


def test_virustotal_lookup_unsupported_kind_raises():
    with pytest.raises(pivot.PivotError):
        pivot.virustotal_lookup("x", "bogus-kind", "fake-key")


def test_certspotter_lookup_collects_hostnames(monkeypatch):
    def fake_get_json(url, headers=None):
        assert "api.certspotter.com" in url and "example.com" in url
        return [
            {"dns_names": ["example.com", "*.example.com"],
             "issuer": {"name": "Let's Encrypt"},
             "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z"},
            {"dns_names": ["vpn.example.com"], "issuer": {"name": "ZeroSSL"},
             "not_before": "2026-02-01T00:00:00Z", "not_after": "2026-05-01T00:00:00Z"},
        ]
    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.certspotter_lookup("example.com")
    assert result["issuance_count"] == 2
    # wildcard prefix stripped, deduped, lower-cased
    assert result["hostnames"] == ["example.com", "vpn.example.com"]
    assert result["issuances"][0]["issuer"] == "Let's Encrypt"


def test_certspotter_lookup_error_is_contained(monkeypatch):
    def raise_error(url, headers=None):
        raise pivot.PivotError("HTTP 429")
    monkeypatch.setattr(pivot, "_get_json", raise_error)
    assert "error" in pivot.certspotter_lookup("example.com")


def test_hackertarget_reverse_ip_parses_lines(monkeypatch):
    monkeypatch.setattr(pivot, "_get_text",
                        lambda url, headers=None: "a.example\nb.example\n\nc.example\n")
    result = pivot.hackertarget_reverse_ip("1.2.3.4")
    assert result["domains"] == ["a.example", "b.example", "c.example"]


def test_hackertarget_reverse_ip_quota_message_is_error(monkeypatch):
    monkeypatch.setattr(pivot, "_get_text",
                        lambda url, headers=None: "API count exceeded - Increase Quota with Membership")
    assert "error" in pivot.hackertarget_reverse_ip("1.2.3.4")


def test_hackertarget_reverse_ip_no_records_message_is_error(monkeypatch):
    # Regression: "No DNS A records found" used to slip through and get
    # parsed as a bogus domain (it isn't caught by a naive "no records"
    # substring check, and has spaces so it isn't a hostname).
    monkeypatch.setattr(pivot, "_get_text", lambda url, headers=None: "No DNS A records found")
    result = pivot.hackertarget_reverse_ip("4.4.3.12")
    assert "error" in result
    assert "domains" not in result


def test_is_shared_hosting_hostname_matches_known_suffixes():
    assert pivot.is_shared_hosting_hostname(
        "a2aa9ff50de748dbe.awsglobalaccelerator.com")
    assert pivot.is_shared_hosting_hostname("D111111ABCDEF8.cloudfront.net")


def test_is_shared_hosting_hostname_false_for_actor_domain():
    assert not pivot.is_shared_hosting_hostname("blog.housby.com")


def test_shodan_internetdb_lookup_parses_fields(monkeypatch):
    monkeypatch.setattr(
        pivot.vm_proxy, "http_fetch",
        lambda url, headers=None: {
            "status": 200,
            "body": '{"ports": [22, 443], "hostnames": ["a.example"], '
                    '"cpes": ["cpe:/a:foo"], "tags": ["cloud"], "vulns": ["CVE-2020-1"]}',
            "error": None,
        })
    result = pivot.shodan_internetdb_lookup("1.2.3.4")
    assert result["ports"] == [22, 443]
    assert result["hostnames"] == ["a.example"]
    assert result["cpes"] == ["cpe:/a:foo"]
    assert result["tags"] == ["cloud"]
    assert result["vulns"] == ["CVE-2020-1"]


def test_shodan_internetdb_lookup_404_is_empty_not_error(monkeypatch):
    monkeypatch.setattr(
        pivot.vm_proxy, "http_fetch",
        lambda url, headers=None: {
            "status": 404, "body": '{"detail": "No information available"}', "error": None})
    result = pivot.shodan_internetdb_lookup("9.9.9.9")
    assert result == {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}
    assert "error" not in result


def test_shodan_internetdb_lookup_real_error_is_contained(monkeypatch):
    monkeypatch.setattr(
        pivot.vm_proxy, "http_fetch",
        lambda url, headers=None: {"status": 503, "body": "", "error": None})
    result = pivot.shodan_internetdb_lookup("1.2.3.4")
    assert "error" in result


def test_shodan_internetdb_lookup_transport_failure_is_contained(monkeypatch):
    def boom(url, headers=None):
        raise pivot.vm_proxy.VMProxyError("ssh failed")
    monkeypatch.setattr(pivot.vm_proxy, "http_fetch", boom)
    result = pivot.shodan_internetdb_lookup("1.2.3.4")
    assert "error" in result


def test_honeylabs_lookup_url_auth_and_normalization(monkeypatch):
    # Field names mirror a real observed-IP response captured 2026-08-17
    # (shodan census IP), not the "totals"-wrapper shape the public docs
    # sketch - see honeylabs_lookup's docstring.
    seen = {}

    def fake_get_json(url, headers=None):
        seen["url"] = url
        seen["headers"] = headers
        return {
            "ip": "203.0.113.5",
            "total_events": 3872,
            "events_24h": 22,
            "events_7d": 140,
            "first_seen": "2026-02-16T14:23:04",
            "last_seen": "2026-08-17T10:42:23",
            "geo": {"country_code": "US", "asn": 10439, "org": "CariNet, Inc."},
            "verdict": {"verdict": "scanner", "label": "Recognized scanner",
                        "detail": "shodan", "confidence": "high"},
            "known_scanners": ["shodan"],
            "top_ports": [{"port": 8443, "proto": "tcp", "count": 68}],
            "fingerprints": {"ssh_hassh": ["a704be05"], "tls_ja4": ["t12i570500_x"]},
            "cve_matches": [],
            "malware": [],
        }
    monkeypatch.setattr(pivot, "_get_json", fake_get_json)
    result = pivot.honeylabs_lookup("203.0.113.5", "hlk_fake")
    assert seen["url"] == "https://honeylabs.net/lookup/203.0.113.5?format=json"
    assert seen["headers"] == {"Authorization": "Bearer hlk_fake"}
    assert result["events"] == 3872
    assert result["events_24h"] == 22
    assert result["first_seen"] == "2026-02-16T14:23:04"
    assert result["country"] == "US"
    assert result["asn"] == 10439
    assert result["as_org"] == "CariNet, Inc."
    assert result["verdict"] == "scanner"
    assert result["verdict_label"] == "Recognized scanner"
    assert result["known_scanners"] == ["shodan"]
    assert result["ports"] == [{"port": 8443, "proto": "tcp", "count": 68}]
    assert result["cves"] == []


def test_honeylabs_lookup_unobserved_ip_shape(monkeypatch):
    # Live no-activity shape: compact, no geo/verdict/top_ports at all.
    monkeypatch.setattr(pivot, "_get_json", lambda url, headers=None: {
        "ip": "203.0.113.5", "observed": False, "total_events": 0,
        "message": "No activity observed for this IP in our sensor network."})
    result = pivot.honeylabs_lookup("203.0.113.5", "hlk_fake")
    assert result["events"] == 0
    assert result["events_24h"] is None
    assert result["verdict"] is None
    assert result["country"] is None


def test_honeylabs_lookup_http_error_propagates(monkeypatch):
    def raise_error(url, headers=None):
        raise pivot.PivotError("HTTP 429")
    monkeypatch.setattr(pivot, "_get_json", raise_error)
    with pytest.raises(pivot.PivotError):
        pivot.honeylabs_lookup("203.0.113.5", "hlk_fake")


def test_honeylabs_lookup_unexpected_shape_raises(monkeypatch):
    monkeypatch.setattr(pivot, "_get_json", lambda url, headers=None: ["not", "a", "dict"])
    with pytest.raises(pivot.PivotError):
        pivot.honeylabs_lookup("203.0.113.5", "hlk_fake")


def test_resolve_host_distinguishes_dead_from_inconclusive(monkeypatch):
    # Resolution now happens on the Win11 VM via vm_proxy.resolve_dns;
    # resolve_host layers its own null-route/loopback filtering on top of
    # whatever that returns.
    monkeypatch.setattr(pivot.vm_proxy, "resolve_dns", lambda host: [])
    assert pivot.resolve_host("nope.invalid") == []  # doesn't resolve (NXDOMAIN)

    monkeypatch.setattr(pivot.vm_proxy, "resolve_dns", lambda host: None)
    assert pivot.resolve_host("nope.invalid") is None  # inconclusive

    monkeypatch.setattr(pivot.vm_proxy, "resolve_dns", lambda host: ["185.10.10.10"])
    assert pivot.resolve_host("live.example") == ["185.10.10.10"]

    def boom(host):
        raise pivot.vm_proxy.VMProxyError("ssh transport failed")
    monkeypatch.setattr(pivot.vm_proxy, "resolve_dns", boom)
    assert pivot.resolve_host("nope.invalid") is None  # transport failure -> inconclusive


def test_ptr_lookup_resolved(monkeypatch):
    monkeypatch.setattr(pivot.vm_proxy, "resolve_ptr", lambda ip: "host.example")
    assert pivot.ptr_lookup("185.10.10.10") == {"hostname": "host.example"}


def test_ptr_lookup_no_ptr_is_not_an_error(monkeypatch):
    monkeypatch.setattr(pivot.vm_proxy, "resolve_ptr", lambda ip: None)
    result = pivot.ptr_lookup("185.10.10.10")
    assert result == {"hostname": None}
    assert "error" not in result


def test_ptr_lookup_inconclusive_becomes_error(monkeypatch):
    def boom(ip):
        raise pivot.vm_proxy.VMProxyError("ssh transport failed")
    monkeypatch.setattr(pivot.vm_proxy, "resolve_ptr", boom)
    assert pivot.ptr_lookup("185.10.10.10") == {"error": "ssh transport failed"}


def test_post_json_sends_post_with_json_body(monkeypatch):
    captured = {}

    def fake_http_fetch(url, headers=None, method="GET", data=None):
        captured["url"], captured["headers"], captured["method"], captured["data"] = (
            url, headers, method, data)
        return {"status": 200, "body": '{"ok": true}', "error": None}

    monkeypatch.setattr(pivot.vm_proxy, "http_fetch", fake_http_fetch)
    result = pivot._post_json("https://example.com/api", {"query": "search_ioc", "search_term": "x"})
    assert result == {"ok": True}
    assert captured["method"] == "POST"
    assert captured["data"] == '{"query": "search_ioc", "search_term": "x"}'
    assert captured["headers"]["Content-Type"] == "application/json"


def test_post_json_transport_failure_becomes_pivoterror(monkeypatch):
    def boom(url, headers=None, method="GET", data=None):
        raise pivot.vm_proxy.VMProxyError("ssh failed")
    monkeypatch.setattr(pivot.vm_proxy, "http_fetch", boom)
    with pytest.raises(pivot.PivotError):
        pivot._post_json("https://example.com/api", {"query": "search_ioc"})


def test_post_json_error_status_surfaces_json_body_detail(monkeypatch):
    # A real observed case: ThreatFox returns 403 with a small JSON body
    # naming the actual problem ("unknown_auth_key") - that's far more
    # actionable than a bare "returned HTTP 403", so it should end up in
    # the raised error's message.
    monkeypatch.setattr(
        pivot.vm_proxy, "http_fetch",
        lambda url, headers=None, method="GET", data=None: {
            "status": 403, "body": '{"query_status": "unknown_auth_key"}', "error": None})
    with pytest.raises(pivot.PivotError, match="unknown_auth_key"):
        pivot._post_json("https://example.com/api", {"query": "search_ioc"})


def test_post_json_error_status_with_non_json_body_still_raises(monkeypatch):
    monkeypatch.setattr(
        pivot.vm_proxy, "http_fetch",
        lambda url, headers=None, method="GET", data=None: {
            "status": 500, "body": "internal server error", "error": None})
    with pytest.raises(pivot.PivotError, match="internal server error"):
        pivot._post_json("https://example.com/api", {"query": "search_ioc"})


def test_threatfox_lookup_sends_auth_key_header(monkeypatch):
    captured = {}

    def fake_post_json(url, payload, headers=None):
        captured["headers"] = headers
        return {"query_status": "no_result"}
    monkeypatch.setattr(pivot, "_post_json", fake_post_json)
    pivot.threatfox_lookup("1.2.3.4", "fake-tf-key")
    assert captured["headers"] == {"Auth-Key": "fake-tf-key"}


def test_threatfox_lookup_ok_status_parses_matches(monkeypatch):
    monkeypatch.setattr(pivot, "_post_json", lambda url, payload, headers=None: {
        "query_status": "ok",
        "data": [
            {
                "ioc": "1.2.3.4:443",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 80,
                "first_seen_utc": "2026-01-01 00:00:00",
                "last_seen_utc": "2026-08-01 00:00:00",
                "tags": ["cobaltstrike"],
            }
        ],
    })
    result = pivot.threatfox_lookup("1.2.3.4", "fake-tf-key")
    assert result["matches"] == [{
        "ioc": "1.2.3.4:443",
        "threat_type": "botnet_cc",
        "malware": "Cobalt Strike",
        "confidence_level": 80,
        "first_seen": "2026-01-01 00:00:00",
        "last_seen": "2026-08-01 00:00:00",
        "tags": ["cobaltstrike"],
    }]


def test_threatfox_lookup_no_result_is_empty_not_error(monkeypatch):
    monkeypatch.setattr(pivot, "_post_json",
                        lambda url, payload, headers=None: {"query_status": "no_result"})
    result = pivot.threatfox_lookup("benign.example", "fake-tf-key")
    assert result == {"matches": []}


def test_threatfox_lookup_unexpected_status_is_error(monkeypatch):
    monkeypatch.setattr(pivot, "_post_json",
                        lambda url, payload, headers=None: {"query_status": "illegal_search_term"})
    result = pivot.threatfox_lookup("bad value", "fake-tf-key")
    assert "error" in result


def test_threatfox_lookup_transport_failure_is_contained(monkeypatch):
    def boom(url, payload, headers=None):
        raise pivot.PivotError("failed to reach threatfox")
    monkeypatch.setattr(pivot, "_post_json", boom)
    result = pivot.threatfox_lookup("1.2.3.4", "fake-tf-key")
    assert "error" in result
