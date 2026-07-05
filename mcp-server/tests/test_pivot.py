"""Tests for cti_tools.pivot. No real network calls - _get_json is
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


def test_get_json_read_timeout_becomes_pivoterror(monkeypatch):
    # A read-phase timeout raises a bare TimeoutError, not URLError; it must
    # still surface as PivotError so callers return {"error": ...} rather
    # than letting the exception escape mid-pivot.
    def boom(req, timeout=None):
        raise TimeoutError("The read operation timed out")
    monkeypatch.setattr(pivot.urllib.request, "urlopen", boom)
    with pytest.raises(pivot.PivotError):
        pivot._get_json("https://rdap.org/domain/example.com")


def test_get_json_unparseable_body_becomes_pivoterror(monkeypatch):
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b"<html>rate limited</html>"
    monkeypatch.setattr(pivot.urllib.request, "urlopen", lambda req, timeout=None: FakeResp())
    with pytest.raises(pivot.PivotError):
        pivot._get_json("https://api.certspotter.com/v1/issuances?domain=x")


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


def test_resolve_host_distinguishes_dead_from_inconclusive(monkeypatch):
    import socket

    def gaierror(*a, **k):
        raise socket.gaierror("NXDOMAIN")
    monkeypatch.setattr(pivot.socket, "getaddrinfo", gaierror)
    assert pivot.resolve_host("nope.invalid") == []  # doesn't resolve

    def oserror(*a, **k):
        raise OSError("timeout")
    monkeypatch.setattr(pivot.socket, "getaddrinfo", oserror)
    assert pivot.resolve_host("nope.invalid") is None  # inconclusive

    monkeypatch.setattr(pivot.socket, "getaddrinfo",
                        lambda *a, **k: [(0, 0, 0, "", ("185.10.10.10", 0))])
    assert pivot.resolve_host("live.example") == ["185.10.10.10"]
