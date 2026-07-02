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
