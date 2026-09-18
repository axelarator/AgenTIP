"""Tests for cti_tools.webamon. No real network - webamon._get is
monkeypatched so the suite runs offline."""
from __future__ import annotations

import json

import pytest

from cti_tools import webamon


@pytest.fixture(autouse=True)
def _isolate_quota(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(webamon, "_DATA_DIR", tmp_path)
    monkeypatch.setenv("WEBAMON_API_KEY", "test-key")
    yield


# --- a representative scan document, trimmed from a real API response ------
_SCAN_DOC = {
    "report_id": "rid-1", "date": "2026-09-11", "scan_status": "success",
    "resolved_url": "https://evil.example/", "resolved_domain": "evil.example",
    "page_title": "Login", "meta": {"risk_score": 80},
    "certificate": [{"issuer": "R3", "subject_name": "evil.example",
                     "san_list": ["evil.example", "www.evil.example"],
                     "valid_from_utc": "2026-09-01T00:00:00Z",
                     "valid_to_utc": "2026-12-01T00:00:00Z", "protocol": "TLS 1.3"}],
    "domain": [{"name": "evil.example", "ip": "203.0.113.7", "server": "nginx",
                "asn": {"number": 64500, "name": "EvilNet", "network": "203.0.113.0/24"},
                "country": {"iso": "RU"}}],
    "technology": ["nginx"],
    "fingerprint": {"dom": "domhash", "ssl": "sslhash", "tech": "techhash",
                    "cookies": "c", "asn": "a", "scripts": "s", "links": "l", "domains": "d"},
    "dom": "<html>... huge ...</html>",   # must be dropped
}


def test_normalize_scan_extracts_fields_and_drops_dom():
    n = webamon.normalize_scan(_SCAN_DOC)
    assert n["report_id"] == "rid-1"
    assert n["risk_score"] == 80
    assert n["certificates"][0]["sans"] == ["evil.example", "www.evil.example"]
    assert n["ips"][0]["asn"] == 64500 and n["ips"][0]["country"] == "RU"
    assert n["fingerprint"]["dom"] == "domhash"
    assert "dom" not in n  # the raw page HTML never survives normalization


def test_search_domain_prefers_own_scan(monkeypatch):
    other = dict(_SCAN_DOC, report_id="rid-other", resolved_domain="attacker.test",
                 date="2026-09-12")
    monkeypatch.setattr(webamon, "_search",
                        lambda params: {"total_hits": 2, "results": [other, _SCAN_DOC]})
    out = webamon.search_domain("evil.example")
    # newest result is `other` (a scan of attacker.test that loaded evil.example),
    # but latest must be the scan actually OF evil.example.
    assert out["latest"]["report_id"] == "rid-1"


def test_search_domain_falls_back_when_no_own_scan(monkeypatch):
    other = dict(_SCAN_DOC, report_id="rid-other", resolved_domain="attacker.test")
    monkeypatch.setattr(webamon, "_search",
                        lambda params: {"total_hits": 1, "results": [other]})
    out = webamon.search_domain("evil.example")
    assert out["latest"]["report_id"] == "rid-other"


def test_search_ip_dedupes_domains(monkeypatch):
    monkeypatch.setattr(webamon, "_search", lambda params: {"total_hits": 3, "results": [
        {"resolved_domain": "a.test", "date": "2026-09-10"},
        {"resolved_domain": "a.test", "date": "2026-09-09"},
        {"resolved_domain": "b.test", "date": "2026-09-08"}]})
    out = webamon.search_ip("203.0.113.7")
    assert out["domains"] == ["a.test", "b.test"]


def test_infostealers_strips_plaintext_password(monkeypatch):
    monkeypatch.setattr(webamon, "_search", lambda params: {"total_hits": 1, "results": [
        {"domain": "evil.example", "url": "https://evil.example/login",
         "username": "bob", "password": "hunter2", "password_peek": "h*****2",
         "source": "telegram", "file_name": "logs.txt", "file_sha256": "abc",
         "ingest_date": "2026-02-10"}]})
    out = webamon.infostealers("evil.example")
    row = out["results"][0]
    assert "password" not in row
    assert row["password_peek"] == "h*****2"


def test_infostealers_drops_rows_that_dont_match_the_term(monkeypatch):
    # The index analyzes `username:@domain` into tokens, so the raw query
    # ORs into a match on most of the index - a nonsense domain returned
    # 572k "hits" (aarp.org, canva.com, netflix.com) and every tracked
    # domain looked compromised. Only rows that really name the term count.
    captured = {}

    def fake_search(params):
        captured.update(params)
        return {"total_hits": 572358, "results": [
            {"domain": "aarp.org", "url": "https://secure.aarp.org/", "username": "x@gomail5.com"},
            {"domain": "canva.com", "url": "https://www.canva.com/login", "username": "y@mailop7.com"},
            {"domain": "evil.example", "url": "https://evil.example/login", "username": "bob"},
            {"domain": "mail.evil.example", "url": "https://mail.evil.example/", "username": "carol"},
            {"domain": "unrelated.test", "url": "https://unrelated.test/", "username": "dave@evil.example"},
        ]}

    monkeypatch.setattr(webamon, "_search", fake_search)
    out = webamon.infostealers("evil.example")

    assert 'username:"@evil.example"' in captured["lucene_query"]   # phrase-quoted
    assert [r["domain"] for r in out["results"]] == [
        "evil.example", "mail.evil.example", "unrelated.test"]      # subdomain + @user kept
    assert out["total_hits"] == 3          # matched rows, not the index's 572358
    assert out["raw_total_hits"] == 572358
    assert out["capped"] is False


def test_search_domain_propagates_error(monkeypatch):
    monkeypatch.setattr(webamon, "_search", lambda params: {"error": "webamon rate limited"})
    assert webamon.search_domain("evil.example") == {"error": "webamon rate limited"}


# --- transport / quota ----------------------------------------------------
def test_get_without_key_returns_error(monkeypatch):
    monkeypatch.delenv("WEBAMON_API_KEY", raising=False)
    assert webamon._get("/search", {"search": "x"}) == {
        "error": "no WEBAMON_API_KEY configured"}


def test_get_respects_daily_budget(monkeypatch):
    monkeypatch.setenv("CTI_WEBAMON_DAILY_BUDGET", "0")
    called = []
    monkeypatch.setattr(webamon.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    assert webamon._get("/search", {"search": "x"}) == {
        "error": "webamon daily budget exhausted"}
    assert not called  # never hit the wire once over budget


def test_get_bumps_quota_and_maps_http_errors(monkeypatch):
    class _Resp:
        def __init__(self, body): self._b = body
        def read(self): return self._b.encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(webamon.urllib.request, "urlopen",
                        lambda *a, **k: _Resp(json.dumps({"total_hits": 1, "results": []})))
    assert webamon.quota_used_today() == 0
    webamon._get("/search", {"search": "x"})
    assert webamon.quota_used_today() == 1

    import urllib.error

    def raise_403(*a, **k):
        raise urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
    monkeypatch.setattr(webamon.urllib.request, "urlopen", raise_403)
    assert webamon._get("/search", {"search": "x"}) == {"error": "webamon forbidden (plan/quota)"}
    assert webamon.quota_used_today() == 2  # a rejected call still counts against the wire attempt
