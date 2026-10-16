"""The Windows-client vantage - cti/probe/win_proxy.py and cti/netwatch/win116.py.

No network: the runner on the VM is stubbed at win_proxy.fetch.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from cti import store
from cti.errors import VMProxyError
from cti.netwatch import watchlist
from cti.netwatch import win116 as W
from cti.probe import vantages, win_proxy

NOW = datetime(2026, 10, 16, 12, 0)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("CTI_WIN_HOST", "192.0.2.16")
    monkeypatch.setenv("CTI_WIN_USER", "client")


def _target(value, lifecycle="active", band=None, kind="domain", ports=()):
    return {"value": value, "kind": kind, "tier": "hot", "ports": list(ports),
            "actor": "APT-W", "cluster": "apt-w", "lifecycle": lifecycle, "band": band}


def _snapshot(con, target, port, *, vantage="probe", status=200, title="Login",
              cert="c" * 64, when=NOW - timedelta(days=1), final_url=None, scan="s1"):
    store.upsert_service_snapshot(con, row={
        "scan_id": f"{scan}-{vantage}", "scanned_at": when, "vantage": vantage,
        "target": target, "port": port, "open": True, "http_status": status,
        "http_title": title, "cert_sha256": cert,
        "record": {"http": {"final_url": final_url}} if final_url else {}})


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #

def test_an_unconfigured_vantage_refuses_clearly(monkeypatch):
    monkeypatch.delenv("CTI_WIN_HOST", raising=False)
    assert not win_proxy.configured()
    assert "win116" not in vantages.available()
    with pytest.raises(VMProxyError, match="not configured"):
        win_proxy.check()


def test_a_configured_vantage_is_available(configured):
    assert "win116" in vantages.available()


def test_runner_output_is_shaped_like_an_observe_result():
    seen = win_proxy.shape({
        "target": "x.example", "url": "https://x.example/", "status": 200, "title": "Hi",
        "server": "nginx", "body_sha256": "b" * 64, "headers": {"server": "nginx"},
        "final_url": "https://x.example/", "error": None,
        "cert": {"sha256": "AB" * 32, "subject_dn": "CN=localhost, O=MyOrg, S=Default, C=RU",
                 "issuer": "CN=localhost, S=Default", "serial": "01", "sans": []}})
    assert seen["http"]["status"] == 200
    # .NET spells the state attribute S=; the store spells it ST=.
    assert seen["tls"]["subject_dn"] == "CN=localhost, O=MyOrg, ST=Default, C=RU"
    assert seen["errors"] == {}


def test_an_unreachable_target_carries_its_error():
    seen = win_proxy.shape({"target": "x", "url": "https://x/", "status": None,
                            "error": "Unable to connect", "cert": None})
    assert seen["http"] == {} and seen["tls"] == {} and seen["error"] == "Unable to connect"


# --------------------------------------------------------------------------- #
# Divergence
# --------------------------------------------------------------------------- #

def _seen(status=200, title="Login", cert="c" * 64, final="https://x.example/"):
    return {"http": {"status": status, "title": title, "final_url": final},
            "tls": {"cert_sha256": cert} if cert else {}}


def test_no_baseline_no_divergence():
    assert W.divergence(None, _seen(), "x.example") is None


def test_the_same_answer_does_not_diverge():
    base = {"status": 200, "title": "login", "cert": "C" * 64, "final_url": None}
    assert W.divergence(base, _seen(), "x.example") is None


def test_payload_gating_is_named_by_what_diverged():
    base = {"status": 404, "title": "Not Found", "cert": "d" * 64, "final_url": None}
    assert W.divergence(base, _seen(), "x.example") == "cert,status:404>200,title"


def test_a_redirect_only_the_windows_client_gets():
    base = {"status": 200, "title": None, "cert": None, "final_url": "https://x.example/"}
    seen = _seen(title=None, cert=None, final="https://cdn.payload.example/setup.msi")
    assert W.divergence(base, seen, "x.example") == "redirect"


def test_a_tls_session_only_the_scanner_could_open():
    base = {"status": 301, "title": None, "cert": None, "final_url": None}
    failed = {"http": {}, "tls": {}, "error":
              "The request was aborted: Could not create SSL/TLS secure channel."}
    assert W.divergence(base, failed, "x.example") == "tls"
    timed_out = {"http": {}, "tls": {}, "error": "The operation has timed out"}
    assert W.divergence(base, timed_out, "x.example") is None


def test_a_body_that_only_differs_is_not_gating():
    """Dynamic pages hash differently on every load."""
    base = {"status": 200, "title": "Login", "cert": "c" * 64, "final_url": None}
    seen = _seen()
    seen["http"]["body_sha256"] = "e" * 64
    assert W.divergence(base, seen, "x.example") is None


# --------------------------------------------------------------------------- #
# Planning: coverage-driven
# --------------------------------------------------------------------------- #

def test_the_plan_takes_overdue_hosts_never_seen_first(monkeypatch):
    monkeypatch.setattr(watchlist, "build", lambda: [
        _target("seen-recently.example"), _target("stale.example"), _target("never.example"),
        _target("weak-cand.example", "candidate", "weak"),
        _target("good-cand.example", "candidate", "probable"),
        _target("2001:db8::1", kind="ip")])
    with store.connect() as con:
        _snapshot(con, "seen-recently.example", 443, vantage="win116",
                  when=NOW - timedelta(days=1))
        _snapshot(con, "stale.example", 443, vantage="win116", when=NOW - timedelta(days=30))
    plan = [t["value"] for t in W.plan(now=NOW)]
    assert plan == ["never.example", "good-cand.example", "stale.example"]


def test_the_plan_is_capped(monkeypatch):
    monkeypatch.setenv("CTI_WIN_TARGETS_PER_RUN", "2")
    monkeypatch.setattr(watchlist, "build",
                        lambda: [_target(f"h{i}.example") for i in range(5)])
    with store.connect():
        pass
    assert len(W.plan(now=NOW)) == 2


def test_urls_cover_https_http_and_known_web_ports():
    urls = [u for _, u in W._urls("x.example", [22, 8443, 8080, 2083])]
    assert urls == ["https://x.example/", "http://x.example/", "https://x.example:8443/",
                    "http://x.example:8080/"]


# --------------------------------------------------------------------------- #
# A run records the client view and the divergence
# --------------------------------------------------------------------------- #

def test_a_run_records_snapshots_selectors_and_divergence(configured, monkeypatch):
    with store.connect() as con:
        _snapshot(con, "gate.example", 443, status=404, title="Not Found")

    def fetch(requests, timeout=15):
        out = []
        for r in requests:
            if r["url"].startswith("https"):
                out.append(win_proxy.shape({
                    "target": r["target"], "url": r["url"], "status": 200,
                    "title": "Invoice viewer", "body_sha256": "f" * 64,
                    "final_url": r["url"], "headers": {},
                    "cert": {"sha256": "c" * 64, "subject_dn": "CN=gate.example"}}))
            else:
                out.append(win_proxy.shape({"target": r["target"], "url": r["url"],
                                            "status": None, "error": "refused"}))
        return out

    monkeypatch.setattr(win_proxy, "fetch", fetch)
    report = W.run(targets=[_target("gate.example")], now=NOW)
    assert report["answered"] == 1
    assert report["divergent"] == [{"target": "gate.example", "port": 443,
                                    "diverged": "status:404>200,title"}]
    with store.connect(read_only=True) as con:
        snaps = con.execute("SELECT port, open FROM service_snapshots WHERE vantage = 'win116' "
                            "ORDER BY port").fetchall()
        spans = {r[0] for r in con.execute(
            "SELECT selector_type FROM selector_spans WHERE vantage = 'win116'").fetchall()}
        change = con.execute("SELECT new_value FROM service_changes "
                             "WHERE field = 'client_divergence'").fetchone()
    assert snaps == [(80, False), (443, True)]
    assert {"http.body_sha256", "tls.cert_sha256", "http.client_divergence"} <= spans
    assert "status:404>200" in change[0]


def test_a_run_without_the_vantage_is_skipped(monkeypatch):
    monkeypatch.delenv("CTI_WIN_HOST", raising=False)
    assert "skipped" in W.run(targets=[_target("x.example")])
