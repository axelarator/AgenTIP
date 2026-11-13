"""Low-severity findings from the 2026-11 audit, each pinned by a test."""
from __future__ import annotations

import asyncio
import json
import tomllib
from pathlib import Path

import pytest

from cti import core, errors, store
from cti.sources import pivot
from cti.store import rarity, relatedness
from cti.store import selectors as S

REPO = Path(__file__).resolve().parents[1]
NOW = "2026-11-13 06:00:00"


def _sel(con, indicator, selector_type, value, actor="A"):
    S.record(con, indicator_value=indicator, selector_type=selector_type,
             selector_value=value, observed_at=NOW, indicator_type="domain",
             actor=actor, source="test")


# S5 ------------------------------------------------------------------------- #

@pytest.mark.parametrize("mx", [
    "aspmx.l.google.com,alt1.aspmx.l.google.com",
    "example-com.mail.protection.outlook.com",
    "mx.zoho.com,mx2.zoho.com",
    "mx1.privateemail.com",
])
def test_a_mass_mail_providers_mx_is_not_a_link(mx):
    """dns.mx_set is structural, and half the internet's mail is at Google."""
    assert rarity.value_is_provider_scale("dns.mx_set", mx)


def test_a_custom_mail_server_is_still_a_link():
    assert not rarity.value_is_provider_scale("dns.mx_set", "mail.evil-actor.com")


# S8 ------------------------------------------------------------------------- #

def test_a_shared_value_containing_a_pipe_is_one_value():
    title = "Login | Admin Panel | v2"
    with store.connect() as con:
        _sel(con, "a.example", "http.title", title)
        _sel(con, "b.example", "http.title", title)
        found = S.neighbours(con, "a.example", promotable_only=False)
    assert [n["indicator_value"] for n in found] == ["b.example"]
    assert found[0]["via"] == ["http.title"]


# S10 ------------------------------------------------------------------------ #

def test_a_selector_is_assessed_once_however_many_members_share_it(monkeypatch):
    with store.connect() as con:
        for host in ("a.example", "b.example", "c.example", "d.example"):
            _sel(con, host, "tls.cert_sha256", "c" * 64)
        calls = []
        real = relatedness.assess
        monkeypatch.setattr(relatedness, "assess",
                            lambda con, t, v: calls.append((t, v)) or real(con, t, v))
        relatedness.score_against(con, "a.example", ["b.example", "c.example", "d.example"])
    assert len(calls) == len(set(calls))


# T5 ------------------------------------------------------------------------- #

def test_the_asn_overlap_query_runs_with_no_shared_hosting_list(monkeypatch):
    """The list was formatted into the SQL; empty, it was `NOT IN ()`."""
    from cti.tracking import analytics
    monkeypatch.setattr(analytics, "SHARED_HOSTING_ASNS", ())
    with store.connect() as con:
        assert analytics.cross_actor_asn_overlap(con) == []


# R4 ------------------------------------------------------------------------- #

def test_a_value_is_quoted_before_it_goes_into_a_lookup_url(monkeypatch):
    asked = []
    monkeypatch.setattr(pivot, "_get_json", lambda url, headers=None: asked.append(url) or {})
    pivot.rdap_lookup("evil.example/../admin?x=1 y", "domain")
    assert asked and " " not in asked[0] and "?x=1" not in asked[0] and "/../" not in asked[0]


# C6 ------------------------------------------------------------------------- #

def test_there_is_one_cluster_not_found_error():
    assert core.ClusterNotFound is errors.ClusterNotFound
    with pytest.raises(errors.ClusterNotFound, match="Nope"):
        core.load_cluster("Nope")


# C8 ------------------------------------------------------------------------- #

def test_a_technique_id_is_stored_once_whatever_its_case():
    core.create_cluster("Case Test")
    core.update_ttp("Case Test", "t1059.001", "PowerShell", 1)
    core.update_ttp("Case Test", "T1059.001", "PowerShell", 3)
    ttps = core.load_cluster("Case Test")["ttps"]
    assert [(t["id"], t["status"]) for t in ttps] == [("T1059.001", 3)]


# M4 ------------------------------------------------------------------------- #

def test_a_validin_history_lookup_needs_a_stated_reason():
    """Fifty lookups a month. A default reason is no reason."""
    from cti.mcp import server
    tool = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == "validin_history")
    assert "reason" in tool.inputSchema["required"]


# I3 ------------------------------------------------------------------------- #

def test_a_note_with_a_pipe_or_a_line_break_does_not_break_the_rendered_table():
    core.create_cluster("Render Test")
    core.add_gap("Render Test", "who runs the panel?\nasked | twice", "high")
    core.update_ttp("Render Test", "T1059", "Command and Scripting Interpreter", 2,
                    notes="seen via cmd | powershell\nsecond line")
    md = (core.DATA_DIR / "render-test.md").read_text()
    rows = [line for line in md.splitlines() if line.startswith("| ")]
    gap_row = next(r for r in rows if "who runs the panel" in r)
    ttp_row = next(r for r in rows if "T1059" in r)
    assert "asked \\| twice" in gap_row and "<br>" in gap_row
    assert gap_row.count(" | ") == 2 and ttp_row.count(" | ") == 4


# D4 ------------------------------------------------------------------------- #

def test_one_unreadable_cluster_does_not_take_the_dashboard_down():
    from starlette.testclient import TestClient
    from dashboard import server
    core.create_cluster("Readable")
    (core.DATA_DIR / "broken.json").write_text("{not json")
    client = TestClient(server.app, raise_server_exceptions=False)

    listing = client.get("/api/clusters")
    stats = client.get("/api/stats")

    assert listing.status_code == 200 and stats.status_code == 200
    by_slug = {c["slug"]: c for c in listing.json()}
    assert by_slug["readable"]["name"] == "Readable"
    assert "error" in by_slug["broken"]


# D5, F2 --------------------------------------------------------------------- #

@pytest.mark.parametrize("package", ["starlette", "uvicorn", "pyyaml", "requests"])
def test_every_imported_third_party_package_is_declared(package):
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    declared = " ".join(project["dependencies"]).lower()
    assert package in declared


# G6 ------------------------------------------------------------------------- #

def test_no_empty_leftover_package_directories():
    for name in ("graph/nodes/analyze", "graph/nodes/collect", "cti/enrich"):
        assert not (REPO / name).exists(), f"{name}/ sits beside a module of the same name"


# S3 ------------------------------------------------------------------------- #

@pytest.mark.parametrize("value, stored", [
    ("njRAT", '"njRAT"'),                 # a plain string is not JSON until encoded
    ('["a", "b"]', '["a", "b"]'),         # already-serialised JSON is left alone
    (["a"], '["a"]'), ({"k": 1}, '{"k": 1}'), (None, None),
])
def test_a_json_column_always_receives_valid_json(value, stored):
    import importlib
    writes = importlib.import_module("cti.store.writes")
    changes = importlib.import_module("cti.store.changes")
    for encode in (writes._json, changes._as_json):
        out = encode(value)
        assert out == stored
        if out is not None:
            json.loads(out)


# S14 ------------------------------------------------------------------------ #

def test_staleness_is_measured_in_utc_not_local_time(monkeypatch):
    """Timestamps are stored as naive UTC. Compared with local time they are
    wrong by the host's offset; the host is on UTC today, which hid it."""
    from datetime import datetime, timedelta
    from cti import util
    fixed = datetime(2026, 11, 13, 12, 0, 0)
    monkeypatch.setattr(util, "utcnow_naive", lambda: fixed)
    assert util.is_stale(fixed - timedelta(days=3), days=2)
    assert not util.is_stale(fixed - timedelta(days=1), days=2)
    assert util.utcnow_naive.__name__      # the helper exists


def test_no_store_or_tracking_code_reads_the_local_clock():
    for path in ("cti/store/query.py", "cti/tracking/enrich.py", "cti/util.py",
                 "cti/tracking/ingest.py"):
        code = (REPO / path).read_text()
        assert "datetime.now()" not in code.replace("datetime.now().", "datetime.now()"), path
        assert "date.today()" not in code, path


# S7 ------------------------------------------------------------------------- #

def test_refresh_zeroes_a_value_nothing_holds_and_keeps_its_price():
    with store.connect() as con:
        _sel(con, "a.example", "tls.cert_sha256", "c" * 64)
        _sel(con, "b.example", "tls.cert_sha256", "c" * 64)
        rarity.refresh(con)
        con.execute("UPDATE selector_stats SET global_count = 7, global_source = 'webamon'")
        con.execute("DELETE FROM selectors")
        rarity.refresh(con)
        row = con.execute("SELECT local_count, global_count FROM selector_stats").fetchone()
    assert row == (0, 7)


# R5 ------------------------------------------------------------------------- #

def test_no_request_names_the_project_this_one_replaced():
    for path in ("cti/sources/webamon.py", "cti/report/ingest.py"):
        code = (REPO / path).read_text()
        assert 'USER_AGENT = "cti-agent' not in code, path
    assert "_DAILY_BUDGET_ENV" not in (REPO / "cti/sources/webamon.py").read_text()
