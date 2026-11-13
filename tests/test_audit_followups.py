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


# C7 ------------------------------------------------------------------------- #

LONG_GAP = ("Who hosts the admin panel? Pivoted the certificate serial on 2026-11-12 "
            "and found three more hosts, none confirmed.")


@pytest.fixture
def gaps():
    core.create_cluster("Gap Test")
    core.add_gap("Gap Test", LONG_GAP, "medium")
    core.add_gap("Gap Test", "Who hosts the staging server?", "low")
    return "Gap Test"


def test_a_gap_can_be_named_by_the_start_of_its_text(gaps):
    """A caller had to resend the whole paragraph, exactly, to change a
    priority."""
    core.update_gap(gaps, "Who hosts the admin panel?", priority="high")
    by_text = {g["description"]: g["priority"] for g in core.load_cluster(gaps)["gaps"]}
    assert by_text[LONG_GAP] == "high"

    out = core.remove_gap(gaps, "who hosts the staging")       # case does not matter
    assert out["removed"]["description"] == "Who hosts the staging server?"


def test_text_that_fits_more_than_one_gap_changes_none(gaps):
    with pytest.raises(ValueError, match="2 gaps"):
        core.update_gap(gaps, "Who hosts the", priority="high")
    with pytest.raises(ValueError, match="2 gaps"):
        core.remove_gap(gaps, "Who hosts the")
    assert len(core.load_cluster(gaps)["gaps"]) == 2


def test_an_exact_description_wins_over_a_longer_one_that_starts_the_same():
    core.create_cluster("Exact Test")
    core.add_gap("Exact Test", "Find the panel", "low")
    core.add_gap("Exact Test", "Find the panel operator", "low")
    core.update_gap("Exact Test", "Find the panel", priority="high")
    by_text = {g["description"]: g["priority"] for g in core.load_cluster("Exact Test")["gaps"]}
    assert by_text == {"Find the panel": "high", "Find the panel operator": "low"}


# R3 ------------------------------------------------------------------------- #

@pytest.mark.parametrize("value, kind", [
    ("203.0.113.5", "ip"), ("2001:db8::1", "ip"),
    ("evil.example", "domain"), ("Sub.Evil.Example.", "domain"),
    ("http://evil.example/x", "url"),
    ("a" * 32, "hash"), ("a" * 64, "hash"), ("a" * 128, "hash"),
    ("sha256:" + "a" * 64, "hash"),              # how the cluster store writes a hash
    ("cert-sha256:" + "a" * 64, "hash"),
    ("user@evil.example", "email"), ("CVE-2026-1234", "cve"),
    ("203.0.113.5:8443", "unknown"), ("evil.example/path", "unknown"),
    ("203.0.113.0/24", "unknown"), ("localhost", "unknown"), ("", "unknown"),
    ("two words.example", "unknown"),
])
def test_one_answer_to_what_kind_of_value_this_is(value, kind):
    """classify called a prefixed hash, an email, a CVE and host:port a
    "domain", because domain was the fallback for anything unrecognised."""
    assert pivot.classify(value) == kind


@pytest.mark.parametrize("value", ["sha256:" + "a" * 64, "user@evil.example",
                                   "CVE-2026-1234", "203.0.113.5:8443"])
def test_a_value_that_is_not_a_host_gets_no_domain_lookups(monkeypatch, value):
    """Each of these used to be sent to RDAP and Webamon as a domain and
    probed from the VM as a hostname."""
    from cluster_patching import patch_clusters
    reached = []
    for name in ("rdap_lookup", "ripestat_lookup", "ptr_lookup"):
        monkeypatch.setattr(pivot, name, lambda *a, _n=name, **k: reached.append(_n) or {})
    for name in ("_webamon_domain", "_webamon_infostealers", "_webamon_ip",
                 "_observe", "_live_http"):
        patch_clusters(monkeypatch, name, lambda *a, _n=name, **k: reached.append(_n) or {})

    out = core.pivot_observable(value)

    assert reached == []
    assert out["kind"] not in ("domain", "ip")


@pytest.mark.parametrize("target", ["203.0.113.5:8443", "user@evil.example",
                                    "evil.example/admin", "sha256:" + "a" * 64])
def test_active_scan_refuses_a_target_that_is_not_a_host(monkeypatch, target):
    monkeypatch.setattr(core.vm_proxy, "nmap",
                        lambda *a, **k: pytest.fail("a scan was started"))
    monkeypatch.setattr(core.vm_proxy, "dirsearch",
                        lambda *a, **k: pytest.fail("a scan was started"))
    with pytest.raises(ValueError, match="domain/ip"):
        core.active_scan(target)


# S9 ------------------------------------------------------------------------- #

def test_only_a_serialised_list_or_object_is_unpacked_for_a_json_field():
    import importlib
    observations = importlib.import_module("cti.store.observations")
    assert observations._encode('["a", "b"]') == ["a", "b"]
    assert observations._encode('{"k": 1}') == {"k": 1}
    assert observations._encode("123") == "123"          # a string stays a string
    assert observations._encode("true") == "true"
    assert observations._encode(["a"]) == ["a"]


# New: an empty CTI_DATA_DIR ---------------------------------------------------- #

def test_an_empty_data_dir_setting_means_the_default_not_the_current_directory():
    """`CTI_DATA_DIR=` (set but empty) made the cluster store the current
    working directory, so every *.json in it was read as a cluster."""
    import subprocess
    import sys
    done = subprocess.run(
        [sys.executable, "-c",
         "from cti.clusters import storage; print(storage.DATA_DIR)"],
        capture_output=True, text=True, cwd=str(REPO),
        env={"PATH": "/usr/bin:/bin", "CTI_DATA_DIR": ""})
    assert done.stdout.strip().endswith("data/clusters"), done.stdout + done.stderr


# S13 ------------------------------------------------------------------------ #

_QUERY_CALLS = {
    "run_readonly_query": lambda q: q.run_readonly_query("SELECT 1"),
    "save_correlation": lambda q: q.save_correlation(
        "A", sorted(q.CORRELATION_TYPES)[0], ["203.0.113.5"], "n"),
    "actor_summary": lambda q: q.actor_summary("A"),
    "tracked_observables": lambda q: q.tracked_observables(),
    "finding_days": lambda q: q.finding_days(),
    "findings_for": lambda q: q.findings_for("2026-11-13"),
    "indicator_index": lambda q: q.indicator_index(),
    "selector_types_for": lambda q: q.selector_types_for("x"),
    "selector_detail": lambda q: q.selector_detail("tls.jarm", "x"),
    "indicator_profile": lambda q: q.indicator_profile("203.0.113.5"),
    "observable_history": lambda q: q.observable_history("203.0.113.5"),
    "opendir_samples": lambda q: q.opendir_samples("203.0.113.5"),
}


@pytest.mark.parametrize("name", sorted(_QUERY_CALLS))
@pytest.mark.parametrize("failure, word", [("busy", "busy"), ("io", "unavailable")])
def test_every_store_query_reports_a_locked_or_missing_database_the_same_way(
        monkeypatch, name, failure, word):
    import importlib

    import duckdb
    query = importlib.import_module("cti.store.query")
    with store.connect():
        pass

    def broken(*a, **k):
        if failure == "busy":
            raise store.TrackingBusy("locked by pid 1")
        raise duckdb.IOException("cannot open file")
    monkeypatch.setattr(query, "connect_retry", broken)

    out = _QUERY_CALLS[name](query)

    assert word in out["error"]


def test_the_error_mapping_is_written_once():
    code = (REPO / "cti/store/query.py").read_text()
    assert code.count("tracking DB busy") == 1
    assert code.count("except TrackingBusy") == 1


# C10 ------------------------------------------------------------------------ #

def _counting(monkeypatch, name):
    from cluster_patching import patch_clusters
    from cti.clusters import storage
    calls = []
    real = getattr(storage, name)
    patch_clusters(monkeypatch, name, lambda *a, **k: calls.append(a) or real(*a, **k))
    return calls


@pytest.fixture
def three_clusters():
    for name in ("Det A", "Det B", "Det C"):
        core.create_cluster(name)
        core.update_ttp(name, "T1059", "Command and Scripting Interpreter", 1)
    return ["Det A", "Det B", "Det C"]


def test_add_detection_reads_each_cluster_and_the_registry_once(three_clusters, monkeypatch):
    """It loaded every cluster twice, and every load re-read the registry."""
    loads = _counting(monkeypatch, "load_cluster")
    registry_reads = _counting(monkeypatch, "_load_detection_registry")

    out = core.add_detection("DET-1", "PowerShell ancestry", ["T1059"], "draft", "Det A",
                             scope="technique")

    assert len(loads) <= len(three_clusters) + 1          # was 2 x clusters + 2
    assert len(registry_reads) == 1
    # and it still does its job: joined onto all three, saved on each
    assert [d["id"] for d in out["detections"]] == ["DET-1"]
    for name in three_clusters:
        assert [d["id"] for d in core.load_cluster(name)["detections"]] == ["DET-1"]
        assert "DET-1" in (core.DATA_DIR / f"{name.lower().replace(' ', '-')}.md").read_text()


def test_narrowing_a_detection_still_refreshes_the_clusters_it_left(three_clusters):
    core.add_detection("DET-2", "generic", ["T1059"], "draft")              # technique scope
    core.add_detection("DET-2", "generic", ["T1059"], "draft", "Det A", scope="cluster")
    assert [d["id"] for d in core.load_cluster("Det A")["detections"]] == ["DET-2"]
    for name in ("Det B", "Det C"):
        assert core.load_cluster(name)["detections"] == []
        assert "DET-2" not in (core.DATA_DIR / f"{name.lower().replace(' ', '-')}.md").read_text()


def test_the_reverse_index_reads_the_registry_once(three_clusters, monkeypatch):
    core.add_detection("DET-3", "generic", ["T1059"], "draft")
    registry_reads = _counting(monkeypatch, "_load_detection_registry")
    usage = core.get_technique_usage("T1059")
    assert len(usage["used_by"]) == 3 and len(registry_reads) <= 1


def test_the_ipv4_check_agrees_with_the_one_classifier():
    from cti.clusters import enrich
    from cti.store import entities
    for value in ("203.0.113.5", " 203.0.113.5 ", "2001:db8::1", "evil.example",
                  "203.0.113.5:80", "999.1.1.1", ""):
        assert enrich._is_ipv4(value) == (entities.entity_type(value) == "ipv4"), value
