"""probe_helper: where it may fetch from, and what a netwatch scan reports.

The crawler and the downloader take their URLs from an adversary's own
directory listing, so everything here treats a URL as hostile input.
"""
from __future__ import annotations

import importlib.util
import json
import threading
import time
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def ph(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_NETWATCH_SPOOL", str(tmp_path / "spool"))
    monkeypatch.delenv("CTI_PROBE_ALLOW_PRIVATE", raising=False)
    spec = importlib.util.spec_from_file_location(
        "probe_helper_guard", REPO / "probe_vm" / "probe_helper.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LISTING = ('<html><head><title>Index of /f</title></head><body><pre>'
           '<a href="../">Parent Directory</a>\n{rows}</pre></body></html>')


def _listing(*hrefs):
    return LISTING.format(rows="".join(
        f'<a href="{h}">{h.rsplit("/", 1)[-1] or h}</a>  2026-09-12 14:03   1K\n'
        for h in hrefs))


# --------------------------------------------------------------------------- #
# H3: a listing cannot point the crawler anywhere else
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("href", [
    "file:///home/detonate/.ssh/id_ed25519",
    "FILE:///etc/passwd",
    "ftp://203.0.113.9/x",
    "//10.0.0.1/admin/",
    "http://10.0.0.1/admin/",
    "HTTP://10.0.0.1/admin/",
    "https://other.example/payload.bin",
    "http://1.2.3.4:8080/other-port.bin",
    "gopher://1.2.3.4/x",
    "data:text/plain,hello",
])
def test_a_listing_entry_that_leaves_the_host_is_not_listed(ph, href):
    files = ph.parse_autoindex(_listing("payload.bin", href), "http://1.2.3.4/f/")
    assert [f["href"] for f in files] == ["http://1.2.3.4/f/payload.bin"]


def test_same_host_entries_are_still_listed_however_they_are_written(ph):
    files = ph.parse_autoindex(
        _listing("a.bin", "/abs/b.bin", "sub/", "http://1.2.3.4/f/c.bin"),
        "http://1.2.3.4/f/")
    assert [f["href"] for f in files] == [
        "http://1.2.3.4/f/a.bin", "http://1.2.3.4/abs/b.bin",
        "http://1.2.3.4/f/sub/", "http://1.2.3.4/f/c.bin"]


@pytest.mark.parametrize("url", [
    "file:///etc/hostname", "ftp://1.2.3.4/x", "FILE:///etc/hostname",
    "/etc/hostname", "",
])
def test_fetch_refuses_anything_but_http(ph, url):
    out = ph._fetch(url)
    assert out["status"] is None and "http" in out["error"]


@pytest.mark.parametrize("url", ["file:///etc/hostname", "ftp://1.2.3.4/x"])
def test_download_refuses_anything_but_http(ph, tmp_path, url):
    dest = tmp_path / "out"
    assert "error" in ph._download(url, dest, 1000)
    assert not dest.exists()


def test_download_refuses_a_lab_address(ph, tmp_path):
    out = ph._download("http://10.0.0.1/backup.tgz", tmp_path / "out", 1000)
    assert "private" in out["error"]


def test_a_private_address_is_allowed_when_the_operator_says_so(ph, monkeypatch):
    monkeypatch.setattr(ph, "ALLOW_PRIVATE", True)
    assert ph._refusal("http://10.0.0.1/x", origin=None, strict=False) is None


@pytest.mark.parametrize("new, ok", [
    ("http://1.2.3.4/elsewhere/", True),
    ("https://1.2.3.4/elsewhere/", True),           # same host, upgraded
    ("http://1.2.3.4:8080/x", False),
    ("http://10.0.0.1/", False),
    ("http://other.example/", False),
    ("file:///etc/hostname", False),
])
def test_a_crawl_redirect_must_stay_on_the_listing_host(ph, new, ok):
    reason = ph._refusal(new, origin=ph._origin("http://1.2.3.4/f/"), strict=True)
    assert (reason is None) is ok


@pytest.mark.parametrize("new, ok", [
    ("https://www.example.org/", True),             # a probe may follow offsite
    ("http://127.0.0.1:8420/api/clusters", False),  # but never into the lab
    ("http://169.254.169.254/latest/meta-data/", False),
    ("http://192.168.1.10:8420/", False),
    ("file:///etc/hostname", False),
])
def test_a_probe_redirect_may_leave_the_host_but_not_enter_the_lab(ph, new, ok):
    reason = ph._refusal(new, origin=ph._origin("http://203.0.113.5/"), strict=False)
    assert (reason is None) is ok


def test_the_redirect_handler_enforces_the_rule(ph):
    handler = ph._GuardedRedirect(ph._origin("http://1.2.3.4/f/"), strict=True)
    req = ph.urllib.request.Request("http://1.2.3.4/f/")
    with pytest.raises(urllib.error.URLError, match="redirect refused"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://10.0.0.1/")
    assert handler.redirect_request(
        req, None, 302, "Found", {}, "http://1.2.3.4/g/") is not None


def test_the_crawl_never_requests_an_offsite_directory(ph, monkeypatch):
    asked = []

    def fake_fetch(url, **kw):
        asked.append((url, kw.get("strict")))
        if url == "http://1.2.3.4/":
            return {"status": 200, "final_url": url, "headers": {}, "error": None,
                    "body": _listing("ok/", "//10.0.0.1/lab/", "a.bin")}
        return {"status": 200, "final_url": url, "headers": {}, "error": None,
                "body": _listing("b.bin")}
    monkeypatch.setattr(ph, "_fetch", fake_fetch)

    files: list[dict] = []
    ph._crawl_opendir("http://1.2.3.4/", {}, 3, 100, set(), files)

    assert asked == [("http://1.2.3.4/", True), ("http://1.2.3.4/ok/", True)]
    assert all("10.0.0.1" not in f["href"] for f in files)


# --------------------------------------------------------------------------- #
# H5, H6, H7
# --------------------------------------------------------------------------- #

def test_a_dirsearch_failure_is_reported_not_read_as_no_hits(ph, monkeypatch):
    monkeypatch.setattr(ph.shutil, "which", lambda name: "/usr/bin/dirsearch")
    monkeypatch.setattr(ph, "_baseline_404", lambda base: {"status": 404, "size": 0})
    monkeypatch.setattr(ph, "_crawl_opendir", lambda *a, **k: None)

    def boom(*a, **k):
        raise ph.subprocess.TimeoutExpired("dirsearch", 600)
    monkeypatch.setattr(ph.subprocess, "run", boom)

    out = ph.action_dirsearch({"url": "http://1.2.3.4/"})

    assert out["hits"] == [] and "TimeoutExpired" in out["dirsearch_error"]


def test_http_fetch_refuses_a_file_url(ph):
    out = ph.action_http_fetch({"url": "file:///etc/hostname"})
    assert out["status"] is None and out["body"] is None and "http" in out["error"]


def test_http_fetch_caps_what_it_reads(ph, monkeypatch):
    class Resp:
        status, headers = 200, {}
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def geturl(self): return "http://203.0.113.5/big"
        def read(self, n=None):
            assert n is not None, "an unbounded read"
            return b"x" * n
    monkeypatch.setattr(ph, "_open", lambda req, **kw: Resp())
    monkeypatch.setattr(ph, "HTTP_FETCH_MAX_BYTES", 1000)

    out = ph.action_http_fetch({"url": "http://203.0.113.5/big"})

    assert len(out["body"]) == 1000 and out["truncated"] is True


@pytest.mark.parametrize("url, name", [
    ("http://1.2.3.4/.bash_history", ".bash_history"),
    ("http://1.2.3.4/a/b/..hidden", "..hidden"),
    ("http://1.2.3.4/dir/My%20File.bin", "My File.bin"),
    ("http://1.2.3.4/", ""),
])
def test_the_reported_filename_is_the_one_on_the_server(ph, url, name):
    assert ph._original_name(url) == name
    staged = ph._safe_name(url, 0)
    assert "/" not in staged and not staged.startswith(".")


def test_results_carry_each_files_own_url_and_real_name(ph, monkeypatch, tmp_path):
    import types
    monkeypatch.setattr(ph.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(ph, "_download",
                        lambda url, dest, budget: dest.write_bytes(b"x") and {"bytes": 1})

    def fake_run(cmd, **kw):
        staging = Path(cmd[cmd.index("-v") + 1].split(":")[0])
        results = [{"path": p.name, "sha256": "0" * 64} for p in sorted(staging.iterdir())]
        return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(
            {"results": results, "analyzed": len(results), "errors": []}))
    monkeypatch.setattr(ph.subprocess, "run", fake_run)

    out = ph.action_fetch_and_analyze({"urls": [
        "http://1.2.3.4/a/.bash_history", "http://1.2.3.4/b/.bash_history"]})

    assert [(r["url"], r["path"]) for r in out["results"]] == [
        ("http://1.2.3.4/a/.bash_history", ".bash_history"),
        ("http://1.2.3.4/b/.bash_history", ".bash_history")]


# --------------------------------------------------------------------------- #
# H1, H2, H4: what a netwatch scan reports, and how long it takes
# --------------------------------------------------------------------------- #

def _quiet_tools(ph, monkeypatch, *, live, c2=None):
    monkeypatch.setattr(ph, "resolve_target_ip", lambda t: "203.0.113.5")
    monkeypatch.setattr(ph, "tcp_precheck", lambda ip, port: port in live)
    monkeypatch.setattr(ph, "_httpx_by_port", lambda t, ports: {})
    monkeypatch.setattr(ph, "_tlsx_by_port", lambda t, ports: {})
    monkeypatch.setattr(ph, "_banner_sha256", lambda ip, port: None)
    monkeypatch.setattr(ph, "_nuclei_c2", lambda t, ports: c2 or {})


def test_a_port_that_was_checked_and_did_not_answer_is_recorded_closed(ph, monkeypatch):
    _quiet_tools(ph, monkeypatch, live={443})

    records = ph._scan_target({"value": "203.0.113.5", "ports": [443, 8199]},
                              "probe", "hot", "hot-1")

    state = {r["port"]: r["open"] for r in records}
    assert state[443] is True and state[8199] is False
    # Every port the hot profile checks is accounted for, open or not.
    assert set(state) == {443, 80, 8443, 8080, 8199}


def test_a_dark_host_reports_each_checked_port_closed(ph, monkeypatch):
    _quiet_tools(ph, monkeypatch, live=set())

    records = ph._scan_target({"value": "203.0.113.5", "ports": [8199]},
                              "probe", "hot", "hot-1")

    assert {r["port"] for r in records} == {0, 443, 80, 8443, 8080, 8199}
    assert not any(r["open"] for r in records)


def test_a_port_sweep_that_failed_does_not_report_ports_closed(ph, monkeypatch):
    """naabu erroring is not evidence that anything closed."""
    _quiet_tools(ph, monkeypatch, live=set())
    monkeypatch.setattr(ph, "_netwatch_ports",
                        lambda t, profile, known: ([443, 8199], "naabu: timed out"))

    records = ph._scan_target({"value": "203.0.113.5", "ports": [8199]},
                              "probe", "full", "full-1")

    assert [r["port"] for r in records] == [0]
    assert records[0]["error"] == "naabu: timed out"


def test_a_c2_hit_is_recorded_on_the_port_it_matched(ph, monkeypatch):
    _quiet_tools(ph, monkeypatch, live={443, 8199}, c2={8199: ["sliver-mtls"]})

    records = ph._scan_target({"value": "203.0.113.5", "ports": [443, 8199]},
                              "probe", "hot", "hot-1")

    hits = {r["port"]: r.get("c2_hits") for r in records if r["open"]}
    assert hits == {443: None, 8199: ["sliver-mtls"]}


def test_nuclei_hits_are_keyed_by_the_port_in_the_match(ph, monkeypatch):
    monkeypatch.setattr(ph, "_tool_present", lambda cmd: True)
    monkeypatch.setattr(ph.os.path, "isdir", lambda p: True)
    monkeypatch.setattr(ph, "_json_records", lambda *a, **k: [
        {"template-id": "sliver-mtls", "matched-at": "203.0.113.5:8199"},
        {"template-id": "cs-beacon", "matched-at": "https://203.0.113.5:443/a"},
        {"template-id": "cs-beacon", "host": "203.0.113.5", "port": "443"},
        {"template-id": "mystery"},
    ])

    assert ph._nuclei_c2("203.0.113.5", [443, 8199]) == {
        8199: ["sliver-mtls"], 443: ["cs-beacon"], 0: ["mystery"]}


def test_ports_are_prechecked_together_not_one_after_another(ph, monkeypatch):
    def slow(ip, port):
        time.sleep(0.2)
        return port == 443
    monkeypatch.setattr(ph, "tcp_precheck", slow)

    started = time.monotonic()
    live = ph._live_ports("203.0.113.5", list(range(430, 454)))

    assert live == [443]
    assert time.monotonic() - started < 1.5          # 24 x 0.2 s in sequence is 4.8 s


def test_the_worker_scans_several_targets_at_once_and_keeps_every_record(ph, monkeypatch):
    running, peak, lock = [0], [0], threading.Lock()

    def scan(entry, vantage, profile, scan_id):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.2)
        with lock:
            running[0] -= 1
        if entry["value"] == "203.0.113.3":
            raise RuntimeError("tool crashed")
        return [{"scan_id": scan_id, "target": entry["value"], "port": 443, "open": True}]
    monkeypatch.setattr(ph, "_scan_target", scan)
    ph.action_netwatch_submit({"job": {"job_id": "job-p", "profile": "hot", "targets": [
        {"value": f"203.0.113.{i}"} for i in range(8)]}})

    ph.run_netwatch_worker(once=True)

    records = ph.action_netwatch_collect({"job_id": "job-p"})["records"]
    assert peak[0] > 1
    assert sorted(r["target"] for r in records) == [f"203.0.113.{i}" for i in range(8)]
    crashed = next(r for r in records if r["target"] == "203.0.113.3")
    assert crashed["open"] is False and "tool crashed" in crashed["error"]
    assert ph.action_netwatch_status({"job_id": "job-p"})["state"] == "done"
