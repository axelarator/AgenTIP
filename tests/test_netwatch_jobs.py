"""netwatch.jobs.run: submit everything, poll together, lose nothing."""
from __future__ import annotations

import json

import pytest

from cti.netwatch import jobs, queue
from cti.probe import vm_proxy
from cti.sources import budget


class FakeProbe:
    """Stands in for the probe VM: records the order of calls and finishes
    the jobs it is told to."""

    def __init__(self, monkeypatch, *, finish=lambda job_id: True, reject=()):
        self.calls: list[tuple[str, str]] = []
        self.jobs: dict[str, dict] = {}
        self.finish, self.reject = finish, set(reject)
        monkeypatch.setattr(vm_proxy, "netwatch_submit", self.submit)
        monkeypatch.setattr(vm_proxy, "netwatch_status", self.status)
        monkeypatch.setattr(vm_proxy, "netwatch_collect", self.collect)
        monkeypatch.setattr(jobs.time, "sleep", lambda s: None)

    def submit(self, job):
        self.calls.append(("submit", job["job_id"]))
        if job["profile"] in self.reject:
            return {"error": "spool full"}
        self.jobs[job["job_id"]] = job
        return {"job_id": job["job_id"], "queued": len(job["targets"])}

    def status(self, job_id):
        self.calls.append(("status", job_id))
        if job_id not in self.jobs:
            return {"state": "unknown"}
        return {"state": "done" if self.finish(job_id) else "running"}

    def collect(self, job_id, *, purge=False):
        self.calls.append(("collect", job_id))
        done = self.finish(job_id)
        records = [{"scan_id": job_id, "target": t["value"], "port": 443,
                    "open": True} for t in self.jobs[job_id]["targets"]]
        if purge and done:
            del self.jobs[job_id]
        return {"records": records if done else records[:1], "done": done}


def _watch(monkeypatch, targets):
    monkeypatch.setattr(jobs.watchlist, "for_tiers",
                        lambda tiers, clusters=None: [dict(t) for t in targets
                                                      if t["tier"] in tiers])
    monkeypatch.setattr(budget, "spend", lambda provider, n=1: n)


def _t(value, tier="hot"):
    return {"value": value, "tier": tier, "ports": [443], "actor": "APT-W"}


def test_every_job_is_submitted_before_any_is_awaited(monkeypatch):
    _watch(monkeypatch, [_t("203.0.113.1"), _t("203.0.113.2", "full")])
    probe = FakeProbe(monkeypatch)

    out = jobs.run()

    kinds = [k for k, _ in probe.calls]
    assert kinds.index("status") > max(i for i, k in enumerate(kinds) if k == "submit")
    assert out["jobs"] == 2 and out["records"] == 2 and out["outstanding"] == []
    assert sorted(p.stem for p in jobs.spool_dir().glob("*.jsonl")) == sorted(out["spooled"])


def test_a_job_that_outlasts_the_run_is_collected_whole_by_the_next(monkeypatch):
    _watch(monkeypatch, [_t("203.0.113.1"), _t("203.0.113.2")])
    monkeypatch.setattr(jobs, "POLL_TIMEOUT", 0.0)
    finished = False
    probe = FakeProbe(monkeypatch, finish=lambda job_id: finished)

    first = jobs.run()

    # Nothing half-collected: a partial file would be ingested as the scan.
    assert first["spooled"] == [] and first["records"] == 0
    assert list(jobs.spool_dir().glob("*.jsonl")) == []
    (job_id,) = first["outstanding"]
    assert job_id in probe.jobs

    finished = True
    probe.calls.clear()
    second = jobs.run()

    assert job_id in second["spooled"]
    lines = (jobs.spool_dir() / f"{job_id}.jsonl").read_text().splitlines()
    assert {json.loads(x)["target"] for x in lines} == {"203.0.113.1", "203.0.113.2"}
    assert not jobs.outstanding_path().exists()


def test_targets_of_a_job_still_running_are_not_submitted_again(monkeypatch):
    _watch(monkeypatch, [_t("203.0.113.1")])
    monkeypatch.setattr(jobs, "POLL_TIMEOUT", 0.0)
    probe = FakeProbe(monkeypatch, finish=lambda job_id: False)

    jobs.run()
    second = jobs.run()

    assert [k for k, _ in probe.calls].count("submit") == 1
    assert second["targets"] == 0 and len(second["outstanding"]) == 1


def test_an_outstanding_job_the_probe_has_lost_is_dropped(monkeypatch):
    _watch(monkeypatch, [])
    FakeProbe(monkeypatch)
    jobs.outstanding_path().write_text(json.dumps(
        [{"job_id": "hot-gone", "profile": "hot", "values": ["203.0.113.1"]}]))

    out = jobs.run()

    assert out["outstanding"] == [] and not jobs.outstanding_path().exists()


def test_an_unreachable_probe_keeps_the_outstanding_job(monkeypatch):
    _watch(monkeypatch, [])
    FakeProbe(monkeypatch)

    def down(job_id):
        raise vm_proxy.VMProxyError("ssh: connect timed out")
    monkeypatch.setattr(vm_proxy, "netwatch_status", down)
    jobs.outstanding_path().write_text(json.dumps(
        [{"job_id": "hot-late", "profile": "hot", "values": ["203.0.113.1"]}]))

    assert jobs.run()["outstanding"] == ["hot-late"]


def test_a_budget_refusal_puts_queued_targets_back(monkeypatch):
    _watch(monkeypatch, [])
    FakeProbe(monkeypatch)

    def refuse(provider, n=1):
        raise budget.BudgetExhausted("netwatch: 500/500 today")
    monkeypatch.setattr(budget, "spend", refuse)
    queue.enqueue([{**_t("198.51.100.9"), "discovered_via": "ct"}], source="ct")

    out = jobs.run(tiers={"hot"})

    assert "skipped" in out
    (back,) = queue.drain(tiers={"hot"})
    assert back["value"] == "198.51.100.9" and back["discovered_via"] == "ct"


def test_a_rejected_submit_puts_its_queued_targets_back(monkeypatch):
    _watch(monkeypatch, [_t("203.0.113.1", "full")])
    FakeProbe(monkeypatch, reject={"hot"})
    queue.enqueue([_t("198.51.100.9")], source="ct")

    out = jobs.run()

    assert out["jobs"] == 1
    assert [t["value"] for t in queue.drain(tiers={"hot"})] == ["198.51.100.9"]


# --------------------------------------------------------------------------- #
# control target: a host with known ports, scanned with every job
# --------------------------------------------------------------------------- #

CONTROL = "192.0.2.50"


def _rec(scan_id, target, port, open_=True):
    return {"scan_id": scan_id, "ts": "2026-11-13T02:00:00+00:00",
            "vantage": "probe", "profile": "hot", "target": target,
            "ip": target, "port": port, "open": open_, "actor": "APT-W",
            "banner_sha256": "ab" * 32 if open_ else None}


def _spool_file(scan_id, records):
    (jobs.spool_dir() / f"{scan_id}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records))


def _snapshot_targets():
    from cti import store
    with store.connect(read_only=True) as con:
        return {r[0] for r in con.execute(
            "SELECT DISTINCT target FROM service_snapshots").fetchall()}


def test_every_job_carries_the_control_target(monkeypatch):
    monkeypatch.setenv("CTI_NETWATCH_CONTROL", f"{CONTROL}=22,443")
    planned = jobs.plan([_t("203.0.113.1"), _t("203.0.113.2", "full")])

    assert len(planned) == 2
    for job in planned:
        assert job["targets"][0] == {"value": CONTROL, "ports": [22, 443],
                                     "actor": None}


def test_no_control_target_unless_one_is_set():
    (job,) = jobs.plan([_t("203.0.113.1")])
    assert [t["value"] for t in job["targets"]] == ["203.0.113.1"]


def test_a_job_whose_control_scan_is_wrong_is_set_aside(monkeypatch):
    from cti.netwatch import ingest
    monkeypatch.setenv("CTI_NETWATCH_CONTROL", f"{CONTROL}=443")
    # The egress path answers on 8080 for everything, the control included.
    _spool_file("hot-bad", [_rec("hot-bad", CONTROL, 443),
                            _rec("hot-bad", CONTROL, 8080),
                            _rec("hot-bad", "203.0.113.1", 8080)])
    _spool_file("hot-good", [_rec("hot-good", CONTROL, 443),
                             _rec("hot-good", "203.0.113.2", 443)])

    out = ingest.ingest(client=None)

    assert out["quarantined"] == ["hot-bad"]
    assert (ingest.quarantine_dir() / "hot-bad.jsonl").exists()
    assert list(jobs.spool_dir().glob("*.jsonl")) == []
    # The good job is ingested, without the control host itself.
    assert _snapshot_targets() == {"203.0.113.2"}


def test_a_control_port_that_went_missing_also_sets_the_job_aside(monkeypatch):
    from cti.netwatch import ingest
    monkeypatch.setenv("CTI_NETWATCH_CONTROL", f"{CONTROL}=443")
    _spool_file("hot-dark", [_rec("hot-dark", CONTROL, 443, open_=False),
                             _rec("hot-dark", "203.0.113.1", 443, open_=False)])

    assert ingest.ingest(client=None)["quarantined"] == ["hot-dark"]


def test_a_job_without_a_control_scan_is_still_ingested(monkeypatch):
    from cti.netwatch import ingest
    monkeypatch.setenv("CTI_NETWATCH_CONTROL", f"{CONTROL}=443")
    _spool_file("hot-old", [_rec("hot-old", "203.0.113.3", 443)])

    out = ingest.ingest(client=None)

    assert out["quarantined"] == [] and _snapshot_targets() == {"203.0.113.3"}


# --------------------------------------------------------------------------- #
# things that used to disappear without a word
# --------------------------------------------------------------------------- #

def test_a_busy_store_drops_candidates_with_a_warning_not_silently(monkeypatch, caplog):
    from cti import store
    from cti.netwatch import watchlist

    def busy(slug, min_band="noise"):
        raise store.TrackingBusy("locked by pid 1")
    monkeypatch.setattr(watchlist.membership, "candidates", busy)

    with caplog.at_level("WARNING"):
        assert watchlist._candidate_targets("apt-w", "APT-W") == []
    assert "apt-w" in caplog.text and "candidates" in caplog.text


def test_an_unreadable_cluster_is_named_in_the_log(monkeypatch, caplog):
    from cti import core
    from cti.netwatch import watchlist
    core.DATA_DIR.mkdir(parents=True, exist_ok=True)
    (core.DATA_DIR / "broken.json").write_text("{not json")

    with caplog.at_level("WARNING"):
        assert watchlist.build(clusters=["broken"]) == []
    assert "broken" in caplog.text


def test_a_programming_error_in_the_watchlist_is_not_swallowed(monkeypatch):
    from cti.netwatch import watchlist

    def bug(slug, min_band="noise"):
        raise TypeError("unexpected keyword")
    monkeypatch.setattr(watchlist.membership, "candidates", bug)

    with pytest.raises(TypeError):
        watchlist._candidate_targets("apt-w", "APT-W")


def test_a_malformed_record_does_not_stop_the_rest_of_the_spool(caplog):
    from cti.netwatch import ingest
    good = _rec("hot-mixed", "203.0.113.4", 443)
    (jobs.spool_dir() / "hot-mixed.jsonl").write_text("\n".join([
        json.dumps({"port": 443, "open": True}),          # no scan_id, no target
        "{truncated",
        json.dumps(good)]))

    with caplog.at_level("WARNING"):
        out = ingest.ingest(client=None)

    assert out["snapshots"] == 1 and out["rejected"] == 2
    assert _snapshot_targets() == {"203.0.113.4"}
    assert "hot-mixed" in caplog.text
    assert list(jobs.spool_dir().glob("*.jsonl")) == []


def test_a_queue_file_that_cannot_be_read_is_kept_for_inspection():
    path = queue.queue_dir() / "ct-broken.json"
    path.write_text("{not json")

    assert queue.drain(tiers={"hot"}) == []
    assert not path.exists()
    assert (queue.queue_dir() / "ct-broken.json.bad").read_text() == "{not json"
    assert queue.pending() == 0


# --------------------------------------------------------------------------- #
# ports closing and opening
# --------------------------------------------------------------------------- #

def _full(scan_id, target, port, ts, open_=True, **kw):
    return {**_rec(scan_id, target, port, open_), "profile": "full", "ts": ts, **kw}


def _changes():
    from cti import store
    with store.connect(read_only=True) as con:
        return sorted(con.execute(
            "SELECT port, change_type, scan_id FROM service_changes").fetchall())


T1, T2, T3 = ("2026-11-10T06:00:00+00:00", "2026-11-11T06:00:00+00:00",
              "2026-11-12T06:00:00+00:00")
HOST = "203.0.113.9"


def _ingest_scan(scan_id, records):
    from cti.netwatch import ingest
    _spool_file(scan_id, records)
    return ingest.ingest(client=None)


def test_a_closed_record_after_an_open_one_is_a_port_closed():
    _ingest_scan("full-1", [_full("full-1", HOST, 8199, T1)])
    _ingest_scan("full-2", [_full("full-2", HOST, 8199, T2, open_=False)])
    assert _changes() == [(8199, "port_closed", "full-2")]


def test_a_port_the_sweep_no_longer_finds_is_closed_without_a_record_for_it():
    """naabu reports what answers. A port outside the fixed lists that stops
    answering leaves no record at all; the previous sweep of the same kind
    is the evidence that it was there."""
    _ingest_scan("full-1", [_full("full-1", HOST, 443, T1),
                            _full("full-1", HOST, 31337, T1)])
    _ingest_scan("full-2", [_full("full-2", HOST, 443, T2)])

    assert _changes() == [(31337, "port_closed", "full-2")]
    from cti import store
    with store.connect(read_only=True) as con:
        row = con.execute("SELECT open, record FROM service_snapshots "
                          "WHERE scan_id = 'full-2' AND port = 31337").fetchone()
    assert row[0] is False and "full-1" in row[1]


def test_a_closing_is_reported_once_not_on_every_later_scan():
    _ingest_scan("full-1", [_full("full-1", HOST, 443, T1),
                            _full("full-1", HOST, 31337, T1)])
    _ingest_scan("full-2", [_full("full-2", HOST, 443, T2)])
    _ingest_scan("full-3", [_full("full-3", HOST, 443, T3)])
    assert _changes() == [(31337, "port_closed", "full-2")]


def test_a_hot_scan_does_not_close_ports_it_never_looked_at():
    """The hot profile checks a short list. Only the full sweep can speak
    for a port outside it."""
    _ingest_scan("full-1", [_full("full-1", HOST, 443, T1),
                            _full("full-1", HOST, 31337, T1)])
    _ingest_scan("hot-2", [{**_rec("hot-2", HOST, 443), "ts": T2}])
    assert _changes() == []


def test_a_sweep_that_errored_closes_nothing():
    _ingest_scan("full-1", [_full("full-1", HOST, 31337, T1)])
    _ingest_scan("full-2", [_full("full-2", HOST, 0, T2, open_=False,
                                  error="naabu: timed out")])
    assert _changes() == []


def test_a_new_port_on_a_host_swept_before_is_a_port_opened():
    _ingest_scan("full-1", [_full("full-1", HOST, 443, T1)])
    _ingest_scan("full-2", [_full("full-2", HOST, 443, T2),
                            _full("full-2", HOST, 8199, T2)])
    assert _changes() == [(8199, "port_opened", "full-2")]


def test_the_first_sweep_of_a_host_opens_nothing():
    _ingest_scan("full-1", [_full("full-1", HOST, 443, T1),
                            _full("full-1", HOST, 8199, T1)])
    assert _changes() == []
