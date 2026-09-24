"""Runtime behaviour of the graph: what the collect nodes report, and what
the trace records.

Both are things the first scheduled run (2026-09-19) got wrong and nobody
could see, which is why they are tested at the seams where they went wrong:
a failed cluster read all-ok in the digest, and one stage's trace replaced
another's.
"""
from __future__ import annotations

import importlib.util
import json
import operator
from datetime import date
from pathlib import Path
from typing import Annotated

import pytest
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from cti import core
from cti.tracking import digest
from graph import trace
from graph.nodes import collect

REPO = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# collect: failures must be visible in the digest
# --------------------------------------------------------------------------- #

def _state(results):
    return {"sweep_results": results, "skip_enrich": True, "day": "2026-09-19"}


def test_sweep_lifts_the_history_note_out_of_pivot_cluster(monkeypatch):
    """pivot_cluster reports a failed history write as a note rather than
    raising. If the sweep does not carry it, it vanishes: the cluster JSON
    is current, the DuckDB history change detection depends on is not, and
    nothing says so."""
    monkeypatch.setattr(core, "pivot_cluster",
                        lambda slug: {"history_note": "enrichment history not recorded: X"})
    out = collect.sweep({"cluster": "fox-tempest", "day": "2026-09-19"})
    entry = out["sweep_results"][0]
    assert entry["ok"] and entry["history_note"].startswith("enrichment history")


def test_a_failed_sweep_is_recorded_with_its_error(monkeypatch):
    def boom(slug):
        raise RuntimeError("probe VM down")
    monkeypatch.setattr(core, "pivot_cluster", boom)
    entry = collect.sweep({"cluster": "x", "day": "2026-09-19"})["sweep_results"][0]
    assert not entry["ok"] and "probe VM down" in entry["error"]


def test_a_clean_sweep_reports_ok():
    sections = collect.enrich_and_write(_state([
        {"cluster": "a", "ok": True, "history_note": None},
        {"cluster": "b", "ok": True, "history_note": None}]))["sections"]
    assert sections["status"]["pivot_sweep"] == "ok"


def test_a_failed_cluster_makes_the_phase_status_not_ok():
    """fox-tempest sat in pivot_sweep.errors while the digest's phase block
    read all-ok, because the sweep set no status at all."""
    sections = collect.enrich_and_write(_state([
        {"cluster": "a", "ok": True, "history_note": None},
        {"cluster": "fox-tempest", "ok": False, "error": "catalog conflict"}]))["sections"]
    status = sections["status"]["pivot_sweep"]
    assert status != "ok" and "fox-tempest" in status
    assert sections["pivot_sweep"]["errors"] == {"fox-tempest": "catalog conflict"}


def test_a_swept_cluster_with_lost_history_is_also_flagged():
    sections = collect.enrich_and_write(_state([
        {"cluster": "a", "ok": True, "history_note": "not recorded: TransactionException"}
    ]))["sections"]
    assert sections["status"]["pivot_sweep"] != "ok"
    assert sections["pivot_sweep"]["history_errors"] == {
        "a": "not recorded: TransactionException"}


def test_the_digest_renders_the_failed_phase(tmp_path):
    sections = collect.enrich_and_write(_state([
        {"cluster": "fox-tempest", "ok": False, "error": "x"}]))["sections"]
    path = digest.write(date(2026, 9, 19), sections)
    text = path.read_text()
    assert "Phase status" in text and "pivot_sweep" in text and "fox-tempest" in text


def test_skip_enrich_routes_past_the_sweep_instead_of_stranding_the_graph():
    """An empty conditional fan-out does not skip the fan-out - it strands
    everything downstream and reports success while writing no digest."""
    assert collect.fan_out_clusters({"skip_enrich": True, "clusters": ["a"]}) == [
        "enrich_and_write"]
    assert collect.fan_out_clusters({"clusters": []}) == ["enrich_and_write"]


# --------------------------------------------------------------------------- #
# trace: one file per stage, and subgraph nodes are recorded
# --------------------------------------------------------------------------- #

@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_RUNS_DIR", str(tmp_path / "runs"))
    return tmp_path / "runs"


class _S(TypedDict, total=False):
    n: int


def _toy(name_a="a", name_b="b"):
    g = StateGraph(_S)
    g.add_node(name_a, lambda s: {"n": 1})
    g.add_node(name_b, lambda s: {"n": 2})
    g.add_edge(START, name_a); g.add_edge(name_a, name_b); g.add_edge(name_b, END)
    return g.compile()


async def test_two_stages_on_one_day_do_not_overwrite_each_other(runs):
    """The 06:45 analyze run replaced the 06:15 collect trace, so the day's
    record had no collect nodes and the fan-out timing was gone."""
    await trace.run_traced(_toy("ingest", "write"), {}, day="2026-09-19", stage="collect")
    await trace.run_traced(_toy("rank", "narrate"), {}, day="2026-09-19", stage="analyze")
    files = dict(trace.run_files("2026-09-19"))
    assert set(files) == {"collect", "analyze"}
    collect_nodes = [n["node"] for n in trace.summarize(files["collect"])["nodes"]]
    assert collect_nodes == ["ingest", "write"]


async def test_rerunning_a_stage_replaces_only_that_stage(runs):
    await trace.run_traced(_toy("a1", "a2"), {}, day="2026-09-19", stage="collect")
    await trace.run_traced(_toy("b1", "b2"), {}, day="2026-09-19", stage="analyze")
    await trace.run_traced(_toy("c1", "c2"), {}, day="2026-09-19", stage="analyze")
    files = dict(trace.run_files("2026-09-19"))
    assert [n["node"] for n in trace.summarize(files["collect"])["nodes"]] == ["a1", "a2"]
    assert [n["node"] for n in trace.summarize(files["analyze"])["nodes"]] == ["c1", "c2"]


async def test_nodes_inside_a_subgraph_are_recorded_and_labelled(runs):
    """Without subgraphs=True a `daily` run records two events, `collect`
    and `analyze`, and nothing about what happened inside either."""
    parent = StateGraph(_S)
    parent.add_node("inner", _toy("step_one", "step_two"))
    parent.add_edge(START, "inner"); parent.add_edge("inner", END)
    final, path = await trace.run_traced(parent.compile(), {}, day="2026-09-19",
                                         stage="daily")
    names = [n["node"] for n in trace.summarize(path)["nodes"]]
    assert "inner:step_one" in names and "inner:step_two" in names
    assert final.get("n") == 2, "the parent's final state must still be returned"


async def test_a_subgraph_label_does_not_carry_the_per_run_task_id(runs):
    parent = StateGraph(_S)
    parent.add_node("inner", _toy())
    parent.add_edge(START, "inner"); parent.add_edge("inner", END)
    _, path = await trace.run_traced(parent.compile(), {}, day="2026-09-19", stage="daily")
    for n in trace.summarize(path)["nodes"]:
        assert n["node"].count(":") <= 1 and len(n["node"]) < 40


class _Fan(TypedDict, total=False):
    done: Annotated[list, operator.add]


async def test_parallel_nodes_are_timed_by_their_own_duration(runs):
    """The first tracer timed a node as the gap since the previous event.
    Nine parallel sweeps then read as a serial chain: each got "the time
    since the last cluster finished", and famoussparrow showed 1s after
    running for 13 minutes. Three sleeps of 0.2/0.4/0.6s that start
    together must record those durations and a shared start."""
    import time
    from langgraph.types import Send

    def work(payload):
        time.sleep(payload["d"])
        return {"done": [payload["d"]]}

    inner = StateGraph(_Fan)
    inner.add_node("start", lambda s: {})
    inner.add_node("sweep", work)
    inner.add_edge(START, "start")
    inner.add_conditional_edges(
        "start", lambda s: [Send("sweep", {"d": d}) for d in (0.2, 0.4, 0.6)], ["sweep"])
    inner.add_edge("sweep", END)
    parent = StateGraph(_Fan)
    parent.add_node("collect", inner.compile())
    parent.add_edge(START, "collect"); parent.add_edge("collect", END)

    final, path = await trace.run_traced(parent.compile(), {}, day="2026-09-24",
                                         stage="daily")
    sweeps = [r for r in trace.read(path) if r.get("node") == "collect:sweep"]
    assert [round(r["elapsed_s"], 1) for r in sweeps] == [0.2, 0.4, 0.6]
    starts = [r["started_s"] for r in sweeps]
    assert max(starts) - min(starts) < 0.1, "they ran together, not in turn"
    assert sorted(final["done"]) == [0.2, 0.4, 0.6]


async def test_a_failed_node_is_recorded_with_its_error(runs):
    g = StateGraph(_S)
    g.add_node("boom", lambda s: (_ for _ in ()).throw(RuntimeError("probe VM down")))
    g.add_edge(START, "boom"); g.add_edge("boom", END)
    with pytest.raises(RuntimeError):
        await trace.run_traced(g.compile(), {}, day="2026-09-24", stage="collect")
    [record] = [r for r in trace.read(trace.run_path("2026-09-24", "collect"))
                if r.get("event") == "node"]
    assert record["node"] == "boom" and "probe VM down" in record["error"]


def test_a_pre_fix_trace_without_a_stage_is_still_readable(runs):
    runs.mkdir(parents=True)
    (runs / "2026-09-18.jsonl").write_text(
        json.dumps({"event": "run_start", "day": "2026-09-18", "ts": 0}) + "\n"
        + json.dumps({"event": "node", "node": "rank", "elapsed_s": 0.02, "output": {}}) + "\n"
        + json.dumps({"event": "run_end", "elapsed_s": 0.03}) + "\n")
    [(stage, path)] = trace.run_files("2026-09-18")
    assert stage == "legacy" and trace.summarize(path)["nodes"][0]["node"] == "rank"


def test_a_day_with_several_stages_is_listed_once(runs):
    runs.mkdir(parents=True)
    for name in ("2026-09-19.collect.jsonl", "2026-09-19.analyze.jsonl", "2026-09-18.jsonl"):
        (runs / name).write_text("")
    assert trace.run_days() == ["2026-09-19", "2026-09-18"]


def test_run_files_come_back_in_pipeline_order(runs):
    runs.mkdir(parents=True)
    for name in ("2026-09-19.analyze.jsonl", "2026-09-19.collect.jsonl"):
        (runs / name).write_text("")
    assert [s for s, _ in trace.run_files("2026-09-19")] == ["collect", "analyze"]


# --------------------------------------------------------------------------- #
# dashboard API
# --------------------------------------------------------------------------- #

def _dashboard():
    spec = importlib.util.spec_from_file_location("dash_server", REPO / "dashboard" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_run_api_merges_a_days_stages_and_tags_each_node(runs):
    from starlette.testclient import TestClient

    runs.mkdir(parents=True)
    def rec(stage, nodes, total):
        lines = [{"event": "run_start", "day": "2026-09-19", "stage": stage, "ts": 0}]
        lines += [{"event": "node", "node": n, "elapsed_s": t, "output": {}} for n, t in nodes]
        lines += [{"event": "run_end", "elapsed_s": total}]
        return "\n".join(json.dumps(l) for l in lines) + "\n"

    (runs / "2026-09-19.collect.jsonl").write_text(
        rec("collect", [("ingest_inbox", 0.5), ("sweep", 90.0)], 91.0))
    (runs / "2026-09-19.analyze.jsonl").write_text(
        rec("analyze", [("rank", 0.02), ("hosting", 15.9)], 16.0))

    client = TestClient(_dashboard().app)
    assert client.get("/api/runs").json() == {"dates": ["2026-09-19"]}
    body = client.get("/api/runs/2026-09-19").json()
    assert [(n["stage"], n["node"]) for n in body["nodes"]] == [
        ("collect", "ingest_inbox"), ("collect", "sweep"),
        ("analyze", "rank"), ("analyze", "hosting")]
    assert body["summary"]["total_s"] == 107.0
    assert body["summary"]["slowest"] == "sweep"
    assert [s["stage"] for s in body["summary"]["stages"]] == ["collect", "analyze"]


def test_the_run_api_rejects_a_path_traversing_date(runs):
    from starlette.testclient import TestClient
    resp = TestClient(_dashboard().app).get("/api/runs/..%2f..%2fetc")
    assert resp.status_code in (400, 404)


# --------------------------------------------------------------------------- #
# The scenario that lost fox-tempest: a real fan-out, real DuckDB writes
# --------------------------------------------------------------------------- #

async def test_eight_clusters_fanned_out_all_record_their_history(monkeypatch, tmp_path):
    """Only the network is stubbed. Each fake sweep does what the real
    pivot_cluster does at its end - core._log_cluster_enrichment_history,
    which opens a read-write connection and writes observations and
    attribute changes - so the eight sweeps really do contend for the store
    from LangGraph's worker threads.

    Unit tests of the connection module prove the lock; this proves the
    graph actually goes through it. On the pre-fix code this lost clusters
    to "Catalog write-write conflict" and "Unique file handle conflict".
    """
    from datetime import datetime

    from graph.build import build_collect

    for name in (*collect.PROBE_ENV, *collect.KEY_ENV):
        monkeypatch.setenv(name, "x")   # the sweep is gated on preflight
    slugs = [f"cluster-{n}" for n in range(8)]
    monkeypatch.setattr(core, "list_clusters", lambda: slugs)
    monkeypatch.setattr(collect.ingest, "register_new_clusters", lambda con: {})
    monkeypatch.setattr(collect.enrich, "build_worklist", lambda con: ([], set()))

    def fake_pivot_cluster(slug):
        observed_at = datetime(2026, 9, 19, 6, 0)
        results = {}
        for n in range(6):
            host = f"{slug}-{n}.example"
            results[("domains", host)] = (
                "active", {"resolved": [f"10.{n}.0.1"]},
                {"http": {"status": 200, "title": f"t{n}", "server": "nginx",
                          "final_url": f"https://{host}/"},
                 "tls": {"cert": {"sha256": f"h{n}", "issuer": "LE",
                                  "subject": host, "sans": [host]}}})
        note = core._log_cluster_enrichment_history(slug, observed_at, results)
        return {"history_note": note} if note else {}

    monkeypatch.setattr(core, "pivot_cluster", fake_pivot_cluster)

    final, _ = await trace.run_traced(build_collect(), {"day": "2026-09-19"},
                                      day="2026-09-19", stage="collect")
    sweep = final["sections"]["pivot_sweep"]
    assert sweep["errors"] == {}, sweep["errors"]
    assert sweep["history_errors"] == {}, sweep["history_errors"]
    assert sweep["clusters_swept"] == 8
    assert final["sections"]["status"]["pivot_sweep"] == "ok"

    from cti import store
    with store.connect(read_only=True) as con:
        written = con.execute(
            "SELECT count(DISTINCT actor) FROM observations WHERE source = 'http_live'"
        ).fetchone()[0]
    assert written == 8, f"only {written} of 8 clusters recorded any history"


# --------------------------------------------------------------------------- #
# The first scheduled run collected nothing and said nothing
# --------------------------------------------------------------------------- #

_FULL_ENV = {v: "x" for v in (*collect.PROBE_ENV, *collect.KEY_ENV)}


def test_preflight_is_ok_with_the_full_environment():
    assert collect.preflight(_FULL_ENV) == ("ok", [])


def test_preflight_blocks_the_sweep_when_the_probe_settings_are_missing():
    """Cron ran with an empty environment, so the probe transport fell back
    to a default address that is not this lab's VM. Every lookup failed, and
    pivot_cluster wrote the resulting 'unknown' over 82 real statuses."""
    verdict, missing = collect.preflight({})
    assert verdict.startswith("blocked") and "CTI_PROBE_HOST" in verdict
    assert set(collect.PROBE_ENV) <= set(missing)
    assert "bashrc" in verdict, "the message should name the likely cause"


def test_a_missing_api_key_warns_but_does_not_block():
    """The keys only degrade a sweep - those sources are skipped - whereas a
    missing probe host poisons every result."""
    env = {v: "x" for v in collect.PROBE_ENV}
    verdict, missing = collect.preflight(env)
    assert verdict.startswith("warning") and "WEBAMON_API_KEY" in verdict
    assert not verdict.startswith("blocked")


def test_a_partial_probe_configuration_is_still_blocked():
    env = dict(_FULL_ENV)
    del env["CTI_PROBE_KNOWN_HOSTS"]
    assert collect.preflight(env)[0].startswith("blocked")


def test_a_blocked_preflight_routes_past_the_sweep():
    state = {"clusters": ["a", "b"], "sections": {"status": {"preflight": "blocked: x"}}}
    assert collect.fan_out_clusters(state) == ["enrich_and_write"]


def test_a_warning_preflight_still_sweeps():
    state = {"clusters": ["a"], "day": "2026-09-19",
             "sections": {"status": {"preflight": "warning: keys"}}}
    sends = collect.fan_out_clusters(state)
    assert len(sends) == 1 and sends[0] != "enrich_and_write"


def test_the_blocked_sweep_is_reported_in_the_phase_status():
    state = {"sweep_results": [], "skip_enrich": True,
             "sections": {"status": {"preflight": "blocked: x"}}}
    assert "preflight" in collect.enrich_and_write(state)["sections"]["status"]["pivot_sweep"]


def _swept(cluster, statuses):
    rows = [{"value": f"{cluster}-{n}", "status": s} for n, s in enumerate(statuses)]
    return {"cluster": cluster, "ok": True, "history_note": None,
            "result": {"domains": rows, "ips": []}}


def test_a_sweep_where_everything_came_back_unknown_is_flagged():
    """The real 2026-09-19 06:15 run: 82 of 82 observables 'unknown', every
    cluster 'swept', and a digest whose phase block read all-ok."""
    sections = collect.enrich_and_write(_state([
        _swept("jadeprox", ["unknown"] * 27), _swept("stac4749", ["unknown"] * 36)]
    ))["sections"]
    status = sections["status"]["pivot_sweep"]
    assert status != "ok" and "63 of 63 domains" in status and "outage" in status


def test_a_normal_mix_of_statuses_is_not_flagged():
    """Yesterday's real distribution had 1 'unknown' in 148."""
    sections = collect.enrich_and_write(_state([
        _swept("a", ["active"] * 60 + ["dead"] * 30 + ["sinkholed"] * 3 + ["unknown"])
    ]))["sections"]
    assert sections["status"]["pivot_sweep"] == "ok"


def test_genuinely_dead_infrastructure_is_not_mistaken_for_an_outage():
    """'dead' and 'sinkholed' are definitive answers. Only 'unknown' - could
    not check - counts toward the alarm."""
    sections = collect.enrich_and_write(_state([_swept("a", ["dead"] * 20)]))["sections"]
    assert sections["status"]["pivot_sweep"] == "ok"


def test_the_printed_cron_lines_source_bashrc():
    """The printed lines were the root cause: they dropped the prefix the old
    crontab had, and cron ran with an empty environment."""
    lines = [l for l in (REPO / "setup.sh").read_text().splitlines()
             if 'echo "  ' in l and "* * *" in l]
    assert lines, "no cron line is printed at all"
    assert all("$HOME/.bashrc" in l for l in lines), lines


def test_the_printed_cron_runs_the_stages_as_one_job():
    """Two jobs half an hour apart is a guess about how long collect takes.
    It took 21 minutes on 2026-09-20 with an empty enrich worklist, and has
    since grown a corroborate stage; when it overruns, analyze exits with
    "no digest for <today>" and the day's analysis is lost."""
    lines = [l for l in (REPO / "setup.sh").read_text().splitlines()
             if 'echo "  ' in l and "* * *" in l]
    assert len(lines) == 1, "collect and analyze must not be separate jobs"
    assert "graph daily" in lines[0]


def test_no_test_can_write_pipeline_traces_into_the_live_data_dir():
    """conftest redirects CTI_RUNS_DIR for every test. Without it, running the
    suite silently overwrote data/runs/<today>.collect.jsonl with fake stub
    clusters, which the dashboard then presented as a real run."""
    live = Path(__file__).resolve().parents[1] / "data" / "runs"
    assert live not in trace.runs_dir().parents and trace.runs_dir() != live


def test_domains_failing_are_flagged_even_when_the_ips_are_healthy():
    """The real 2026-09-19 18:41 run: 49 of 57 domains 'unknown' (every one an
    SSH timeout) beside 47 healthy IPs. Blended, that is 49/104 = 47% and
    slipped under the 50% alarm, so the phase status read 'ok'."""
    domains = _swept("jadeprox", ["unknown"] * 49 + ["active"] * 8)
    ips = {"cluster": "sliver", "ok": True, "history_note": None,
           "result": {"domains": [], "ips": [{"value": f"1.1.1.{n}", "status": "routed"}
                                             for n in range(47)]}}
    status = collect.enrich_and_write(_state([domains, ips]))["sections"]["status"]["pivot_sweep"]
    assert status != "ok" and "49 of 57 domains" in status
    assert "ips" not in status.split("came back")[0], "healthy IPs must not be named"


def test_the_unknown_share_is_reported_per_category():
    sections = collect.enrich_and_write(_state([_swept("a", ["unknown", "active", "dead"])]))["sections"]
    assert sections["pivot_sweep"]["unknown"] == {
        "domains": {"unknown": 1, "checked": 3}, "ips": {"unknown": 0, "checked": 0}}



def test_a_slow_optional_lookup_does_not_cost_a_domain_its_status(monkeypatch):
    """The actual bug behind 20 'unknown' domains: a subfinder timeout
    escaped as a raw TimeoutExpired, reached _sweep_lifecycle's catch-all, and
    discarded the RDAP and DNS results the domain's status was computed from."""
    import subprocess

    monkeypatch.setattr(core.pivot, "rdap_lookup",
                        lambda v, kind: {"handle": "H", "events": [], "nameservers": ["ns1.example"],
                                         "status": ["active"]})
    monkeypatch.setattr(core.pivot, "resolve_host", lambda h: ["93.184.216.34"])
    for fn in ("http_probe", "wayback_cdx"):
        monkeypatch.setattr(core.vm_proxy, fn, lambda *a, **k: {"error": None})
    monkeypatch.setattr(core.webamon, "search_domain", lambda d: {"error": "skipped"})
    monkeypatch.setattr(core.webamon, "infostealers", lambda d: {"error": "skipped"})

    # Go through the REAL transport: subprocess.run itself times out. Stubbing
    # vm_proxy.subfinder to raise VMProxyError - as an earlier version of this
    # test did - passed on the broken code, because that exception was always
    # handled. The bug was a raw TimeoutExpired.
    #
    # conftest replaces vm_proxy._ssh_json_rpc with a raiser for every test, so
    # the real one - where the bug lives - has to be loaded fresh. The first
    # attempt at this test never reached it and passed on the broken code.
    spec = importlib.util.spec_from_file_location(
        "cti.probe.vm_proxy_real", REPO / "cti" / "probe" / "vm_proxy.py")
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    monkeypatch.setattr(core.vm_proxy, "_ssh_json_rpc", real._ssh_json_rpc)

    def ssh_that_times_out(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 60)
    monkeypatch.setattr(real.subprocess, "run", ssh_that_times_out)
    monkeypatch.setattr(core, "_cached_pivot", lambda source, value, fetch: fetch())   # no cache here

    status, detail, enrichment = core._domain_lifecycle("example.com")
    assert status != "unknown", "the domain lost its status to one slow optional lookup"
    assert detail["resolved"] == ["93.184.216.34"]
    assert "error" in enrichment["subdomains"], "the slow source should be reported as failed"
