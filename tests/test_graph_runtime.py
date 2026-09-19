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
from datetime import date
from pathlib import Path

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
