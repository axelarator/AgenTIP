"""The MCP layer: short replies from mutators, errors a caller can act on."""
from __future__ import annotations

import json

import pytest

from cti import core, store
from cti.mcp import server

SMALL = 1500          # bytes; the fixture cluster is several times this
N = 25


@pytest.fixture
def big():
    """A cluster large enough that returning it whole is the bug."""
    core.create_cluster("Scratch", "d")
    for i in range(N):
        core.add_observable("Scratch", "ips", f"203.0.113.{i}", "seed")
        core.append_hunt_log("Scratch", f"entry {i} " + "x" * 80)
    return "Scratch"


def test_the_suite_never_points_at_the_live_cluster_store(tmp_path):
    assert tmp_path in core.DATA_DIR.parents


def _size(reply):
    return len(json.dumps(reply, default=str))


@pytest.mark.parametrize("call", [
    lambda n: server.add_gap(n, "who hosts the panel"),
    lambda n: server.append_hunt_log(n, "looked at the panel"),
    lambda n: server.update_profile(n, description="new"),
    lambda n: server.update_ttp(n, "T1059", "Command and Scripting Interpreter", 2),
    lambda n: server.add_observable(n, "domains", "example.net", "report"),
    lambda n: server.remove_observable(n, "ips", "203.0.113.5"),
    lambda n: server.add_relationship(n, "related-to", "Scratch", "d", "s"),
    lambda n: server.add_detection("det-1", "d", ["T1059"], cluster_name=n),
], ids=["add_gap", "append_hunt_log", "update_profile", "update_ttp",
        "add_observable", "remove_observable", "add_relationship",
        "add_detection"])
def test_a_mutator_replies_with_an_acknowledgement_not_the_cluster(big, call):
    reply = call(big)

    assert "error" not in reply, reply
    assert reply["cluster"] == "Scratch"
    assert "hunt_log" not in reply and "observables" not in reply
    assert reply["counts"]["hunt_log"] >= N
    assert _size(reply) < SMALL


def test_the_acknowledgement_says_what_changed_and_the_change_is_stored(big):
    reply = server.add_gap(big, "who hosts the panel", "high")
    assert reply["gap_added"] == "high" and reply["counts"]["gaps"] == 1
    assert core.load_cluster(big)["gaps"][0]["description"] == "who hosts the panel"

    reply = server.add_observable(big, "domains", "example.net", "report")
    assert reply["added"] == "example.net"
    assert reply["counts"]["observables"] == {"ips": N, "domains": 1}


def test_a_core_warning_survives_the_acknowledgement(big):
    reply = server.update_ttp(big, "T9999", "Not A Technique", 1)
    assert "warning" in reply


def test_pivot_and_scan_results_carry_counts_not_the_cluster(big, monkeypatch):
    state = core.load_cluster(big)
    monkeypatch.setattr(core, "pivot_and_expand",
                        lambda *a: {"filed": {"ips": ["203.0.113.200"]},
                                    "cluster_state": state})
    monkeypatch.setattr(core, "active_scan",
                        lambda *a: {"target": "203.0.113.1", "cluster_state": state})

    for reply in (server.pivot_and_expand("203.0.113.1", big),
                  server.active_scan("203.0.113.1", big)):
        assert "cluster_state" not in reply
        assert reply["cluster"]["counts"]["observables"]["ips"] == N
        assert _size(reply) < SMALL


def test_get_cluster_still_returns_the_whole_profile(big):
    assert len(server.get_cluster(big)["hunt_log"]) == N


def test_an_unknown_cluster_is_an_error_reply():
    assert "error" in server.add_gap("Nope", "g")
    assert "error" in server.get_cluster("Nope")


def test_a_rejected_argument_is_an_error_reply(big):
    assert "status must be 0-4" in server.update_ttp(big, "T1059", "x", 9)["error"]


@pytest.mark.parametrize("call", [
    lambda: server.hunt_pairs("203.0.113.1"),
    lambda: server.indicator_coverage("203.0.113.1"),
    lambda: server.netwatch_suggest_rule("Scratch"),
], ids=["hunt_pairs", "indicator_coverage", "netwatch_suggest_rule"])
def test_a_busy_database_is_an_error_reply(big, monkeypatch, call):
    def busy(**kw):
        raise store.TrackingBusy("locked by pid 1")
    monkeypatch.setattr(store, "connect_retry", busy)
    monkeypatch.setattr(store, "connect", busy)

    assert "busy" in call()["error"]
