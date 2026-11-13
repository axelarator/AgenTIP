"""Membership is stored twice (cluster JSON and DuckDB). This checks they agree."""
from __future__ import annotations

import pytest

from cti import core, membership, store
from cluster_patching import patch_clusters


@pytest.fixture
def cluster(monkeypatch):
    patch_clusters(monkeypatch, "_sweep_lifecycle", lambda domains, ips: {})
    core.create_cluster("Drift Test")
    core.add_observable("Drift Test", "ips", "203.0.113.5", "report")
    core.add_observable("Drift Test", "domains", "Evil.Example", "report")
    core.add_observable("Drift Test", "hashes", "sha256:" + "a" * 64, "report")
    return "Drift Test"


def test_a_cluster_filed_normally_has_no_drift(cluster):
    assert core.membership_drift() == {}


def test_an_observable_with_no_membership_is_reported(cluster):
    with store.connect() as con:
        con.execute("DELETE FROM memberships WHERE entity = '203.0.113.5'")

    drift = core.membership_drift()

    assert drift == {"drift-test": {"no_membership": ["203.0.113.5"]}}


def test_a_membership_with_no_observable_is_reported(cluster):
    membership.mirror_seeds("drift-test", [("ips", "198.51.100.9")],
                            origin="report", decided_by="report")

    assert core.membership_drift(["Drift Test"]) == {
        "drift-test": {"no_observable": ["198.51.100.9"]}}


def test_an_observable_the_store_holds_as_rejected_is_reported_with_its_role(cluster):
    with store.connect() as con:
        con.execute("UPDATE memberships SET role = 'rejected' WHERE entity = 'evil.example'")

    assert core.membership_drift() == {
        "drift-test": {"role_mismatch": [{"value": "evil.example", "store_role": "rejected"}]}}


def test_a_failed_store_write_leaves_the_cluster_file_unchanged(cluster, monkeypatch):
    """remove_observable saved the file and then told the store. A locked
    database between the two left a membership for a host the file no
    longer listed."""
    def busy(cluster, value):
        raise store.TrackingBusy("locked by pid 1")
    monkeypatch.setattr(membership, "forget", busy)

    with pytest.raises(store.TrackingBusy):
        core.remove_observable(cluster, "ips", "203.0.113.5")

    assert "203.0.113.5" in core.member_values(core.load_cluster(cluster))
    assert core.membership_drift() == {}


def test_the_doctor_command_reports_drift_and_exits_nonzero(cluster, monkeypatch, capsys):
    from graph import __main__ as cli
    monkeypatch.setattr("sys.argv", ["graph", "doctor"])
    assert cli.main() == 0
    assert "agree" in capsys.readouterr().out

    with store.connect() as con:
        con.execute("DELETE FROM memberships WHERE entity = '203.0.113.5'")
    assert cli.main() == 1
    out = capsys.readouterr().out
    assert "drift-test" in out and "203.0.113.5" in out


def test_the_daily_run_records_drift(cluster):
    from graph.nodes import collect
    with store.connect() as con:
        con.execute("DELETE FROM memberships WHERE entity = '203.0.113.5'")

    sections = collect.check_membership({"sections": {}})["sections"]

    assert sections["membership_drift"] == {"drift-test": {"no_membership": ["203.0.113.5"]}}
    assert sections["status"]["membership_check"] == "ok"
