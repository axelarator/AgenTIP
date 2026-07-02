"""Tests for cti_tools.core. Run with:

    cd mcp-server && source .venv/bin/activate && pip install -e '.[test]'
    pytest
"""
from __future__ import annotations

import json

import pytest

from cti_tools import core


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Never touch the real data/clusters/ directory from tests."""
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    yield tmp_path


def test_create_and_get_cluster():
    core.create_cluster("Test Cluster", description="desc")
    data = core.get_cluster("Test Cluster")
    assert data["name"] == "Test Cluster"
    assert data["description"] == "desc"
    assert data["stix_id"].startswith("intrusion-set--")


def test_create_duplicate_fails():
    core.create_cluster("Dup")
    with pytest.raises(FileExistsError):
        core.create_cluster("Dup")


def test_get_missing_cluster_raises():
    with pytest.raises(core.ClusterNotFound):
        core.get_cluster("Nope")


def test_update_profile_partial():
    core.create_cluster("Profile Test")
    core.update_profile("Profile Test", adversary="APT-Fake", confidence=70)
    data = core.get_cluster("Profile Test")
    assert data["diamond"]["adversary"] == "APT-Fake"
    assert data["confidence"] == 70
    assert data["diamond"]["capability"] == "unknown"  # untouched


def test_update_profile_bad_confidence():
    core.create_cluster("Bad Confidence")
    with pytest.raises(ValueError):
        core.update_profile("Bad Confidence", confidence=150)


def test_update_ttp_insert_and_upsert():
    core.create_cluster("TTP Test")
    core.update_ttp("TTP Test", "T1059", "Command and Scripting Interpreter", 1)
    data = core.update_ttp("TTP Test", "T1059", "Command and Scripting Interpreter", 3, notes="validated")
    assert len(data["ttps"]) == 1
    assert data["ttps"][0]["status"] == 3
    assert data["ttps"][0]["notes"] == "validated"


def test_update_ttp_bad_status():
    core.create_cluster("Bad Status")
    with pytest.raises(ValueError):
        core.update_ttp("Bad Status", "T1059", "x", 9)


def test_hunt_log_append_only():
    core.create_cluster("Hunt Log Test")
    core.append_hunt_log("Hunt Log Test", "first")
    data = core.append_hunt_log("Hunt Log Test", "second")
    assert [h["entry"] for h in data["hunt_log"]] == ["first", "second"]


def test_navigator_layer_shape():
    core.create_cluster("Nav Test")
    core.update_ttp("Nav Test", "T1059", "Command and Scripting Interpreter", 4)
    layer = core.export_navigator_layer("Nav Test")
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1059"
    assert layer["techniques"][0]["score"] == 4


def test_stix_export_roundtrip():
    core.create_cluster("Stix Test", description="desc")
    core.update_profile("Stix Test", aliases=["Alias A"], first_seen="2026-01-01")
    core.update_ttp("Stix Test", "T1059.001", "PowerShell", 2, notes="loader stage")
    core.append_hunt_log("Stix Test", "beacon confirmed")

    bundle = core.export_stix_bundle("Stix Test")
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert types == {"intrusion-set", "attack-pattern", "relationship", "note"}

    imported = core.import_stix_bundle(bundle, name="Stix Import")
    assert imported["name"] == "Stix Import"
    assert imported["aliases"] == ["Alias A"]
    assert imported["ttps"][0]["id"] == "T1059.001"
    assert imported["hunt_log"][0]["entry"] == "beacon confirmed"


def test_stix_attack_pattern_ids_are_deterministic():
    core.create_cluster("Determinism A")
    core.create_cluster("Determinism B")
    core.update_ttp("Determinism A", "T1566", "Phishing", 1)
    core.update_ttp("Determinism B", "T1566", "Phishing", 3)

    bundle_a = core.export_stix_bundle("Determinism A")
    bundle_b = core.export_stix_bundle("Determinism B")

    ap_a = next(o for o in bundle_a["objects"] if o["type"] == "attack-pattern")
    ap_b = next(o for o in bundle_b["objects"] if o["type"] == "attack-pattern")
    assert ap_a["id"] == ap_b["id"]


def test_import_stix_requires_intrusion_set():
    with pytest.raises(ValueError):
        core.import_stix_bundle({"type": "bundle", "objects": []})


def test_import_stix_existing_cluster_requires_overwrite():
    core.create_cluster("Collision")
    bundle = core.export_stix_bundle("Collision")
    with pytest.raises(FileExistsError):
        core.import_stix_bundle(bundle, name="Collision")
    # succeeds with overwrite=True
    core.import_stix_bundle(bundle, name="Collision", overwrite=True)


def test_markdown_regenerated_on_save(tmp_path):
    core.create_cluster("Markdown Test")
    md_path = tmp_path / "markdown-test.md"
    assert md_path.exists()
    content = md_path.read_text()
    assert "STIX ID" in content
    assert "Markdown Test" in content


def test_ingest_report_creates_cluster_from_actor_name(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(
        "Fox Tempest deployed a loader using T1059.001. "
        "C2 at badactor-c2[.]xyz, hash 098f6bcd4621d373cade4e832627b4f6."
    )
    data = core.ingest_report(str(report))
    assert data["name"] == "Fox Tempest"
    assert "fox-tempest" in core.list_clusters()
    assert any(o["value"] == "badactor-c2.xyz" for o in data["observables"]["domains"])
    assert any(t["id"] == "T1059.001" and t["status"] == 0 for t in data["ttps"])


def test_ingest_report_merges_into_existing_cluster_without_clobbering_status():
    core.create_cluster("Fox Tempest")
    core.update_ttp("Fox Tempest", "T1059.001", "PowerShell", 3, notes="validated")

    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.write(fd, b"Fox Tempest seen again using T1059.001 and T1053.005, "
                  b"C2 at second-c2[.]xyz")
    os.close(fd)
    try:
        data = core.ingest_report(path, cluster_name="Fox Tempest")
    finally:
        os.remove(path)

    ttp_lookup = {t["id"]: t for t in data["ttps"]}
    assert ttp_lookup["T1059.001"]["status"] == 3  # untouched by extraction
    assert ttp_lookup["T1053.005"]["status"] == 0  # newly added
    assert any(o["value"] == "second-c2.xyz" for o in data["observables"]["domains"])


def test_ingest_report_ambiguous_name_raises(tmp_path):
    report = tmp_path / "ambiguous.txt"
    report.write_text("Both Fox Tempest and UNC4321 were observed at shared-infra[.]xyz.")
    with pytest.raises(ValueError):
        core.ingest_report(str(report))


def test_ingest_report_no_candidate_raises(tmp_path):
    report = tmp_path / "no_names.txt"
    report.write_text("C2 at random-c2[.]xyz, no actor name mentioned here.")
    with pytest.raises(ValueError):
        core.ingest_report(str(report))


def test_get_observables_view():
    core.create_cluster("Obs View Test")
    view = core.get_observables("Obs View Test")
    assert view["observables"] == {"hashes": [], "domains": [], "ips": [], "urls": []}
    assert view["report_sources"] == []
