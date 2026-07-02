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


# --- MITRE technique validation -------------------------------------------

def test_update_ttp_unknown_id_warns():
    core.create_cluster("Unknown TTP Test")
    data = core.update_ttp("Unknown TTP Test", "T9999", "Not A Real Technique", 1)
    assert "not a known ATT&CK" in data["warning"]


def test_update_ttp_correct_pair_no_warning():
    core.create_cluster("Correct TTP Test")
    data = core.update_ttp("Correct TTP Test", "T1558.003", "Kerberoasting", 1)
    assert "warning" not in data
    data = core.update_ttp("Correct TTP Test", "T1059.001",
                            "Command and Scripting Interpreter: PowerShell", 2)
    assert "warning" not in data


def test_update_ttp_name_mismatch_warns():
    core.create_cluster("Mismatch TTP Test")
    data = core.update_ttp("Mismatch TTP Test", "T1558.003", "AS-REP Roasting", 1)
    assert "canonical name is" in data["warning"]
    assert "Kerberoasting" in data["warning"]


def test_update_ttp_revoked_technique_warns_with_replacement():
    core.create_cluster("Revoked TTP Test")
    data = core.update_ttp("Revoked TTP Test", "T1562", "Impair Defenses", 1)
    assert "revoked" in data["warning"]
    assert "T1685" in data["warning"]


def test_warning_is_not_persisted():
    core.create_cluster("Warning Persist Test")
    core.update_ttp("Warning Persist Test", "T9999", "Fake", 1)
    reloaded = core.get_cluster("Warning Persist Test")
    assert "warning" not in reloaded


def test_ingest_report_autofill_uses_canonical_name(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("Fake Cluster used T1558.003 during the intrusion. "
                       "C2 at fakecluster-c2[.]xyz.")
    data = core.ingest_report(str(report), cluster_name="Fake Cluster")
    ttp = next(t for t in data["ttps"] if t["id"] == "T1558.003")
    assert ttp["name"] == "Steal or Forge Kerberos Tickets: Kerberoasting"


# --- extraction-empty warning ----------------------------------------------

def test_analyze_report_warns_when_nothing_extracted(tmp_path):
    report = tmp_path / "empty.txt"
    report.write_text("This report mentions no hashes, domains, IPs, or ATT&CK IDs at all.")
    result = core.analyze_report(str(report))
    assert "warning" in result


def test_analyze_report_no_warning_when_something_found(tmp_path):
    report = tmp_path / "full.txt"
    report.write_text("Seen using T1059.001 from infra-c2[.]xyz.")
    result = core.analyze_report(str(report))
    assert "warning" not in result


def test_ingest_report_warns_when_nothing_extracted(tmp_path):
    report = tmp_path / "empty.txt"
    report.write_text("Empty Actor malware showed up with nothing extractable in this text.")
    data = core.ingest_report(str(report), cluster_name="Empty Actor")
    assert "warning" in data


# --- shared detection registry ---------------------------------------------

def test_add_detection_requires_technique_ids():
    core.create_cluster("Detection Req Test")
    with pytest.raises(ValueError):
        core.add_detection("DET-1", "desc", [])


def test_add_detection_shared_across_clusters():
    core.create_cluster("Detection Cluster A")
    core.create_cluster("Detection Cluster B")
    core.update_ttp("Detection Cluster A", "T1558.003", "Kerberoasting", 0)
    core.update_ttp("Detection Cluster B", "T1558.003", "Kerberoasting", 0)

    core.add_detection("DET-KERB", "Kerberoasting ticket request volume", ["T1558.003"],
                        status="validated", cluster_name="Detection Cluster A")

    a = core.get_cluster("Detection Cluster A")
    b = core.get_cluster("Detection Cluster B")
    assert any(d["id"] == "DET-KERB" for d in a["detections"])
    assert any(d["id"] == "DET-KERB" for d in b["detections"])  # shared, not duplicated per cluster


def test_add_detection_upsert_merges_technique_ids():
    core.add_detection("DET-2", "first pass", ["T1558.003"])
    det = core.add_detection("DET-2", "refined", ["T1558.003", "T1003"])
    assert set(det["technique_ids"]) == {"T1558.003", "T1003"}
    assert det["description"] == "refined"


def test_get_technique_usage_single_technique():
    core.create_cluster("Usage Test A")
    core.create_cluster("Usage Test B")
    core.update_ttp("Usage Test A", "T1003", "OS Credential Dumping", 2)
    core.update_ttp("Usage Test B", "T1003", "OS Credential Dumping", 0)
    core.add_detection("DET-3", "LSASS access monitoring", ["T1003"])

    usage = core.get_technique_usage("T1003")
    used_by_clusters = {u["cluster"] for u in usage["used_by"]}
    assert {"Usage Test A", "Usage Test B"} <= used_by_clusters
    assert any(d["id"] == "DET-3" for d in usage["detections"])


def test_get_technique_usage_full_matrix():
    core.create_cluster("Matrix Test")
    core.update_ttp("Matrix Test", "T1078", "Valid Accounts", 1)
    matrix = core.get_technique_usage()
    assert any(e["technique_id"] == "T1078" for e in matrix["techniques"])


# --- cross-cluster relationships -------------------------------------------

def test_add_relationship_requires_existing_target():
    core.create_cluster("Rel Source Test")
    with pytest.raises(core.ClusterNotFound):
        core.add_relationship("Rel Source Test", "uses", "Nonexistent Cluster")


def test_add_relationship_and_stix_roundtrip():
    core.create_cluster("Rel Source")
    core.create_cluster("Rel Target")
    core.add_relationship("Rel Source", "uses", "Rel Target",
                           description="customer relationship", source="https://example.com/report")

    data = core.get_cluster("Rel Source")
    assert data["relationships"][0]["target_cluster"] == "Rel Target"
    target_stix_id = data["relationships"][0]["target_stix_id"]
    assert target_stix_id == core.get_cluster("Rel Target")["stix_id"]

    bundle = core.export_stix_bundle("Rel Source")
    cross_rels = [o for o in bundle["objects"] if o.get("type") == "relationship"
                  and o.get("target_ref") == target_stix_id]
    assert len(cross_rels) == 1
    assert cross_rels[0]["relationship_type"] == "uses"
    assert cross_rels[0]["x_cti_agent_target_name"] == "Rel Target"

    imported = core.import_stix_bundle(bundle, name="Rel Source Import")
    assert imported["relationships"][0]["target_cluster"] == "Rel Target"
    assert imported["relationships"][0]["relationship_type"] == "uses"
