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


@pytest.fixture(autouse=True)
def isolated_tracking_db(tmp_path, monkeypatch):
    """Never touch the real data/tracking/tracking.duckdb from tests -
    pivot_cluster now writes Shodan/ThreatFox history there. Same
    CTI_DUCKDB_PATH override test_tracking.py uses."""
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "tracking-test.duckdb"))


@pytest.fixture(autouse=True)
def default_lifecycle_stubs(monkeypatch):
    """add_observable/ingest_report/pivot_and_expand now run a live
    asn/ports/cert enrichment sweep (core._sweep_lifecycle) for every
    genuinely new domain/ip they file - stub its network sources
    (the same ones _domain_lifecycle/_ip_lifecycle call) to fast, empty,
    no-network defaults by default so tests that don't care about
    enrichment content stay hermetic and fast. A test that DOES care
    about enrichment content overrides the specific pivot.* function
    itself - monkeypatch layers fine on top of this, same as
    stub_pivot_net/stub_cluster_sweep_net already do."""
    monkeypatch.setattr(core.pivot, "rdap_lookup",
                        lambda value, kind: {"nameservers": [], "status": [], "events": []})
    monkeypatch.setattr(core.pivot, "resolve_host", lambda host: [])
    monkeypatch.setattr(core.pivot, "ripestat_lookup", lambda ip: {"asn": []})
    monkeypatch.setattr(core.pivot, "ptr_lookup", lambda ip: {"hostname": None})
    # Live enrichment now flows through webamon.* (host-direct) and
    # vm_proxy.* (probe VM) rather than the retired scan-platform pivots -
    # stub both boundaries to empty, no-network defaults.
    monkeypatch.setattr(core.vm_proxy, "tls_grab",
                        lambda host, port=443: {"cert": None, "resolved_ip": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "http_probe",
                        lambda url, insecure=False: {"status": None, "final_url": url, "title": None,
                                                     "server": None, "content_type": None,
                                                     "body_sha256": None, "autoindex": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "subfinder", lambda domain: {"subdomains": [], "error": None})
    monkeypatch.setattr(core.vm_proxy, "wayback_cdx",
                        lambda domain: {"urls": [], "subdomains": [], "error": None})
    monkeypatch.setattr(core.webamon, "search_domain",
                        lambda domain, size=5: {"total_hits": 0, "results": [], "latest": None})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 0, "domains": [], "results": []})
    monkeypatch.setattr(core.webamon, "infostealers",
                        lambda term, size=25: {"total_hits": 0, "results": []})


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


def test_remove_ttp_drops_technique():
    core.create_cluster("TTP Remove")
    core.update_ttp("TTP Remove", "T1059", "Command and Scripting Interpreter", 1)
    core.update_ttp("TTP Remove", "T1566", "Phishing", 2)
    result = core.remove_ttp("TTP Remove", "t1059")  # case-insensitive
    assert result["removed"] == "t1059"
    ids = {t["id"] for t in core.get_cluster("TTP Remove")["ttps"]}
    assert ids == {"T1566"}


def test_remove_ttp_not_found_raises():
    core.create_cluster("TTP Remove Miss")
    with pytest.raises(ValueError):
        core.remove_ttp("TTP Remove Miss", "T9999")


def test_add_gap_defaults_to_medium_priority():
    core.create_cluster("Gap Test")
    data = core.add_gap("Gap Test", "no initial access vector reported")
    assert data["gaps"] == [{
        "description": "no initial access vector reported",
        "priority": "medium",
        "created": data["gaps"][0]["created"],
    }]


def test_update_gap_changes_only_fields_passed():
    core.create_cluster("Gap Update")
    core.add_gap("Gap Update", "sample coverage missing", priority="medium")
    data = core.update_gap("Gap Update", "sample coverage missing", priority="low")
    gap = data["gaps"][0]
    assert gap["description"] == "sample coverage missing"
    assert gap["priority"] == "low"
    assert "updated" in gap

    data = core.update_gap("Gap Update", "sample coverage missing",
                            new_description="pivot tried, came up empty")
    gap = data["gaps"][0]
    assert gap["description"] == "pivot tried, came up empty"
    assert gap["priority"] == "low"  # untouched by the second call


def test_update_gap_not_found_raises():
    core.create_cluster("Gap Update Miss")
    with pytest.raises(ValueError):
        core.update_gap("Gap Update Miss", "nonexistent gap", priority="low")


def test_remove_gap_drops_matching_gap():
    core.create_cluster("Gap Remove")
    core.add_gap("Gap Remove", "gap one")
    core.add_gap("Gap Remove", "gap two")
    result = core.remove_gap("Gap Remove", "gap one")
    assert result["removed"]["description"] == "gap one"
    remaining = [g["description"] for g in core.get_cluster("Gap Remove")["gaps"]]
    assert remaining == ["gap two"]


def test_remove_gap_not_found_raises():
    core.create_cluster("Gap Remove Miss")
    with pytest.raises(ValueError):
        core.remove_gap("Gap Remove Miss", "nonexistent gap")


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


def test_ingest_report_stamps_ip_ports_from_extraction(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(
        "TA4922 loader uses T1059.001. "
        "Atlas RAT: TCP port 886 (IPs: 206.238.115.58, 154.211.86.110). "
        "RomulusLoader: TCP port 1234 (IP: 43.156.77.97). "
        "Unrelated IP 185.220.101.47 has no nearby port mention."
    )
    data = core.ingest_report(str(report), cluster_name="TA4922 Port Test")
    by_value = {o["value"]: o for o in data["observables"]["ips"]}
    assert by_value["206.238.115.58"]["ports"] == [886]
    assert by_value["154.211.86.110"]["ports"] == [886]
    assert by_value["43.156.77.97"]["ports"] == [1234]
    assert "ports" not in by_value["185.220.101.47"]


def test_ingest_report_appends_new_port_without_dropping_old(tmp_path):
    core.create_cluster("Port Merge Test")
    core.add_observable("Port Merge Test", "ips", "206.238.115.58", "manual")

    report = tmp_path / "report.txt"
    report.write_text("Second report: Atlas RAT: TCP port 886 (IP: 206.238.115.58).")
    data = core.ingest_report(str(report), cluster_name="Port Merge Test",
                               create_if_missing=False)
    entry = next(o for o in data["observables"]["ips"] if o["value"] == "206.238.115.58")
    assert entry["ports"] == [886]

    # Re-ingesting the same port again shouldn't duplicate it.
    data = core.ingest_report(str(report), cluster_name="Port Merge Test",
                               create_if_missing=False)
    entry = next(o for o in data["observables"]["ips"] if o["value"] == "206.238.115.58")
    assert entry["ports"] == [886]


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
    assert view["observables"] == {c: [] for c in core.OBSERVABLE_CATEGORIES}
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


# --- observable reverse index -----------------------------------------------

def test_find_observable_matches_across_clusters(tmp_path):
    core.create_cluster("Observable Cluster A")
    core.create_cluster("Observable Cluster B")

    report_a = tmp_path / "a.txt"
    report_a.write_text("Observable Cluster A seen at shared-c2[.]xyz.")
    core.ingest_report(str(report_a), cluster_name="Observable Cluster A")

    report_b = tmp_path / "b.txt"
    report_b.write_text("Observable Cluster B also seen at shared-c2[.]xyz.")
    core.ingest_report(str(report_b), cluster_name="Observable Cluster B")

    result = core.find_observable("shared-c2.xyz")
    clusters = {m["cluster"] for m in result["matches"]}
    assert clusters == {"Observable Cluster A", "Observable Cluster B"}
    assert all(m["category"] == "domains" for m in result["matches"])


def test_find_observable_matches_hash_with_or_without_prefix(tmp_path):
    core.create_cluster("Hash Cluster")
    report = tmp_path / "hash.txt"
    report.write_text("Hash Cluster dropped 098f6bcd4621d373cade4e832627b4f6 on disk.")
    core.ingest_report(str(report), cluster_name="Hash Cluster")

    bare = core.find_observable("098f6bcd4621d373cade4e832627b4f6")
    prefixed = core.find_observable("md5:098f6bcd4621d373cade4e832627b4f6")
    assert len(bare["matches"]) == 1
    assert len(prefixed["matches"]) == 1
    assert bare["matches"][0]["cluster"] == "Hash Cluster"


def test_find_observable_no_match():
    core.create_cluster("Empty Observable Cluster")
    result = core.find_observable("never-seen-anywhere.example")
    assert result["matches"] == []


# --- multi-cluster STIX ecosystem export ------------------------------------

def test_export_stix_ecosystem_includes_related_clusters():
    core.create_cluster("Ecosystem A")
    core.create_cluster("Ecosystem B")
    core.create_cluster("Ecosystem C")
    core.add_relationship("Ecosystem A", "uses", "Ecosystem B", description="A uses B")
    core.add_relationship("Ecosystem B", "uses", "Ecosystem C", description="B uses C")

    bundle = core.export_stix_ecosystem("Ecosystem A")
    intrusion_sets = {o["name"] for o in bundle["objects"] if o["type"] == "intrusion-set"}
    assert intrusion_sets == {"Ecosystem A", "Ecosystem B", "Ecosystem C"}

    # every relationship's target_ref must resolve to an object actually in the bundle
    ids_in_bundle = {o["id"] for o in bundle["objects"]}
    for rel in (o for o in bundle["objects"] if o["type"] == "relationship"):
        assert rel["target_ref"] in ids_in_bundle


def test_export_stix_ecosystem_dedupes_shared_technique():
    core.create_cluster("Ecosystem D")
    core.create_cluster("Ecosystem E")
    core.add_relationship("Ecosystem D", "related-to", "Ecosystem E")
    core.update_ttp("Ecosystem D", "T1566", "Phishing", 1)
    core.update_ttp("Ecosystem E", "T1566", "Phishing", 2)

    bundle = core.export_stix_ecosystem("Ecosystem D")
    attack_patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(attack_patterns) == 1  # same technique -> same deterministic id, not duplicated


def test_export_stix_ecosystem_unknown_cluster_raises():
    with pytest.raises(core.ClusterNotFound):
        core.export_stix_ecosystem("Does Not Exist")


def test_export_stix_ecosystem_single_cluster_no_relationships():
    core.create_cluster("Lonely Cluster")
    bundle = core.export_stix_ecosystem("Lonely Cluster")
    intrusion_sets = [o for o in bundle["objects"] if o["type"] == "intrusion-set"]
    assert len(intrusion_sets) == 1
    assert intrusion_sets[0]["name"] == "Lonely Cluster"


# --- pivot_observable orchestration -----------------------------------------

@pytest.fixture
def stub_pivot_net(monkeypatch):
    """Stub every pivot network source so pivot_observable tests are
    hermetic. Individual tests override specific sources as needed."""
    monkeypatch.setattr(core.pivot, "rdap_lookup", lambda value, kind: {"handle": "H"})
    monkeypatch.setattr(core.pivot, "ripestat_lookup", lambda ip: {"asn": [999]})
    monkeypatch.setattr(core.pivot, "ptr_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr(core.vm_proxy, "tls_grab",
                        lambda host, port=443: {"cert": None, "resolved_ip": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "http_probe",
                        lambda url, insecure=False: {"status": None, "final_url": url, "title": None,
                                                     "server": None, "content_type": None,
                                                     "body_sha256": None, "autoindex": None, "error": None})
    monkeypatch.setattr(core.webamon, "search_domain",
                        lambda domain, size=5: {"total_hits": 0, "results": [], "latest": None})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 0, "domains": [], "results": []})
    monkeypatch.setattr(core.webamon, "infostealers",
                        lambda term, size=25: {"total_hits": 0, "results": []})
    # Unset by default so pivot_observable's ThreatFox/HoneyLabs branches
    # short-circuit to their skip notes instead of reaching the real
    # lookup functions; tests that want the lookup set the env var and
    # stub the function themselves.
    monkeypatch.delenv("THREATFOX_API_KEY", raising=False)
    monkeypatch.delenv("HONEYLABS_API_KEY", raising=False)
    return monkeypatch


def test_pivot_observable_domain_calls_rdap_and_webamon_not_ripestat(stub_pivot_net):
    stub_pivot_net.setattr(core.webamon, "search_domain",
                           lambda domain, size=5: {"total_hits": 3, "results": [], "latest": None})
    result = core.pivot_observable("example.com")
    assert result["kind"] == "domain"
    assert result["rdap"] == {"handle": "H"}
    assert result["webamon"]["total_hits"] == 3
    assert "webamon_infostealers" in result
    assert "tls" in result and "http" in result
    assert "ripestat" not in result
    assert "webamon_ip" not in result  # domain, not ip
    assert "skipped" in result["threatfox"]


def test_pivot_observable_ip_calls_rdap_ripestat_and_webamon_ip(stub_pivot_net):
    stub_pivot_net.setattr(core.webamon, "search_ip",
                           lambda ip, size=50: {"total_hits": 1, "domains": ["co-hosted.example"],
                                                "results": []})
    result = core.pivot_observable("1.2.3.4")
    assert result["kind"] == "ip"
    assert result["rdap"] == {"handle": "H"}
    assert result["ripestat"] == {"asn": [999]}
    assert result["webamon_ip"]["domains"] == ["co-hosted.example"]
    assert "ptr" in result
    assert "webamon" not in result  # ip, not domain (domain-only Webamon scan)
    assert "tls" not in result  # no live grab on a bare IP


def test_pivot_observable_hash_skips_network_sources(stub_pivot_net):
    result = core.pivot_observable("098f6bcd4621d373cade4e832627b4f6")
    assert result["kind"] == "hash"
    assert "rdap" not in result
    assert "ripestat" not in result
    assert "webamon" not in result
    assert "webamon_ip" not in result
    assert "tls" not in result
    assert "skipped" in result["threatfox"]


def test_pivot_observable_threatfox_skipped_without_key(stub_pivot_net):
    result = core.pivot_observable("1.2.3.4")
    assert "skipped" in result["threatfox"]
    assert "THREATFOX_API_KEY" in result["threatfox"]["skipped"]


def test_pivot_observable_threatfox_used_with_key(stub_pivot_net):
    stub_pivot_net.setenv("THREATFOX_API_KEY", "fake-tf-key")
    stub_pivot_net.setattr(core.pivot, "threatfox_lookup",
                           lambda value, api_key: {"matches": [{"malware": "Cobalt Strike"}],
                                                    "key_used": api_key})
    result = core.pivot_observable("098f6bcd4621d373cade4e832627b4f6")
    assert result["threatfox"]["matches"] == [{"malware": "Cobalt Strike"}]
    assert result["threatfox"]["key_used"] == "fake-tf-key"


def test_pivot_observable_threatfox_lookup_error_passes_through(stub_pivot_net):
    # threatfox_lookup itself never raises (it catches PivotError
    # internally, same contract as rdap_lookup/ripestat_lookup), so
    # pivot_observable doesn't need its own try/except around it - an
    # {"error": ...} result from the lookup should just pass through.
    stub_pivot_net.setenv("THREATFOX_API_KEY", "fake-tf-key")
    stub_pivot_net.setattr(core.pivot, "threatfox_lookup",
                           lambda value, api_key: {"error": "threatfox down"})
    result = core.pivot_observable("1.2.3.4")
    assert result["threatfox"] == {"error": "threatfox down"}


def test_pivot_observable_domain_webamon_and_tls(stub_pivot_net):
    stub_pivot_net.setattr(core.webamon, "search_domain",
                           lambda domain, size=5: {"total_hits": 2, "results": [],
                                                    "latest": {"report_id": "rid", "risk_score": 55}})
    stub_pivot_net.setattr(core.vm_proxy, "tls_grab",
                           lambda host, port=443: {"cert": {"sha256": "abc", "issuer": "R3"},
                                                   "resolved_ip": "1.2.3.4", "error": None})
    result = core.pivot_observable("example.com")
    assert result["webamon"]["latest"]["report_id"] == "rid"
    assert result["tls"]["cert"]["sha256"] == "abc"


def test_pivot_observable_does_not_write_to_any_cluster(stub_pivot_net):
    core.create_cluster("Pivot Side Effect Test")
    before = core.get_cluster("Pivot Side Effect Test")
    core.pivot_observable("example.com")
    after = core.get_cluster("Pivot Side Effect Test")
    assert before == after


# --- HoneyLabs enrichment ----------------------------------------------------

def test_pivot_observable_ip_honeylabs_skipped_without_key(stub_pivot_net):
    stub_pivot_net.delenv("VT_API_KEY", raising=False)
    result = core.pivot_observable("1.2.3.4")
    assert "skipped" in result["honeylabs"]
    assert "HONEYLABS_API_KEY" in result["honeylabs"]["skipped"]


def test_pivot_observable_domain_has_no_honeylabs_section(stub_pivot_net):
    stub_pivot_net.delenv("VT_API_KEY", raising=False)
    result = core.pivot_observable("example.com")
    assert "honeylabs" not in result


def test_honeylabs_context_used_with_key(stub_pivot_net):
    stub_pivot_net.setenv("HONEYLABS_API_KEY", "hlk_fake")
    stub_pivot_net.setattr(core.pivot, "honeylabs_lookup",
                           lambda ip, api_key: {"events": 5, "key_used": api_key})
    assert core.honeylabs_context("1.2.3.4") == {"events": 5, "key_used": "hlk_fake"}


def test_honeylabs_context_error_is_contained(stub_pivot_net):
    stub_pivot_net.setenv("HONEYLABS_API_KEY", "hlk_fake")

    def raise_error(ip, api_key):
        raise core.pivot.PivotError("credits exhausted: HTTP 402")
    stub_pivot_net.setattr(core.pivot, "honeylabs_lookup", raise_error)
    result = core.honeylabs_context("1.2.3.4")
    assert "credits exhausted" in result["error"]


def test_summarize_honeylabs_none_for_skip_and_error():
    assert core.summarize_honeylabs({"skipped": "set HONEYLABS_API_KEY ..."}) is None
    assert core.summarize_honeylabs({"error": "HTTP 429"}) is None


def test_summarize_honeylabs_no_activity_line():
    line = core.summarize_honeylabs({"events": 0, "ports": None, "cves": None})
    assert line is not None
    assert "no honeypot activity" in line
    assert "quiet infrastructure" in line


def test_summarize_honeylabs_verdict_line():
    line = core.summarize_honeylabs({
        "events": 3872, "events_24h": 22,
        "first_seen": "2026-02-16T14:23:04", "last_seen": "2026-08-17T10:42:23",
        "verdict": "scanner", "verdict_label": "Recognized scanner",
        "verdict_detail": "shodan", "verdict_confidence": "high",
        "ports": [{"port": 8443, "count": 68}, {"port": 9443, "count": 59}],
        "cves": [],
    })
    assert line is not None
    assert "3872 honeypot events" in line
    assert "22 in 24h" in line
    assert "seen 2026-02-16 to 2026-08-17" in line
    assert "top ports 8443,9443" in line
    assert "verdict: Recognized scanner (shodan, high)" in line
    # HoneyLabs' own verdict replaces our generic interpretation line
    assert "opportunistic scanner profile" not in line


def test_summarize_honeylabs_generic_line_without_verdict():
    line = core.summarize_honeylabs({
        "events": 500, "events_24h": 10,
        "ports": [{"port": 22, "count": 400}],
        "cves": ["CVE-2024-4577"],
    })
    assert line is not None
    assert "500 honeypot events" in line
    assert "top ports 22" in line
    assert "probing CVE-2024-4577" in line
    assert "opportunistic scanner profile" in line


# --- manual observable entry -------------------------------------------------

def test_add_observable_files_new_entry():
    core.create_cluster("Manual Observable Test")
    data = core.add_observable("Manual Observable Test", "ips", "31.59.58.9",
                                "VirusTotal pivot on signspace.cloud (resolution history)")
    ip = next(o for o in data["observables"]["ips"] if o["value"] == "31.59.58.9")
    assert ip["sources"] == ["VirusTotal pivot on signspace.cloud (resolution history)"]


def test_add_observable_dedupes_by_value_appends_source():
    core.create_cluster("Manual Observable Dedup Test")
    core.add_observable("Manual Observable Dedup Test", "domains", "evil.example", "source A")
    data = core.add_observable("Manual Observable Dedup Test", "domains", "evil.example", "source B")
    domain = next(o for o in data["observables"]["domains"] if o["value"] == "evil.example")
    assert domain["sources"] == ["source A", "source B"]
    assert len(data["observables"]["domains"]) == 1


def test_add_observable_bad_category_raises():
    core.create_cluster("Bad Category Test")
    with pytest.raises(ValueError):
        core.add_observable("Bad Category Test", "bogus", "value", "source")


# --- live enrichment at add-time --------------------------------------------

def test_add_observable_new_ip_captures_asn_hostnames_tags_live(monkeypatch):
    core.create_cluster("Live Enrich IP")
    monkeypatch.setattr(core.pivot, "ripestat_lookup",
                        lambda ip: {"asn": [64500], "as_holder": "EVIL-NET"})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 1, "domains": ["evil.example"],
                                             "results": []})
    monkeypatch.setenv("THREATFOX_API_KEY", "fake-tf-key")
    monkeypatch.setattr(core.pivot, "threatfox_lookup",
                        lambda value, api_key: {"matches": [{"malware": "AsyncRAT"}]})

    data = core.add_observable("Live Enrich IP", "ips", "185.10.10.10", "report: r.pdf")
    ip = next(o for o in data["observables"]["ips"] if o["value"] == "185.10.10.10")
    assert ip["asn"] == 64500
    assert ip["netname"] == "EVIL-NET"
    assert ip["ip_hostnames"] == ["evil.example"]
    assert "threatfox:malware:AsyncRAT" in ip["tags"]
    # Ports are no longer discovered automatically (nmap is on-demand).
    assert "ports" not in ip


def test_add_observable_new_domain_captures_cert_snapshot(monkeypatch):
    core.create_cluster("Live Enrich Domain")
    monkeypatch.setattr(core.vm_proxy, "tls_grab", lambda host, port=443: {
        "cert": {"sha256": "deadbeef", "issuer": "Let's Encrypt", "subject": "evil.example",
                 "sans": ["evil.example", "mail.evil.example"],
                 "not_before": "2026-01-01", "not_after": "2026-04-01", "protocol": "TLSv1.3"},
        "resolved_ip": "185.10.10.10", "error": None})

    data = core.add_observable("Live Enrich Domain", "domains", "evil.example", "report: r.pdf")
    domain = next(o for o in data["observables"]["domains"] if o["value"] == "evil.example")
    assert domain["cert"]["issuer"] == "Let's Encrypt"
    assert domain["cert"]["sha256"] == "deadbeef"
    assert domain["cert"]["sans"] == ["evil.example", "mail.evil.example"]
    assert domain["cert"]["source"] == "tls_live"
    # The cert sha256 is auto-filed onto the cluster's hashes bucket.
    assert any(h["value"] == "cert-sha256:deadbeef" for h in data["observables"]["hashes"])


def test_add_observable_existing_value_does_not_re_enrich(monkeypatch):
    core.create_cluster("No Re-enrich")
    core.add_observable("No Re-enrich", "ips", "185.10.10.10", "first source")

    calls = []
    monkeypatch.setattr(core.pivot, "ripestat_lookup",
                        lambda ip: calls.append(ip) or {"asn": [1]})
    data = core.add_observable("No Re-enrich", "ips", "185.10.10.10", "second source")
    assert calls == []  # already tracked - not re-swept at add-time
    ip = next(o for o in data["observables"]["ips"] if o["value"] == "185.10.10.10")
    assert ip["sources"] == ["first source", "second source"]


def test_ingest_report_enriches_only_newly_extracted_indicators(tmp_path, monkeypatch):
    core.create_cluster("Selective Enrich")
    core.add_observable("Selective Enrich", "ips", "206.238.115.58", "seed")

    calls = []
    monkeypatch.setattr(core.pivot, "ripestat_lookup",
                        lambda ip: calls.append(ip) or {"asn": []})
    report = tmp_path / "report.txt"
    report.write_text(
        "Actor infra at 206.238.115.58 (already known) and 154.211.86.110 (new), "
        "T1059.001."
    )
    core.ingest_report(str(report), cluster_name="Selective Enrich", create_if_missing=False)
    assert calls == ["154.211.86.110"]  # only the genuinely new IP was swept


def test_ingest_report_network_phase_does_not_hold_data_lock(tmp_path, monkeypatch):
    """Regression for the locking hazard _sweep_lifecycle exists to avoid:
    add_observable/ingest_report/pivot_and_expand's live enrichment lookups
    must run outside _data_lock, or every other MCP tool call would block
    behind a batch of network round-trips for the duration (see
    _sweep_lifecycle's docstring). Verified by attempting a second,
    independent non-blocking flock on the real lock file while
    ingest_report's network phase is running - it must succeed."""
    import fcntl
    core.create_cluster("Lock Test")  # creates _registry/ so the lock file exists
    lock_path = core.DATA_DIR / "_registry" / ".lock"

    real_sweep = core._sweep_lifecycle
    contended = []

    def probing_sweep(domains, ips):
        f = open(lock_path, "w")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            contended.append(True)  # lock was free while the network phase ran
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            contended.append(False)  # lock was held - the hazard this test guards against
        finally:
            f.close()
        return real_sweep(domains, ips)

    monkeypatch.setattr(core, "_sweep_lifecycle", probing_sweep)
    report = tmp_path / "report.txt"
    report.write_text("New actor infra at c2-lock-test.xyz. T1059.001.")
    core.ingest_report(str(report), cluster_name="Lock Test", create_if_missing=False)

    assert contended == [True]


def test_pivot_and_expand_new_sibling_captures_enrichment_snapshot(monkeypatch):
    # subfinder surfaces the sibling to file; the enrichment sweep on the
    # newly-filed sibling then snapshots its own live cert via tls_grab.
    # Stubbed BEFORE seeding via add_observable, same reason as the tests
    # above - that call's own enrichment sweep for "evil.example" would
    # otherwise cache the autouse fixture's empty default first.
    monkeypatch.setattr(core.vm_proxy, "subfinder",
                        lambda domain: {"subdomains": ["mail.evil.example"], "error": None})
    monkeypatch.setattr(core.vm_proxy, "tls_grab", lambda host, port=443: {
        "cert": {"sha256": "sib1", "issuer": "ZeroSSL", "subject": host, "sans": [host],
                 "not_before": None, "not_after": None, "protocol": "TLSv1.3"},
        "resolved_ip": "1.2.3.4", "error": None})
    core.create_cluster("Expand Enrich")
    core.add_observable("Expand Enrich", "domains", "evil.example", "seed")

    result = core.pivot_and_expand("evil.example", "Expand Enrich")
    assert result["filed"]["domains"] == ["mail.evil.example"]
    data = core.get_cluster("Expand Enrich")
    sibling = next(o for o in data["observables"]["domains"] if o["value"] == "mail.evil.example")
    assert sibling["cert"]["issuer"] == "ZeroSSL"


def test_pivot_cluster_persists_cert_snapshot_onto_observable(stub_cluster_sweep_net):
    # Stub BEFORE seeding via add_observable, same reason as
    # test_pivot_cluster_logs_tls_history above: add_observable's own
    # enrichment sweep would otherwise cache the fixture's empty defaults
    # under these values before pivot_cluster gets to run.
    stub_cluster_sweep_net.setattr(core.vm_proxy, "tls_grab", lambda host, port=443: {
        "cert": {"sha256": "cafe", "issuer": "Let's Encrypt", "subject": host, "sans": [host],
                 "not_before": None, "not_after": None, "protocol": "TLSv1.3"},
        "resolved_ip": "1.2.3.4", "error": None})
    core.create_cluster("Persist Sweep")
    core.add_observable("Persist Sweep", "ips", "185.10.10.10", "r")
    core.add_observable("Persist Sweep", "domains", "evil-cert.example", "r")

    core.pivot_cluster("Persist Sweep")

    # persisted onto the observable itself, not just the transient summary
    data = core.get_cluster("Persist Sweep")
    domain = next(o for o in data["observables"]["domains"] if o["value"] == "evil-cert.example")
    assert domain["cert"]["issuer"] == "Let's Encrypt"
    assert domain["cert"]["sha256"] == "cafe"


def test_remove_observable_drops_entry():
    core.create_cluster("Prune Test")
    core.add_observable("Prune Test", "domains", "keep.example", "r")
    core.add_observable("Prune Test", "domains", "noise.example", "r")
    result = core.remove_observable("Prune Test", "domains", "noise.example")
    assert result["removed"] == ["noise.example"]
    domains = {o["value"] for o in core.get_cluster("Prune Test")["observables"]["domains"]}
    assert domains == {"keep.example"}


def test_remove_observable_case_insensitive_removes_all_variants():
    core.create_cluster("Prune Case")
    core.add_observable("Prune Case", "domains", "UKR.NET", "r")
    core.add_observable("Prune Case", "domains", "ukr.net", "r")
    result = core.remove_observable("Prune Case", "domains", "ukr.net")
    assert set(result["removed"]) == {"UKR.NET", "ukr.net"}
    assert core.get_cluster("Prune Case")["observables"]["domains"] == []


def test_remove_observable_hash_bare_or_prefixed():
    core.create_cluster("Prune Hash")
    core.add_observable("Prune Hash", "hashes", "md5:098f6bcd4621d373cade4e832627b4f6", "r")
    core.remove_observable("Prune Hash", "hashes", "098f6bcd4621d373cade4e832627b4f6")  # bare
    assert core.get_cluster("Prune Hash")["observables"]["hashes"] == []


def test_remove_observable_not_found_raises():
    core.create_cluster("Prune Miss")
    with pytest.raises(ValueError):
        core.remove_observable("Prune Miss", "ips", "1.2.3.4")


def test_remove_observable_bad_category_raises():
    core.create_cluster("Prune Bad Cat")
    with pytest.raises(ValueError):
        core.remove_observable("Prune Bad Cat", "bogus", "x")


def test_add_observable_new_categories():
    core.create_cluster("New Cats")
    core.add_observable("New Cats", "emails", "ops@evil.example", "src")
    core.add_observable("New Cats", "cves", "CVE-2024-1234", "src")
    data = core.add_observable("New Cats", "wallets", "0x52908400098527886E0F7030069857D2E4169EE7", "src")
    assert any(o["value"] == "ops@evil.example" for o in data["observables"]["emails"])
    assert any(o["value"] == "CVE-2024-1234" for o in data["observables"]["cves"])
    assert data["observables"]["wallets"][0]["value"].startswith("0x")


def test_add_observable_ja4_and_jarm_categories():
    core.create_cluster("Fingerprint Cats")
    data = core.add_observable("Fingerprint Cats", "ja4",
                                "t13d1516h2_8daaf6152771_02713d6af862", "JA4 via isolated VM")
    data = core.add_observable("Fingerprint Cats", "jarm",
                                "2ad2ad0002ad2ad00002ad2ad2ad00c25be1de0dc4400e5cadb8c840f2ba9",
                                "JARM via isolated VM")
    assert data["observables"]["ja4"][0]["value"] == "t13d1516h2_8daaf6152771_02713d6af862"
    assert data["observables"]["jarm"][0]["sources"] == ["JARM via isolated VM"]


# --- pending fingerprint queue -----------------------------------------------

def test_new_domain_or_ip_is_queued_for_fingerprinting():
    core.create_cluster("Queue Test")
    core.add_observable("Queue Test", "domains", "evil.example", "report X")
    core.add_observable("Queue Test", "ips", "185.220.101.47", "report X")
    core.add_observable("Queue Test", "hashes", "md5:098f6bcd4621d373cade4e832627b4f6", "report X")
    pending = core.list_pending_fingerprints()
    queued = {(e["cluster"], e["category"], e["value"]) for e in pending}
    assert ("Queue Test", "domains", "evil.example") in queued
    assert ("Queue Test", "ips", "185.220.101.47") in queued
    assert not any(e["category"] == "hashes" for e in pending)


def test_already_tracked_value_is_not_requeued():
    core.create_cluster("Requeue Test")
    core.add_observable("Requeue Test", "domains", "evil.example", "report X")
    core.pop_pending_fingerprints()
    core.add_observable("Requeue Test", "domains", "evil.example", "report Y")
    assert core.list_pending_fingerprints() == []


def test_pop_pending_fingerprints_clears_the_queue():
    core.create_cluster("Pop Test")
    core.add_observable("Pop Test", "domains", "evil.example", "report X")
    popped = core.pop_pending_fingerprints()
    assert any(e["value"] == "evil.example" for e in popped)
    assert core.list_pending_fingerprints() == []
    assert core.pop_pending_fingerprints() == []


def test_pending_fingerprints_respect_isolated_data_dir(isolated_data_dir):
    """Regression test: the queue file must follow a monkeypatched
    DATA_DIR like cluster files do, not a path computed once at import
    time - otherwise tests (or any DATA_DIR override) would leak into
    the real data dir instead of the isolated one."""
    core.create_cluster("Isolation Test")
    core.add_observable("Isolation Test", "domains", "evil.example", "report X")
    assert (isolated_data_dir.parent / "pending_fingerprints.json").exists()


# --- fingerprint queue validation gate ---------------------------------------

def test_private_ip_is_tracked_but_not_queued():
    # pending_fingerprints.json lives one level above the (monkeypatched)
    # per-test DATA_DIR, which pytest's tmp_path makes a shared sibling
    # dir across tests in the same session - so assert this value isn't
    # queued, not that the whole (possibly session-shared) queue is empty.
    core.create_cluster("Gate Test IP")
    data = core.add_observable("Gate Test IP", "ips", "10.20.0.9", "report X")
    assert any(o["value"] == "10.20.0.9" for o in data["observables"]["ips"])
    assert not any(e["value"] == "10.20.0.9" for e in core.list_pending_fingerprints())
    assert data["fingerprint_queue_skipped"] == [
        {"category": "ips", "value": "10.20.0.9",
         "reason": "private/reserved/loopback/link-local address, not routable adversary infra"}
    ]


def test_public_dns_resolver_is_tracked_but_not_queued():
    core.create_cluster("Gate Test Resolver")
    data = core.add_observable("Gate Test Resolver", "ips", "8.8.8.8", "report X")
    assert any(o["value"] == "8.8.8.8" for o in data["observables"]["ips"])
    assert not any(e["value"] == "8.8.8.8" for e in core.list_pending_fingerprints())
    assert data["fingerprint_queue_skipped"][0]["reason"] == "known non-actor infrastructure (public DNS resolver)"


def test_known_non_actor_domain_is_tracked_but_not_queued():
    core.create_cluster("Gate Test Domain")
    data = core.add_observable("Gate Test Domain", "domains", "microsoft.com", "report X")
    assert any(o["value"] == "microsoft.com" for o in data["observables"]["domains"])
    assert not any(e["value"] == "microsoft.com" for e in core.list_pending_fingerprints())
    assert data["fingerprint_queue_skipped"][0]["reason"] == \
        "known non-actor infrastructure (major vendor/CDN/sinkhole domain)"


def test_subdomain_of_known_non_actor_domain_is_not_skipped():
    """Deliberately exact-match only: a subdomain of hosting-platform-style
    apex domains (github.io, amazonaws.com, ...) is routine attacker-
    controlled shared hosting, not a false positive, so only the bare
    apex is gated - a subdomain must still queue normally."""
    core.create_cluster("Gate Test Subdomain")
    data = core.add_observable("Gate Test Subdomain", "domains", "evil.github.com", "report X")
    assert any(e["value"] == "evil.github.com" for e in core.list_pending_fingerprints())
    assert "fingerprint_queue_skipped" not in data


def test_ipv6_ip_is_tracked_but_not_queued():
    """Functional rule: ignore IPv6 for pivoting and probing - the probe
    VM has no IPv6 route, so an IPv6 literal in the queue would only ever
    time out."""
    core.create_cluster("Gate Test IPv6")
    data = core.add_observable("Gate Test IPv6", "ips", "2a10:1fc0:6::de96:9634", "report X")
    assert any(o["value"] == "2a10:1fc0:6::de96:9634" for o in data["observables"]["ips"])
    assert not any(e["value"] == "2a10:1fc0:6::de96:9634" for e in core.list_pending_fingerprints())
    assert data["fingerprint_queue_skipped"][0]["reason"] == \
        "IPv6 - the probe VM has no IPv6 route, active fingerprinting would only ever time out"


def test_ordinary_domain_and_ip_are_unaffected_by_the_gate():
    core.create_cluster("Gate Test Normal")
    data = core.add_observable("Gate Test Normal", "domains", "evil.example", "report X")
    data = core.add_observable("Gate Test Normal", "ips", "185.220.101.47", "report X")
    assert "fingerprint_queue_skipped" not in data
    queued = {(e["category"], e["value"]) for e in core.list_pending_fingerprints()}
    assert ("domains", "evil.example") in queued
    assert ("ips", "185.220.101.47") in queued


def test_ingest_report_records_skipped_entries_in_report_sources(tmp_path):
    core.create_cluster("Gate Test Ingest")
    report = tmp_path / "report.txt"
    report.write_text("Fancy Bear infrastructure includes evil.example and "
                       "microsoft.com (mentioned only in passing).")
    data = core.ingest_report(str(report), cluster_name="Gate Test Ingest")
    skipped = data["report_sources"][-1]["fingerprint_queue_skipped"]
    assert any(s["value"] == "microsoft.com" for s in skipped)
    queued = {e["value"] for e in core.list_pending_fingerprints()}
    assert "evil.example" in queued
    assert "microsoft.com" not in queued


# --- observables in STIX export/import --------------------------------------

def test_stix_export_emits_indicators_for_observables():
    core.create_cluster("IOC Export")
    core.add_observable("IOC Export", "domains", "evil.example", "report X")
    core.add_observable("IOC Export", "ips", "185.220.101.47", "report X")
    core.add_observable("IOC Export", "hashes", "md5:098f6bcd4621d373cade4e832627b4f6", "report X")
    core.add_observable("IOC Export", "emails", "admin@evil.example", "report X")

    bundle = core.export_stix_bundle("IOC Export")
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 4
    iset_id = next(o["id"] for o in bundle["objects"] if o["type"] == "intrusion-set")
    indicates = [o for o in bundle["objects"]
                 if o.get("relationship_type") == "indicates"]
    assert len(indicates) == 4
    assert all(r["target_ref"] == iset_id for r in indicates)
    patterns = {i["pattern"] for i in indicators}
    assert "[domain-name:value = 'evil.example']" in patterns
    assert "[file:hashes.'MD5' = '098f6bcd4621d373cade4e832627b4f6']" in patterns


def test_stix_observable_roundtrip():
    core.create_cluster("IOC Round")
    core.add_observable("IOC Round", "domains", "evil.example", "report X")
    core.add_observable("IOC Round", "ips", "185.220.101.47", "report X")
    core.add_observable("IOC Round", "hashes", "md5:098f6bcd4621d373cade4e832627b4f6", "report X")
    core.add_observable("IOC Round", "emails", "admin@evil.example", "report X")

    bundle = core.export_stix_bundle("IOC Round")
    imported = core.import_stix_bundle(bundle, name="IOC Round Import")
    obs = imported["observables"]
    assert any(o["value"] == "evil.example" for o in obs["domains"])
    assert any(o["value"] == "185.220.101.47" for o in obs["ips"])
    assert any(o["value"] == "md5:098f6bcd4621d373cade4e832627b4f6" for o in obs["hashes"])
    assert any(o["value"] == "admin@evil.example" for o in obs["emails"])


def test_stix_export_skips_non_scoable_observables():
    core.create_cluster("NonSCO")
    core.add_observable("NonSCO", "cves", "CVE-2024-1234", "r")
    core.add_observable("NonSCO", "wallets", "0x52908400098527886E0F7030069857D2E4169EE7", "r")
    bundle = core.export_stix_bundle("NonSCO")
    # CVEs/wallets have no clean STIX SCO pattern, so no indicators are emitted.
    assert not any(o["type"] == "indicator" for o in bundle["objects"])


def test_stix_shared_indicator_id_dedupes_across_clusters():
    core.create_cluster("Shared IOC A")
    core.create_cluster("Shared IOC B")
    core.add_observable("Shared IOC A", "domains", "shared.example", "r")
    core.add_observable("Shared IOC B", "domains", "shared.example", "r")
    core.add_relationship("Shared IOC A", "related-to", "Shared IOC B")
    bundle = core.export_stix_ecosystem("Shared IOC A")
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1  # same pattern -> same id -> one object


# --- reverse index -----------------------------------------------------------

def test_find_observable_email_via_index():
    core.create_cluster("Email Idx")
    core.add_observable("Email Idx", "emails", "ops@evil.example", "r")
    res = core.find_observable("ops@evil.example")
    assert res["matches"][0]["cluster"] == "Email Idx"
    assert res["matches"][0]["category"] == "emails"


def test_reverse_index_reflects_new_writes():
    core.create_cluster("Idx Fresh")
    core.add_observable("Idx Fresh", "domains", "one.example", "r")
    assert core.find_observable("one.example")["matches"]  # builds + caches the index
    core.add_observable("Idx Fresh", "domains", "two.example", "r")  # bumps fingerprint
    # a stale cache would miss this; the index must rebuild and see it
    assert core.find_observable("two.example")["matches"]


def test_reverse_index_technique_usage_after_detection():
    core.create_cluster("Idx Tech")
    core.update_ttp("Idx Tech", "T1003", "OS Credential Dumping", 1)
    core.get_technique_usage("T1003")  # cache the index
    core.add_detection("DET-IDX", "LSASS monitoring", ["T1003"])  # bumps registry mtime
    usage = core.get_technique_usage("T1003")
    assert any(d["id"] == "DET-IDX" for d in usage["detections"])


# --- atomic writes -----------------------------------------------------------

def test_no_leftover_temp_files(isolated_data_dir):
    core.create_cluster("Atomic Test")
    core.update_ttp("Atomic Test", "T1059", "Command and Scripting Interpreter", 1)
    leftover = list(isolated_data_dir.rglob("*.tmp"))
    assert leftover == []


# --- pivot caching -----------------------------------------------------------

def test_pivot_cache_avoids_refetch(stub_pivot_net):
    stub_pivot_net.delenv("VT_API_KEY", raising=False)
    stub_pivot_net.delenv("CTI_PIVOT_CACHE_TTL", raising=False)
    calls = {"n": 0}

    def fake_rdap(value, kind):
        calls["n"] += 1
        return {"handle": "H"}

    stub_pivot_net.setattr(core.pivot, "rdap_lookup", fake_rdap)
    core.pivot_observable("example.com")
    core.pivot_observable("example.com")
    assert calls["n"] == 1  # second lookup served from cache


def test_pivot_cache_disabled_with_ttl_zero(stub_pivot_net):
    stub_pivot_net.delenv("VT_API_KEY", raising=False)
    stub_pivot_net.setenv("CTI_PIVOT_CACHE_TTL", "0")
    calls = {"n": 0}

    def fake_rdap(value, kind):
        calls["n"] += 1
        return {"handle": "H"}

    stub_pivot_net.setattr(core.pivot, "rdap_lookup", fake_rdap)
    core.pivot_observable("example.com")
    core.pivot_observable("example.com")
    assert calls["n"] == 2  # caching off -> refetched


def test_pivot_cache_does_not_cache_errors(stub_pivot_net):
    stub_pivot_net.delenv("VT_API_KEY", raising=False)
    stub_pivot_net.delenv("CTI_PIVOT_CACHE_TTL", raising=False)
    calls = {"n": 0}

    def fake_rdap(value, kind):
        calls["n"] += 1
        return {"error": "rdap down"}

    stub_pivot_net.setattr(core.pivot, "rdap_lookup", fake_rdap)
    core.pivot_observable("example.com")
    core.pivot_observable("example.com")
    assert calls["n"] == 2  # soft errors aren't cached, so they're retried


# --- lifecycle classification (pure) ----------------------------------------

def test_classify_domain_lifecycle_sinkholed():
    rdap = {"nameservers": ["ns1.microsoftinternetsafety.net"], "status": ["active"]}
    assert core.pivot.classify_domain_lifecycle(rdap, ["10.0.0.1"]) == "sinkholed"


def test_classify_domain_lifecycle_expired_by_status():
    rdap = {"nameservers": [], "status": ["client hold", "pending delete"]}
    assert core.pivot.classify_domain_lifecycle(rdap, None) == "expired"


def test_classify_domain_lifecycle_expired_by_event():
    rdap = {"nameservers": [], "status": [],
            "events": [{"action": "expiration", "date": "2000-01-01T00:00:00Z"}]}
    assert core.pivot.classify_domain_lifecycle(rdap, None) == "expired"


def test_classify_domain_lifecycle_active_and_dead():
    rdap = {"nameservers": ["ns1.legit.example"], "status": ["active"]}
    assert core.pivot.classify_domain_lifecycle(rdap, ["185.10.10.10"]) == "active"
    assert core.pivot.classify_domain_lifecycle(rdap, []) == "dead"
    assert core.pivot.classify_domain_lifecycle(rdap, None) == "unknown"


def test_classify_domain_lifecycle_degrades_when_rdap_errors():
    # RDAP timed out/failed (dict carries only an "error"), but the name
    # still resolves -> classify from resolution instead of "unknown".
    assert core.pivot.classify_domain_lifecycle({"error": "timed out"}, ["1.2.3.4"]) == "active"
    assert core.pivot.classify_domain_lifecycle({"error": "timed out"}, []) == "dead"
    assert core.pivot.classify_domain_lifecycle({"error": "timed out"}, None) == "unknown"


def test_classify_ip_lifecycle():
    assert core.pivot.classify_ip_lifecycle({"prefix": "185.10.0.0/16", "asn": [64500]}) == "routed"
    assert core.pivot.classify_ip_lifecycle({"prefix": None}) == "unrouted"
    assert core.pivot.classify_ip_lifecycle({"network_info_error": "boom"}) == "unknown"
    assert core.pivot.classify_ip_lifecycle(None) == "unknown"


# --- pivot_cluster sweep -----------------------------------------------------

@pytest.fixture
def stub_cluster_sweep_net(monkeypatch):
    """Stub every network source pivot_cluster's sweep now touches
    (lifecycle sources plus the Shodan/Cert Spotter/PTR enrichment added
    alongside them), so sweep tests are hermetic. THREATFOX_API_KEY/
    VT_API_KEY are left unset by default - tests that want ThreatFox/
    VirusTotal set the key and stub the relevant pivot.* function
    themselves. Note: resolve_host's stub ([] - NXDOMAIN/dead) now also
    drives the automatic resolved_ip/dns_resolve write path for every
    domain swept through this fixture, in addition to lifecycle
    classification - no existing test in this file asserts a total
    observation-row count without filtering by source, so this is
    hermetic-safe."""
    monkeypatch.setattr(core.pivot, "rdap_lookup",
                        lambda value, kind: {"nameservers": [], "status": [], "events": []})
    monkeypatch.setattr(core.pivot, "resolve_host", lambda host: [])  # NXDOMAIN -> dead
    monkeypatch.setattr(core.pivot, "ripestat_lookup",
                        lambda ip: {"prefix": "185.10.0.0/16", "asn": [64500]})
    monkeypatch.setattr(core.pivot, "ptr_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr(core.vm_proxy, "tls_grab",
                        lambda host, port=443: {"cert": None, "resolved_ip": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "http_probe",
                        lambda url, insecure=False: {"status": None, "final_url": url, "title": None,
                                                     "server": None, "content_type": None,
                                                     "body_sha256": None, "autoindex": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "subfinder", lambda domain: {"subdomains": [], "error": None})
    monkeypatch.setattr(core.vm_proxy, "wayback_cdx",
                        lambda domain: {"urls": [], "subdomains": [], "error": None})
    monkeypatch.setattr(core.webamon, "search_domain",
                        lambda domain, size=5: {"total_hits": 0, "results": [], "latest": None})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 0, "domains": [], "results": []})
    monkeypatch.setattr(core.webamon, "infostealers",
                        lambda term, size=25: {"total_hits": 0, "results": []})
    monkeypatch.delenv("THREATFOX_API_KEY", raising=False)
    return monkeypatch


def test_pivot_cluster_stamps_lifecycle_status(stub_cluster_sweep_net):
    core.create_cluster("Sweep")
    core.add_observable("Sweep", "domains", "dead-c2.example", "r")
    core.add_observable("Sweep", "ips", "185.10.10.10", "r")

    summary = core.pivot_cluster("Sweep")
    assert summary["domains"][0]["status"] == "dead"
    assert summary["ips"][0]["status"] == "routed"

    # status is persisted onto the observable, not just returned
    data = core.get_cluster("Sweep")
    dom = next(o for o in data["observables"]["domains"] if o["value"] == "dead-c2.example")
    assert dom["status"] == "dead"
    assert dom["status_checked"]


def test_pivot_cluster_logs_tls_history(stub_cluster_sweep_net):
    # Stub the real return value BEFORE seeding via add_observable: that
    # call now also runs a live lifecycle sweep for the new domain (see
    # _sweep_lifecycle) and caches its tls result (_cached_pivot) -
    # overriding the stub afterward would just be shadowed by the cache.
    stub_cluster_sweep_net.setattr(core.vm_proxy, "tls_grab", lambda host, port=443: {
        "cert": {"sha256": "beef", "issuer": "R3", "subject": host, "sans": [host],
                 "not_before": "2026-01-01", "not_after": "2026-04-01", "protocol": "TLSv1.3"},
        "resolved_ip": "1.2.3.4", "error": None})
    core.create_cluster("TLS Sweep")
    core.add_observable("TLS Sweep", "domains", "evil-tls.example", "r")

    summary = core.pivot_cluster("TLS Sweep")
    assert summary["domains"][0]["cert_sha256"] == "beef"
    assert "history_note" not in summary

    from cti_tools.tracking import store as tracking_store
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            """SELECT tls_sha256, tls_issuer FROM observations
               WHERE indicator_value = ? AND source = 'tls_live'""",
            ["evil-tls.example"]).fetchone()
    assert row == ("beef", "R3")


def test_pivot_cluster_logs_ptr_history(stub_cluster_sweep_net):
    stub_cluster_sweep_net.setattr(
        core.pivot, "ptr_lookup", lambda ip: {"hostname": "host.example"})
    core.create_cluster("PTR Sweep")
    core.add_observable("PTR Sweep", "ips", "185.10.10.10", "r")

    core.pivot_cluster("PTR Sweep")

    # observable_history()'s SELECT list doesn't carry ptr_hostname (same
    # pre-existing gap as cert_issuer/discovered_hostnames) - query the
    # tracking DB directly instead.
    from cti_tools.tracking import store as tracking_store
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            """SELECT ptr_hostname FROM observations
               WHERE indicator_value = ? AND source = 'ptr'""",
            ["185.10.10.10"]).fetchone()
    assert row[0] == "host.example"


def test_pivot_cluster_logs_resolved_ip_history(stub_cluster_sweep_net):
    stub_cluster_sweep_net.setattr(
        core.pivot, "resolve_host", lambda host: ["203.0.113.7"])
    core.create_cluster("Resolve Sweep")
    core.add_observable("Resolve Sweep", "domains", "c2.example", "r")

    core.pivot_cluster("Resolve Sweep")

    from cti_tools.tracking import store as tracking_store
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            """SELECT resolved_ip FROM observations
               WHERE indicator_value = ? AND source = 'dns_resolve'""",
            ["c2.example"]).fetchone()
    assert json.loads(row[0]) == ["203.0.113.7"]


def test_pivot_cluster_logs_threatfox_history_when_keyed(stub_cluster_sweep_net):
    core.create_cluster("TF Sweep")
    core.add_observable("TF Sweep", "ips", "185.10.10.10", "r")
    stub_cluster_sweep_net.setenv("THREATFOX_API_KEY", "fake-tf-key")
    stub_cluster_sweep_net.setattr(
        core.pivot, "threatfox_lookup",
        lambda value, api_key: {"matches": [{"malware": "Cobalt Strike"}]})

    summary = core.pivot_cluster("TF Sweep")
    assert summary["ips"][0]["threatfox_matches"] == 1

    from cti_tools.tracking import store as tracking_store
    history = tracking_store.observable_history("185.10.10.10")
    tf_rows = [o for o in history["observations"] if o["source"] == "threatfox"]
    assert len(tf_rows) == 1
    assert tf_rows[0]["threatfox_matches"] == [{"malware": "Cobalt Strike"}]


def test_pivot_cluster_skips_threatfox_history_without_key(stub_cluster_sweep_net):
    core.create_cluster("No TF Sweep")
    core.add_observable("No TF Sweep", "ips", "185.10.10.10", "r")

    summary = core.pivot_cluster("No TF Sweep")
    assert "threatfox_matches" not in summary["ips"][0]

    from cti_tools.tracking import store as tracking_store
    history = tracking_store.observable_history("185.10.10.10")
    assert not [o for o in history["observations"] if o["source"] == "threatfox"]


def test_pivot_cluster_survives_tracking_store_failure(stub_cluster_sweep_net, monkeypatch):
    core.create_cluster("Busy Sweep")
    core.add_observable("Busy Sweep", "ips", "185.10.10.10", "r")

    def boom(actor, observed_at, results):
        return "enrichment history not recorded: simulated failure"
    monkeypatch.setattr(core, "_log_cluster_enrichment_history", boom)

    summary = core.pivot_cluster("Busy Sweep")
    # the cluster-JSON write still succeeded despite the tracking-store note
    assert summary["ips"][0]["status"] == "routed"
    assert "history_note" in summary
    data = core.get_cluster("Busy Sweep")
    assert data["observables"]["ips"][0]["status"] == "routed"


# --- pivot_and_expand filing loop -------------------------------------------

def test_pivot_and_expand_files_subfinder_siblings(monkeypatch):
    # Stub subfinder BEFORE seeding via add_observable: that call now also
    # runs a live lifecycle sweep for the new domain (see _sweep_lifecycle)
    # and caches its subfinder result (_cached_pivot) - stubbing afterward
    # would just be shadowed by the cache.
    monkeypatch.setattr(core.vm_proxy, "subfinder", lambda domain: {
        "subdomains": ["mail.evil.example", "vpn.evil.example", "unrelated.other.example"],
        "error": None})
    core.create_cluster("Expand")
    core.add_observable("Expand", "domains", "evil.example", "seed report")

    result = core.pivot_and_expand("evil.example", "Expand")
    assert set(result["filed"]["domains"]) == {"mail.evil.example", "vpn.evil.example"}
    # the non-sibling hostname is surfaced for review, not filed
    assert "unrelated.other.example" in result["review"]["other_hostnames"]

    data = core.get_cluster("Expand")
    domains = {o["value"] for o in data["observables"]["domains"]}
    assert {"mail.evil.example", "vpn.evil.example"} <= domains
    # a hunt-log entry documents the expansion
    assert any("pivot_and_expand on evil.example" in h["entry"] for h in data["hunt_log"])


def test_pivot_and_expand_surfaces_webamon_fingerprint_siblings(monkeypatch):
    monkeypatch.setattr(core.vm_proxy, "subfinder",
                        lambda domain: {"subdomains": [], "error": None})
    monkeypatch.setattr(core.webamon, "search_domain", lambda domain, size=5: {
        "total_hits": 1, "results": [],
        "latest": {"report_id": "r", "fingerprint": {"dom": "kithash", "ssl": None}}})
    monkeypatch.setattr(core.webamon, "fingerprint_siblings",
                        lambda h, kind="dom", size=25: {"total_hits": 2,
                                                        "domains": ["kit-a.example", "kit-b.example"]})
    core.create_cluster("Expand FP")
    core.add_observable("Expand FP", "domains", "evil.example", "seed")

    result = core.pivot_and_expand("evil.example", "Expand FP")
    # kit siblings are surfaced for review, never auto-filed
    assert result["review"]["webamon_fingerprint_siblings"]["dom"] == \
        ["kit-a.example", "kit-b.example"]
    assert "domains" not in result.get("filed", {})


def test_pivot_and_expand_only_files_new_indicators(monkeypatch):
    # Stub subfinder BEFORE seeding, same reason as the test above.
    monkeypatch.setattr(core.vm_proxy, "subfinder", lambda domain: {
        "subdomains": ["mail.evil.example", "new.evil.example"], "error": None})
    core.create_cluster("Expand Dedup")
    core.add_observable("Expand Dedup", "domains", "evil.example", "seed")
    core.add_observable("Expand Dedup", "domains", "mail.evil.example", "already tracked")

    result = core.pivot_and_expand("evil.example", "Expand Dedup")
    assert result["filed"]["domains"] == ["new.evil.example"]  # mail.* already tracked, not refiled


def test_pivot_and_expand_cohosted_gated(monkeypatch):
    # Stub webamon.search_ip + ripestat BEFORE seeding (cache convention).
    monkeypatch.setattr(core.webamon, "search_ip", lambda ip, size=50: {
        "total_hits": 2, "domains": ["shared-a.example", "shared-b.example"], "results": []})
    monkeypatch.setattr(core.pivot, "ripestat_lookup", lambda ip: {"asn": [64500]})  # not shared
    core.create_cluster("Expand IP")
    core.add_observable("Expand IP", "ips", "185.10.10.10", "seed")

    # default: co-hosted domains are surfaced for review, not filed
    result = core.pivot_and_expand("185.10.10.10", "Expand IP")
    assert result["filed"] == {}
    assert set(result["review"]["cohosted_domains"]) == {"shared-a.example", "shared-b.example"}

    # opt-in: they get filed
    result = core.pivot_and_expand("185.10.10.10", "Expand IP", include_cohosted=True)
    assert set(result["filed"]["domains"]) == {"shared-a.example", "shared-b.example"}


def test_pivot_and_expand_suppresses_cohosted_domains_for_shared_hosting_ip(monkeypatch):
    # An IP in a known shared-hosting ASN is multi-tenant - the domains
    # Webamon reports on it are every OTHER tenant, not this actor's infra.
    # include_cohosted=True must NOT file them, and `review` should explain
    # what was suppressed rather than dumping the raw noisy list.
    shared_asn = sorted(core.SHARED_HOSTING_ASNS)[0]
    monkeypatch.setattr(core.webamon, "search_ip", lambda ip, size=50: {
        "total_hits": 2, "domains": ["unrelated-tenant-1.example", "unrelated-tenant-2.example"],
        "results": []})
    monkeypatch.setattr(core.pivot, "ripestat_lookup", lambda ip: {"asn": [shared_asn]})
    core.create_cluster("Expand Shared Hosting")
    core.add_observable("Expand Shared Hosting", "ips", "185.10.10.10", "seed")

    result = core.pivot_and_expand("185.10.10.10", "Expand Shared Hosting",
                                   include_cohosted=True)
    assert result["filed"] == {}
    assert "cohosted_domains" not in result["review"]
    assert str(shared_asn) in result["review"]["cohosted_domains_suppressed"]


def test_pivot_and_expand_rejects_hash(monkeypatch):
    core.create_cluster("Expand Hash")
    with pytest.raises(ValueError):
        core.pivot_and_expand("098f6bcd4621d373cade4e832627b4f6", "Expand Hash")


def test_pivot_and_expand_skips_ipv6_target():
    """Pivoting directly on an IPv6 IP is a no-op - no VT/reverse-IP
    lookup is even attempted, since nothing downstream can use IPv6."""
    core.create_cluster("Expand IPv6 Target")
    core.add_observable("Expand IPv6 Target", "ips", "2a10:1fc0:6::de96:9634", "seed")

    result = core.pivot_and_expand("2a10:1fc0:6::de96:9634", "Expand IPv6 Target")
    assert result["filed"] == {}
    data = core.get_cluster("Expand IPv6 Target")
    assert any("skipped (IPv6" in h["entry"] for h in data["hunt_log"])


def test_requeue_fingerprint_rejects_ipv6():
    core.create_cluster("Requeue IPv6")
    core.add_observable("Requeue IPv6", "ips", "2a10:1fc0:6::de96:9634", "seed")
    with pytest.raises(ValueError):
        core.requeue_fingerprint("Requeue IPv6", "ips", "2a10:1fc0:6::de96:9634")
