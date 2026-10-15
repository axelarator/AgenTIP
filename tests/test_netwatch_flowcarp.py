"""Phase 4: FlowCarp protocol labels over Arkime pcap."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from cti import store
from cti.netwatch import flowcarp
from cti.sources import budget

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# Eve JSON parsing
# --------------------------------------------------------------------------- #

def test_parse_eve_picks_protocol_and_alerts_and_counts_flows():
    eve = "\n".join([
        json.dumps({"event_type": "flow", "app_proto": "Gh0st RAT"}),
        json.dumps({"event_type": "alert",
                    "alert": {"signature": "FlowCarp Gh0st RAT"}}),
        json.dumps({"event_type": "flow", "app_proto": None}),
    ])
    out = flowcarp.parse_eve(eve)
    assert out["app_proto"] == "Gh0st RAT"
    assert out["c2_hits"] == ["FlowCarp Gh0st RAT"]
    assert out["flows"] == 2          # both flow events, label or not


def test_parse_eve_ignores_null_and_failed_labels_and_bad_lines():
    eve = "\n".join([
        "not json",
        json.dumps({"event_type": "flow", "app_proto": "failed"}),
        json.dumps({"event_type": "flow", "app_proto": None}),
    ])
    out = flowcarp.parse_eve(eve)
    assert out["app_proto"] is None
    assert out["c2_hits"] == []
    assert out["flows"] == 2


def test_expression_requires_payload_packets():
    expr = flowcarp.expression_for("10.0.0.1", "203.0.113.9", 8443)
    assert "ip.src == 10.0.0.1" in expr
    assert "ip.dst == 203.0.113.9" in expr
    assert "port.dst == 8443" in expr
    assert "packets.dst > 3" in expr


def test_build_model_command_quotes_name_and_tags():
    cmd = flowcarp.build_model_command(
        "Example RAT", "MALICIOUS", "directory:Once:/caps/", "ex.fcp")
    assert cmd[0] == flowcarp.FLOWCARP_BIN
    assert '--input' in cmd and 'directory:Once:/caps/' in cmd
    assert any(a == 'model:"Example RAT":MALICIOUS:ex.fcp' for a in cmd)


# --------------------------------------------------------------------------- #
# candidate selection
# --------------------------------------------------------------------------- #

def _snapshot(con, *, scan_id, target, port, scanned_at=NOW, open=True,
              app_proto=None, cert=None, status=None, c2_hits=None, ip=None):
    store.upsert_service_snapshot(con, row={
        "scan_id": scan_id, "scanned_at": scanned_at, "vantage": "probe",
        "profile": "full", "target": target, "ip": ip or target, "port": port,
        "open": open, "actor": "APT-W", "app_proto": app_proto,
        "cert_sha256": cert, "http_status": status, "c2_hits": c2_hits,
        "record": {}})


def test_candidates_only_unnamed_open_services():
    with store.connect() as con:
        _snapshot(con, scan_id="s1", target="203.0.113.1", port=4444)   # bare
        _snapshot(con, scan_id="s1", target="203.0.113.2", port=443, cert="c")
        _snapshot(con, scan_id="s1", target="203.0.113.3", port=80, status=200)
        _snapshot(con, scan_id="s1", target="203.0.113.4", port=9001,
                  app_proto="DNS")
        _snapshot(con, scan_id="s1", target="203.0.113.5", port=0)      # dark
        _snapshot(con, scan_id="s1", target="203.0.113.6", port=4444, open=False)
    with store.connect(read_only=True) as con:
        out = flowcarp.candidates(con, scan_ids=["s1"])
    assert [(c["target"], c["port"]) for c in out] == [("203.0.113.1", 4444)]


def test_candidates_standalone_takes_only_latest_scan():
    old = NOW - timedelta(days=2)
    with store.connect() as con:
        _snapshot(con, scan_id="old", target="203.0.113.1", port=4444,
                  scanned_at=old)
        _snapshot(con, scan_id="new", target="203.0.113.1", port=4444,
                  scanned_at=NOW)
    with store.connect(read_only=True) as con:
        out = flowcarp.candidates(con)       # no scan_ids -> latest only
    assert [c["scan_id"] for c in out] == ["new"]


# --------------------------------------------------------------------------- #
# the batch pass, with Arkime + binary injected
# --------------------------------------------------------------------------- #

def test_label_services_writes_proto_merges_hits_and_diffs(monkeypatch):
    monkeypatch.setenv("CTI_PROBE_ZEEK_IP", "10.0.0.9")
    monkeypatch.setattr(flowcarp, "_VANTAGE_IP", {"probe": "10.0.0.9"})
    budget.reset("flowcarp")
    # a prior scan already saw njRAT here; the new scan is unnamed but keeps
    # a nuclei template hit, which FlowCarp must not clobber.
    with store.connect() as con:
        _snapshot(con, scan_id="old", target="203.0.113.1", port=4444,
                  scanned_at=NOW - timedelta(days=1), app_proto="njRAT")
        _snapshot(con, scan_id="new", target="203.0.113.1", port=4444,
                  c2_hits=["nuclei-cobalt"])

    eve = "\n".join([
        json.dumps({"event_type": "flow", "app_proto": "Gh0st RAT"}),
        json.dumps({"event_type": "alert",
                    "alert": {"signature": "FlowCarp Gh0st RAT"}}),
    ])
    out = flowcarp.label_services(
        scan_ids=["new"], pull=lambda expr: b"PCAP", run=lambda pcap: eve)

    assert out["labelled"] == 1 and out["flows"] == 1
    assert budget.used_today("flowcarp") == 1
    with store.connect(read_only=True) as con:
        row = con.execute(
            "SELECT app_proto, c2_hits FROM service_snapshots "
            "WHERE scan_id='new'").fetchone()
        proto, hits = row
        assert proto == "Gh0st RAT"
        assert set(json.loads(hits)) == {"nuclei-cobalt", "FlowCarp Gh0st RAT"}
        changes = {r[0]: (r[1], r[2]) for r in con.execute(
            "SELECT change_type, old_value, new_value FROM service_changes "
            "WHERE scan_id='new'").fetchall()}
    # proto moved njRAT -> Gh0st RAT, and a new signature fired
    assert changes["app_proto_changed"][0] == '"njRAT"'
    assert "c2_signature_hit" in changes


def test_label_services_skips_when_pcap_or_binary_absent(monkeypatch):
    monkeypatch.setattr(flowcarp, "_VANTAGE_IP", {"probe": "10.0.0.9"})
    budget.reset("flowcarp")
    with store.connect() as con:
        _snapshot(con, scan_id="s1", target="203.0.113.1", port=4444)
        _snapshot(con, scan_id="s1", target="203.0.113.2", port=4444)

    # no pcap for the first, binary missing (run->None) for the second
    def pull(expr):
        return None if "203.0.113.1" in expr else b"PCAP"

    out = flowcarp.label_services(
        scan_ids=["s1"], pull=pull, run=lambda pcap: None)
    assert out["candidates"] == 2
    assert out["labelled"] == 0
    assert out["skipped"] == 2
    assert budget.used_today("flowcarp") == 0


def test_label_services_stops_at_budget(monkeypatch):
    monkeypatch.setattr(flowcarp, "_VANTAGE_IP", {"probe": "10.0.0.9"})
    monkeypatch.setenv("CTI_FLOWCARP_DAILY_BUDGET", "1")
    budget.reset("flowcarp")
    with store.connect() as con:
        _snapshot(con, scan_id="s1", target="203.0.113.1", port=4444)
        _snapshot(con, scan_id="s1", target="203.0.113.2", port=5555)

    # each session reports 2 flows; the first spend (0->2) already exceeds a
    # cap of 1, so nothing is labelled and the loop stops.
    eve = "\n".join([json.dumps({"event_type": "flow", "app_proto": "DNS"}),
                     json.dumps({"event_type": "flow", "app_proto": "DNS"})])
    out = flowcarp.label_services(
        scan_ids=["s1"], pull=lambda e: b"P", run=lambda p: eve)
    assert out["labelled"] == 0
    assert budget.used_today("flowcarp") == 0


def test_model_args_lists_built_models(monkeypatch, tmp_path):
    monkeypatch.setattr(flowcarp, "models_dir", lambda: tmp_path)
    (tmp_path / "xworm.fcp").write_text("x")
    (tmp_path / "readme.txt").write_text("ignore me")
    assert flowcarp.model_args() == ["--model", str(tmp_path / "xworm.fcp")]
