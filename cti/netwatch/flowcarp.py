"""Protocol labels for the services httpx/tlsx could not name.

A netwatch scan recognises HTTP and TLS. What it cannot name is the host
on an odd port answering with raw bytes - a Gh0st or njRAT listener, a
custom C2 handshake, a bare banner. That is exactly where a *flow*
classifier earns its keep: FlowCarp (https://flowcarp.com) identifies a
protocol from flow statistics alone, no parser and no payload signature,
and it already ships models for the common families.

## Why batch, over Arkime pcap

FlowCarp's community edition labels at most 10k flows/day (CC BY-ND); past
that it still extracts flows but names nothing. Live mode on the sniff NIC
would spend that budget on port-scan SYNs. Instead we run it *after* a
scan, only over the sessions our own probe opened to services we could not
otherwise name, pulling just those flows' pcap from Arkime:

    probe -> host:port, where the host sent back more than a bare RST
    (`packets.dst>3`), so only sessions that actually exchanged payload.

The pcap never touches disk here: Arkime streams it, we pipe it straight
into `flowcarp --input - --output - --format EveJson` and read the Eve JSON
back. The protocol fills the snapshot's `app_proto`; any malware-tagged
alert is unioned into its `c2_hits`, next to the nuclei template hits.
Every flow FlowCarp reports spends one `flowcarp` budget unit, so a run
stops labelling before it crosses the licence's daily limit.

## Degradation

Three things can be absent - the `flowcarp` binary, the Arkime viewer, the
`CTI_ARKIME_*` config - and each is a clean skip, never a crash: a missing
protocol label is a gap in one snapshot, exactly like a missing passive
join. Nothing here is required for a netwatch run to succeed.

## Custom models (confirmed available in the community edition)

The free edition *can* build models: collect >=10 sessions (100+ for
precision) of one family's traffic into a directory and run
`flowcarp --input directory:Once:<dir> --output model:"<name>":MALICIOUS:<out>.fcp`,
then load it with `--model`. `build_model_command` assembles that line and
`model_args` loads every `.fcp` under data/flowcarp/models/ into a label
run. See data/flowcarp/training/README.md for the workflow.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Iterable

from .. import store
from ..sources import budget
from ..util import data_dir

log = logging.getLogger(__name__)

# The probe's IP as Arkime/Zeek see it on the mirrored bridge - the same
# mapping the passive join uses, so the two agree on what "the probe" is.
_VANTAGE_IP = {
    "probe": os.environ.get("CTI_PROBE_ZEEK_IP") or os.environ.get("CTI_PROBE_HOST"),
    "win116": os.environ.get("CTI_WIN_ZEEK_IP"),
}

FLOWCARP_BIN = os.environ.get("CTI_FLOWCARP_BIN", "flowcarp")
# Only sessions that exchanged payload: a bare SYN/RST tells us nothing a
# flow classifier can use, and it would still cost a flow of budget.
MIN_RESP_PACKETS = 3
ARKIME_TIMEOUT = 60
FLOWCARP_TIMEOUT = 120
# Don't try to name a service we already named, and don't re-label history:
# candidates are open ports with no protocol from httpx/tlsx and no label
# yet. A sane ceiling keeps one run inside the flow budget.
DEFAULT_LIMIT = 200


def models_dir() -> Path:
    d = data_dir() / "flowcarp" / "models"
    d.mkdir(parents=True, exist_ok=True)
    return d


# --------------------------------------------------------------------------- #
# Eve JSON parsing - pure, and the part most worth testing
# --------------------------------------------------------------------------- #

def parse_eve(text: str) -> dict[str, Any]:
    """FlowCarp's Suricata-Eve output -> one verdict for a session.

    FlowCarp writes one JSON object per line. Flow events carry `app_proto`
    (the protocol, or null when nothing matched); alert events carry
    `alert.signature`, the malware family's name. We take the most specific
    protocol seen (any non-null, non-"failed" value over none) and the set
    of alert signatures, and count the flow events for budgeting.
    """
    app_proto: str | None = None
    alerts: set[str] = set()
    flows = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = evt.get("event_type")
        if etype == "flow" or (etype is None and "app_proto" in evt):
            flows += 1
            proto = evt.get("app_proto")
            if proto and str(proto).lower() not in ("failed", "unknown", "none"):
                app_proto = app_proto or str(proto)
        if etype == "alert":
            sig = (evt.get("alert") or {}).get("signature")
            if sig:
                alerts.add(str(sig))
    return {"app_proto": app_proto, "c2_hits": sorted(alerts), "flows": flows}


def expression_for(src_ip: str, dst_ip: str, port: int) -> str:
    """The Arkime session expression for one probe->host:port conversation
    that actually exchanged payload."""
    return (f"ip.src == {src_ip} && ip.dst == {dst_ip} "
            f"&& port.dst == {port} && packets.dst > {MIN_RESP_PACKETS}")


# --------------------------------------------------------------------------- #
# the two external legs - each degrades to None, never raises
# --------------------------------------------------------------------------- #

def _arkime_pcap(expression: str) -> bytes | None:
    """Pull the raw pcap for a session expression from the Arkime viewer.

    Our own infra on VM 118, queried by expression (not by reaching the
    indicator), so it goes direct with digest auth from CTI_ARKIME_*. A
    missing URL, an auth failure or an empty capture all return None.
    """
    url = os.environ.get("CTI_ARKIME_URL")
    if not url:
        return None
    try:
        import requests
        from requests.auth import HTTPDigestAuth
    except ImportError:  # pragma: no cover - requests is in the venv
        log.warning("flowcarp: requests not available for Arkime pull")
        return None
    user = os.environ.get("CTI_ARKIME_USER")
    pw = os.environ.get("CTI_ARKIME_PASSWORD")
    auth = HTTPDigestAuth(user, pw) if user and pw else None
    try:
        resp = requests.get(
            url.rstrip("/") + "/api/sessions/pcap",
            params={"expression": expression}, auth=auth,
            timeout=ARKIME_TIMEOUT, verify=os.environ.get("CTI_ARKIME_CA", True))
    except Exception as e:  # network, TLS, DNS - all a clean skip
        log.warning("flowcarp: Arkime pull failed: %s", e)
        return None
    if resp.status_code != 200:
        log.warning("flowcarp: Arkime returned %s for %s",
                    resp.status_code, expression)
        return None
    return resp.content or None


def _run_flowcarp(pcap: bytes, extra_args: Iterable[str] = ()) -> str | None:
    """Pipe pcap through the flowcarp binary, return its Eve JSON stdout.

    A missing binary (FileNotFoundError) or a non-zero exit is a skip: the
    service just stays unlabelled. Models under data/flowcarp/models/ are
    loaded so a custom family is recognised alongside the built-in ones.
    """
    cmd = [FLOWCARP_BIN, "--input", "-", "--output", "-",
           "--format", "EveJson", *model_args(), *extra_args]
    try:
        proc = subprocess.run(cmd, input=pcap, capture_output=True,
                              timeout=FLOWCARP_TIMEOUT)
    except FileNotFoundError:
        log.warning("flowcarp: binary %r not found; skipping protocol labels",
                    FLOWCARP_BIN)
        return None
    except subprocess.TimeoutExpired:
        log.warning("flowcarp: binary timed out")
        return None
    if proc.returncode != 0:
        log.warning("flowcarp: exit %s: %s", proc.returncode,
                    (proc.stderr or b"").decode(errors="replace")[:300])
        return None
    return (proc.stdout or b"").decode(errors="replace")


def model_args() -> list[str]:
    """`--model <f>` for every custom model on disk, so label runs see
    them. Empty when none are built - the built-ins still apply."""
    args: list[str] = []
    for fcp in sorted(models_dir().glob("*.fcp")):
        args += ["--model", str(fcp)]
    return args


def build_model_command(name: str, tags: str, pcap_source: str,
                        out_path: str) -> list[str]:
    """The exact command to train a model from a directory or file of one
    family's captures. Tags with MALICIOUS make matches raise alerts.
    Assembled here (not run) so the training step is explicit and testable;
    it needs the binary and real pcap, both operator-supplied."""
    return [FLOWCARP_BIN, "--input", pcap_source,
            "--output", f'model:"{name}":{tags}:{out_path}']


# --------------------------------------------------------------------------- #
# the batch pass
# --------------------------------------------------------------------------- #

def candidates(con, *, scan_ids: list[str] | None = None,
               limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    """Open services a scan left unnamed: no http status, no TLS cert, no
    protocol label yet. Scoped to the given scans when the pipeline passes
    them (the just-finished run); otherwise the most recent scan of each
    service, so a standalone run never re-labels history."""
    where = ["open", "app_proto IS NULL", "cert_sha256 IS NULL",
             "http_status IS NULL", "ip IS NOT NULL", "port > 0"]
    params: list[Any] = []
    if scan_ids:
        where.append(f"scan_id IN ({', '.join('?' for _ in scan_ids)})")
        params += scan_ids
    else:
        where.append(
            "scanned_at = (SELECT max(s2.scanned_at) FROM service_snapshots s2 "
            "WHERE s2.target = service_snapshots.target "
            "AND s2.port = service_snapshots.port)")
    rows = con.execute(
        f"""SELECT scan_id, scanned_at, target, ip, port, vantage, actor
            FROM service_snapshots WHERE {' AND '.join(where)}
            ORDER BY scanned_at DESC LIMIT ?""", [*params, limit]).fetchall()
    cols = ("scan_id", "scanned_at", "target", "ip", "port", "vantage", "actor")
    return [dict(zip(cols, r)) for r in rows]


def label_services(*, con=None, scan_ids: list[str] | None = None,
                   limit: int = DEFAULT_LIMIT,
                   pull: Callable[[str], bytes | None] = _arkime_pcap,
                   run: Callable[[bytes], str | None] = _run_flowcarp,
                   ) -> dict[str, Any]:
    """Label every unnamed service with FlowCarp over its Arkime pcap.

    For each candidate: build the session expression, pull its pcap, run
    FlowCarp, spend one budget unit per flow it reported, fold the protocol
    and any alerts onto the snapshot, and log an `app_proto_changed` /
    `c2_signature_hit` change the same way ingest's diff does. `pull`/`run`
    are injected so the batch is testable without Arkime or the binary.
    """
    summary = {"candidates": 0, "pulled": 0, "labelled": 0, "flows": 0,
               "changes": 0, "skipped": 0}
    with ExitStack() as stack:
        if con is None:
            con = stack.enter_context(store.connect_retry(read_only=False))
        targets = candidates(con, scan_ids=scan_ids, limit=limit)
        summary["candidates"] = len(targets)
        for t in targets:
            src = _VANTAGE_IP.get(t["vantage"])
            if not src:
                summary["skipped"] += 1
                continue
            pcap = pull(expression_for(src, t["ip"], t["port"]))
            if not pcap:
                summary["skipped"] += 1
                continue
            summary["pulled"] += 1
            eve = run(pcap)
            if eve is None:
                summary["skipped"] += 1
                continue
            verdict = parse_eve(eve)
            if verdict["flows"]:
                try:
                    budget.spend("flowcarp", verdict["flows"])
                except budget.BudgetExhausted as e:
                    log.warning("flowcarp budget: %s", e)
                    break
                summary["flows"] += verdict["flows"]
            if not verdict["app_proto"] and not verdict["c2_hits"]:
                continue
            summary["changes"] += _apply(con, t, verdict)
            summary["labelled"] += 1
    return summary


def _apply(con, target: dict[str, Any], verdict: dict[str, Any]) -> int:
    """Fold a verdict onto the snapshot and record what moved against the
    previous scan - mirroring ingest._diff's rules exactly."""
    prior = store.update_service_flow(
        con, scan_id=target["scan_id"], target=target["target"],
        port=target["port"], app_proto=verdict["app_proto"],
        c2_hits=verdict["c2_hits"])
    if prior is None:
        return 0
    base = store.latest_service_snapshot(
        con, target["target"], target["port"], before_scan_id=target["scan_id"])
    changes = 0
    new_proto = verdict["app_proto"]
    old_proto = (base or {}).get("app_proto")
    if new_proto and old_proto and new_proto != old_proto:
        store.record_service_change(
            con, detected_at=target["scanned_at"], scan_id=target["scan_id"],
            target=target["target"], port=target["port"], actor=target.get("actor"),
            field="app_proto", change_type="app_proto_changed",
            old_value=old_proto, new_value=new_proto)
        changes += 1
    new_hits = set(verdict["c2_hits"])
    old_hits_json = (base or {}).get("c2_hits")
    old_hits = set(json.loads(old_hits_json)) if old_hits_json else set()
    if new_hits - old_hits:
        store.record_service_change(
            con, detected_at=target["scanned_at"], scan_id=target["scan_id"],
            target=target["target"], port=target["port"], actor=target.get("actor"),
            field="c2_hits", change_type="c2_signature_hit",
            old_value=sorted(old_hits) or None, new_value=sorted(new_hits))
        changes += 1
    return changes
