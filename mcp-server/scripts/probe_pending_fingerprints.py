"""Runs on the cti host itself - drains the pending-fingerprints queue
and drives a remote probe plus an OpenSearch lookup to fill it in. See
the threat-cluster-tracking skill's "Automating the handoff" section.

One remote hop and one HTTPS query per target now, not two SSH hops:

  1. win_probe_helper.py on the Win11 probe VM (10.20.0.9) - generates
     a JARM scan and one ordinary TLS handshake against the target.
  2. An OpenSearch query against the Arkime VM (10.20.0.14:9200) -
     reads back whatever that handshake produced in ssl.log/conn.log,
     which a separate ingestion pipeline already ships there reliably.

This replaces an earlier design that SSHed into the Zeek sensor VM and
read /opt/zeek/logs/current/{ssl,conn}.log directly. That broke in two
ways once tested against a real multi-target run: the "current" log
files are periodically rotated out from under a reader (a bare
FileNotFoundError mid-poll used to abort that target's whole Zeek
lookup, even though the file reappeared moments later), and recency
filtering needed either a fixed-duration guess or a foreign timestamp
compared against a different host's clock (see the git history of this
file for the clock-skew bug that already forced one redesign). Querying
OpenSearch - which the same lab's own dashboard already shows reliably
indexing ssl.log/conn.log regardless of Zeek's own file rotation -
sidesteps both problems at the source instead of working around them
here.

zeek_log_query.py is retired from this automated pipeline as of this
change (kept only if you still want to read raw logs by hand directly
on the Zeek VM for troubleshooting - it's no longer invoked from here,
and its SSH hop/key are unused by this script).

Freshness without cross-host clock comparison: _current_max_ts() takes
a snapshot of the newest `ts` already indexed in OpenSearch - itself
always sourced from the Zeek VM's own clock, regardless of which
document it came from - right before dispatching each target's probe.
collect_zeek_fingerprints() later only accepts documents newer than
that snapshot. Every ts compared is stamped by the same clock (Zeek's,
via OpenSearch), never a wall-clock reading taken on the cti host or
the Win11 probe VM - that's what actually caused the earlier bug, not
just "clocks can drift", so a fixed offset/window wouldn't have been a
real fix. Taking the snapshot before the probe fires (rather than
right before querying, after the probe already finished) also means
the window naturally covers the probe's entire actual duration -
DNS resolution, JARM, and the handshake - instead of a fixed guess
that could be too short for a slow probe or unnecessarily long for a
fast one.

Direction still matters for the one remaining SSH hop: the OPNsense LAN
(VLAN30, where the Win11 VM lives) is firewalled so it can never
connect back out to the cti host's home-LAN segment - deliberate lab
hygiene. This script runs as part of the cti_tools package (it imports
core.py directly - no listener, nothing accepts inbound connections
here) and *initiates* the SSH connection itself, outbound into the lab.
The OpenSearch query is a plain outbound HTTPS call to the Arkime VM,
which - per lab setup - is reachable directly from the cti host over
the same Tailscale/home-LAN routes as the Win11 VM, not proxied through
any other lab host.

Usage (run manually, or on a cron/systemd timer):

    python3 probe_pending_fingerprints.py

Every run validates both the Win11 SSH hop and OpenSearch reachability
first (see check_access()) and aborts before touching the queue if
either fails - probing/pivoting shouldn't start without confirmed
access. To check access on its own, without draining the queue:

    python3 probe_pending_fingerprints.py --check-access

Requires: cti_tools importable (run from within the mcp-server venv/repo
checkout); an SSH keypair authorized to reach the Win11 probe VM; and
CTI_OPENSEARCH_PASSWORD set in the environment. The password is
deliberately not a constant in this file - this script lives in a
git-tracked repo, and a plaintext credential written here would end up
in git history the same way the SSH private keys never do (they're
referenced by local file path instead, never embedded).
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti_tools import core, vm_proxy  # noqa: E402

# --- adjust for your environment --------------------------------------------
# SSH connection details for the Win11 probe VM (WIN_PROBE_USER/HOST,
# WIN_SSH_KEY, WIN_KNOWN_HOSTS, WIN_HELPER_CMD) now live in
# cti_tools.vm_proxy - that module is the shared chokepoint pivot.py
# also routes through, so there's one source of truth for how this
# process reaches the VM instead of two copies drifting apart.

OPENSEARCH_URL = "https://10.20.0.14:9200"
OPENSEARCH_INDEX = "zeek-*"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASSWORD_ENV = "CTI_OPENSEARCH_PASSWORD"  # not a constant - see module docstring
# Self-signed cert in this lab (the same as passing -k to curl). Point this
# at a real CA bundle instead if you put a real cert in front of OpenSearch.
_OPENSEARCH_TLS_CONTEXT = ssl.create_default_context()
_OPENSEARCH_TLS_CONTEXT.check_hostname = False
_OPENSEARCH_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

SOURCE_LABEL = "Win11 probe VM"
# -----------------------------------------------------------------------------


class ProbeError(RuntimeError):
    pass


# Some ingested report text embeds a port after a path segment rather than
# in the URL's actual authority component (e.g. "http://1.2.3.4/slw:8080" -
# note the port comes after the path, not the host) - urlsplit alone won't
# recover that, so this catches a bare trailing :PORT anywhere in the URL
# as a fallback.
_TRAILING_PORT_RE = re.compile(r":(\d{2,5})(?:/|$)")


def _lookup_port(cluster: str, target: str) -> int:
    """Best-effort port lookup for a fingerprint-queue target: the queue
    only ever carries a bare domain/ip (see core._enqueue_pending_fingerprints),
    not the port its C2 traffic actually uses, and win_probe_helper.py
    defaults to 443 if none is given - which silently fingerprints
    whatever's on 443 (or nothing) instead of the real service for any
    C2 running on a nonstandard port. Three sources, most direct first,
    443 only if none apply:

    1. For an IP target: the `ports` list report_ingest._extract_ip_ports
       stamped onto that IP's own observable entry (a report saying "TCP
       port 886 (IPs: 1.2.3.4, ...)" or a bare "1.2.3.4:8080" - see
       core.ingest_report). Checked first since it's the most direct
       signal a report gives about *that specific* IP's own port,
       ahead of the more indirect "does some unrelated tracked URL
       happen to share this host" heuristic below. Uses the first
       entry if more than one port was ever recorded for the IP.
    2. Scans the cluster's tracked URLs for one whose host matches
       target and pulls its port - the original mechanism, still the
       only source for domain targets (report_ingest doesn't attempt
       port-near-domain extraction, only port-near-IP).
    3. 443.

    Also matches target against "{target}.sslip.io" and vice versa,
    since sslip.io wildcard-DNS hostnames literally encode the IP in the
    name - a queued bare-IP entry should still find the port from its
    own sslip.io hostname's tracked URL."""
    try:
        data = core.load_cluster(cluster)
    except Exception:
        return 443
    needle = target.strip().lower()

    for entry in data["observables"].get("ips", []):
        if entry["value"].strip().lower() != needle:
            continue
        ports = entry.get("ports")
        if ports:
            return ports[0]
        break

    sslip_alias = f"{needle}.sslip.io"
    for entry in data["observables"].get("urls", []):
        url = entry["value"]
        host = (urlsplit(url).hostname or "").lower()
        if host != needle and host != sslip_alias:
            continue
        port = urlsplit(url).port
        if port:
            return port
        m = _TRAILING_PORT_RE.search(url)
        if m:
            return int(m.group(1))
    return 443


def probe_win(target: str, port: int) -> dict[str, object]:
    try:
        return vm_proxy.probe_win(target, port)
    except vm_proxy.VMProxyError as e:
        raise ProbeError(str(e)) from e


def _opensearch_password() -> str:
    password = os.environ.get(OPENSEARCH_PASSWORD_ENV)
    if not password:
        raise ProbeError(f"{OPENSEARCH_PASSWORD_ENV} is not set in the environment")
    return password


def _opensearch_search(query: dict[str, object], size: int = 50) -> list[dict[str, object]]:
    """POST a query to OpenSearch's _search endpoint, sorted newest-first,
    and return the list of _source documents. Raises ProbeError on any
    auth/transport/HTTP failure - callers treat that the same as the SSH
    hop failing."""
    body = json.dumps({"size": size, "sort": [{"ts": "desc"}], "query": query}).encode()
    auth = base64.b64encode(f"{OPENSEARCH_USER}:{_opensearch_password()}".encode()).decode()
    req = urllib.request.Request(
        f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_OPENSEARCH_TLS_CONTEXT) as resp:
            payload = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
        raise ProbeError(f"OpenSearch query failed: {e}") from e
    return [hit["_source"] for hit in payload["hits"]["hits"]]


def _current_max_ts() -> float:
    """Snapshot of the newest `ts` already indexed for ANY target, taken
    right before dispatching a probe - see the module docstring for why
    this (not a wall-clock reading, not a fixed window) is the freshness
    baseline. Returns 0.0 if the index is empty - everything found later
    then counts as fresh."""
    hits = _opensearch_search({"match_all": {}}, size=1)
    return float(hits[0]["ts"]) if hits else 0.0


def collect_zeek_fingerprints(resolved_ip: str, baseline_ts: float,
                               attempts: int = 8, interval: float = 2.0) -> dict[str, str | None]:
    """Poll OpenSearch for ssl.log/conn.log documents for resolved_ip newer
    than baseline_ts. Polls rather than a single query since the Zeek ->
    OpenSearch ingestion pipeline has its own lag after a connection
    completes.

    A single probe produces roughly a dozen ssl.log rows for the same
    target, not one: JARM's ~10 malformed-ClientHello attempts each get
    their own row alongside win_probe_helper's one *ordinary* handshake,
    and Zeek's ja4 plugin computes a ja4s for every row that negotiated
    far enough to have one - which most of JARM's malformed variants do,
    each producing a genuinely different ja4s (that's the point of
    JARM's algorithm: observing how the server's response differs per
    malformed hello). Confirmed live: filtering one real target's
    OpenSearch documents by ja4s showed 4-5 distinct non-empty values in
    a single run, none of them wrong exactly, but only one of them -
    the row with established:true - represents what an everyday client
    actually gets connecting normally. ja4s is filtered to that row
    specifically for that reason; ja4ts/ja4l (from conn.log, not
    ssl.log) don't have this problem the same way - ja4ts is a TCP-layer
    fingerprint set before any TLS bytes are sent, so it doesn't vary by
    which ClientHello followed, and ja4l is a per-connection latency
    measurement where some variance across attempts is just real network
    jitter, not a JARM-probe artifact to filter out - so those two keep
    "first non-empty value seen" as before."""
    wanted: dict[str, str | None] = {"ja4s": None, "ja4ts": None, "ja4l": None}
    for _ in range(attempts):
        for hit in _opensearch_search({"term": {"dst_ip": resolved_ip}}):
            if hit.get("ts", 0) <= baseline_ts:
                continue
            log_file = hit.get("log_file", "")
            if log_file.endswith("ssl.log"):
                if hit.get("established") and hit.get("ja4s") and not wanted["ja4s"]:
                    wanted["ja4s"] = hit["ja4s"]
            elif log_file.endswith("conn.log"):
                if hit.get("ja4ts") and not wanted["ja4ts"]:
                    wanted["ja4ts"] = hit["ja4ts"]
                if hit.get("ja4l") and not wanted["ja4l"]:
                    wanted["ja4l"] = hit["ja4l"]
        if all(wanted.values()):
            return wanted
        time.sleep(interval)
    return wanted


def check_access() -> list[str]:
    """Validates both the Win11 SSH hop and OpenSearch reachability before
    any probing starts - probing/pivoting shouldn't start without
    confirmed access. The SSH hop is checked the same way as before
    (round-trip an incomplete request through the forced `command=`
    channel, confirm a JSON reply comes back - proves the key
    authenticated and the remote helper ran). The OpenSearch hop is
    checked with the exact same query _current_max_ts() would make.
    Returns one problem string per failed hop; empty means both are
    reachable and authorized."""
    problems = []
    try:
        vm_proxy._ssh_json_rpc({})
    except vm_proxy.VMProxyError as e:
        problems.append(f"win probe VM ({vm_proxy.WIN_PROBE_HOST}): {e}")
    try:
        _opensearch_search({"match_all": {}}, size=1)
    except ProbeError as e:
        problems.append(f"OpenSearch ({OPENSEARCH_URL}): {e}")
    return problems


def main() -> None:
    problems = check_access()
    if "--check-access" in sys.argv:
        if problems:
            for p in problems:
                print(p, file=sys.stderr)
            raise SystemExit(1)
        print("access OK: both hops reachable and authorized")
        return
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        raise SystemExit("aborting: access check failed for one or both hops, see errors above")

    queue = core.pop_pending_fingerprints()
    if not queue:
        return

    today = datetime.date.today().isoformat()
    for entry in queue:
        cluster, target = entry["cluster"], entry["value"]
        port = _lookup_port(cluster, target)
        baseline_ts = _current_max_ts()  # start "watching" before the probe fires

        try:
            probe_result = probe_win(target, port)
        except ProbeError as e:
            print(f"probe failed for {target!r} (port {port}): {e}", file=sys.stderr)
            continue
        if probe_result.get("error"):
            print(f"probe reported an error for {target!r} (port {port}): {probe_result['error']}", file=sys.stderr)

        if probe_result.get("jarm"):
            core.add_observable(cluster, "jarm", probe_result["jarm"],
                                 f"JARM against {target}:{port} via {SOURCE_LABEL}, {today}")

        resolved_ip = probe_result.get("resolved_ip")
        if not resolved_ip:
            continue

        try:
            zeek_result = collect_zeek_fingerprints(resolved_ip, baseline_ts)
        except ProbeError as e:
            print(f"OpenSearch lookup failed for {target!r} ({resolved_ip}): {e}", file=sys.stderr)
            continue

        for category in ("ja4s", "ja4ts", "ja4l"):
            value = zeek_result.get(category)
            if value:
                core.add_observable(cluster, category, value,
                                     f"Zeek passive (tap107, via OpenSearch) handshake against "
                                     f"{target}:{port} ({resolved_ip}), {today}")


if __name__ == "__main__":
    main()
