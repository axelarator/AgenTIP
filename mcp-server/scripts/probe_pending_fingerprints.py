"""Runs on the cti host itself - drains the pending-fingerprints queue
and drives a remote probe plus an OpenSearch lookup to fill it in. See
the threat-cluster-tracking skill's "Automating the handoff" section.

One remote hop and one HTTPS query per target, not two SSH hops - and,
as of this change, every target in a queued batch is dispatched
concurrently rather than one at a time (see below):

  1. win_probe_helper.py on the Win11 probe VM (10.20.30.16) - generates
     a JARM scan and one ordinary TLS handshake against the target.
  2. An OpenSearch query against the Arkime VM (10.20.0.18:9200) -
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
document it came from - once, before the whole batch of queued targets
is dispatched (not per target - every target in a batch is dispatched
concurrently anyway, see below, so one snapshot ahead of all of them
covers the same ground a per-target one did).
collect_zeek_fingerprints_batch() later only accepts documents newer
than that snapshot, for every resolved IP in the batch at once. Every ts
compared is stamped by the same clock (Zeek's, via OpenSearch), never a
wall-clock reading taken on the cti host or the Win11 probe VM - that's
what actually caused the earlier bug, not just "clocks can drift", so a
fixed offset/window wouldn't have been a real fix. Taking the snapshot
before any probe fires (rather than right before querying, after the
probes already finished) also means the window naturally covers the
whole batch's actual duration - DNS resolution, JARM, and the
handshakes - instead of a fixed guess that could be too short for a
slow probe or unnecessarily long for a fast one.

Probes themselves are dispatched concurrently, not one target at a
time: main() fires every queued target's probe through a
ThreadPoolExecutor (PROBE_WORKERS), multiplexed over vm_proxy's shared
ControlMaster SSH connection, then runs one shared OpenSearch poll for
the whole batch once every dispatched probe has returned - see
_dispatch_one() and collect_zeek_fingerprints_batch(). A strictly serial
version of this loop (one target's whole probe-then-poll cycle before
even starting the next) is what a real 17-target run measured at close
to 15 minutes; concurrency here is the main lever against that, on top
of batching the polling itself and reusing one OpenSearch connection for
the whole run instead of opening a fresh one per query
(_opensearch_connection()).

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
checkout); an SSH keypair authorized to reach the Win11 probe VM. No
OpenSearch credential is required - the Arkime VM's OpenSearch (as of
the 10.20.0.18 move) sits on plain HTTP with no login in front of it,
lab-internal only.
"""
from __future__ import annotations

import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import os
import re
import sys
import time
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

OPENSEARCH_URL = "http://10.20.0.18:9200"
OPENSEARCH_INDEX = "zeek-*"
# Field this lab's ingestion pipeline maps Zeek's `id.resp_p` to.
# Confirmed live (2026-07-20) by sampling real documents across
# ssh.log/ssl.log/conn.log/dns.log/notice.log/files.log via this same
# _opensearch_search() path - every one carries a flat integer `dst_port`
# (alongside `src_port` for the initiator's side), consistent with the
# already-confirmed `id.resp_h` -> `dst_ip` rename. Only load-bearing for
# a target with more than one queued port (see
# collect_zeek_fingerprints_batch) - if you're pointed at a differently-named
# index/pipeline, re-verify with the same kind of sample query before
# trusting multi-port results.
_DST_PORT_FIELD = "dst_port"

SOURCE_LABEL = "Win11 probe VM"

# Concurrent SSH channels dispatched to the probe VM at once, multiplexed
# over the one shared ControlMaster connection (see vm_proxy.py) rather
# than run one-target-at-a-time - the original strictly serial loop spent
# most of a 15-minute/17-target run idle, waiting on one target's JARM
# scan + Zeek poll before even starting the next target's SSH round-trip,
# despite the targets having no dependency on each other. Same
# worker-count convention as core.py's pivot_cluster sweep
# (_PIVOT_CLUSTER_WORKERS) - concurrent outbound network I/O to
# independent targets, not a number tuned specifically for this script.
PROBE_WORKERS = 6
# -----------------------------------------------------------------------------


class ProbeError(RuntimeError):
    pass


# Some ingested report text embeds a port after a path segment rather than
# in the URL's actual authority component (e.g. "http://1.2.3.4/slw:8080" -
# note the port comes after the path, not the host) - urlsplit alone won't
# recover that, so this catches a bare trailing :PORT anywhere in the URL
# as a fallback.
_TRAILING_PORT_RE = re.compile(r":(\d{2,5})(?:/|$)")


def _lookup_ports(cluster: str, target: str) -> list[int]:
    """Best-effort port lookup for a fingerprint-queue target: the queue
    only ever carries a bare domain/ip (see core._enqueue_pending_fingerprints),
    not the port(s) its C2 traffic actually uses, and win_probe_helper.py
    defaults to 443 if none is given - which silently fingerprints
    whatever's on 443 (or nothing) instead of the real service for any
    C2 running on a nonstandard port. Returns every port worth probing
    for this target, not just one - a genuinely multi-port C2 (several
    listeners on the same IP) should get each of its known ports probed,
    since JARM/JA4S can differ by port and only probing one would miss
    the others entirely. Sources, most direct first, [443] only if none
    apply:

    1. For an IP target: the full `ports` list report_ingest._extract_ip_ports
       stamped onto that IP's own observable entry (a report saying "TCP
       port 886 (IPs: 1.2.3.4, ...)" or a bare "1.2.3.4:8080" - see
       core.ingest_report). Checked first since it's the most direct
       signal a report gives about *that specific* IP's own port(s),
       ahead of the more indirect "does some unrelated tracked URL
       happen to share this host" heuristic below.
    2. Scans *every* one of the cluster's tracked URLs whose host matches
       target and collects each one's port - the original mechanism
       (extended from "stop at the first match" to "collect them all"),
       still the only source for domain targets (report_ingest doesn't
       attempt port-near-domain extraction, only port-near-IP).
    3. [443], if nothing from either source above applied.

    Ports from both sources are combined and deduped (order preserved,
    source 1 first) rather than one source short-circuiting the other -
    a report might name a port near the IP itself while a different
    tracked URL for the same host names a second, equally real port.

    Also matches target against "{target}.sslip.io" and vice versa,
    since sslip.io wildcard-DNS hostnames literally encode the IP in the
    name - a queued bare-IP entry should still find the port from its
    own sslip.io hostname's tracked URL."""
    try:
        data = core.load_cluster(cluster)
    except Exception:
        return [443]
    needle = target.strip().lower()
    found: list[int] = []

    def _add(port: int) -> None:
        if port not in found:
            found.append(port)

    for entry in data["observables"].get("ips", []):
        if entry["value"].strip().lower() != needle:
            continue
        for port in entry.get("ports") or []:
            _add(port)
        break

    sslip_alias = f"{needle}.sslip.io"
    for entry in data["observables"].get("urls", []):
        url = entry["value"]
        host = (urlsplit(url).hostname or "").lower()
        if host != needle and host != sslip_alias:
            continue
        port = urlsplit(url).port
        if port:
            _add(port)
            continue
        m = _TRAILING_PORT_RE.search(url)
        if m:
            _add(int(m.group(1)))

    return found or [443]


def probe_win(target: str, port: int) -> dict[str, object]:
    try:
        return vm_proxy.probe_win(target, port)
    except vm_proxy.VMProxyError as e:
        raise ProbeError(str(e)) from e


_opensearch_host = urlsplit(OPENSEARCH_URL).hostname
_opensearch_port = urlsplit(OPENSEARCH_URL).port or 9200
_opensearch_path = f"/{OPENSEARCH_INDEX}/_search"
# One HTTP connection reused for every OpenSearch query in a run, instead
# of a fresh urllib.request.urlopen (and so a fresh TCP handshake) per
# call - previously paid up to ~9 times per target (one _current_max_ts
# snapshot plus up to 8 poll attempts), which added up across a real
# multi-target run to dozens of redundant handshakes to the same host in
# a tight loop. Batching the poll loop itself (collect_zeek_fingerprints_batch)
# already cut the call count from O(targets) to O(poll attempts) for a
# whole run; this cuts the remaining per-call setup cost on top of that.
_opensearch_conn: http.client.HTTPConnection | None = None


def _opensearch_connection() -> http.client.HTTPConnection:
    global _opensearch_conn
    if _opensearch_conn is None:
        _opensearch_conn = http.client.HTTPConnection(
            _opensearch_host, _opensearch_port, timeout=15)
    return _opensearch_conn


def _reset_opensearch_connection() -> None:
    global _opensearch_conn
    if _opensearch_conn is not None:
        try:
            _opensearch_conn.close()
        except Exception:
            pass
        _opensearch_conn = None


def _opensearch_search(query: dict[str, object], size: int = 50) -> list[dict[str, object]]:
    """POST a query to OpenSearch's _search endpoint, sorted newest-first,
    and return the list of _source documents. Raises ProbeError on any
    transport/HTTP failure - callers treat that the same as the SSH hop
    failing. No auth - this VM's OpenSearch has no login in front of it.

    Retries once over a fresh connection if the reused one was dropped
    from under us (an idle keep-alive connection closed server-side, or
    any other transport hiccup) - this function is only ever called
    single-threaded (dispatch and polling are separate phases in main(),
    never concurrent with each other), so there's no concurrent access to
    guard against, just a connection that can go stale between calls."""
    body = json.dumps({"size": size, "sort": [{"ts": "desc"}], "query": query}).encode()
    headers = {"Content-Type": "application/json"}

    last_error: Exception | None = None
    for attempt in range(2):
        conn = _opensearch_connection()
        try:
            conn.request("POST", _opensearch_path, body=body, headers=headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read())
            if resp.status >= 400:
                raise ProbeError(f"OpenSearch query failed: HTTP {resp.status}: {payload}")
            return [hit["_source"] for hit in payload["hits"]["hits"]]
        except (http.client.HTTPException, TimeoutError, OSError, ValueError) as e:
            last_error = e
            _reset_opensearch_connection()
    raise ProbeError(f"OpenSearch query failed: {last_error}") from last_error


def _current_max_ts() -> float:
    """Snapshot of the newest `ts` already indexed for ANY target, taken
    right before dispatching a probe - see the module docstring for why
    this (not a wall-clock reading, not a fixed window) is the freshness
    baseline. Returns 0.0 if the index is empty - everything found later
    then counts as fresh."""
    hits = _opensearch_search({"match_all": {}}, size=1)
    return float(hits[0]["ts"]) if hits else 0.0


def collect_zeek_fingerprints_batch(resolved: list[tuple[str, int]], baseline_ts: float,
                                     attempts: int = 8, interval: float = 2.0
                                     ) -> dict[tuple[str, int], dict[str, str | None]]:
    """Poll OpenSearch for ssl.log/conn.log documents newer than baseline_ts,
    for every (resolved_ip, port) pair from an entire dispatched batch at
    once - one shared poll loop, not one per target. Polls rather than a
    single query since the Zeek -> OpenSearch ingestion pipeline has its
    own lag after a connection completes.

    Dispatching probes concurrently (see main()) only pays off if what
    comes after doesn't go back to serializing per target - the original
    per-target version of this function polled one IP at a time, which
    would have re-serialized a concurrent batch right back into "wait out
    this target's poll budget before even looking at the next one". A
    `terms` query covering every IP still waiting on a value, each
    attempt, keeps the whole batch's poll loop shared instead. IPs that
    already have every field filled in drop out of `remaining` early so
    later attempts (and their query size) shrink as the batch finishes.

    Keyed by (ip, port), not just ip, because probing more than one port
    on the same IP (see _lookup_ports) means more than one entry in this
    batch can share an IP while genuinely being different connections -
    without a port split, a fingerprint from one port's connection could
    get attributed to a different port's queued entry just because they
    share dst_ip and both fall inside the same freshness window. The
    query itself still only filters on dst_ip (`ports_by_ip` groups the
    queued ports per IP so the query pulls every candidate document for
    an IP regardless of port) - the port-level split happens locally,
    against `_DST_PORT_FIELD`. That field name is confirmed (2026-07-20,
    by sampling real documents - see the constant's own comment), not
    just assumed by analogy with `dst_ip` - if you're pointed at a
    differently-named pipeline, re-verify with the same kind of sample
    query before trusting `_DST_PORT_FIELD` here.

    Disambiguation by port is only *enforced* when an IP actually has
    more than one port queued in this batch - the overwhelmingly common
    case (one port per IP) works exactly as it did before regardless of
    whether `_DST_PORT_FIELD` is right for your own pipeline, since
    there's nothing to disambiguate between. Only a genuinely multi-port
    IP depends on the field actually being there and correctly named.

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
    ports_by_ip: dict[str, set[int]] = {}
    for ip, port in resolved:
        ports_by_ip.setdefault(ip, set()).add(port)

    wanted: dict[tuple[str, int], dict[str, str | None]] = {
        (ip, port): {"ja4s": None, "ja4ts": None, "ja4l": None} for ip, port in resolved
    }
    remaining = set(wanted)
    for _ in range(attempts):
        if not remaining:
            break
        ips = {ip for ip, _ in remaining}
        size = min(len(remaining) * 50, 5000)  # OpenSearch's default max_result_window
        for hit in _opensearch_search({"terms": {"dst_ip": sorted(ips)}}, size=size):
            ip = hit.get("dst_ip")
            candidate_ports = ports_by_ip.get(ip)
            if candidate_ports is None or hit.get("ts", 0) <= baseline_ts:
                continue
            if len(candidate_ports) > 1:
                # Ambiguous IP (more than one port queued for it) - only
                # trust a document that names its own port and matches
                # one actually being waited on; see _DST_PORT_FIELD note
                # above.
                doc_port = hit.get(_DST_PORT_FIELD)
                if doc_port not in candidate_ports:
                    continue
                key = (ip, doc_port)
            else:
                # Only one port queued for this IP - no ambiguity to
                # resolve, so attribute to it regardless of whether
                # _DST_PORT_FIELD is even present in this schema.
                key = (ip, next(iter(candidate_ports)))
            entry = wanted.get(key)
            if entry is None:
                continue
            log_file = hit.get("log_file", "")
            if log_file.endswith("ssl.log"):
                if hit.get("established") and hit.get("ja4s") and not entry["ja4s"]:
                    entry["ja4s"] = hit["ja4s"]
            elif log_file.endswith("conn.log"):
                if hit.get("ja4ts") and not entry["ja4ts"]:
                    entry["ja4ts"] = hit["ja4ts"]
                if hit.get("ja4l") and not entry["ja4l"]:
                    entry["ja4l"] = hit["ja4l"]
        remaining = {key for key in remaining if not all(wanted[key].values())}
        if not remaining:
            break
        time.sleep(interval)
    return wanted


def _dispatch_one(job: dict[str, object]) -> dict[str, object]:
    """Runs in a worker thread (see main()'s ThreadPoolExecutor): fires one
    (cluster, target, port) job's probe. Port resolution already happened
    in main() before the batch was built (see _lookup_ports) - a target
    with more than one known port becomes more than one job here, each
    dispatched independently, rather than this function looking the port
    up itself. Deliberately does no OpenSearch access here - Zeek/JARM-side
    polling is batched once, after every dispatched job in the run has
    returned, rather than per job (see collect_zeek_fingerprints_batch),
    so this function's only job is the SSH round-trip to the probe VM.

    Catches broadly, not just ProbeError: a single job blowing up (an
    unexpected exception from vm_proxy) shouldn't take down every other
    job's future in the same batch - the caller collects every future's
    result via as_completed regardless of whether it succeeded."""
    cluster, target, port = job["cluster"], job["target"], job["port"]
    try:
        probe_result = probe_win(target, port)
    except ProbeError as e:
        return {"cluster": cluster, "target": target, "port": port,
                "probe_result": None, "probe_error": str(e)}
    except Exception as e:
        return {"cluster": cluster, "target": target, "port": port,
                "probe_result": None, "probe_error": f"unexpected error: {e}"}
    return {"cluster": cluster, "target": target, "port": port,
            "probe_result": probe_result, "probe_error": None}


def _enrich_with_honeylabs(pairs: set[tuple[str, str]]) -> None:
    """Annotate each (cluster, ip) with a one-line HoneyLabs
    honeypot-telemetry summary as extra provenance on the ips observable
    (core.add_observable's merge appends the source line to an
    already-tracked value rather than duplicating it). The lookup is
    passive and independent of probe success, so queued IP targets get
    enriched even when their TLS probe failed. Deliberately does NOT
    auto-file HoneyLabs' per-IP CVEs/fingerprints as their own
    observables - those describe attacker-client tooling seen against
    honeypots and would pollute clusters with mass-scanner noise; the
    summary line carries them for the analyst to file by hand.

    Credit frugality: only queue-gated IPs reach this (already filtered
    by _is_probe_worthy), lookups are cached (CTI_PIVOT_CACHE_TTL), and
    they run sequentially - a typical batch stays well under HoneyLabs'
    free-tier 10 calls/min."""
    if not pairs:
        return
    if not os.environ.get(core.pivot.HONEYLABS_API_KEY_ENV):
        print("HoneyLabs enrichment skipped: set HONEYLABS_API_KEY to enable it",
              file=sys.stderr)
        return
    for cluster, ip in sorted(pairs):
        note = core.summarize_honeylabs(core.honeylabs_context(ip))
        if note:
            core.add_observable(cluster, "ips", ip, note)


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

    # Fan each queued target out into one job per known port (see
    # _lookup_ports) - a target with two recorded ports becomes two jobs,
    # each probed and fingerprinted independently, instead of only ever
    # checking the first one. Port lookup is a local disk read (fast,
    # sequential here in the main thread) - the concurrency that matters
    # is in dispatching the resulting jobs' probes, next.
    jobs: list[dict[str, object]] = []
    for entry in queue:
        cluster, target = entry["cluster"], entry["value"]
        for port in _lookup_ports(cluster, target):
            jobs.append({"cluster": cluster, "target": target, "port": port})

    # One shared "start watching" snapshot taken before ANY probe in this
    # batch fires - not one per job. See the module docstring: what
    # actually matters for freshness is that baseline_ts and every ts it's
    # compared against later come from the same clock (Zeek's, via
    # OpenSearch), and that the snapshot precedes the traffic it's meant
    # to catch. A single snapshot ahead of the whole concurrently-dispatched
    # batch satisfies both exactly as well as one per job did, without
    # forcing the dispatch loop back into "wait for this job's baseline
    # query to complete before starting the next one".
    baseline_ts = _current_max_ts()

    dispatched: list[dict[str, object]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        futures = [pool.submit(_dispatch_one, job) for job in jobs]
        for future in concurrent.futures.as_completed(futures):
            dispatched.append(future.result())

    resolved_by_ip_port: dict[tuple[str, int], list[dict[str, object]]] = {}
    for d in dispatched:
        cluster, target, port = d["cluster"], d["target"], d["port"]
        if d["probe_error"]:
            print(f"probe failed for {target!r} (port {port}): {d['probe_error']}", file=sys.stderr)
            continue
        probe_result = d["probe_result"]
        if probe_result.get("error"):
            print(f"probe reported an error for {target!r} (port {port}): {probe_result['error']}", file=sys.stderr)

        if probe_result.get("jarm"):
            core.add_observable(cluster, "jarm", probe_result["jarm"],
                                 f"JARM against {target}:{port} via {SOURCE_LABEL}, {today}")

        resolved_ip = probe_result.get("resolved_ip")
        if resolved_ip:
            resolved_by_ip_port.setdefault((resolved_ip, port), []).append(d)

    # HoneyLabs enrichment targets: every queued IP target (probe success
    # or not - the lookup is passive) plus every IP a domain target
    # resolved to, deduped per (cluster, ip).
    honeylabs_pairs: set[tuple[str, str]] = set()
    for entry in queue:
        try:
            ipaddress.ip_address(entry["value"])
        except ValueError:
            continue
        honeylabs_pairs.add((entry["cluster"], entry["value"]))
    for (resolved_ip, _port), entries in resolved_by_ip_port.items():
        for d in entries:
            honeylabs_pairs.add((d["cluster"], resolved_ip))
    _enrich_with_honeylabs(honeylabs_pairs)

    if not resolved_by_ip_port:
        return

    try:
        zeek_results = collect_zeek_fingerprints_batch(list(resolved_by_ip_port), baseline_ts)
    except ProbeError as e:
        print(f"OpenSearch lookup failed for this batch: {e}", file=sys.stderr)
        return

    for (resolved_ip, _port), entries in resolved_by_ip_port.items():
        zeek_result = zeek_results.get((resolved_ip, _port), {})
        for d in entries:
            cluster, target, port = d["cluster"], d["target"], d["port"]
            for category in ("ja4s", "ja4ts", "ja4l"):
                value = zeek_result.get(category)
                if value:
                    core.add_observable(cluster, category, value,
                                         f"Zeek passive (tap107, via OpenSearch) handshake against "
                                         f"{target}:{port} ({resolved_ip}), {today}")


if __name__ == "__main__":
    main()
