"""RETIRED from the automated pipeline: probe_pending_fingerprints.py no
longer calls this script or SSHes to this VM at all. It now reads
ssl.log/conn.log results from OpenSearch directly (an existing
ingestion pipeline already indexes them reliably, sidestepping the log
rotation/FileNotFoundError races and the cross-host clock-skew issues
this file's polling approach ran into - see probe_pending_fingerprints.py's
module docstring for the full story). This file is left in place only
for manual, by-hand troubleshooting directly on the Zeek VM if you ever
need to inspect the raw logs yourself; nothing in the automated
pipeline invokes it, and its SSH hop/key are unused.

Runs on the Zeek sensor VM (10.20.0.7 in this lab - the box hosting
Zeek itself, NOT where probes should be generated from). Read-only half
of the fingerprinting handoff: probe_pending_fingerprints.py on the cti
host calls win_probe_helper.py on a separate probe VM to actually touch
the target, then calls this script separately to read back whatever
Zeek logged for that connection. See the threat-cluster-tracking
skill's "Automating the handoff" section.

Why probing and log-reading are two different scripts on two different
hosts now, instead of one combined script: this Zeek build's port
mirror only captures traffic that's genuinely third-party to the
sensor - a probe generated FROM the Zeek VM's own interface showed up
as a one-sided ghost in conn.log (response visible, the VM's own
outbound SYN never mirrored back to itself, or vice versa depending on
mirror direction), producing empty/garbage ja4ts and ja4l no matter how
long you wait. A dedicated probe VM on the same mirrored bridge (same
footing as any other lab VM) doesn't have that problem - its traffic
is exactly the kind of third-party flow the mirror is built to capture
cleanly in both directions.

Standalone - not part of the cti_tools package. Reads one JSON object
from stdin:

    {"target": "<already-resolved IP>"}

target must already be an IP - Zeek's id.resp_h is always the resolved
address, never a hostname string, and DNS resolution happened on the
probe VM (whatever it actually connected to), not here.

No since_ts from the caller - an earlier version accepted one, anchored
to the probe VM's own clock, but that VM and this one aren't NTP-synced
(caught this in testing: ~1hr of drift between them), so a foreign
wall-clock value compared against this box's own ts field was
meaningless. Recency is instead measured entirely against *this* box's
own clock (RECENCY_WINDOW_SECONDS below) - the two SSH hops run back to
back right after the probe fires, so a window covering that round trip
plus conn.log's usual finalization lag is enough to isolate the fresh
entry from stale lab traffic to the same IP without needing the caller
to supply anything.

Writes one JSON object to stdout:

    {"ja4s": "<hash-or-null>", "ja4ts": "...", "ja4l": "...", "error": null}

ja4x isn't collected - needs x509.log and isn't computed yet upstream
on this Zeek build ("awaiting Zeek object support"). ja4t is deliberately
skipped even though it sits in the same conn.log rows as ja4ts - it
fingerprints whoever *initiates*, so it's the probe VM's own signature,
not intel about the target (same reasoning applies to ja4/ja4h,
collected from nowhere in this pipeline). conn.log's ja4ls (server half
of JA4L) is also left alone - this tool only tracks one ja4l category,
not a client/server split, so ja4l here is conn.log's own "ja4l" field
as-is.
"""
from __future__ import annotations

import json
import sys
import time

# --- adjust for your environment --------------------------------------------
ZEEK_SSL_LOG = "/opt/zeek/logs/current/ssl.log"    # JSON-lines (LogAscii::json)
ZEEK_CONN_LOG = "/opt/zeek/logs/current/conn.log"  # JSON-lines (LogAscii::json)
# Measured on this box's own clock, from when this script starts running.
# Needs to cover: SSH-hop latency, plus conn.log's usual finalization lag
# (only written once a connection tears down - see poll_zeek_logs).
RECENCY_WINDOW_SECONDS = 120
# -----------------------------------------------------------------------------


def _scan_json_log(path: str, target: str, window_start: float,
                    fields: tuple[str, ...]) -> tuple[dict[str, str | None], bool]:
    """Last non-empty value of each of `fields` logged for target at or
    after window_start (this box's own clock) - a window, not just
    "most recent line for this IP", so a probe never picks up a stale
    entry left by unrelated lab traffic to the same target. Also
    returns whether *any* line for this resp_h exists regardless of
    window_start, purely as a diagnostic - lets a caller tell "Zeek
    just hasn't flushed the new entry yet" apart from "this target has
    never once been logged", which look identical if you only check
    the window-filtered result."""
    found: dict[str, str | None] = {f: None for f in fields}
    saw_any_for_target = False
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("id.resp_h") != target:
                continue
            saw_any_for_target = True
            if row.get("ts", 0) >= window_start:
                for field in fields:
                    if row.get(field):
                        found[field] = row[field]
    return found, saw_any_for_target


def poll_zeek_logs(target: str,
                    attempts: int = 6, interval: float = 2.0) -> tuple[dict[str, str | None], bool]:
    """Zeek's log writer doesn't flush every connection to disk
    immediately - conn.log in particular is normally only finalized
    once a connection is torn down (clean FIN or idle timeout), which
    can lag well behind ssl.log's handshake-time write. Poll instead of
    a single fixed sleep, and stop as soon as everything we care about
    has turned up rather than waiting out the full budget regardless.

    window_start is computed once, here, at the start of the whole poll
    loop (not recomputed per attempt) so it doesn't drift forward and
    accidentally exclude the very entry we're waiting on."""
    window_start = time.time() - RECENCY_WINDOW_SECONDS
    wanted = {"ja4s": None, "ja4ts": None, "ja4l": None}
    saw_any_ever = False
    for _ in range(attempts):
        ssl_found, ssl_saw = _scan_json_log(ZEEK_SSL_LOG, target, window_start, ("ja4s",))
        conn_found, conn_saw = _scan_json_log(ZEEK_CONN_LOG, target, window_start, ("ja4ts", "ja4l"))
        saw_any_ever = saw_any_ever or ssl_saw or conn_saw
        for key, value in {**ssl_found, **conn_found}.items():
            if value:
                wanted[key] = value
        if all(wanted.values()):
            return wanted, saw_any_ever
        time.sleep(interval)
    return wanted, saw_any_ever


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
        target = request["target"]
    except Exception as e:
        json.dump({"error": f"bad request: {e}"}, sys.stdout)
        return 1

    found, saw_any = poll_zeek_logs(target)
    response: dict[str, str | None] = {**found, "error": None}
    if not any(found.values()) and not saw_any:
        response["error"] = f"no ssl.log/conn.log entry ever seen for {target}"

    json.dump(response, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
