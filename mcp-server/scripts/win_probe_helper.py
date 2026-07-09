"""Runs on the probe VM - a Windows 11 box at 10.20.0.9 in this lab,
sitting as an ordinary port on the same mirrored bridge as every other
lab VM (not the Zeek sensor itself - see zeek_log_query.py's docstring
for why that distinction matters). The active half of the fingerprinting
handoff: probe_pending_fingerprints.py on the cti host calls this to
generate real traffic against a target, then separately calls
zeek_log_query.py on the Zeek VM to read back whatever got logged. See
the threat-cluster-tracking skill's "Automating the handoff" section.

Standalone - not part of the cti_tools package, pure standard library
(no openssl.exe dependency - uses Python's own ssl/socket modules so
this runs the same way regardless of what's installed on the box
beyond Python itself and your JARM tool). Reads one JSON object from
stdin:

    {"target": "<domain-or-ip>"}

and writes one JSON object to stdout:

    {"jarm": "<hash-or-null>", "resolved_ip": "<ip>", "error": null}

resolved_ip gets handed straight back to probe_pending_fingerprints.py,
which passes it on to zeek_log_query.py - Zeek's id.resp_h is always an
IP, never a hostname. Resolved once here and reused for the handshake
itself (not re-resolved) so the IP reported back is guaranteed to be
the one actually connected to - some targets (e.g. anycast/CDN-fronted
domains) can return a different A record on a second, separate lookup
moments later, which would otherwise silently point the Zeek query at
an IP nothing was ever sent to.

No since_ts either: an earlier version tried to anchor the Zeek-side
log search to a timestamp taken on this VM's clock, but this VM and the
Zeek VM aren't NTP-synced against each other, so a foreign wall-clock
value is meaningless compared against Zeek's own ts field. Zeek-side
recency is now handled entirely with the Zeek VM's own local clock -
see zeek_log_query.py.

Only runs a JARM scan and one ordinary TLS handshake (the handshake's
result is discarded - it exists purely to give Zeek something real to
fingerprint via ja4s/ja4ts/ja4l, read back separately). Same
client-vs-responder reasoning as the rest of this pipeline applies:
ja4/ja4h/ja4t aren't collected anywhere in this flow since they'd only
ever reflect this probe VM's own signature, not the target's.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import subprocess
import sys

# --- adjust for your environment --------------------------------------------
JARM_CMD = ["python", r"C:\tools\jarm\jarm.py"]  # salesforce/jarm CLI; swap for yours
# -----------------------------------------------------------------------------


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_target_ip(target: str) -> str:
    return target if is_ip_literal(target) else socket.gethostbyname(target)


def run_jarm(target: str) -> str | None:
    proc = subprocess.run([*JARM_CMD, target], capture_output=True, text=True, timeout=30)
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if ":" not in line:
        return None
    return line.split(":", 1)[1].strip() or None


def run_tls_handshake(target: str, resolved_ip: str) -> None:
    """Just puts one ordinary handshake on the wire - result intentionally
    discarded, Zeek's log (read separately, on the Zeek VM) is the
    source of truth for what came back. Connects to resolved_ip
    directly (not target) so this can't silently hit a different IP
    than the one reported back to the caller - see the module
    docstring."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_hostname = None if is_ip_literal(target) else target
    with socket.create_connection((resolved_ip, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname):
            pass


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
        target = request["target"]
    except Exception as e:
        json.dump({"error": f"bad request: {e}"}, sys.stdout)
        return 1

    response: dict[str, object] = {"jarm": None, "resolved_ip": None, "error": None}
    try:
        resolved_ip = resolve_target_ip(target)
        response["resolved_ip"] = resolved_ip
    except Exception as e:
        json.dump({"error": f"DNS resolution failed for {target!r}: {e}"}, sys.stdout)
        return 1

    try:
        response["jarm"] = run_jarm(target)
    except Exception as e:
        response["error"] = f"jarm failed: {e}"

    try:
        run_tls_handshake(target, resolved_ip)
    except Exception as e:
        existing = response.get("error")
        response["error"] = f"{existing}; handshake failed: {e}" if existing else f"handshake failed: {e}"

    json.dump(response, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
