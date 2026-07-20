"""Runs on the probe VM - a Windows 11 box at 10.20.30.16 in this lab,
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
stdin and writes one JSON object to stdout. Three actions, selected by
the request's "action" field (see cti_tools/vm_proxy.py, the cti-host
side of this protocol, for the full rationale - short version: every
outbound request that names a tracked indicator, active probe or
passive lookup alike, is meant to originate from this VM rather than
the analyst's desktop):

1. "jarm_probe" (default - also selected when "action" is omitted, for
   back-compat with the original single-purpose version of this
   script):

       {"target": "<domain-or-ip>", "port": 443}

   port is optional, defaulting to 443 - the caller
   (probe_pending_fingerprints.py) looks up the actual port a target's
   C2 traffic uses from the cluster's tracked URLs and sends it
   explicitly, since plenty of tracked C2s run on nonstandard ports and
   a hardcoded 443 here would silently fingerprint whatever's on 443
   (or nothing, "connection refused") instead of the real service.
   Responds with:

       {"jarm": "<hash-or-null>", "resolved_ip": "<ip>", "error": null}

2. "http_fetch" - fetch a URL from this VM on the caller's behalf
   (RDAP/RIPEstat/VirusTotal/etc. pivot lookups run through this
   instead of reaching out directly from the cti host):

       {"action": "http_fetch", "url": "...", "method": "GET", "headers": {...}}

   Responds with:

       {"status": 200, "body": "...", "error": null}

3. "resolve_dns" - resolve a hostname from this VM:

       {"action": "resolve_dns", "host": "example.com"}

   Responds with one of:

       {"status": "resolved", "addrs": ["1.2.3.4", ...]}
       {"status": "nxdomain"}
       {"status": "error", "error": "..."}

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
import urllib.error
import urllib.request

import certifi

# --- adjust for your environment --------------------------------------------
JARM_CMD = ["python", r"C:\tools\jarm\jarm.py"]  # salesforce/jarm CLI; swap for yours
HTTP_TIMEOUT = 20
# -----------------------------------------------------------------------------

# Pinned to certifi's CA bundle rather than relying on urllib's platform
# default context - on Windows that walks the OS root store, which lazily
# fetches unseen roots from Windows Update on first use and fails closed
# if this box's egress doesn't reach ctldl.windowsupdate.com.
HTTPS_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_target_ip(target: str) -> str:
    return target if is_ip_literal(target) else socket.gethostbyname(target)


def run_jarm(target: str, port: int) -> str | None:
    proc = subprocess.run([*JARM_CMD, "-p", str(port), target],
                          capture_output=True, text=True, timeout=30)
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if ":" not in line:
        return None
    return line.split(":", 1)[1].strip() or None


def run_tls_handshake(target: str, resolved_ip: str, port: int) -> None:
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
    with socket.create_connection((resolved_ip, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname):
            pass


def run_http_fetch(url: str, method: str, headers: dict[str, str]) -> dict[str, object]:
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=HTTPS_CONTEXT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", errors="replace"), "error": None}
    except urllib.error.URLError as e:
        return {"status": None, "body": None, "error": f"failed to reach {url}: {e.reason}"}
    except (TimeoutError, OSError) as e:
        return {"status": None, "body": None, "error": f"failed to reach {url}: {e}"}


def run_resolve_dns(host: str) -> dict[str, object]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return {"status": "nxdomain"}
    except OSError as e:
        return {"status": "error", "error": str(e)}
    addrs = sorted({info[4][0] for info in infos})
    return {"status": "resolved", "addrs": addrs}


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
        action = request.get("action", "jarm_probe")
    except Exception as e:
        json.dump({"error": f"bad request: {e}"}, sys.stdout)
        return 1

    if action == "http_fetch":
        try:
            result = run_http_fetch(request["url"], request.get("method", "GET"), request.get("headers") or {})
        except Exception as e:
            result = {"status": None, "body": None, "error": f"bad request: {e}"}
        json.dump(result, sys.stdout)
        return 0

    if action == "resolve_dns":
        try:
            result = run_resolve_dns(request["host"])
        except Exception as e:
            result = {"status": "error", "error": f"bad request: {e}"}
        json.dump(result, sys.stdout)
        return 0

    try:
        target = request["target"]
        port = int(request.get("port") or 443)
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
        response["jarm"] = run_jarm(target, port)
    except Exception as e:
        response["error"] = f"jarm failed: {e}"

    try:
        run_tls_handshake(target, resolved_ip, port)
    except Exception as e:
        existing = response.get("error")
        response["error"] = f"{existing}; handshake failed: {e}" if existing else f"handshake failed: {e}"

    json.dump(response, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
