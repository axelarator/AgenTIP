"""Single chokepoint for outbound network activity that touches a
tracked indicator - active fingerprinting AND passive pivot lookups
alike. Every one of those requests is proxied through the Win11 VM at
10.20.30.16 over the same restricted SSH forced-command channel, rather
than originating from the cti host itself: an RDAP/RIPEstat/VirusTotal
lookup on a malicious domain is still traffic that names that domain to
a third party, and the analyst's own desktop IP has no business being
the source of it any more than a live JARM probe would.

Protocol: one JSON object on stdin, one JSON object on stdout, handled
by win_probe_helper.py on the VM (see that module's docstring for the
full request/response shapes per action). Four actions:

- "jarm_probe" (default, back-compat with requests that omit "action"):
  active TLS/JARM fingerprinting - see probe_win().
- "http_fetch": fetch a URL from the VM and return status/body - see
  http_fetch(). What pivot.py's RDAP/RIPEstat/VirusTotal/Cert
  Spotter/Hackertarget/ThreatFox lookups now run through instead of
  calling urllib.request.urlopen directly from this host. Accepts an
  optional "data" body for POST requests (e.g. ThreatFox's JSON query
  API), passed through as-is to urllib.request.Request.
- "resolve_dns": DNS resolution performed from the VM - see
  resolve_dns(). What pivot.resolve_host now runs through instead of
  calling socket.getaddrinfo directly from this host.
- "resolve_ptr": reverse-DNS (PTR) lookup performed from the VM - see
  resolve_ptr(). What pivot.ptr_lookup runs through instead of calling
  socket.gethostbyaddr directly from this host.

Same key/host used for all four - the VM-side forced command already
has to trust this key with live network access on the analyst's
behalf, so widening what it's asked to do doesn't widen what it's
trusted to do.
"""
from __future__ import annotations

import json
import os
import subprocess

# --- adjust for your environment --------------------------------------------
WIN_PROBE_USER = "detonate"
WIN_PROBE_HOST = "10.20.30.16"  # Win11 probe VM's LAN IP/hostname
WIN_SSH_KEY = os.path.expanduser("~/.ssh/id_ed25519_win_probe")
WIN_KNOWN_HOSTS = os.path.expanduser("~/.ssh/known_hosts_win_probe")
# Sent as the SSH command but only matters if the probe VM's
# authorized_keys entry for this key does NOT set command=... - if it
# does (recommended, see the skill doc), the forced command wins
# regardless of what's requested here.
WIN_HELPER_CMD = [r"C:\Users\detonate\AppData\Local\Programs\Python\Python312\python.exe", r"C:\tools\probe\win_probe_helper.py"]

SSH_TIMEOUT = 60
# Reuse one already-authenticated connection across calls instead of paying
# a fresh TCP handshake + SSH key exchange + pubkey auth on every single
# pivot/probe lookup - each _ssh_json_rpc call still opens its own channel
# on that connection (and so still starts its own instance of the forced
# remote command; this isn't a persistent server on the far end), but the
# expensive setup happens once per ControlPersist window instead of once
# per call. This mattered less when this host was an analyst desktop
# reaching the lab over a VPN/home-LAN hop, where the SSH setup cost was
# small next to the link's own latency; now that this runs as a VM
# colocated on the same lab server as the probe VM, that per-call setup
# overhead is proportionally the dominant cost for anything that isn't
# already latency-bound server-side (JARM's own scan time, Zeek's
# indexing lag) - i.e. exactly the plain pivot lookups (RDAP/RIPEstat/
# VT/CertSpotter/Hackertarget/resolve_dns/http_fetch), which are single
# round trips with no server-side wait built in.
WIN_SSH_CONTROL_PATH = os.path.expanduser("~/.ssh/cti-vm-proxy-control.sock")
WIN_SSH_CONTROL_PERSIST = "300"  # seconds the shared connection is kept warm after the last use
# -----------------------------------------------------------------------------


class VMProxyError(RuntimeError):
    pass


def _ssh_json_rpc(request: dict[str, object]) -> dict[str, object]:
    proc = subprocess.run(
        ["ssh", "-i", WIN_SSH_KEY,
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={WIN_KNOWN_HOSTS}",
         "-o", "ControlMaster=auto",
         "-o", f"ControlPersist={WIN_SSH_CONTROL_PERSIST}",
         "-o", f"ControlPath={WIN_SSH_CONTROL_PATH}",
         f"{WIN_PROBE_USER}@{WIN_PROBE_HOST}", *WIN_HELPER_CMD],
        input=json.dumps(request), capture_output=True, text=True, timeout=SSH_TIMEOUT)
    if proc.returncode != 0 and not proc.stdout:
        raise VMProxyError(f"ssh transport to {WIN_PROBE_HOST!r} failed: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise VMProxyError(f"non-JSON response from {WIN_PROBE_HOST!r}: {proc.stdout!r}") from e


def probe_win(target: str, port: int) -> dict[str, object]:
    return _ssh_json_rpc({"action": "jarm_probe", "target": target, "port": port})


def http_fetch(url: str, headers: dict[str, str] | None = None, method: str = "GET",
                data: str | None = None, insecure: bool = False) -> dict[str, object]:
    """Fetch url from the VM. Returns {"status": int, "body": str,
    "error": str|None} - status/body are None if error is set. `data`,
    when given, is sent as the request body (e.g. a POST endpoint like
    ThreatFox's JSON query API) - omit it for a plain GET. `insecure`
    (default False) skips TLS certificate verification on the VM side -
    leave it False for every normal pivot lookup (RDAP/RIPEstat/VT/
    ThreatFox all hit legitimate services and should fail closed on a
    bad cert); only pass True for a deliberate check against
    infrastructure already confirmed adversary-controlled, where a
    self-signed cert is expected and shouldn't block the request."""
    response = _ssh_json_rpc({
        "action": "http_fetch", "url": url, "method": method, "headers": headers or {},
        "data": data, "insecure": insecure,
    })
    if response.get("error"):
        raise VMProxyError(str(response["error"]))
    return response


def resolve_dns(host: str) -> list[str] | None:
    """DNS resolution performed on the VM. Returns the raw address list
    on success, [] for a definitive non-resolution (NXDOMAIN), or None
    for an inconclusive lookup (resolver error) - same three-way
    contract as pivot.resolve_host, which layers its own
    sinkhole/null-route filtering on top of whatever this returns."""
    response = _ssh_json_rpc({"action": "resolve_dns", "host": host})
    status = response.get("status")
    if status == "resolved":
        return list(response.get("addrs") or [])
    if status == "nxdomain":
        return []
    return None


def resolve_ptr(ip: str) -> str | None:
    """Reverse-DNS (PTR) hostname for `ip`, resolved on the VM. Returns
    the hostname string on success, or None if the IP has a confirmed
    absent PTR record (status='no_ptr' - common, not a failure). Unlike
    resolve_dns, an inconclusive lookup raises VMProxyError rather than
    also returning None, so pivot.ptr_lookup's caller can tell "no PTR
    configured" (real, recordable data) apart from "couldn't check
    right now" (skip, don't record) using the same isinstance(...)/
    "error" gating every other enrichment source already uses."""
    response = _ssh_json_rpc({"action": "resolve_ptr", "ip": ip})
    status = response.get("status")
    if status == "resolved":
        return response.get("hostname")
    if status == "no_ptr":
        return None
    raise VMProxyError(str(response.get("error") or "PTR lookup failed"))
