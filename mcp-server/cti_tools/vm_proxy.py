"""Single chokepoint for outbound network activity that touches a
tracked indicator - active fingerprinting AND passive pivot lookups
alike. Every one of those requests is proxied through the Win11 VM at
10.20.0.9 over the same restricted SSH forced-command channel, rather
than originating from the cti host itself: an RDAP/RIPEstat/VirusTotal
lookup on a malicious domain is still traffic that names that domain to
a third party, and the analyst's own desktop IP has no business being
the source of it any more than a live JARM probe would.

Protocol: one JSON object on stdin, one JSON object on stdout, handled
by win_probe_helper.py on the VM (see that module's docstring for the
full request/response shapes per action). Three actions:

- "jarm_probe" (default, back-compat with requests that omit "action"):
  active TLS/JARM fingerprinting - see probe_win().
- "http_fetch": fetch a URL from the VM and return status/body - see
  http_fetch(). What pivot.py's RDAP/RIPEstat/VirusTotal/Cert
  Spotter/Hackertarget lookups now run through instead of calling
  urllib.request.urlopen directly from this host.
- "resolve_dns": DNS resolution performed from the VM - see
  resolve_dns(). What pivot.resolve_host now runs through instead of
  calling socket.getaddrinfo directly from this host.

Same key/host used for all three - the VM-side forced command already
has to trust this key with live network access on the analyst's
behalf, so widening what it's asked to do doesn't widen what it's
trusted to do.
"""
from __future__ import annotations

import json
import subprocess

# --- adjust for your environment --------------------------------------------
WIN_PROBE_USER = "jadmin"
WIN_PROBE_HOST = "10.20.0.9"  # Win11 probe VM's LAN IP/hostname
WIN_SSH_KEY = "/home/axelarator/.ssh/id_ed25519_win_probe"
WIN_KNOWN_HOSTS = "/home/axelarator/.ssh/known_hosts_win_probe"
# Sent as the SSH command but only matters if the probe VM's
# authorized_keys entry for this key does NOT set command=... - if it
# does (recommended, see the skill doc), the forced command wins
# regardless of what's requested here.
WIN_HELPER_CMD = [r"C:\Users\jadmin\AppData\Local\Python\bin\python.exe", r"C:\tools\probe\win_probe_helper.py"]

SSH_TIMEOUT = 60
# -----------------------------------------------------------------------------


class VMProxyError(RuntimeError):
    pass


def _ssh_json_rpc(request: dict[str, object]) -> dict[str, object]:
    proc = subprocess.run(
        ["ssh", "-i", WIN_SSH_KEY,
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={WIN_KNOWN_HOSTS}",
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


def http_fetch(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> dict[str, object]:
    """Fetch url from the VM. Returns {"status": int, "body": str,
    "error": str|None} - status/body are None if error is set."""
    response = _ssh_json_rpc({
        "action": "http_fetch", "url": url, "method": method, "headers": headers or {},
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
