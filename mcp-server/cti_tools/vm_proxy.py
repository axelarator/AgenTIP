"""Single chokepoint for outbound network activity that touches a
tracked indicator - active fingerprinting AND passive lookups alike.
Every one of those requests is proxied through the lab probe VM over a
restricted SSH forced-command channel, rather than originating from the
cti host itself: an RDAP/RIPEstat lookup on a malicious domain is still
traffic that names that domain to a third party, and a live TLS/HTTP
grab or nmap/dirsearch run reaches the adversary's own infrastructure -
all of it belongs on the lab VM (VPN egress, mirrored to Zeek/Arkime),
never on whatever host the MCP server itself runs on.

Webamon and HoneyLabs lookups are the deliberate exceptions - they hit
those vendors' SaaS, not the indicator's own infrastructure, and are
called directly from the host (see cti_tools/webamon.py, tracking/hl_mcp.py).

Connection details come from the environment so the same code runs
against whatever probe VM the lab currently uses (a Linux box now; a
Windows box historically) without editing this file:

  CTI_PROBE_HOST         probe VM's LAN IP/hostname
  CTI_PROBE_USER         SSH user
  CTI_PROBE_SSH_KEY      private key path (~ expanded)
  CTI_PROBE_KNOWN_HOSTS  known_hosts file for StrictHostKeyChecking
  CTI_PROBE_HELPER_CMD   remote command that runs the helper (shell-split);
                         defaults to `python3 /opt/cti/probe_helper.py`
  CTI_PROBE_SSH_TIMEOUT  per-call SSH timeout for the quick actions (s)
  CTI_PROBE_LONG_TIMEOUT SSH timeout for the long actions (nmap/dirsearch, s)

Protocol: one JSON object on stdin, one JSON object on stdout, handled
by probe_helper.py on the VM (see that module for the full request/
response shapes per action). Actions:

- "jarm_probe" (default, back-compat with requests that omit "action"):
  active TLS/JARM fingerprinting - see probe_jarm().
- "http_fetch": fetch a URL from the VM, return status/body - what
  pivot.py's RDAP/RIPEstat/ThreatFox lookups run through instead of
  calling urllib directly from this host. Accepts an optional "data"
  body for POST (e.g. ThreatFox's JSON query API).
- "resolve_dns" / "resolve_ptr": DNS / reverse-DNS from the VM - what
  pivot.resolve_host / pivot.ptr_lookup run through.
- "dns_lookup": multi-record-type DNS (A/AAAA/MX/NS/TXT) from the VM.
- "tls_grab": one live TLS handshake, returning the peer certificate
  (sha256/issuer/subject/SANs/validity) - the live replacement for
  Cert Spotter's CT-log cert lookup, current as of the moment checked.
- "http_probe": one HTTP(S) GET, returning status/title/server/final
  URL plus any autoindex (open-directory) listing detected at that URL.
- "subfinder": passive subdomain enumeration for a domain.
- "wayback_cdx": historical URLs/subdomains from the Wayback Machine.
- "nmap": top-ports service scan (on-demand only - long).
- "dirsearch": web path map + recursive open-directory listing
  (on-demand only - long).

Same key/host for every action - the VM-side forced command already
has to trust this key with live network access on the analyst's behalf,
so widening what it's asked to do doesn't widen what it's trusted to do.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

# --- probe VM connection (from the environment - see module docstring) ------
PROBE_USER = os.environ.get("CTI_PROBE_USER", "detonate")
PROBE_HOST = os.environ.get("CTI_PROBE_HOST", "10.20.30.16")
PROBE_SSH_KEY = os.path.expanduser(
    os.environ.get("CTI_PROBE_SSH_KEY", "~/.ssh/id_ed25519_probe"))
PROBE_KNOWN_HOSTS = os.path.expanduser(
    os.environ.get("CTI_PROBE_KNOWN_HOSTS", "~/.ssh/known_hosts_probe"))
# Sent as the SSH command but only matters if the VM's authorized_keys
# entry for this key does NOT set command=... - if it does (recommended,
# see the skill doc), the forced command wins regardless of what's here.
PROBE_HELPER_CMD = (shlex.split(os.environ.get("CTI_PROBE_HELPER_CMD", ""))
                    or ["python3", "/opt/cti/probe_helper.py"])

# Per-call SSH timeout. The quick actions (pivots, DNS, one TLS/HTTP grab)
# finish in seconds; nmap/dirsearch can run for many minutes, so those pass
# LONG_TIMEOUT explicitly. This is a synchronous, analyst-initiated path -
# a blocking multi-minute SSH channel is acceptable and much simpler than a
# job server on the VM.
SSH_TIMEOUT = int(os.environ.get("CTI_PROBE_SSH_TIMEOUT", "60"))
LONG_TIMEOUT = int(os.environ.get("CTI_PROBE_LONG_TIMEOUT", "900"))

# Reuse one already-authenticated connection across calls instead of paying
# a fresh TCP handshake + SSH key exchange + pubkey auth on every lookup -
# each _ssh_json_rpc call still opens its own channel (and so its own
# instance of the forced remote command; this isn't a persistent server on
# the far end), but the expensive setup happens once per ControlPersist
# window. This matters most for the plain single-round-trip pivots
# (RDAP/RIPEstat/resolve_dns/http_fetch/tls_grab), where per-call SSH setup
# would otherwise dominate wall time.
SSH_CONTROL_PATH = os.path.expanduser(
    os.environ.get("CTI_PROBE_CONTROL_PATH", "~/.ssh/cti-vm-proxy-control.sock"))
SSH_CONTROL_PERSIST = os.environ.get("CTI_PROBE_CONTROL_PERSIST", "300")
# ----------------------------------------------------------------------------


class VMProxyError(RuntimeError):
    pass


def _ssh_json_rpc(request: dict[str, object], timeout: int | None = None) -> dict[str, object]:
    proc = subprocess.run(
        ["ssh", "-i", PROBE_SSH_KEY,
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={PROBE_KNOWN_HOSTS}",
         "-o", "ControlMaster=auto",
         "-o", f"ControlPersist={SSH_CONTROL_PERSIST}",
         "-o", f"ControlPath={SSH_CONTROL_PATH}",
         f"{PROBE_USER}@{PROBE_HOST}", *PROBE_HELPER_CMD],
        input=json.dumps(request), capture_output=True, text=True,
        timeout=timeout if timeout is not None else SSH_TIMEOUT)
    if proc.returncode != 0 and not proc.stdout:
        raise VMProxyError(f"ssh transport to {PROBE_HOST!r} failed: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise VMProxyError(f"non-JSON response from {PROBE_HOST!r}: {proc.stdout!r}") from e


def probe_jarm(target: str, port: int) -> dict[str, object]:
    return _ssh_json_rpc({"action": "jarm_probe", "target": target, "port": port})


# Back-compat alias: probe_pending_fingerprints.py calls vm_proxy.probe_win.
probe_win = probe_jarm


def http_fetch(url: str, headers: dict[str, str] | None = None, method: str = "GET",
                data: str | None = None, insecure: bool = False) -> dict[str, object]:
    """Fetch url from the VM. Returns {"status": int, "body": str,
    "error": str|None} - status/body are None if error is set. `data`,
    when given, is sent as the request body (e.g. ThreatFox's POST JSON
    query API). `insecure` (default False) skips TLS verification on the
    VM side - only for a deliberate check against infrastructure already
    confirmed adversary-controlled where a self-signed cert is expected."""
    response = _ssh_json_rpc({
        "action": "http_fetch", "url": url, "method": method, "headers": headers or {},
        "data": data, "insecure": insecure,
    })
    if response.get("error"):
        raise VMProxyError(str(response["error"]))
    return response


def resolve_dns(host: str) -> list[str] | None:
    """DNS resolution on the VM. Returns the raw address list on success,
    [] for a definitive non-resolution (NXDOMAIN), or None for an
    inconclusive lookup - same three-way contract as pivot.resolve_host."""
    response = _ssh_json_rpc({"action": "resolve_dns", "host": host})
    status = response.get("status")
    if status == "resolved":
        return list(response.get("addrs") or [])
    if status == "nxdomain":
        return []
    return None


def resolve_ptr(ip: str) -> str | None:
    """Reverse-DNS (PTR) hostname for `ip`, resolved on the VM. Returns
    the hostname on success, None for a confirmed-absent PTR record
    (status='no_ptr'). An inconclusive lookup raises VMProxyError so
    pivot.ptr_lookup's caller can tell "no PTR configured" (recordable)
    apart from "couldn't check right now" (skip)."""
    response = _ssh_json_rpc({"action": "resolve_ptr", "ip": ip})
    status = response.get("status")
    if status == "resolved":
        return response.get("hostname")
    if status == "no_ptr":
        return None
    raise VMProxyError(str(response.get("error") or "PTR lookup failed"))


def dns_lookup(host: str, types: list[str] | None = None) -> dict[str, object]:
    """Multi-record-type DNS from the VM. Returns
    {"records": {"A": [...], "AAAA": [...], ...}, "error": str|None}."""
    return _ssh_json_rpc({"action": "dns_lookup", "host": host,
                          "types": types or ["A", "AAAA", "MX", "NS", "TXT"]})


def tls_grab(host: str, port: int = 443) -> dict[str, object]:
    """One live TLS handshake from the VM, returning the peer certificate:
    {"cert": {"sha256","issuer","subject","sans":[...],"not_before",
    "not_after","protocol"}, "resolved_ip": str, "error": str|None}.
    The current-cert replacement for Cert Spotter's CT-log lookup."""
    return _ssh_json_rpc({"action": "tls_grab", "host": host, "port": port})


def http_probe(url: str, insecure: bool = False) -> dict[str, object]:
    """One HTTP(S) GET from the VM: {"status","final_url","title","server",
    "content_type","body_sha256","autoindex": {...}|None, "error"}.
    A browser-like visit - the automatic-sweep liveness/tech check."""
    return _ssh_json_rpc({"action": "http_probe", "url": url, "insecure": insecure})


def subfinder(domain: str) -> dict[str, object]:
    """Passive subdomain enumeration on the VM:
    {"subdomains": [...], "error": str|None}."""
    return _ssh_json_rpc({"action": "subfinder", "domain": domain})


def wayback_cdx(domain: str) -> dict[str, object]:
    """Historical URLs/subdomains from the Wayback Machine, fetched from
    the VM: {"urls": [...], "subdomains": [...], "error": str|None}."""
    return _ssh_json_rpc({"action": "wayback_cdx", "domain": domain})


def nmap(target: str, top_ports: int = 100, service_detection: bool = True) -> dict[str, object]:
    """Top-ports service scan from the VM (on-demand, long):
    {"ports": [{"port","proto","service","product","version"}],
    "resolved_ip": str, "error": str|None}."""
    return _ssh_json_rpc(
        {"action": "nmap", "target": target, "top": top_ports, "sv": service_detection},
        timeout=LONG_TIMEOUT)


def dirsearch(url: str, extensions: list[str] | None = None, rate: int = 20,
              max_depth: int = 3, max_files: int = 2000) -> dict[str, object]:
    """Web path map + recursive open-directory listing from the VM
    (on-demand, long): {"hits": [{"path","status","size"}],
    "opendirs": [{"url","files":[{"name","size","mtime","href"}]}],
    "baseline_404": {...}, "error": str|None}."""
    return _ssh_json_rpc({
        "action": "dirsearch", "url": url,
        "extensions": extensions or ["php", "html", "js", "json", "txt", "bak", "zip"],
        "rate": rate, "max_depth": max_depth, "max_files": max_files,
    }, timeout=LONG_TIMEOUT)
