"""Runs on the cti host itself - drains the pending-fingerprints queue
and drives two separate remote helpers to fill it in. See the
threat-cluster-tracking skill's "Automating the handoff" section.

Two hops per target, not one, because probing and log-reading now live
on two different VMs:

  1. win_probe_helper.py on the Win11 probe VM (10.20.0.9) - generates
     a JARM scan and one ordinary TLS handshake against the target.
  2. zeek_log_query.py on the Zeek sensor VM (10.20.0.7) - reads back
     whatever that handshake produced in ssl.log/conn.log.

They used to be one combined script running directly on the Zeek VM,
until testing showed that VM's own self-generated traffic doesn't get
mirrored the same clean way third-party VMs' traffic does (a probe
launched from the sensor's own interface came back as a one-sided
ghost connection - response visible, outbound SYN never mirrored back
to itself). A dedicated probe VM sitting as an ordinary port on the
same mirrored bridge doesn't have that problem.

Direction matters here too: the OPNsense LAN (VLAN30, where both VMs
live) is firewalled so it can never connect back out to the cti host's
home-LAN segment - that's deliberate lab hygiene, not an accident to
route around. So this script runs as part of the cti_tools package (it
imports core.py directly - no SSH server on this end, no network
listener accepting anything inbound) and *initiates* both SSH
connections itself, outbound into the lab, either over the OPNsense
Tailscale subnet route or the direct home-LAN<->VLAN30 route - either
works, nothing here cares which one wins.

Usage (run manually, or on a cron/systemd timer):

    python3 probe_pending_fingerprints.py

Requires: cti_tools importable (run from within the mcp-server venv/repo
checkout), and SSH keypairs authorized to reach both remote VMs.
"""
from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti_tools import core  # noqa: E402

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

ZEEK_USER = "zeek"
ZEEK_HOST = "10.20.0.7"  # Zeek sensor VM's LAN IP/hostname
ZEEK_SSH_KEY = "/home/axelarator/.ssh/id_ed25519_lab_probe"
ZEEK_KNOWN_HOSTS = "/home/axelarator/.ssh/known_hosts_lab_probe"
ZEEK_HELPER_CMD = ["python3", "/opt/zeek_log_query.py"]

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
    C2 running on a nonstandard port. Scans the cluster's tracked URLs
    for one whose host matches target and pulls its port; falls back to
    443 if nothing matches.

    Also matches target against "{target}.sslip.io" and vice versa,
    since sslip.io wildcard-DNS hostnames literally encode the IP in the
    name - a queued bare-IP entry should still find the port from its
    own sslip.io hostname's tracked URL."""
    try:
        data = core.load_cluster(cluster)
    except Exception:
        return 443
    needle = target.strip().lower()
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


def _ssh_json_rpc(user: str, host: str, key: str, known_hosts: str,
                   remote_cmd: list[str], request: dict[str, object]) -> dict[str, object]:
    proc = subprocess.run(
        ["ssh", "-i", key,
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={known_hosts}",
         f"{user}@{host}", *remote_cmd],
        input=json.dumps(request), capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and not proc.stdout:
        raise ProbeError(f"ssh transport to {host!r} failed: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ProbeError(f"non-JSON response from {host!r}: {proc.stdout!r}") from e


def probe_win(target: str, port: int) -> dict[str, object]:
    return _ssh_json_rpc(WIN_PROBE_USER, WIN_PROBE_HOST, WIN_SSH_KEY, WIN_KNOWN_HOSTS,
                          WIN_HELPER_CMD, {"target": target, "port": port})


def query_zeek(resolved_ip: str) -> dict[str, object]:
    return _ssh_json_rpc(ZEEK_USER, ZEEK_HOST, ZEEK_SSH_KEY, ZEEK_KNOWN_HOSTS,
                          ZEEK_HELPER_CMD, {"target": resolved_ip})


def main() -> None:
    queue = core.pop_pending_fingerprints()
    if not queue:
        return

    today = datetime.date.today().isoformat()
    for entry in queue:
        cluster, target = entry["cluster"], entry["value"]
        port = _lookup_port(cluster, target)

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
            zeek_result = query_zeek(resolved_ip)
        except ProbeError as e:
            print(f"zeek log query failed for {target!r} ({resolved_ip}): {e}", file=sys.stderr)
            continue
        if zeek_result.get("error"):
            print(f"zeek log query reported an error for {target!r}: {zeek_result['error']}", file=sys.stderr)

        for category in ("ja4s", "ja4ts", "ja4l"):
            value = zeek_result.get(category)
            if value:
                core.add_observable(cluster, category, value,
                                     f"Zeek passive (tap107) via {SOURCE_LABEL} handshake against "
                                     f"{target}:{port} ({resolved_ip}), {today}")


if __name__ == "__main__":
    main()
