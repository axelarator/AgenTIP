"""The Windows-client vantage: win116, reached over SSH.

The probe VM (`vm_proxy`) sees infrastructure as a Linux scanner does. This
sees it as a Windows machine does - .NET over Schannel with an ordinary
Edge User-Agent - because payload servers gate on exactly that. The runner
on the VM is `probe_vm/win116/win_runner.ps1` (deployed by `deploy.sh`
beside it): one JSON request on stdin, one JSON response on stdout, the same
protocol shape as the probe helper.

Like the probe, win116's VPN terminates at the lab firewall, so every
session it opens is mirrored to Zeek and Arkime.

Connection details come from the environment - nothing about the lab is in
this file, which is public:

  CTI_WIN_HOST         the VM's address (required; unset = vantage unavailable)
  CTI_WIN_USER         SSH user (required)
  CTI_WIN_SSH_KEY      private key (default ~/.ssh/id_ed25519_win_probe)
  CTI_WIN_KNOWN_HOSTS  known_hosts file (default ~/.ssh/known_hosts_win_probe)
  CTI_WIN_RUNNER       runner path on the VM (default C:\\tools\\cti\\win_runner.ps1)
  CTI_WIN_SSH_TIMEOUT  per-call timeout, seconds (default 300)
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from ..errors import VMProxyError

VANTAGE = "win116"
BATCH = 10            # targets per SSH call; each can take the full fetch timeout


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def configured() -> bool:
    return bool(_env("CTI_WIN_HOST") and _env("CTI_WIN_USER"))


def _rpc(request: dict[str, Any], timeout: int | None = None) -> dict[str, Any]:
    if not configured():
        raise VMProxyError("the win116 vantage is not configured - set CTI_WIN_HOST and "
                           "CTI_WIN_USER (see cti/probe/win_proxy.py)")
    key = os.path.expanduser(_env("CTI_WIN_SSH_KEY", "~/.ssh/id_ed25519_win_probe"))
    known = os.path.expanduser(_env("CTI_WIN_KNOWN_HOSTS", "~/.ssh/known_hosts_win_probe"))
    runner = _env("CTI_WIN_RUNNER", r"C:\tools\cti\win_runner.ps1")
    limit = timeout or int(_env("CTI_WIN_SSH_TIMEOUT", "300"))
    cmd = ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={known}",
           f"{_env('CTI_WIN_USER')}@{_env('CTI_WIN_HOST')}",
           f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{runner}"']
    try:
        proc = subprocess.run(cmd, input=json.dumps(request), capture_output=True,
                              text=True, timeout=limit)
    except subprocess.TimeoutExpired as e:
        raise VMProxyError(f"win116 call timed out after {limit}s") from e
    if proc.returncode != 0:
        raise VMProxyError(f"ssh to win116 failed: {proc.stderr.strip()[:300]}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise VMProxyError(f"non-JSON response from win116: {proc.stdout[:200]!r}") from e
    if not result.get("ok"):
        raise VMProxyError(f"win116 runner error: {result.get('error')}")
    return result


def check() -> dict[str, Any]:
    return _rpc({"action": "check"}, timeout=60)


def _canonical_subject(dn: str | None) -> str | None:
    """.NET writes the state attribute as `S=`; everything else in this
    store writes `ST=`. Same certificate, so one spelling."""
    if not dn:
        return dn
    parts = [p.strip() for p in dn.split(",")]
    return ", ".join("ST=" + p[2:] if p.startswith("S=") else p for p in parts)


def shape(raw: dict[str, Any]) -> dict[str, Any]:
    """One runner result as an observe-shaped dict, so observe.selectors_from
    applies the same rules to it as to the probe's."""
    cert = raw.get("cert") or {}
    subject = _canonical_subject(cert.get("subject_dn"))
    http = {}
    if raw.get("status") is not None:
        http = {"status": raw["status"], "title": raw.get("title"),
                "server": raw.get("server"), "body_sha256": raw.get("body_sha256"),
                "headers": raw.get("headers") or {}, "final_url": raw.get("final_url")}
    tls = {}
    if cert.get("sha256"):
        tls = {"cert_sha256": cert["sha256"], "subject_dn": subject,
               "issuer": _canonical_subject(cert.get("issuer")),
               "serial": cert.get("serial"), "sans": cert.get("sans") or [],
               "not_before": cert.get("not_before"), "not_after": cert.get("not_after")}
    return {"target": raw.get("target"), "url": raw.get("url"), "http": http, "tls": tls,
            "dns": {}, "whois": {}, "cdn": {}, "errors": (
                {"http": raw["error"]} if raw.get("error") else {}),
            "error": raw.get("error")}


def fetch(targets: list[dict[str, str]], *, timeout: int = 15) -> list[dict[str, Any]]:
    """GET each {target, url} from win116. Returns observe-shaped results in
    order; a target the runner could not reach carries `error`."""
    out: list[dict[str, Any]] = []
    for i in range(0, len(targets), BATCH):
        chunk = targets[i:i + BATCH]
        result = _rpc({"action": "fetch", "targets": chunk, "timeout": timeout},
                      timeout=max(120, (timeout + 10) * len(chunk) * 2))
        out.extend(shape(r) for r in result.get("results") or [])
    return out
