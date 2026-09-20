"""Client for the probe VM's provisioning command.

Separate from `vm_proxy` on purpose. That module speaks to the probe helper
with one key; this speaks to `cti-provision` with a different key pinned to
a different forced command. Keeping them apart means a bug here cannot
accidentally borrow the helper's credential, and the two grants stay
legible: one runs observations, one installs scanners.

## What this can and cannot do

`cti-provision` installs named tools from an allowlist baked into the
script on the VM, and reports status. It has no verb that writes code.
Updating probe_helper.py or the sandbox image still goes through
setup_probe_vm.sh, run by a human who has read the diff - which is the
review step worth keeping, because a helper update is arbitrary code
running as the probe user.
"""
from __future__ import annotations

import os
import shlex
import subprocess

from ..errors import VMProxyError
from . import vm_proxy

# Its own key. Defaulting to a path that will simply not exist until the key
# is installed is deliberate: provisioning should fail closed and say so.
PROVISION_SSH_KEY = os.path.expanduser(
    os.environ.get("CTI_PROVISION_SSH_KEY", "~/.ssh/id_ed25519_cti_provision"))

PROVISION_TIMEOUT = int(os.environ.get("CTI_PROVISION_TIMEOUT", "900"))

# Mirrors the allowlist in probe_vm/cti-provision. Duplicated deliberately:
# the VM's copy is the one that enforces, this one only gives a clear local
# error instead of a round trip that ends in "not in the allowlist".
TOOLS = ("whois", "dnsutils", "nmap", "openssl",
         "httpx", "tlsx", "dnsx", "naabu", "cdncheck", "asnmap")


def _run(request: str, *, timeout: int | None = None) -> str:
    if not os.path.exists(PROVISION_SSH_KEY):
        raise VMProxyError(
            f"no provisioning key at {PROVISION_SSH_KEY} - this is the second "
            "key, separate from the probe key, and it has to be installed on "
            "the VM against the cti-provision forced command first")
    proc = subprocess.run(
        ["ssh", "-i", PROVISION_SSH_KEY,
         "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={vm_proxy.PROBE_KNOWN_HOSTS}",
         f"{vm_proxy.PROBE_USER}@{vm_proxy.PROBE_HOST}", request],
        capture_output=True, text=True,
        timeout=timeout if timeout is not None else PROVISION_TIMEOUT)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 and not proc.stdout:
        raise VMProxyError(
            f"cti-provision {request!r} failed ({proc.returncode}): "
            f"{output.strip()[:400]}")
    return output.strip()


def status() -> str:
    """What is installed on the probe VM. Read-only."""
    return _run("status")


def install(tool: str = "all") -> str:
    """Install one allowlisted tool, or every one of them.

    The VM enforces the allowlist; this checks locally only so a typo fails
    immediately rather than after an SSH round trip.
    """
    if tool != "all" and tool not in TOOLS:
        raise ValueError(
            f"{tool!r} is not in the provisioning allowlist. "
            f"Allowed: {', '.join(TOOLS)}, or 'all'. Adding one means "
            "deploying a new cti-provision to the VM, which is the review step.")
    return _run(f"install {shlex.quote(tool)}")


def update(tool: str) -> str:
    """Reinstall a Go tool at its latest version."""
    return _run(f"update {shlex.quote(tool)}")


def missing_tools() -> list[str]:
    """Which observe-pass tools the VM does not have.

    Reads the status output rather than trusting a cached idea of the VM's
    state, so a VM rebuilt underneath us is noticed.
    """
    try:
        text = status()
    except VMProxyError:
        return list(TOOLS)
    absent = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in TOOLS and parts[1] == "missing":
            absent.append(parts[0])
    return absent
