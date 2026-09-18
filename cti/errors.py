"""Every error type and the one result-shape predicate they replace.

The old tree answered "did this source fail?" four different ways:
core._is_soft_failure, core._norm_live, an inline `"error" not in x`
guard repeated seventeen times, and pivot's raise-then-catch-into-a-dict.
Three of those disagreed about what a failure looked like, which is how a
run where every RIPEstat sub-call failed got cached as if it were the
answer (see _is_soft_failure's history below). One predicate now, used
everywhere.
"""
from __future__ import annotations

from typing import Any


class ClusterNotFound(KeyError):
    """No cluster JSON under this name."""


class TrackingBusy(RuntimeError):
    """DuckDB's write lock is held by another process.

    DuckDB is process-exclusive for read-write, so the daily cron holding
    the lock is a normal condition, not a bug. MCP-facing callers turn
    this into an error dict rather than raising at the agent.
    """


class VMProxyError(RuntimeError):
    """The SSH hop to the probe VM failed, or the helper returned garbage."""


class ProbeError(RuntimeError):
    """A probe action ran but could not produce a fingerprint."""


class SandboxError(RuntimeError):
    """The probe VM's analysis container failed to run or returned garbage."""


def is_failure(result: Any) -> bool:
    """True for a source result that reports failure instead of raising.

    Sources signal failure two ways: a top-level "error", or a per-sub-call
    "<name>_error" (ripestat returns one per sub-call so a partial answer
    still comes back). Only the first used to count, so a run where every
    RIPEstat sub-call failed cached {"network_info_error": ...} as if it
    were the answer - and for the whole TTL afterwards every sweep reported
    the IP as "unknown" with no error anywhere to explain it. Seen for real
    when the MCP server started without CTI_PROBE_* set and passed the
    literal "${CTI_PROBE_HOST}" to ssh.
    """
    if not isinstance(result, dict):
        return False
    return any(k == "error" or str(k).endswith("_error") for k in result)


def ok(result: Any) -> bool:
    """Inverse of is_failure, for the `if ok(r):` call sites that read
    better positively. Replaces the inline `isinstance(x, dict) and
    "error" not in x` guard."""
    return isinstance(result, dict) and not is_failure(result)


def normalize_probe(result: Any) -> dict[str, Any]:
    """Normalize a vm_proxy live-grab response (tls_grab/http_probe/
    dns_lookup), which always carries an `error` key - None on success -
    into the {...} | {"error": ...} shape every consumer gates on. Drops
    the `error: None` key on success so a good result isn't misread as a
    failure or refused by the cache."""
    if not isinstance(result, dict):
        return {"error": "unexpected probe response"}
    if result.get("error"):
        return {"error": str(result["error"])}
    return {k: v for k, v in result.items() if k != "error"}
