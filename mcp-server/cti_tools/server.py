"""MCP server for threat cluster tracking.

Wraps core.py behind the MCP protocol so harnesses with native MCP
support (Claude Code, GitHub Copilot / VS Code) can call these as
structured tools. Pi's core loop doesn't speak MCP directly — use
cli.py via the Bash tool there instead, or an MCP-capable Pi extension
if you've installed one. Both surfaces hit the same JSON store.

Run:
    python -m cti_tools.server
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import core

mcp = FastMCP("cti-tools")


@mcp.tool()
def list_clusters() -> list[str]:
    """List the names of all tracked threat clusters."""
    return core.list_clusters()


@mcp.tool()
def get_cluster(name: str) -> dict:
    """Get the full profile for a threat cluster by name."""
    return core.get_cluster(name)


@mcp.tool()
def create_cluster(name: str, description: str = "") -> dict:
    """Create a new threat cluster profile. Fails if one already exists."""
    return core.create_cluster(name, description)


@mcp.tool()
def update_profile(name: str, adversary: str | None = None,
                    capability: str | None = None,
                    infrastructure: str | None = None,
                    victim: str | None = None,
                    aliases: list[str] | None = None,
                    confidence: int | None = None,
                    first_seen: str | None = None,
                    last_seen: str | None = None) -> dict:
    """Update Diamond Model corners and/or STIX profile metadata
    (aliases, confidence 0-100, first_seen, last_seen). Only fields
    you pass are changed."""
    return core.update_profile(name, adversary, capability, infrastructure,
                                victim, aliases, confidence, first_seen, last_seen)


@mcp.tool()
def update_ttp(name: str, technique_id: str, technique_name: str,
                status: int, notes: str = "") -> dict:
    """Upsert an ATT&CK technique's coverage status (0-4) on a cluster."""
    return core.update_ttp(name, technique_id, technique_name, status, notes)


@mcp.tool()
def append_hunt_log(name: str, entry: str) -> dict:
    """Append an entry to a cluster's hunt log. Append-only, never edits."""
    return core.append_hunt_log(name, entry)


@mcp.tool()
def add_detection(name: str, detection_id: str, description: str,
                   status: str = "draft") -> dict:
    """Record a detection in a cluster's detection inventory."""
    return core.add_detection(name, detection_id, description, status)


@mcp.tool()
def add_gap(name: str, description: str, priority: str = "medium") -> dict:
    """Add an item to a cluster's gaps backlog."""
    return core.add_gap(name, description, priority)


@mcp.tool()
def export_navigator_layer(name: str) -> dict:
    """Export a cluster's TTP table as an ATT&CK Navigator layer JSON."""
    return core.export_navigator_layer(name)


@mcp.tool()
def get_observables(name: str) -> dict:
    """Get all observables (hashes, domains, ips, urls) tracked for a
    cluster, with provenance (report sources) and first/last seen."""
    return core.get_observables(name)


@mcp.tool()
def analyze_report(source: str) -> dict:
    """Fetch a threat report (URL or local file path) and extract
    observables/ATT&CK TTPs/candidate cluster names WITHOUT writing
    anything. Use to preview before calling ingest_report, especially
    when you want to pick the cluster_name yourself."""
    return core.analyze_report(source)


@mcp.tool()
def ingest_report(source: str, cluster_name: str | None = None,
                   create_if_missing: bool = True) -> dict:
    """Fetch a threat report (URL or local file path), extract
    observables and ATT&CK TTPs, and file them into a cluster —
    creating it if needed. If cluster_name is omitted, tries to infer
    the threat actor/malware name from the report text and raises if
    that's ambiguous (pass cluster_name explicitly in that case)."""
    return core.ingest_report(source, cluster_name, create_if_missing)


@mcp.tool()
def export_stix_bundle(name: str) -> dict:
    """Export a cluster as a STIX 2.1 bundle (Intrusion Set, Attack
    Patterns, Relationships, Notes) for sharing with other tools/orgs."""
    return core.export_stix_bundle(name)


@mcp.tool()
def import_stix_bundle(bundle: dict[str, Any], name: str | None = None,
                        overwrite: bool = False) -> dict:
    """Create or update a cluster from an external STIX 2.1 bundle
    containing an Intrusion Set. Set overwrite=True to merge into an
    existing cluster of the same name instead of failing."""
    return core.import_stix_bundle(bundle, name, overwrite)


if __name__ == "__main__":
    mcp.run()
