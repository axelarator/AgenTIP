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
def update_profile(name: str, description: str | None = None,
                    adversary: str | None = None,
                    capability: str | None = None,
                    infrastructure: str | None = None,
                    victim: str | None = None,
                    aliases: list[str] | None = None,
                    confidence: int | None = None,
                    first_seen: str | None = None,
                    last_seen: str | None = None) -> dict:
    """Update a cluster's description, Diamond Model corners, and/or
    STIX profile metadata (aliases, confidence 0-100, first_seen,
    last_seen). Only fields you pass are changed."""
    return core.update_profile(name, description, adversary, capability,
                                infrastructure, victim, aliases, confidence,
                                first_seen, last_seen)


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
def add_detection(detection_id: str, description: str, technique_ids: list[str],
                   status: str = "draft", cluster_name: str | None = None) -> dict:
    """Upsert a detection into the shared, technique-keyed detection
    registry (not into one cluster's own record) - the same detection
    can cover every adversary that uses a given technique instead of
    being duplicated per cluster. technique_ids is required. Pass
    cluster_name to also get that cluster's refreshed view back."""
    return core.add_detection(detection_id, description, technique_ids, status, cluster_name)


@mcp.tool()
def get_technique_usage(technique_id: str | None = None) -> dict:
    """Reverse index from ATT&CK technique to adversary: which tracked
    clusters use a technique and which detections cover it. Omit
    technique_id for the full matrix across every technique any tracked
    cluster has logged."""
    return core.get_technique_usage(technique_id)


@mcp.tool()
def add_relationship(name: str, relationship_type: str, target_cluster: str,
                      description: str = "", source: str = "") -> dict:
    """Record a structured relationship from this cluster to another
    tracked cluster (e.g. relationship_type="uses" for a supply-chain/
    tooling link, "related-to" for a suspected overlap). Exports as a
    real STIX Relationship between the two Intrusion Sets."""
    return core.add_relationship(name, relationship_type, target_cluster, description, source)


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
def find_observable(value: str) -> dict:
    """Reverse index from an observable value (hash - with or without
    its algo prefix - domain, ip, or url) to every tracked cluster that
    has seen it, with provenance and first/last seen. The symmetric
    counterpart to get_technique_usage, but for IOCs."""
    return core.find_observable(value)


@mcp.tool()
def add_observable(name: str, category: str, value: str, source: str) -> dict:
    """Manually file a single observable onto a cluster - the
    counterpart to ingest_report's automatic extraction, for an
    indicator from somewhere other than a parseable report (e.g. a
    pivot_observable finding). category must be one of "hashes",
    "domains", "ips", "urls", "emails", "cves", "wallets". Dedupes by
    value like ingest_report does."""
    return core.add_observable(name, category, value, source)


@mcp.tool()
def remove_observable(name: str, category: str, value: str) -> dict:
    """Remove an observable (a false positive or benign reference the
    extractor over-matched) from a cluster - the counterpart to
    add_observable. Matches case-insensitively and, for hashes, with or
    without the algo prefix, removing every match. category is one of
    "hashes", "domains", "ips", "urls", "emails", "cves", "wallets"."""
    return core.remove_observable(name, category, value)


@mcp.tool()
def pivot_observable(value: str) -> dict:
    """On-demand infrastructure pivot for a hash/domain/ip/url against
    free public sources: RDAP (registration data), RIPEstat (ASN/
    network, IP only), and VirusTotal (reputation + resolution
    history, if VT_API_KEY is set - skipped gracefully otherwise).
    Display only - nothing is written to any cluster; record anything
    worth keeping yourself via append_hunt_log/add_gap/etc."""
    return core.pivot_observable(value)


@mcp.tool()
def pivot_cluster(name: str) -> dict:
    """Sweep every tracked domain/ip for a cluster through the free pivot
    sources and stamp a lifecycle status onto each observable: domains
    become active/dead/sinkholed/expired/unknown (RDAP + live
    resolution), ips routed/unrouted/unknown (RIPEstat). Unlike
    pivot_observable, this WRITES the status back onto the cluster.
    Returns a per-observable summary."""
    return core.pivot_cluster(name)


@mcp.tool()
def pivot_and_expand(value: str, cluster_name: str,
                     include_cohosted: bool = False) -> dict:
    """Pivot a domain/ip and file the high-confidence new indicators it
    surfaces onto an existing cluster (with provenance + a hunt-log
    entry): CT-log sibling subdomains and VirusTotal historical
    resolutions. Reverse-IP co-hosted domains are returned for review
    unless include_cohosted=True. Only genuinely new indicators are
    filed; the `review` block lists everything left for manual
    follow-up."""
    return core.pivot_and_expand(value, cluster_name, include_cohosted)


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
    Patterns, Indicators, Relationships, Notes) for sharing with other
    tools/orgs. Tracked observables are exported as Indicators."""
    return core.export_stix_bundle(name)


@mcp.tool()
def export_stix_ecosystem(name: str) -> dict:
    """Export this cluster and every cluster it's transitively related
    to (via add_relationship) as one self-contained STIX 2.1 bundle -
    unlike export_stix_bundle, every cross-cluster Relationship's
    target is guaranteed to actually be present as an object, not just
    referenced by id."""
    return core.export_stix_ecosystem(name)


@mcp.tool()
def import_stix_bundle(bundle: dict[str, Any], name: str | None = None,
                        overwrite: bool = False) -> dict:
    """Create or update a cluster from an external STIX 2.1 bundle
    containing an Intrusion Set. Set overwrite=True to merge into an
    existing cluster of the same name instead of failing."""
    return core.import_stix_bundle(bundle, name, overwrite)


if __name__ == "__main__":
    mcp.run()
