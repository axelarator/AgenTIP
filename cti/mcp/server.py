"""MCP server for threat cluster tracking.

Wraps core.py behind the MCP protocol so any harness with an MCP
client (Claude Code, GitHub Copilot / VS Code, Pi via pi-mcp-adapter)
can call these as structured tools.

Run:
    python -m cti_tools.server
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .. import core
from .. import store as tracking
from ..sources import validin

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
def remove_ttp(name: str, technique_id: str) -> dict:
    """Remove a technique from a cluster's TTP coverage table - the
    counterpart to update_ttp, for dropping a mis-attributed technique or
    one whose ATT&CK ID was revoked. Matches technique_id case-insensitively."""
    return core.remove_ttp(name, technique_id)


@mcp.tool()
def append_hunt_log(name: str, entry: str) -> dict:
    """Append an entry to a cluster's hunt log. Append-only, never edits."""
    return core.append_hunt_log(name, entry)


@mcp.tool()
def add_detection(detection_id: str, description: str, technique_ids: list[str],
                   status: str = "draft", cluster_name: str | None = None,
                   scope: str | None = None) -> dict:
    """Upsert a detection into the shared detection registry (not into
    one cluster's own record). scope="technique" for a generic behavioral
    detection that covers every cluster using the technique; scope=
    "cluster" for one keyed to a specific actor's artifacts (C2 port,
    signer, loader YARA), shown only on the clusters it names. Defaults
    to "cluster" when cluster_name is given, else "technique"; unchanged
    on update unless passed. technique_ids is required. cluster_name adds
    that cluster to the detection and returns its refreshed view."""
    return core.add_detection(detection_id, description, technique_ids, status,
                               cluster_name, scope)


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
def update_gap(name: str, description: str, new_description: str | None = None,
                priority: str | None = None) -> dict:
    """Revise a gap in place - for when it's been investigated and its
    status/priority needs updating but is worth keeping a record of
    (e.g. "pivoted against X, came up empty, don't re-try without new
    data") rather than silently disappearing the way remove_gap would.
    Only fields you pass are changed. Matches the gap to update by its
    current exact description text - gaps have no separate id."""
    return core.update_gap(name, description, new_description, priority)


@mcp.tool()
def remove_gap(name: str, description: str) -> dict:
    """Remove a gap from a cluster's backlog outright - the counterpart
    to add_gap, for a gap that's fully closed and not worth keeping a
    record of (see update_gap to revise in place instead). Matches by
    exact description text (case-sensitive)."""
    return core.remove_gap(name, description)


@mcp.tool()
def export_navigator_layer(name: str) -> dict:
    """Export a cluster's TTP table as an ATT&CK Navigator layer JSON."""
    return core.export_navigator_layer(name)


@mcp.tool()
def get_observables(name: str) -> dict:
    """Get all observables (hashes, domains, ips, urls, emails, cves,
    wallets, and the JA4+/JARM fingerprint categories: ja4, ja4s, ja4h,
    ja4l, ja4x, ja4t, ja4ts, ja4ssh, jarm) tracked for a cluster, with
    provenance (report sources) and first/last seen."""
    return core.get_observables(name)


@mcp.tool()
def find_observable(value: str) -> dict:
    """Reverse index from an observable value (hash - with or without
    its algo prefix - domain, ip, or url) to every tracked cluster that
    has seen it, with provenance and first/last seen. The symmetric
    counterpart to get_technique_usage, but for IOCs."""
    return core.find_observable(value)


@mcp.tool()
def add_observable(name: str, category: str, value: str, source: str,
                   metadata: dict | None = None) -> dict:
    """Manually file a single observable onto a cluster - the
    counterpart to ingest_report's automatic extraction, for an
    indicator from somewhere other than a parseable report (e.g. a
    pivot_observable finding, or a JA4+/JARM fingerprint you collected
    by actively probing a tracked domain/IP). category must be one of
    "hashes", "domains", "ips", "urls", "emails", "cves", "wallets",
    "ja4", "ja4s", "ja4h", "ja4l", "ja4x", "ja4t", "ja4ts", "ja4ssh",
    "jarm". Dedupes by value like ingest_report does. A genuinely new
    domain/ip also gets a live asn/cert/http/webamon/tags enrichment
    lookup, stamped onto the observable alongside `source`.

    metadata is stamped onto the entry only if it's genuinely new (an
    already-tracked value only gets `source` appended) - use it to record
    a file hash's filenames when filing one by hand, e.g.
    metadata={"hash_kind": "file", "filenames": ["update.exe"]}, so that
    detail isn't lost the way it is in a pivot_observable/pivot_cluster
    finding that's never been manually filed."""
    return core.add_observable(name, category, value, source, metadata)


@mcp.tool()
def remove_observable(name: str, category: str, value: str) -> dict:
    """Remove an observable (a false positive or benign reference the
    extractor over-matched) from a cluster - the counterpart to
    add_observable. Matches case-insensitively and, for hashes, with or
    without the algo prefix, removing every match. category is one of
    "hashes", "domains", "ips", "urls", "emails", "cves", "wallets",
    "ja4", "ja4s", "ja4h", "ja4l", "ja4x", "ja4t", "ja4ts", "ja4ssh",
    "jarm"."""
    return core.remove_observable(name, category, value)


@mcp.tool()
def list_pending_fingerprints() -> list[dict]:
    """Peek at domains/ips newly tracked (via add_observable,
    ingest_report, or import_stix_bundle) since the last
    pop_pending_fingerprints call - infrastructure that hasn't been
    actively fingerprinted (JA4+/JARM) yet. Read-only, doesn't clear the
    queue. Each entry is {cluster, category, value, queued_at}."""
    return core.list_pending_fingerprints()


@mcp.tool()
def pop_pending_fingerprints() -> list[dict]:
    """Return every queued pending-fingerprint entry and clear the queue
    in one step - call this from wherever you actively collect JA4+/JARM
    fingerprints (e.g. an isolated VM) each cycle to claim everything
    waiting without re-processing it next time. File results back with
    add_observable. Use list_pending_fingerprints instead to check
    without consuming."""
    return core.pop_pending_fingerprints()


@mcp.tool()
def requeue_fingerprint(name: str, category: str, value: str) -> list[dict]:
    """Put an already-tracked domain/ip back on the JA4+/JARM pending
    queue for re-probing - use this after a prior fingerprint attempt
    errored, timed out, or came back as a null/placeholder result (e.g.
    JARM's all-zero no-response sentinel). add_observable/ingest_report
    only enqueue a value the first time it's seen, so touching an
    existing observable again does NOT requeue it on its own - this is
    the supported way to force that instead of hand-editing the queue
    file. category must be "domains" or "ips". Raises if the cluster or
    the observable isn't found."""
    return core.requeue_fingerprint(name, category, value)


@mcp.tool()
def pivot_observable(value: str) -> dict:
    """On-demand infrastructure pivot for a hash/domain/ip/url: RDAP
    (registration data), RIPEstat (ASN/network, IP only), Webamon (a
    domain's latest scan - cert, DNS, ASN, tech, kit fingerprints - plus
    its infostealer hits; an IP's hosted domains), a live TLS grab and
    HTTP probe from the probe VM (a domain's current certificate and
    liveness), PTR (IP), ThreatFox (known malware-C2 IOC match, if
    THREATFOX_API_KEY is set), and HoneyLabs honeypot telemetry (IP, if
    HONEYLABS_API_KEY is set). Display only - nothing is written to any
    cluster; record anything worth keeping yourself via
    append_hunt_log/add_gap/etc."""
    return core.pivot_observable(value)


@mcp.tool()
def pivot_cluster(name: str) -> dict:
    """Sweep every tracked domain/ip for a cluster through the free pivot
    sources and stamp a lifecycle status onto each observable: domains
    become active/dead/sinkholed/expired/unknown (RDAP + live
    resolution), ips routed/unrouted/unknown (RIPEstat). Unlike
    pivot_observable, this WRITES the status back onto the cluster.
    Domains are enriched via a live TLS grab (current certificate), a
    live HTTP probe, and Webamon (kit fingerprints); ips via Webamon
    hosted-domains; both via ThreatFox if THREATFOX_API_KEY is set - the
    latest asn/cert/http/webamon/tags snapshot is stamped onto each
    observable, and a dated snapshot of that enrichment is logged to
    the tracking-store history, which also diffs cert/http/fingerprint/
    hosted-domains against the prior check and records a genuine change
    (open ports are tracked separately by the on-demand active_scan, not
    here). Best-effort history logging (a
    tracking-store hiccup surfaces as a "history_note" in the summary,
    not a failure) so the daily tracking narrative can call it out.
    Returns a per-observable summary."""
    return core.pivot_cluster(name)


@mcp.tool()
def pivot_and_expand(value: str, cluster_name: str,
                     include_cohosted: bool = False) -> dict:
    """Pivot a domain/ip and file the high-confidence new indicators it
    surfaces onto an existing cluster (with provenance + a hunt-log
    entry): for a domain, sibling subdomains under it from subfinder +
    Wayback (Webamon kit-fingerprint siblings go to `review`); for an ip,
    the domains Webamon has scanned resolving to it. Co-hosted domains on
    a shared-hosting ASN are suppressed; otherwise they are returned for
    review unless include_cohosted=True. Only genuinely new indicators are
    filed; the `review` block lists everything left for manual follow-up.
    Each newly-filed indicator also gets its own live asn/cert/tags
    enrichment snapshot."""
    return core.pivot_and_expand(value, cluster_name, include_cohosted)


@mcp.tool()
def active_scan(target: str, cluster: str | None = None,
                tools: list[str] | None = None) -> dict:
    """On-demand LOUD active scan of a domain/ip from the probe VM - nmap
    (top-ports service scan) and/or dirsearch (web path map + recursive
    open-directory file listing). Distinct from the automatic light-touch
    enrichment sweep: this reaches the target's own infrastructure, so only
    run it when explicitly asked. Open ports feed the port-change signal;
    open-directory files are diffed day over day (new files flagged). If
    `cluster` is given and the target is tracked there, results are stamped
    onto its observable. The run is audited with the Zeek timestamp window
    its traffic falls in, so the captured packets can be found in
    OpenSearch/Arkime. `tools` defaults to both nmap and dirsearch."""
    return core.active_scan(target, cluster, tools)


@mcp.tool()
def analyze_opendir_samples(indicator: str, urls: list[str],
                            cluster: str | None = None) -> dict:
    """Download specific open-directory files on the probe VM and triage
    them in an isolated container there, returning JSON verdicts only.

    LOUD and explicit. `active_scan` lists what is in an open directory;
    this fetches named files from it. Listing is reconnaissance,
    downloading is collection - a separate decision, so a separate tool.
    Only ever call it when the analyst has asked for specific files.

    Each file is fetched on the lab probe VM, analyzed in a container with
    no network access and no capabilities, and deleted. What comes back is
    sha256, detected type, YARA matches, a strings sample and extracted
    URLs/addresses. No sample bytes reach this host.
    """
    from .. import core
    from ..probe import sandbox

    return sandbox.analyze_urls(urls, indicator=indicator, actor=cluster)


@mcp.tool()
def get_opendir_samples(indicator: str) -> dict:
    """Sandbox verdicts already recorded for an indicator's open-directory
    files. Read-only - it never fetches anything."""
    from ..store import run_readonly_query

    return run_readonly_query(
        "SELECT path, url, sha256, size, magic, mime, verdict, yara_hits, "
        "analyzed_at FROM opendir_samples "
        f"WHERE indicator_value = '{indicator.replace(chr(39), chr(39) * 2)}' "
        "ORDER BY analyzed_at DESC")


@mcp.tool()
def analyze_report(source: str) -> dict:
    """Fetch a threat report (URL or local file path) and extract
    observables/ATT&CK TTPs/candidate cluster names WITHOUT writing
    anything. Use to preview before calling ingest_report, especially
    when you want to pick the cluster_name yourself."""
    return core.analyze_report(source)


@mcp.tool()
def ingest_report(source: str, cluster_name: str | None = None,
                   create_if_missing: bool = True,
                   exclude: list[str] | None = None) -> dict:
    """Fetch a threat report (URL or local file path), extract
    observables and ATT&CK TTPs, and file them into a cluster —
    creating it if needed. If cluster_name is omitted, tries to infer
    the threat actor/malware name from the report text and raises if
    that's ambiguous (pass cluster_name explicitly in that case). Every
    genuinely new domain/ip extracted also gets a live asn/ports/cert/
    tags enrichment lookup before it's filed.

    Run analyze_report first and pass `exclude` for anything that is not
    adversary infrastructure - the vendor's own domain, a hosting provider
    named in the text, a contact email. Extraction over-matches, and each
    new domain/ip gets a live probe-VM lookup, so pruning afterwards is too
    late. Dropped values come back under `excluded`."""
    return core.ingest_report(source, cluster_name, create_if_missing, exclude)


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


@mcp.tool()
def query_duckdb(sql: str) -> dict:
    """Run a read-only SQL query against the actor-tracking DuckDB
    (tables: observations, asn_changes, attribute_changes, actors,
    correlations, zeek_matches). Writes are rejected; output is capped at
    200 rows - aggregate or filter instead of paging through raw tables."""
    return tracking.run_readonly_query(sql)


@mcp.tool()
def save_correlation(actor: str, correlation_type: str, indicators: list[str],
                     narrative: str, confidence: str = "medium",
                     suggested_opensearch_query: str | None = None) -> dict:
    """Persist a correlation finding for a tracked actor.
    correlation_type: asn_pivot | port_pattern | temporal_cluster |
    new_infrastructure | zeek_hit. confidence: high | medium | low."""
    return tracking.save_correlation(actor, correlation_type, indicators,
                                     narrative, confidence,
                                     suggested_opensearch_query)


@mcp.tool()
def get_actor_summary(actor: str) -> dict:
    """Compact aggregate for one tracked actor: observation counts,
    known ASNs/ports, recent ASN changes and Zeek matches, correlation
    count. Prefer this over composing the same via query_duckdb."""
    return tracking.actor_summary(actor)


# --------------------------------------------------------------------------- #
# Validin - manual only, and metered
# --------------------------------------------------------------------------- #
#
# These four are the ONLY way Validin is reachable. They are tools rather
# than pipeline steps on purpose: a tool is invoked because somebody asked
# for it, which is the condition this source is allowed under. Each spends
# one of fifty monthly lookups, so each takes a `reason` and reports what is
# left.

@mcp.tool()
def validin_status() -> dict:
    """Validin quota: lookups left today and this month, ours and theirs.

    Costs nothing. Call this before any validin_* lookup - the source is
    capped at 10 a day and 50 a month, and the monthly cap is the binding
    one. `drift` means our count and the provider's disagree; run
    validin_sync to adopt theirs."""
    return validin.status()


@mcp.tool()
def validin_sync() -> dict:
    """Adopt Validin's own count of what this key has spent this month.

    Costs nothing. Needed because the local counter starts at zero and the
    account does not - lookups made through Validin's web UI are invisible
    here until this runs."""
    return validin.sync()


@mcp.tool()
def validin_reverse_selector(selector_type: str, value: str, reason: str) -> dict:
    """Who else has this selector value, according to Validin. ONE lookup.

    Use it for the two things nothing else here can do: `tls.cert_sha256`,
    which Webamon cannot reverse because it publishes no leaf-certificate
    digest, and `whois.registrant_email` / `whois.registrar`, which
    Webamon's index does not carry at all. For everything else prefer
    webamon - it is effectively unmetered by comparison.

    selector_type must be one of validin.REVERSE_FIELDS; `reason` is
    required and is recorded with the result."""
    with validin.manual_invocation(reason):
        return validin.reverse_selector(selector_type, value)


@mcp.tool()
def validin_history(indicator: str, kind: str = "dns", reason: str = "") -> dict:
    """Passive history for one indicator. ONE lookup.

    kind: "dns" (resolution history - what this resolved to before, which
    no CLI on the probe VM can answer), "dns_ip" (the reverse, for an IP),
    "certificates" (Certificate Transparency - the crt.sh replacement, since
    crt.sh serves a frozen archive and no longer ingests), or "registration"
    (WHOIS/RDAP history, where a registrant who has since gone private is
    still visible)."""
    with validin.manual_invocation(reason or "history lookup"):
        if kind == "dns":
            return validin.dns_history(indicator)
        if kind == "dns_ip":
            return validin.dns_history(indicator, is_ip=True)
        if kind == "certificates":
            return validin.certificates(indicator)
        if kind == "registration":
            return validin.registration_history(indicator)
    return {"error": f"unknown kind {kind!r}: use dns, dns_ip, "
                     "certificates or registration"}


if __name__ == "__main__":
    mcp.run()
