---
name: threat-cluster-tracking
description: Use when the user is investigating, naming, or updating a threat actor cluster; asks to log a hunt, update ATT&CK/TTP coverage, record a detection, or note a gap; or mentions tracking infrastructure/campaign activity over time. Provides the workflow and data model for maintaining persistent cluster profiles instead of one-off notes.
---

# Threat cluster tracking

This skill maintains durable, structured cluster profiles instead of
disposable investigation notes. Each cluster is a JSON record with a
rendered markdown view, backed by the `cti-tools` MCP server (or its CLI
equivalent — see "Tool availability" below). Clusters are modeled so
they can be losslessly exported as STIX 2.1 (Intrusion Set + Attack
Pattern + Relationship + Note objects) for sharing outside this tool.

## When to create vs. update a cluster

- New named activity with no existing profile and enough signal for at
  least one Diamond Model corner (adversary, capability, infrastructure,
  or victim) → create a cluster.
- Activity that maps to JA4/JA4S/JA4X reuse, certificate reuse, ASN
  patterns, or TTPs already logged under an existing cluster → update
  that cluster, do not create a duplicate.
- If unsure whether two clusters are the same actor, log both separately
  with a note in each hunt log cross-referencing the other, and record
  the other cluster's name in `aliases` only once you're confident
  enough to actually merge — do not merge speculatively.
- Receiving a STIX bundle from another team/tool that anchors on an
  Intrusion Set → import it (`import_stix_bundle` / `cti import-stix`)
  rather than hand-transcribing it into a new cluster.
- Given a threat report (URL or file) to work through → use
  `ingest_report` / `cti ingest-report` rather than manually copying
  IOCs and TTPs out of the text. See "Ingesting threat reports" below.

## Cluster fields

- **Diamond Model** (`adversary`, `capability`, `infrastructure`,
  `victim`) — fill in only what's evidenced. Leave a field explicitly
  `unknown` rather than guessing; a visible gap is more useful than a
  false positive you can't take back.
- **Profile metadata** (`aliases`, `confidence` 0–100, `first_seen`,
  `last_seen`) — these map directly onto STIX Intrusion Set properties.
  Set them with `update_profile` / `cti update-profile` as they become
  known; don't leave them stuck at cluster-creation defaults once you
  have signal.
- **STIX ID** — minted once at cluster creation and never changes. It's
  what lets a re-exported bundle be recognized as an update to the same
  Intrusion Set rather than a duplicate. Don't try to set or edit it by
  hand.

## Observables

Each cluster also tracks deduplicated hashes/domains/ips/urls, each with
a provenance list (which report(s) it came from) and first/last seen
timestamps. View them with `get_observables` / `cti get-observables` —
this is the fast path to "what's tied to this cluster", instead of
scrolling the full `get_cluster` dump.

Given a hash/domain/ip/url with no cluster context yet — e.g. an IOC
that showed up somewhere else and you want to know if it's already
tracked — use `find_observable(value)` / `cti find-observable <value>`
instead of checking each cluster by hand. Hash lookups work with or
without the algo prefix (`sha256:...` or bare).

## Infrastructure pivoting

Tracked observables are a static record until you actually check
whether they're still live. `pivot_observable(value)` / `cti
pivot-observable <value>` looks a hash/domain/ip/url up against free
public sources (RDAP registration data; RIPEstat ASN/network context
for IPs; VirusTotal reputation + resolution history if `VT_API_KEY` is
set) — this is what turns "we saw this domain once" into "is this
domain still doing anything." Reach for it when:

- you want to know if a tracked domain/IP is still active or has been
  sinkholed/taken down (check RDAP nameservers/status — a domain
  suddenly pointed at a vendor's sinkhole nameservers, e.g.
  `*.microsoftinternetsafety.net`, means it's dead),
- you want the ASN/network owner behind an IP before deciding it's
  worth its own observable entry vs. shared hosting noise,
- you want other domains/IPs historically tied to an indicator
  (VirusTotal's resolution history) as new pivot leads.

This is explicitly on-demand and display-only — nothing from a pivot is
written to any cluster automatically. If it surfaces something worth
keeping (a new related indicator, confirmation something's dead), record
it yourself: `append_hunt_log` for narrative, `add_gap` if it's a lead
you haven't run down yet, or file a genuinely new indicator into the
right cluster's observables via a fresh `ingest_report`/manual note.
Don't treat pivot output as itself part of the cluster record.

## Ingesting threat reports

`ingest_report(source, cluster_name=None)` / `cti ingest-report <source>
[--name ...]` fetches a report (URL or local file — HTML is stripped to
text; PDFs are not supported yet, extract text first), extracts
hashes/domains/IPs/URLs and ATT&CK technique IDs with regexes, and files
them into a cluster:

- If the named cluster doesn't exist yet, it's created (unless
  `create_if_missing=False` / `--no-create`).
- Observables are deduped by value; a repeated observable adds a new
  source to its provenance list rather than duplicating.
- Newly-seen TTPs are added to the coverage table at status 0 (no
  coverage). **Already-tracked TTPs are never touched** — extraction
  won't silently overwrite a status/notes you set by hand.
- Private/reserved IPs (RFC1918, loopback, link-local, etc.) are
  filtered out; they're essentially never useful as adversary
  infrastructure.

If you omit `cluster_name`, extraction tries to infer the threat
actor/malware name from the report text (Microsoft weather-style,
CrowdStrike animal-style, Mandiant/Proofpoint numbered-cluster naming,
or a name next to a word like "ransomware"). **This is a heuristic, not
attribution** — if it finds zero or multiple plausible names, it raises
rather than guessing, and you should re-run with an explicit
`cluster_name`. Prefer reading the report yourself and passing the name
explicitly whenever you can — you'll virtually always get this right
where the regex can't.

Use `analyze_report` / `cti analyze-report <source>` first if you want a
preview (extraction + candidate names) without writing anything — useful
when you're not sure yet which cluster a report belongs to, or want to
sanity-check the candidates before committing.

## Technique ID validation

`update_ttp` and report-driven TTP extraction both check the
technique_id/technique_name pair against a bundled MITRE ATT&CK
Enterprise corpus. If the ID is unknown, revoked (with its
replacement), deprecated, or the name doesn't match ATT&CK's canonical
name for that ID, the call still succeeds but the returned cluster
carries a `warning` field — read it, don't ignore it, but don't treat
it as a failure either (a slightly stale bundle or a legitimately
private/custom ID shouldn't block recording what you observed). This
warning is never persisted to the cluster's stored JSON.

## TTP coverage scale (0–4)

- 0 — no coverage, technique not addressed
- 1 — detection idea exists, not yet built
- 2 — detection built, not yet validated against real or emulated data
- 3 — validated, in production
- 4 — validated, in production, and tuned against at least one observed
  false-positive class

Adjust this scale in your own copy if your detection lifecycle differs —
what matters is that every technique has a status and it's kept current.
Each TTP entry also becomes a STIX Attack Pattern (identified by its
ATT&CK technique ID via `external_references`) linked to the cluster's
Intrusion Set by a `uses` Relationship on export.

## Detections and technique usage

Detections are **not** stored per-cluster. They live in a shared,
technique-keyed registry — the same Kerberoasting detection covers
every adversary that does Kerberoasting, so it's modeled once and
joined onto whichever clusters' TTP tables reference that technique_id,
rather than hand-copied into each one. `add_detection` requires at
least one `technique_id`; pass `cluster_name` too if you want that
cluster's refreshed view back (optional — it's just provenance for
"which investigation prompted writing this"). A cluster's `detections`
field in `get_cluster` is always this live join, annotated with which
of that cluster's own TTPs each detection covers.

To go the other direction — given a technique, which adversaries use it
and what covers it — use `get_technique_usage(technique_id)` (omit the
ID for the full matrix across every technique any tracked cluster has
logged). This is the "who uses what" view: check it before writing a
new detection, so you don't duplicate coverage that already exists for
a technique another cluster also uses.

## Cross-cluster relationships

Clusters often relate to each other — a customer of another cluster's
service, a downstream payload, a suspected-same-actor overlap. Prose
cross-references in the hunt log ("See cluster 'X'") are still fine for
narrative detail, but for anything you want to survive a STIX export or
be machine-queryable, use `add_relationship(name, relationship_type,
target_cluster, description, source)` / `cti add-relationship` —
common `relationship_type` values are `"uses"` (supply-chain/tooling:
is a customer of, deploys, delivers) and `"related-to"` (suspected
overlap, not confirmed enough to merge via `aliases`). This exports as
a real STIX Relationship between the two Intrusion Sets, not just text
a receiving system has to parse.

## Hunt log discipline

Append-only. Never edit or delete a past entry — if a hypothesis was
wrong, add a new entry saying so. This preserves the actual investigation
history instead of a cleaned-up retelling. Hunt log entries export as
STIX Note objects tied to the cluster's Intrusion Set.

## Workflow

1. Check whether a cluster already exists (`list_clusters` /
   `cti list-clusters`) before creating one.
2. Create or load the cluster.
3. As you learn Diamond Model or profile details (adversary,
   capability, infrastructure, victim, aliases, confidence, first/last
   seen), record them with `update_profile` / `cti update-profile` —
   don't let them sit at `unknown` once you have evidence.
4. As you investigate, append hunt log entries as you go, not at the end
   from memory.
5. When a technique is identified, upsert it into the TTP table with a
   status — don't leave techniques implicit in prose. Check any
   `warning` in the response; it flags an unknown/revoked/mismatched
   technique_id without blocking the write.
6. Before writing a new detection, check `get_technique_usage` — the
   same detection may already cover this technique for another cluster.
   When a detection is written, record it with `add_detection` linked
   to the technique_id(s) it covers, not duplicated per cluster.
7. When you hit something you can't currently detect or verify, add it
   to the gaps backlog instead of letting it drop.
8. When you identify a relationship to another tracked cluster (customer,
   downstream payload, suspected overlap), record it with
   `add_relationship` so it's structured and exportable, in addition to
   any narrative detail in the hunt log.
9. If asked for an ATT&CK Navigator layer, export it from the cluster's
   current TTP table rather than hand-building one — it should always
   reflect the stored data, not a snapshot.
10. If asked to share a cluster, export it, or hand it to another
    tool/team, use `export_stix_bundle` / `cti export-stix` rather than
    serializing the JSON record directly — the STIX form is the
    interoperable one. If the cluster has relationships to other
    tracked clusters and the receiving system won't already have those,
    use `export_stix_ecosystem` / `cti export-stix-ecosystem` instead —
    it bundles every transitively related cluster together so no
    Relationship in the export points at an object the receiving
    system doesn't have.
11. If handed a STIX bundle to ingest, use `import_stix_bundle` /
    `cti import-stix`. It fails on a name collision unless you pass
    `overwrite`/`--overwrite`, which merges rather than replaces
    (existing hunt log and gaps are preserved; TTPs, relationships, and
    notes are unioned in).

## Tool availability

Prefer the MCP tools if the harness exposes them: `list_clusters`,
`get_cluster`, `create_cluster`, `update_profile`, `update_ttp`,
`append_hunt_log`, `add_detection`, `get_technique_usage`,
`add_relationship`, `add_gap`, `export_navigator_layer`,
`export_stix_bundle`, `export_stix_ecosystem`, `import_stix_bundle`,
`get_observables`, `find_observable`, `pivot_observable`,
`analyze_report`, `ingest_report`.

If MCP tools are not available in this harness, use the CLI directly via
the shell/bash tool from the `mcp-server` directory (or run `./setup.sh`
once from the repo root first, to create the venv and wire `.mcp.json`):

```
python -m cti_tools.cli list-clusters
python -m cti_tools.cli get-cluster <name>
python -m cti_tools.cli create-cluster <name> --description "..."
python -m cti_tools.cli update-profile <name> --adversary "..." --confidence 60 --aliases "Alias A,Alias B"
python -m cti_tools.cli update-ttp <name> <technique_id> <technique_name> <status> --notes "..."
python -m cti_tools.cli append-hunt-log <name> "<entry>"
python -m cti_tools.cli add-detection <detection_id> "<description>" <technique_ids> <status> --cluster <name>
python -m cti_tools.cli get-technique-usage [<technique_id>]
python -m cti_tools.cli add-relationship <name> <relationship_type> <target_cluster> --description "..." --source "..."
python -m cti_tools.cli add-gap <name> "<description>" <priority>
python -m cti_tools.cli export-navigator <name>
python -m cti_tools.cli export-stix <name>
python -m cti_tools.cli export-stix-ecosystem <name>
python -m cti_tools.cli import-stix <bundle.json | -> [--name "..."] [--overwrite]
python -m cti_tools.cli get-observables <name>
python -m cti_tools.cli find-observable <value>
python -m cti_tools.cli pivot-observable <value>
python -m cti_tools.cli analyze-report <url-or-file>
python -m cti_tools.cli ingest-report <url-or-file> [--name "..."] [--no-create]
```

Both paths write to the same JSON store, so the data is identical
regardless of which harness you're running in — this is what makes the
harness comparison meaningful.
