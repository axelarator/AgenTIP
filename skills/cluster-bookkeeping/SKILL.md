---
name: cluster-bookkeeping
description: Use when the user is creating, naming, or updating a threat actor cluster; asks to log a hunt, update ATT&CK/TTP coverage, record a detection, note a gap, add or find an observable, ingest a threat report, or import/export a STIX bundle. Provides the workflow and data model for maintaining persistent cluster profiles instead of one-off notes. For what a shared certificate or page hash proves — and for the difference between pivoting and probing — see the infrastructure-pivoting skill instead.
---

# Cluster bookkeeping

This skill maintains durable, structured cluster profiles instead of
disposable investigation notes. Each cluster is a JSON record with a
rendered markdown view, backed by the `cti-tools` MCP server — see
"Tool availability" below. Clusters are modeled so they can be
losslessly exported as STIX 2.1 (Intrusion Set + Attack Pattern +
Relationship + Note objects) for sharing outside this tool.

**This skill is the record-keeping half.** Two neighbours own the rest:

- **`infrastructure-pivoting`** — what a shared value proves, the
  corroboration rule, and the pivot-vs-probe distinction. Read it before
  concluding that two indicators are the same operation.
- **`actor-tracking`** — the DuckDB time-series layer, the daily digest
  and the narrative.

The probe VM's build and runbook are operator documentation and live in
`docs/probe-vm.md`.
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

Extraction is best-effort and over-matches (a legitimate service the
malware merely contacts, a shared-hosting IP, a version string that
looks like an IP). When you spot a false positive or benign reference
in a cluster, prune it with `remove_observable(name, category, value)` /
`cti remove-observable <name> <category> <value>` — the counterpart to
`add_observable`. It matches case-insensitively (and, for hashes, with
or without the algo prefix), removing every matching entry. Note why in
the hunt log when you do, so the removal is auditable rather than silent.

## JA4+ and JARM fingerprints

Beyond hashes/domains/ips/urls/emails/cves/wallets, a cluster can also
track network/TLS/TCP/SSH fingerprints of its infrastructure: the full
JA4+ suite (`ja4`, `ja4s`, `ja4h`, `ja4l`, `ja4x`, `ja4t`, `ja4ts`,
`ja4ssh`) and `jarm`. Unlike every other category, these are **never**
produced by `ingest_report`'s regex extraction — report text doesn't
carry a TLS fingerprint of infrastructure you haven't probed yourself.
They only get filed via `add_observable(name, "ja4", value, source)` /
`cti add-observable <name> ja4 <value> <source>` (swap in whichever of
the nine categories applies), same as any other manually-filed
observable.

Collecting the value itself means having a real handshake with a
tracked domain/IP occur somewhere you can observe it — not something
you can derive from report text. JA4+ and JARM differ in *how* that
handshake has to happen, though:

- **JA4+** (`ja4`/`ja4s`/`ja4h`/`ja4l`/`ja4x`/`ja4t`/`ja4ts`/`ja4ssh`)
  is computed from an ordinary handshake — if you already run a JA4
  plugin on Zeek/Suricata, any traffic mirrored past it (organic, or
  one you deliberately generate) gets fingerprinted for free, no
  dedicated JA4 tooling needed. But four of the eight fingerprint
  whoever *initiates* the connection (`ja4` TLS client, `ja4h` HTTP
  client, `ja4t` TCP client, `ja4ssh` interactive-SSH-session
  timing/length) — so probing *outbound* to a report's IOC only ever
  yields your own vantage point's client signature, not intel about
  the target. Those four only mean something derived from a connection
  the target *itself* initiated (malware calling back to a
  sinkhole/honeypot you control, or a sandboxed sample's traffic
  trace) or an interactive session you actually held with it. The
  other four (`ja4s`, `ja4x`, `ja4ts`, `ja4l`) characterize the
  *responder* and so are exactly what an outbound probe gets you.
- **JARM** doesn't come from a passive plugin at all — its algorithm is
  a specific sequence of intentionally-malformed TLS ClientHellos, a
  distinct active technique from anything a JA4 capture plugin
  produces. It always needs a dedicated probe.

Either way, do the probing from wherever you already trust touching
malicious infrastructure from (an isolated vantage point, VPN egress
you don't mind burning) — never from whatever host runs this MCP
server/CLI unless that's the same trusted vantage point. Cite the
collection method and date as `source` (e.g. `"JARM via isolated VM,
2026-07-05"`), the same way pivot findings are cited, so a later reader
knows the value was actively fingerprinted rather than lifted from a
report.

These categories have no standard STIX 2.1 Cyber-observable type, so
(like `cves` and `wallets`) they're tracked and exportable in this
tool's own data model but silently omitted from `export_stix_bundle` /
`export_stix_ecosystem` rather than forced into a nonstandard pattern.

Every domain/ip newly filed via `add_observable`, `ingest_report` or
`import_stix_bundle` is queued for fingerprinting automatically.
`list_pending_fingerprints()` peeks at the queue;
`pop_pending_fingerprints()` returns everything waiting and clears it
atomically, which is the call a fingerprinting script should make each
cycle. Already-tracked values are never re-queued. How that queue is
drained, what `_is_probe_worthy` rejects before anything reaches it, and
the whole probe-VM pipeline are in `docs/probe-vm.md`.


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
- Every genuinely new domain/ip extracted also gets a live asn/cert/
  http/tags enrichment lookup (RDAP/RIPEstat, Webamon, the probe VM's
  TLS grab/HTTP probe, ThreatFox — same sources `pivot_observable`
  uses) before
  it's filed, stamped onto the observable alongside the report as its
  `sources` entry. An already-tracked value mentioned again is not
  re-enriched here — that's `pivot_cluster`'s job on the next daily
  sweep.

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

When the warning flags a revoked ID or a mis-attribution you'd rather
correct than keep, drop the entry with `remove_ttp(name, technique_id)`
/ `cti remove-ttp <name> <technique_id>` (the counterpart to
`update_ttp`, which only ever upserts) and re-add the right technique —
e.g. replace a revoked `T1562.002` with its successor `T1685.001`.

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

Detections are **not** stored per-cluster. They live in a shared
registry, and each one has a `scope` that decides which clusters it is
joined onto:

- `scope="technique"` — a generic behavioral detection. The same
  Kerberoasting rule covers every adversary that Kerberoasts, so it's
  modeled once and joined onto every cluster whose TTP table references
  that technique_id.
- `scope="cluster"` — keyed to one actor's artifacts (a C2 port, a
  code-signing certificate, a YARA rule for their loader). It shows only
  on the clusters it names. Sharing an ATT&CK ID with another cluster
  doesn't mean the rule would catch that actor, so it isn't shown there
  as coverage.

Pick the scope by asking whether the rule would fire on a *different*
actor doing the same technique. If only this actor's IOCs or tooling
would trip it, it's cluster-scoped. `add_detection` requires at least one
`technique_id`. `scope` defaults to `"cluster"` when you pass
`cluster_name` and to `"technique"` otherwise, so pass
`scope="technique"` explicitly when filing a generic rule from inside
an investigation. A cluster's `detections` field in `get_cluster` is
always this live join, with each entry's `scope` and the cluster TTPs it
covers.

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
   to the gaps backlog instead of letting it drop. When you later
   investigate a gap, don't just leave it as-is once you have an
   answer: `update_gap` to revise it in place (e.g. downgrade priority
   and note what was tried and why it came up empty, so a future pass
   doesn't repeat the same dead-end pivot), or `remove_gap` if it's
   fully resolved and not worth keeping a record of. Both match the
   gap by its current exact description text - gaps have no separate
   id, the description is the identifying content, same as
   `remove_observable` matching by value.
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

Use the MCP tools directly — every harness in this repo (Claude Code,
GitHub Copilot, Pi via `pi-mcp-adapter`) has an MCP client wired to
`.mcp.json` / `.pi/mcp.json` (run `./setup.sh` once from the repo root
first, to create the venv and wire those files): `list_clusters`,
`get_cluster`, `create_cluster`, `update_profile`, `update_ttp`,
`remove_ttp`,
`append_hunt_log`, `add_detection`, `get_technique_usage`,
`add_relationship`, `add_gap`, `update_gap`, `remove_gap`, `export_navigator_layer`,
`export_stix_bundle`, `export_stix_ecosystem`, `import_stix_bundle`,
`get_observables`, `find_observable`, `add_observable`,
`remove_observable`, `list_pending_fingerprints`,
`pop_pending_fingerprints`, `requeue_fingerprint`, `pivot_observable`,
`pivot_cluster`, `pivot_and_expand`, `active_scan` (probing — only when
asked), `analyze_report`, `ingest_report`.

All harnesses write to the same JSON store via the same `cti-tools` MCP
server, so the data is identical regardless of which harness you're
running in — this is what makes the harness comparison meaningful.
