# cti-tools

Self-hosted MCP server + CLI for threat cluster tracking. Cluster
tracking itself makes no external API calls — everything is local JSON
under `../data/clusters/` (shared at the repo root so every harness
surface sees the same store), with a regenerated markdown view
alongside each. `core.py` is the single source of truth; `stix.py`,
`server.py`, and `cli.py` are thin surfaces over it, which is what makes
the same tool behave identically whether it's called over MCP, over
Bash, or exported as STIX. `attack.py` bundles a static, offline MITRE
ATT&CK technique lookup (see "MITRE ATT&CK technique validation" below)
— the one static reference dataset in the repo, refreshed occasionally
and offline, not fetched per call.

The one deliberate exception is `pivot_observable` (see "Infrastructure
pivoting" below): an opt-in, per-call lookup against free third-party
data sources, never automatic and never triggered by anything else in
this tool.

## Install

From the repo root:

```bash
./setup.sh
```

or manually:

```bash
cd mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[test]'
```

Cluster data is read/written under `<repo root>/data/clusters/` by
default (computed relative to `core.py`'s location). Override with the
`CTI_DATA_DIR` environment variable if you want clusters stored
somewhere else — e.g. a separate private repo, or an isolated directory
for tests (the test suite does this automatically via a fixture).

## Run tests

```bash
cd mcp-server && source .venv/bin/activate
pytest
```

## Run standalone (sanity check)

```bash
python -m cti_tools.cli create-cluster "Fox Tempest" --description "..."
python -m cti_tools.cli update-profile "Fox Tempest" --adversary "unattributed" --confidence 40
python -m cti_tools.cli update-ttp "Fox Tempest" T1553.002 "Subvert Trust Controls: Code Signing" 3 --notes "..."
python -m cti_tools.cli export-navigator "Fox Tempest"
python -m cti_tools.cli export-stix "Fox Tempest"
```

## Wiring into each harness

**Claude Code** — native MCP support. `.mcp.json` at the repo root
(written by `setup.sh`) already points at
`mcp-server/.venv/bin/python -m cti_tools.server` with `cwd` set to
`mcp-server`. Drop `skills/threat-cluster-tracking/` into
`.claude/skills/`.

**GitHub Copilot (VS Code)** — MCP support lives in VS Code's own MCP
settings (`Cmd/Ctrl+Shift+P` → "MCP: Add Server"). Point it at the same
interpreter/args as `.mcp.json` uses. Skills go wherever your VS Code
Copilot build reads Agent Skills from — check `docs.github.com` for the
current path, it's moved a couple of times.

**Pi** — core Pi's loop is deliberately Read/Write/Edit/Bash only, no
built-in MCP client. Two options:

1. If you're on `oh-my-pi` or another fork/extension with MCP support,
   wire it the same way as above.
2. Otherwise, skip MCP entirely for Pi and let the skill drive the CLI
   directly through the Bash tool — that's why `cli.py` exists as a
   parallel surface, not an afterthought. `.pi/skills/threat-cluster-tracking/`
   is already populated; Pi reads the CLI usage straight out of its
   `SKILL.md`.

### Why `.mcp.json` uses absolute paths, not `${workspaceFolder}`

Not every MCP client expands workspace-relative variables the same way
(or at all) for stdio server configs, and a wrong assumption here fails
silently as "server won't start" with little signal. `setup.sh` bakes in
absolute paths for your actual checkout instead. Re-run it if you move
or re-clone the repo.

### Providers

Point Pi (or any harness) at Ollama for local runs:

```bash
pi --provider ollama --model qwen3.5:9b
```

and swap to `--provider anthropic` (Claude subscription) when a task
needs frontier-level reasoning (multi-step TTP correlation, ambiguous
cluster merges) that the local model is thrashing on. Because both
providers drive the exact same skill and tool surface, that swap is the
cleanest isolated model-effect comparison you can run — harness and
capabilities held constant, only the model changes.

## MITRE ATT&CK technique validation

`attack.py` bundles a flat `technique_id -> {name, display_name, tactics,
revoked, deprecated, revoked_by}` lookup at
`attack_data/enterprise_attack_techniques.json`, generated from the
official MITRE STIX corpus (`mitre-attack/attack-stix-data`) by
`scripts/refresh_attack_data.py`. `update_ttp` (and TTP auto-extraction
during `ingest_report`) check every technique_id/technique_name pair
against it:

- unknown ID → warns, doesn't block the write (could be a legitimately
  private/custom ID, or the bundle is stale),
- revoked ID → warns with its replacement technique ID if MITRE recorded
  one (ATT&CK restructures periodically — e.g. T1562 "Impair Defenses"
  was revoked and replaced by T1685 "Disable or Modify Tools" upstream),
- deprecated ID → warns,
- name mismatch → warns with the canonical name, checked against both
  ATT&CK's bare technique name and this repo's "Parent: Sub" display
  convention for sub-techniques (e.g. "Steal or Forge Kerberos Tickets:
  Kerberoasting" for T1558.003).

The warning comes back as a `warning` key on the function's return value
and is never written to the cluster's stored JSON — advisory, not a hard
gate. Auto-extracted TTPs from report ingestion now also get their
canonical display name filled in automatically (previously they were
stored with `name` == the bare technique ID until someone corrected them
by hand).

Re-run `python scripts/refresh_attack_data.py` from `mcp-server/` when a
new ATT&CK Enterprise release ships; it's a one-off/occasional script,
not run automatically, consistent with this tool making no network calls
at runtime.

## Detections and technique usage

Detections live in a shared, technique-keyed registry
(`data/clusters/_registry/detections.json`), not duplicated per cluster —
the same Kerberoasting detection covers every adversary that does
Kerberoasting. `add_detection(detection_id, description, technique_ids,
status="draft", cluster_name=None)` requires at least one technique_id;
`cluster_name` is optional provenance for "which investigation prompted
this," not a scoping key. A cluster's `detections` field (from
`get_cluster` / `load_cluster`) is always a live join against the
registry by technique_id — computed at read time, never trusted from
whatever was last written to that cluster's own JSON file — so it never
goes stale relative to the cluster's current TTP table.

`get_technique_usage(technique_id=None)` is the reverse index: given a
technique, which tracked clusters use it and what detections cover it.
Omit `technique_id` for the full matrix across every technique any
tracked cluster has logged. Check this before writing a new detection —
another cluster may already have one for the same technique.

## STIX 2.1 export/import

`export_stix_bundle` / `cti export-stix` renders a cluster as a STIX 2.1
`bundle`:

- one **Intrusion Set** (the cluster itself — name, description,
  aliases, confidence is *not* a native Intrusion Set property so it
  stays local-only, first_seen, last_seen),
- one **Attack Pattern** per TTP entry, keyed to its ATT&CK technique ID
  via `external_references` (`source_name: mitre-attack`), plus a
  non-standard `x_cti_agent_coverage_status` custom property carrying
  the 0-4 coverage score,
- one **Relationship** (`uses`) per TTP, linking the Intrusion Set to
  its Attack Pattern, carrying the TTP's notes as its description,
- one **Relationship** per cross-cluster link added via
  `add_relationship`, linking this Intrusion Set directly to another
  cluster's Intrusion Set `stix_id` (the target object itself isn't
  included in a single-cluster export, so its name is carried through
  via a custom `x_cti_agent_target_name` property for a clean re-import
  elsewhere),
- one **Note** per hunt log entry, linked back to the Intrusion Set.

The Intrusion Set's STIX id is minted once at cluster creation and
persisted (`stix_id` in the cluster JSON), so re-exporting the same
cluster always yields the same id — a receiving system can tell it's an
update, not a duplicate. Attack Pattern ids are derived deterministically
from the ATT&CK technique ID (UUIDv5 under a fixed namespace in
`stix.py`), so the same technique gets the same id across every cluster
and every export, without needing MITRE's own STIX corpus bundled in.
Relationship ids are derived from `(source, target, relationship_type)`
so a TTP `uses` link and a cross-cluster link never collide even when
they'd otherwise share a source/target pair.

`import_stix_bundle` / `cti import-stix` does the reverse: given a
bundle with at least one Intrusion Set, it creates a new cluster (or
merges into an existing one with `--overwrite`, unioning in TTPs,
cross-cluster relationships, and hunt log notes without touching
existing gaps). Detections aren't part of the bundle at all — they're
resolved locally by joining the imported TTPs against your own
detection registry.

`export_stix_bundle` only ever includes *this* cluster's own Intrusion
Set — a cross-cluster Relationship's `target_ref` points at another
cluster's `stix_id`, but that target object isn't itself in the bundle,
so a receiving system without it already loaded gets a dangling
reference. `export_stix_ecosystem(name)` / `cti export-stix-ecosystem
<name>` fixes that: it walks the relationship graph outward from
`name` (via every visited cluster's own `relationships`), exports each
reachable cluster, and merges them into one bundle via
`stix.merge_bundles` (deduplicating objects by id, so a technique two
clusters share doesn't end up as two copies of the same Attack
Pattern). Every Relationship's target is guaranteed to resolve to an
actual object in the result. A relationship pointing at a
since-renamed/deleted cluster is skipped rather than failing the whole
export.

This is hand-rolled JSON, not the `stix2` library — the object graph is
small and a hard dependency on a validating library isn't worth it for a
tool whose whole design point is "no external services, minimal deps."
If a downstream consumer needs strict spec validation, run the exported
bundle through `stix2validator` before sharing it.

## Report ingestion

`ingest_report(source, cluster_name=None)` / `cti ingest-report <source>`
fetches a threat report (URL or local file — `report_ingest.py` strips
HTML to text; PDFs aren't supported yet, extract text first e.g. with
`pdftotext`) and regex-extracts hashes (md5/sha1/sha256), domains, IPs
(private/reserved ranges filtered out), URLs, and ATT&CK technique IDs.
Extracted data is filed into a cluster — created automatically if it
doesn't exist — with observables deduped by value (repeats just add a
new source to that observable's provenance) and new TTPs added at
coverage status 0 without ever touching an already-tracked TTP's
status/notes.

If `cluster_name` is omitted, it's inferred from the report text via a
few vendor-style naming regexes (Microsoft weather names, CrowdStrike
animal names, Mandiant/Proofpoint numbered clusters, or a name next to
"ransomware"/"malware"/etc.). This is a heuristic, not attribution —
zero or multiple candidates raises rather than guessing wrong. Use
`analyze_report` / `cti analyze-report <source>` to preview extraction
and candidate names without writing anything first.

Both `analyze_report` and `ingest_report` add a `warning` field to their
return value when regex extraction finds zero observables *and* zero
TTPs — don't read that the same as "a clean report with nothing to
report." It usually means the source keeps its IOCs/techniques in a
table, image, or appendix the plain-text extractor can't reach (common
in older vendor posts); check the source manually when that seems
unlikely for the report at hand.

`get_observables(name)` / `cti get-observables <name>` returns just the
hashes/domains/ips/urls tracked for a cluster (with provenance and
first/last seen) plus the list of report sources ingested — the fast
path to "what's tied to this cluster" instead of the full cluster dump.

`find_observable(value)` / `cti find-observable <value>` goes the other
direction — given a hash (with or without its algo prefix), domain, ip,
or url, which tracked clusters have seen it. The observable counterpart
to `get_technique_usage`; there's no separate index to keep in sync, it
just scans every tracked cluster the same way `get_technique_usage` does.

`add_observable(name, category, value, source)` / `cti add-observable
<name> <hashes|domains|ips|urls> <value> <source>` manually files a
single observable onto a cluster — the counterpart to `ingest_report`'s
automatic extraction, for an indicator that didn't come from a
parseable report (a `pivot_observable` finding, something told to you
directly). Same dedup/provenance semantics as `ingest_report`: a value
already tracked just gets `source` appended to its provenance list.
Categories also include `emails`, `cves`, `wallets`, and the JA4+/JARM
fingerprint categories (`ja4`, `ja4s`, `ja4h`, `ja4l`, `ja4x`, `ja4t`,
`ja4ts`, `ja4ssh`, `jarm`) — see the threat-cluster-tracking skill for
why those nine are never auto-extracted and have to be filed by hand.

## Infrastructure pivoting

`pivot_observable(value)` / `cti pivot-observable <value>` is an
on-demand "what else is tied to this indicator" lookup against free,
no-recurring-cost public sources — deliberately *not* Censys/hunt.io/
Validin, which are paid. It's the one place this tool makes an outbound
call to a third party that isn't a report URL you handed it yourself,
and it only ever runs when explicitly called — never automatically, never
on a schedule. Nothing it returns is written anywhere; it's display-only.
If a pivot surfaces something worth keeping, record it yourself
(`append_hunt_log`, `add_gap`, or file the new indicator into a cluster).

Sources, all implemented in `pivot.py`:

- **RDAP** (WHOIS's standardized successor) via the public `rdap.org`
  bootstrap redirector — no API key. Domain/IP lookups only: registrar/
  registrant handle, registration/expiry/transfer events, nameservers.
- **RIPEstat**'s free Data API — no API key. IP lookups only: ASN,
  routing prefix, AS holder name, geolocation. Despite the name, it
  covers globally routed space, not just the RIPE region.
- **VirusTotal** public API v3 — requires your own free API key
  (`VT_API_KEY` env var; get one at virustotal.com). Rate-limited (4
  req/min, 500/day as of writing), so fine for on-demand single lookups,
  not bulk sweeps. Domain/IP lookups include VT's resolution history
  (its passive-DNS equivalent); hash lookups return detection verdicts
  and known filenames; URL lookups return detection verdicts. Skipped
  with a note (not an error) if `VT_API_KEY` isn't set — RDAP/RIPEstat
  still run.

Which sources run depends on the observable's type (`pivot.classify`):
domain → RDAP + VT; ip → RDAP + RIPEstat + VT; hash/url → VT only. A
failure in one source doesn't kill the whole lookup — RIPEstat's three
sub-calls and RDAP each record their own failure independently, and a
VirusTotal failure surfaces as `{"error": ...}` in its own section
rather than raising.

If a pivot turns up something worth keeping as a tracked indicator (not
just narrative), use `add_observable` to file it in with a source
citation describing the pivot (e.g. `"pivot_observable(signspace.cloud)
via VirusTotal resolution history, checked 2026-07-02"`), rather than a
bare local file path — `add_observable` doesn't require the source to
look like a report URL the way `ingest_report`'s sources do.

This was deliberately scoped to display-only, on-demand lookups for now
— no caching, no scheduled re-checking of already-tracked observables
for infrastructure changes. That's a real next step (see the project's
own notes) but needs a diff/cache store designed first; don't add one
speculatively.

## Extending toward Censys / hunt.io / Validin

If you do want a paid source later (better bulk/pivot throughput than
the free stack above), the pattern is the same one `pivot.py` follows:
add new functions to `core.py` (e.g. `censys_query(cert_hash)`), mirror
them as a tool in `server.py` and a subcommand in `cli.py`, and mention
them in the skill's "Tool availability" section. Keep API keys out of
this repo — read them from environment variables in `core.py`, never
hardcode them, and don't let a skill or MCP tool description reference a
literal key value.
