# cti-tools

Self-hosted MCP server for threat cluster tracking. Cluster tracking
itself makes no external API calls — everything is local JSON under
`../data/clusters/` (shared at the repo root so every harness surface
sees the same store), with a regenerated markdown view alongside each.
`core.py` is the single source of truth; `stix.py` and `server.py` are
thin surfaces over it, which is what makes the same tool behave
identically whether it's called over MCP or exported as STIX.
`attack.py` bundles a static, offline MITRE ATT&CK technique lookup
(see "MITRE ATT&CK technique validation" below) — the one static
reference dataset in the repo, refreshed occasionally and offline, not
fetched per call.

The deliberate exceptions are infrastructure enrichment (see
"Infrastructure pivoting" below — third-party lookups plus light-touch
live checks from a lab probe VM, run on demand and by the daily
actor-tracking sweep) and the on-demand `active_scan` (nmap/dirsearch
from the same VM, only when explicitly asked).

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
python -c "from cti_tools import core; print(core.list_clusters())"
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

**Pi** — core Pi's loop is Read/Write/Edit/Bash plus the
`pi-mcp-adapter` package (https://pi.dev/packages/pi-mcp-adapter),
which gives it a native MCP client (the `mcp`/`mcpScript` tools). Wire
it the same way as above via `.pi/mcp.json` (already written by
`setup.sh`). `.pi/skills/threat-cluster-tracking/` is already
populated.

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
on-demand "what else is tied to this indicator" lookup. Nothing it
returns is written anywhere; it's display-only. If a pivot surfaces
something worth keeping, record it yourself (`append_hunt_log`,
`add_gap`, or file the new indicator into a cluster). `pivot_cluster`
runs the same enrichment over every tracked domain/ip of a cluster and
*does* write the snapshot back (the daily tracking cron calls it);
`pivot_and_expand` files what a pivot surfaces.

The design favors **live interaction over scan platforms**: accuracy
and timeliness matter, and a scan platform's record of a host can be
weeks old, while a TLS handshake or HTTP GET made right now can't be.
So VirusTotal, Shodan InternetDB, Hackertarget, and Cert Spotter are
retired (crt.sh is shut down), replaced by one passive index (Webamon)
plus live checks from the lab probe VM. There is no passive open-port
source any more; ports come from report text or `active_scan`.

Registry/telemetry sources, implemented in `pivot.py` (all network I/O
except HoneyLabs is proxied through the probe VM via `vm_proxy`):

- **RDAP** (WHOIS's standardized successor) via the public `rdap.org`
  bootstrap redirector — no API key. Domain/IP lookups only: registrar/
  registrant handle, registration/expiry/transfer events, nameservers.
- **RIPEstat**'s free Data API — no API key. IP lookups only: ASN,
  routing prefix, AS holder name, geolocation. Despite the name, it
  covers globally routed space, not just the RIPE region.
- **ThreatFox** (abuse.ch) — free POST-JSON query API, requires your
  own Auth-Key (`THREATFOX_API_KEY` env var; register at
  https://auth.abuse.ch/ — abuse.ch's unified Auth Portal requires this
  header on every ThreatFox call, including `search_ioc`, despite the
  query API historically being keyless). Applies to every observable
  kind: checks the literal value against abuse.ch's own malware-C2 IOC
  database and returns any matching threat/malware-family tags.
  `query_status: "no_result"` (not a known IOC) comes back as an empty
  match list, not an error. Skipped with a note (not an error) if
  `THREATFOX_API_KEY` isn't set.
- **HoneyLabs** (honeylabs.net) — requires your own API key
  (`HONEYLABS_API_KEY` env var; mint one from the HoneyLabs dashboard).
  IP lookups only: honeypot-fleet telemetry — event volume/recency and
  the ports, client fingerprints, and CVEs their sensors saw the IP
  probing. Heavy presence reads as mass-scanner/opportunistic noise (a
  counter-signal for dedicated C2); absence on an active IP is the
  quiet-infrastructure signal. Credits are metered (1 credit per row;
  free tier 500/day, 10 req/min), so cached lookups matter — honeypot
  totals move slowly, so a longer `CTI_PIVOT_CACHE_TTL` (e.g. 86400) is
  sensible if HoneyLabs becomes the dominant source. Skipped with a
  note if the key isn't set; deliberately no keyless fallback. The same
  lookup also backs `core.honeylabs_context`/`core.summarize_honeylabs`,
  which `scripts/probe_pending_fingerprints.py` uses to stamp a one-line
  telemetry summary onto queued IPs as provenance. For interactive
  queries beyond per-IP lookups, the `honeylabs` remote MCP server in
  `.mcp.json` exposes HoneyLabs' own tools directly.

Plus:

- **Webamon** (`cti_tools/webamon.py`, `https://pro.webamon.com`) —
  requires `WEBAMON_API_KEY` (keep it in `~/.bashrc`, never the repo);
  called directly from this host, not via the VM, since it hits
  Webamon's SaaS rather than the indicator's own infrastructure (same
  exception as HoneyLabs). A domain's latest scan from Webamon's index
  (certificate, DNS, ASN, tech stack, page title, DOM/SSL kit
  fingerprints, risk score); its infostealer-log hits (the plaintext
  `password` field is dropped at the client, only the masked peek is
  kept); an IP's hosted domains (the reverse-IP replacement); and
  fingerprint siblings (other scanned domains sharing a kit
  fingerprint). A soft daily budget (`CTI_WEBAMON_DAILY_BUDGET`, default
  1000 calls) is tracked in a small counter file next to the pivot
  cache; 401/403/429 and an exhausted budget come back as
  `{"error": ...}`, never raised.
- **Live checks from the probe VM** (`vm_proxy` → `probe_helper.py`):
  `tls_grab` (the current certificate — sha256/issuer/subject/SANs/
  validity — replacing Cert Spotter's CT lookup), `http_probe` (status/
  final URL/title/server, plus any autoindex listing), `dns_lookup`
  (A/AAAA/MX/NS/TXT), PTR, and passive subdomain discovery via
  `subfinder` and the Wayback Machine's CDX API.

Which sources run depends on the observable's type (`pivot.classify`):
ThreatFox runs for every kind if `THREATFOX_API_KEY` is set; domain →
RDAP + TLS grab + HTTP probe + Webamon scan + Webamon infostealers
(`pivot_cluster` adds live DNS resolution and subdomain discovery); ip → RDAP + RIPEstat + PTR + Webamon hosted-domains +
HoneyLabs. A failure in one source doesn't kill the whole lookup —
each records its own `{"error": ...}` in its own section rather than
raising.

If a pivot turns up something worth keeping as a tracked indicator (not
just narrative), use `add_observable` to file it in with a source
citation describing the pivot (e.g. `"pivot_observable(signspace.cloud)
via Webamon hosted-domains, checked 2026-09-11"`), rather than a bare
local file path — `add_observable` doesn't require the source to look
like a report URL the way `ingest_report`'s sources do.

The daily actor-tracking sweep (below) is the one scheduled use of
these sources; it runs only the light-touch checks. The Zeek/OpenSearch
cross-reference described there stays on-demand.

## Active scanning (`active_scan`)

`active_scan(target, cluster=None, tools=None)` is the loud, on-demand
counterpart to the enrichment above — **probing, not pivoting**, so
only run it when explicitly asked. From the probe VM it runs:

- **nmap** — `--top-ports 100 -sV -Pn`, parsed from XML into
  `[{port, proto, service, product, version}]`. Ports are unioned onto
  the observable and diffed (`ports_changed`) — the only automatic
  source of port changes now that Shodan InternetDB is gone.
- **dirsearch** — a web path map with 404-baseline suppression (a
  catch-all server that 200s everything doesn't flood the results),
  plus a recursive listing of every open directory found: each file's
  path, size, and mtime, recorded in the tracking store's
  `opendir_files` table and diffed day over day, so a newly-dropped
  payload on a known open directory surfaces in the digest.

`tools` defaults to both. If `cluster` is given and the target is
tracked there, results are stamped onto its observable. Every run is
audited in `active_scans` with the Zeek timestamp window its traffic
falls in, so the captured packets can be pulled up in OpenSearch/
Arkime afterwards. The call is synchronous and blocks for up to
`CTI_PROBE_LONG_TIMEOUT` seconds (default 900) — there's deliberately no
job server on the VM; an async queue would be the next step if scans
ever need to outlive an MCP call.

## Probe VM build

Everything that touches an indicator's own infrastructure (and the
registry lookups that name it) runs from a dedicated lab VM, so the
analyst's host never originates that traffic and every packet is
captured. The VM can be any OS that runs the helper; the current build
is Linux (it replaced the Win11 VM — same role, simpler tooling).

1. **Network:** VPN egress only; NIC on the tapped/mirrored bridge so
   the Zeek sensor sees its traffic (Zeek → OpenSearch `zeek-*`,
   Arkime full packet capture). Firewall it so it can't initiate
   connections back to the cti host (the cti host always initiates,
   over SSH).
2. **Packages:** `python3`, `python3-certifi`, `dnsutils` (`dig`),
   `openssl`, `curl`, `nmap`, `subfinder`, `dirsearch`, and Salesforce
   `jarm` (cloned to `/opt/jarm/jarm.py` — adjust `JARM_CMD` in
   `probe_helper.py` if elsewhere).
3. **Helper:** copy `mcp-server/scripts/probe_helper.py` to
   `/opt/cti/probe_helper.py` (check the tool-path constants at its
   top).
4. **SSH:** a dedicated user and key; pin the key in
   `~/.ssh/authorized_keys` with a forced command and no forwarding:
   `command="python3 /opt/cti/probe_helper.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...`
   Make sure no unrestricted line for the same key sits above it.
5. **cti host env** (`~/.bashrc`, sourced by cron): `CTI_PROBE_HOST`,
   `CTI_PROBE_USER`, `CTI_PROBE_SSH_KEY`, `CTI_PROBE_KNOWN_HOSTS`
   (populate it with the VM's host key), and optionally
   `CTI_PROBE_HELPER_CMD` (default `python3 /opt/cti/probe_helper.py`),
   `CTI_PROBE_SSH_TIMEOUT` (default 60s), `CTI_PROBE_LONG_TIMEOUT`
   (default 900s). Re-run `./setup.sh` so `.mcp.json` passes them
   through.
6. **Verify:** on the VM, `python3 /opt/cti/probe_helper.py
   --check-access` reports tool availability; from the cti host,
   `python3 mcp-server/scripts/probe_pending_fingerprints.py
   --check-access` round-trips the SSH hop and OpenSearch. Then run a
   `pivot_observable` on a domain you control and confirm the TLS/HTTP
   request appears in OpenSearch `zeek-*`.

## Actor tracking (DuckDB time-series layer)

`cti_tools/tracking/` keeps per-day observation rows in DuckDB at
`data/tracking/tracking.duckdb` so infrastructure changes on tracked
actors (ASN moves, port shifts, activity gaps) are visible over time —
the cluster JSON store stays canonical for cluster/TTP/diamond data,
linked only by `actors.cluster_slug`.

Daily loop (cron lines printed by `setup.sh`): Stage A
(`scripts/daily_tracking.py`, pure Python) ingests threat-report
CSV/JSON from `data/tracking/inbox/`, runs budgeted HoneyLabs +
RIPEstat/RDAP enrichment — HoneyLabs over their hosted MCP server
(`cti_tools/tracking/hl_mcp.py`), prefiltering each chunk of 32 IPs
as one /32 cidr_set call so only IPs with events cost a full lookup;
the free tier's 500 credits/day at 10 req/min is shared with
interactive pivots, and the loop stays capped at CTI_HL_BUDGET
(default 400) and self-slows on 429s — detects ASN/netname changes,
and writes a bounded digest to `data/tracking/digests/`. The daily
`core.pivot_cluster` sweep also diffs each tracked domain's live
certificate (issuer/SANs, and its sha256 — auto-filed onto the
cluster's own hash list as `cert-sha256:`), live HTTP server/title,
Webamon kit fingerprint, new subdomains (subfinder + Wayback,
flag-only), and infostealer hits, plus new domains Webamon saw on a
tracked IP — surfaced the same way ASN changes are. Open ports and
open-directory files change only via the on-demand `active_scan`,
which also records into the same `attribute_changes` table.
Zeek/OpenSearch/Arkime cross-referencing
(`cti_tools.tracking.opensearch_xref.run_daily_xref`) is a separate,
on-demand capability for correlating tracked infrastructure against
this lab's own captured traffic right after a probe or malware-
execution session — it is deliberately NOT part of this daily loop or
its digest/narrative (those logs only have data when the VM originates
traffic, so checking them daily by default would mostly find nothing
and just add noise); run it by hand via `opensearch_xref.run_daily_xref`
when it's actually relevant.
Stage B (`scripts/daily_narrative.sh`) makes one headless `claude -p`
pass over that digest — a `NO ACTIVITY` digest skips the agent
entirely, so quiet days cost zero tokens.

MCP tools: `query_duckdb` (read-only, row-capped), `get_actor_summary`
(canned per-actor aggregate), `save_correlation` (persist a finding).
See `skills/actor-tracking/SKILL.md` for the schema cheat-sheet and
usage etiquette. One-time seeding from the cluster store:
`scripts/daily_tracking.py --seed`.

## Extending toward Censys / hunt.io / Validin

If you do want a paid source later (better bulk/pivot throughput than
the free stack above), the pattern is the same one `pivot.py` follows:
add new functions to `core.py` (e.g. `censys_query(cert_hash)`), mirror
them as a tool in `server.py`, and mention them in the skill's "Tool
availability" section. Keep API keys out of
this repo — read them from environment variables in `core.py`, never
hardcode them, and don't let a skill or MCP tool description reference a
literal key value.
