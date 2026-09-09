---
name: actor-tracking
description: Use when the user asks about tracked threat actor activity over time, infrastructure pivots / ASN changes, the daily tracking digest or narrative, ingesting threat-report IP lists, or querying the actor-tracking DuckDB (query_duckdb, get_actor_summary, save_correlation).
---

# Actor tracking (DuckDB time-series layer)

Tracks known threat actors over time: threat-report IPs are ingested,
enriched daily via HoneyLabs honeypot telemetry + registry (RIPEstat/
RDAP) data, optionally cross-referenced against the lab's Zeek logs
in OpenSearch (on request only - see below), and stored as per-day
observation rows in DuckDB at
`data/tracking/tracking.duckdb`. This is the temporal complement to
the cluster JSON store (`skills/threat-cluster-tracking/`): clusters
stay canonical for TTP/diamond/profile data, this layer answers "what
changed, and when". A cluster observable's own asn/ports/cert/tags
fields (see `skills/threat-cluster-tracking/`) are a live point-in-time
snapshot for analyst display; the history of when those values changed
lives only here, in DuckDB.

An actor row's `cluster_slug` is the only link to a cluster
(`data/clusters/<slug>.json`); there is no reverse sync.

Note: the repo's usual rule is "no scheduled re-checking of tracked
observables". This subsystem's daily enrichment (HoneyLabs + registry
lookups, ASN/DNS/port/cert attribute-change detection) is the
deliberate, contained exception - a budgeted daily loop, confined to
IPs/domains of tracked actors, using only free/keyless sources
(Shodan InternetDB, Hackertarget, Cert Spotter, RDAP/RIPEstat).
VirusTotal is deliberately NOT called by this daily loop - it was,
briefly, for file-hash pivots on tracked IPs, but a single day's run
against a modest number of tracked IPs exhausted the free tier's daily
quota, so it was pulled back to on-demand only
(`pivot_observable`/`pivot_and_expand`), same as passive-DNS (VT is
never used for that either - see the `hostnames` attribute below for
what does the DNS-discovery job instead). The Zeek/OpenSearch/Arkime
cross-reference is a completely separate, on-demand capability, not
part of this daily loop or its digest/narrative at all: OpenSearch
only has data when the lab VM originates traffic (probing indicators,
or occasionally detonating malware), so checking it every day would
mostly find nothing and just add noise. Run it only when asked, by
calling `cti_tools.tracking.opensearch_xref.run_daily_xref(con, day)`
directly (there is no `daily_tracking.py` flag for this).

## Tables

- `observations` - one row per (day, IP, source). source is
  `report:<file>`, `honeylabs`, `rdap`, `shodan`, `certspotter`,
  `threatfox`, `hostdiscovery`, or `cluster:<slug>`.
  HoneyLabs fields: hl_events, hl_events_7d, hl_first_seen,
  hl_last_seen, hl_ports (JSON int array), hl_tags, hl_threat_level.
  Registry fields: asn, netname, country_code. Shodan fields:
  shodan_ports, shodan_tags. Cert Spotter fields (source=`certspotter`):
  cert_issuer, cert_not_before, cert_not_after, cert_sibling_hostnames
  (JSON array), cert_sha256, cert_revoked. Host-discovery fields
  (source=`hostdiscovery`, IPs only): discovered_hostnames (JSON array
  - Shodan InternetDB's own hostnames field unioned with Hackertarget's
  free reverse-IP lookup; deliberately no VT passive-DNS here). A
  `vt_file_hashes` column and `virustotal_files` source still exist in
  the schema from a short-lived automatic VT file-hash pivot that's
  since been removed (see the note above) - unused going forward.
- `asn_changes` - detected pivots: change_type is `asn_change`,
  `netname_change`, or `first_seen` (baseline, not an event);
  confidence high/medium/low.
- `attribute_changes` - detected pivots from the daily
  Shodan/Cert Spotter/Hackertarget sweep (`pivot_cluster`, the same
  mechanism that feeds `asn_changes`' RDAP/RIPEstat side, but this
  table is written from a separate sweep - see
  `_log_cluster_enrichment_history` in `core.py`). attribute is one of:
  - `ports` - change_type `ports_changed` or `first_seen`.
  - `cert` - issuer/SAN diff; change_type `cert_issuer_changed`,
    `cert_sans_changed`, or `first_seen`. A same-issuer renewal with
    unchanged sibling hostnames is not recorded at all (routine, not a
    signal).
  - `cert_hash` - a tracked domain's certificate SHA256 fingerprint;
    change_type `cert_new` (a genuinely new cert - every renewal mints
    one) or `first_seen`. The new hash is also auto-filed onto the
    cluster's own `hashes` observable list as `cert-sha256:<hash>`
    (`hash_kind: "certificate"`, `cert_for: <domain>`) - this is the
    one attribute type that updates a tracked observable automatically,
    since it's intrinsic to infrastructure already tracked, not a lead.
  - `hostnames` - a new domain discovered pointed at a tracked IP
    (see `hostdiscovery` above); change_type `hostnames_changed` or
    `first_seen`. new_value carries `{hostnames, added, certs}` where
    `certs` is a best-effort Cert Spotter lookup on each newly-added
    hostname. Flag-only: never auto-filed as a tracked observable.
  old_value/new_value are JSON; confidence high/medium/low, downgraded
  on a stale (>90d) baseline.
- `actors` - actor_name PK, first/last observed, known_asns,
  known_ports (JSON arrays), cluster_slug, tracked flag.
- `correlations` - persisted findings (see save_correlation).
- `zeek_matches` - per (day, IP, direction src|dst) aggregate hits
  from the lab's Zeek logs, pre-computed daily.

## Tools

- `query_duckdb(sql)` - read-only, capped at 200 rows. Aggregate and
  filter; never scan raw observations broadly.
- `get_actor_summary(actor)` - canned per-actor aggregate (counts,
  ASNs, top ports, recent changes/matches). Prefer this over
  composing the same via query_duckdb.
- `save_correlation(actor, correlation_type, indicators, narrative,
  confidence, suggested_opensearch_query)` - persist a finding.
  correlation_type: asn_pivot | port_pattern | temporal_cluster |
  new_infrastructure | zeek_hit.

Either write path can return `{"error": "tracking DB busy ..."}` while
the daily job holds the write lock - wait a moment and retry.

## Pre-built analytics

Named SQL constants in `mcp-server/cti_tools/tracking/analytics.py`,
usable verbatim through query_duckdb: RECENT_ACTOR_ACTIVITY (30d),
ASN_PIVOTS (7d), ATTRIBUTE_CHANGES (1d, ports/cert/cert_hash/hostnames
pivots, excludes first_seen baselines - see the `attribute_changes`
table above for what each attribute means), PORT_PATTERN_SUMMARY, NEW_INDICATORS_IN_KNOWN_ASNS
(unattributed, first-seen-in-window only), CROSS_ACTOR_ASN_OVERLAP
(already-attributed indicators whose ASN overlaps a different tracked
actor - excludes large shared-hosting ASNs like AWS/Alibaba/Cloudflare
by default), TEMPORAL_CLUSTERS (weekly IP-count anomalies vs the
actor's median).

## Daily loop and files

Stage A (cron 06:15, `mcp-server/scripts/daily_tracking.py`, pure
Python): ingest `data/tracking/inbox/*.csv|json` (header
`ip,actor,campaign,date_observed,source_url`; processed files move to
`archive/`), budgeted enrichment, the `pivot_cluster` sweep (ASN/DNS/
port/cert/file-hash attribute-change detection), analytics, then
writes `data/tracking/digests/<date>.md`. Zeek/OpenSearch/Arkime
cross-referencing is NOT part of this script at all (no flag for it) -
it's a separate, on-demand capability
(`cti_tools.tracking.opensearch_xref.run_daily_xref`), useful right
after probing a cluster's indicators or running malware that generated
VM network traffic, but deliberately outside the daily narrative.
Stage B (cron 06:45, `daily_narrative.sh`): one headless agent pass
over the digest, saving correlations and
`data/tracking/narratives/<date>.md`; a `NO ACTIVITY` digest skips
the agent entirely.

To ingest a new threat report: drop the CSV/JSON in the inbox and
either wait for the next run or run Stage A manually. One-time seeding
from the cluster store: `daily_tracking.py --seed`.

## Budget etiquette

HoneyLabs' free tier is ~500 credits/day at 10 req/min, shared across
every surface - the daily loop, interactive `pivot_observable`, and
the `honeylabs` MCP tools all draw on the same key. The daily loop
queries HoneyLabs over their hosted MCP server (mcp.honeylabs.net,
same `HONEYLABS_API_KEY`) and stays within the rate limit by
prefiltering: each chunk of 32 tracked IPs is checked as one /32
cidr_set call, and only IPs with events get a full lookup, so a
300-IP day is ~10-40 calls instead of 300. It still caps itself at
CTI_HL_BUDGET (default 400) and paces at CTI_HL_MIN_INTERVAL (default
6s, self-slowing on 429s). Don't burn the remainder on bulk
interactive lookups - for one-off "is this IP noisy" questions use
`pivot_observable` (cached) rather than raw HoneyLabs lookups. Heavy
HoneyLabs event counts on an IP usually mean mass-scanner noise, not
dedicated C2 - weigh verdicts accordingly.
