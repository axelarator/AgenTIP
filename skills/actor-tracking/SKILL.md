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
lookups, and `pivot_cluster`'s live TLS/HTTP/DNS + Webamon + subdomain
sweep with attribute-change detection) is the deliberate, contained
exception - a budgeted daily loop, confined to IPs/domains of tracked
actors. Webamon calls are capped at CTI_WEBAMON_DAILY_BUDGET (default
1000/day); the live checks run from the lab probe VM and are
light-touch (DNS, one TLS handshake, one HTTP GET per domain). The
loud tools - nmap and dirsearch via `active_scan` - are never run by
this loop, only on explicit request; so open ports now change only
when a report names one or an `active_scan` runs (VirusTotal, Shodan
InternetDB, Hackertarget, and Cert Spotter are retired). The Zeek/OpenSearch/Arkime
cross-reference is a completely separate, on-demand capability, not
part of this daily loop or its digest/narrative at all: OpenSearch
only has data when the lab VM originates traffic (probing indicators,
or occasionally detonating malware), so checking it every day would
mostly find nothing and just add noise. Run it only when asked, by
calling `cti_tools.tracking.opensearch_xref.run_daily_xref(con, day)`
directly (there is no `daily_tracking.py` flag for this).

## Tables

- `observations` - one row per (day, indicator, source). Live sources:
  `report:<file>`, `honeylabs`, `rdap`, `threatfox`, `tls_live`,
  `http_live`, `dns_resolve`, `ptr`, `webamon`, `webamon_infostealers`,
  `subdomains` (subfinder + Wayback, unioned), `nmap`, or
  `cluster:<slug>`. Open-directory listings are not an observation
  source - they live in `opendir_files` (below).
  HoneyLabs fields: hl_events, hl_events_7d, hl_first_seen,
  hl_last_seen, hl_ports (JSON int array), hl_tags, hl_threat_level.
  Registry fields: asn, netname, country_code. Live TLS
  (source=`tls_live`): tls_sha256, tls_issuer, tls_subject, tls_sans
  (JSON array), tls_not_before, tls_not_after. Live HTTP
  (source=`http_live`): http_status, http_title, http_server,
  http_final_url. Webamon: webamon_report_id, webamon_risk_score,
  webamon_fingerprint_dom, webamon_fingerprint_ssl, webamon_last_scan,
  ip_hostnames (JSON - hosted domains for an IP), infostealer_count,
  infostealer_urls. Also subdomains (JSON), nmap_ports (JSON),
  ptr_hostname, resolved_ip. The retired sources' columns (shodan_*,
  cert_* from Cert Spotter, discovered_hostnames, vt_file_hashes) stay
  in the schema so old rows remain readable, but nothing writes them
  any more.
- `asn_changes` - detected pivots: change_type is `asn_change`,
  `netname_change`, or `first_seen` (baseline, not an event);
  confidence high/medium/low.
- `attribute_changes` - detected pivots from the daily `pivot_cluster`
  sweep (see `_log_cluster_enrichment_history` in `core.py`) and from
  on-demand `active_scan` runs. change_type is `first_seen` (baseline,
  not an event) or one of the per-attribute values below:
  - `ports` - `ports_changed`. Written only by `active_scan`'s nmap
    run now (no passive port source remains).
  - `cert` - live-TLS issuer/SAN diff; `cert_issuer_changed` or
    `cert_sans_changed`. A same-issuer renewal with unchanged SANs is
    not recorded at all (routine, not a signal).
  - `cert_hash` - a tracked domain's live certificate SHA256; `cert_new`
    (a genuinely new cert - every renewal mints one). The new hash is
    also auto-filed onto the cluster's own `hashes` observable list as
    `cert-sha256:<hash>` (`hash_kind: "certificate"`, `cert_for:
    <domain>`), and exports to STIX as an x509-certificate - this is
    the one attribute type that updates a tracked observable
    automatically, since it's intrinsic to infrastructure already
    tracked, not a lead.
  - `http` - `http_server_changed` or `http_title_changed` (a changed
    landing page or server banner - often a kit swap or takedown).
  - `webamon_fingerprint` - `webamon_fingerprint_changed` (Webamon's
    DOM/SSL kit fingerprint moved).
  - `ip_hostnames` - `ip_hostnames_changed` (new domains Webamon saw on
    a tracked IP; suppressed on shared-hosting ASNs). Flag-only.
  - `subdomains` - `subdomains_changed` (new subfinder/Wayback
    subdomains under a tracked domain). Flag-only here; file them with
    `pivot_and_expand`.
  - `infostealer_hits` - new infostealer-log hits for a tracked domain
    (Webamon; plaintext passwords are never stored).
  - `ptr` / `resolved_ip` - `ptr_changed` / `resolved_ip_changed`.
  - `opendir_files` - new files in an open directory found by
    `active_scan`'s dirsearch (see `opendir_files` below).
  old_value/new_value are JSON; confidence high/medium/low, downgraded
  on a stale (>90d) baseline.
- `opendir_files` - every file listed in an open directory by
  `active_scan` (indicator_value, url, path, is_dir, size, mtime,
  first_seen, last_seen); a path absent from the prior scan is a new
  file.
- `active_scans` - audit of each `active_scan` run (tools, summary)
  with zeek_first_ts/zeek_last_ts, the Zeek timestamp window its
  traffic falls in, for finding the packets in OpenSearch/Arkime.
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
  new_infrastructure | shared_fingerprint | zeek_hit.
  (`shared_fingerprint`: tracked domains tied together by a shared
  Webamon DOM/SSL kit fingerprint - a rebuilt or reused phishing kit.)

Either write path can return `{"error": "tracking DB busy ..."}` while
the daily job holds the write lock - wait a moment and retry.

## Pre-built analytics

Named SQL constants in `mcp-server/cti_tools/tracking/analytics.py`,
usable verbatim through query_duckdb: RECENT_ACTOR_ACTIVITY (30d),
ASN_PIVOTS (7d), ATTRIBUTE_CHANGES (1d, every attribute above,
excludes first_seen baselines - see the `attribute_changes` table
above for what each attribute means), OPEN_DIRECTORIES (open-directory
files first seen in the window), PORT_PATTERN_SUMMARY, NEW_INDICATORS_IN_KNOWN_ASNS
(unattributed, first-seen-in-window only), CROSS_ACTOR_ASN_OVERLAP
(already-attributed indicators whose ASN overlaps a different tracked
actor - excludes large shared-hosting ASNs like AWS/Alibaba/Cloudflare
by default), TEMPORAL_CLUSTERS (weekly IP-count anomalies vs the
actor's median).

## Daily loop and files

Stage A (cron 06:15, `mcp-server/scripts/daily_tracking.py`, pure
Python): ingest `data/tracking/inbox/*.csv|json` (header
`ip,actor,campaign,date_observed,source_url`; processed files move to
`archive/`), budgeted enrichment, the `pivot_cluster` sweep (live
TLS/HTTP/DNS + Webamon + subdomain attribute-change detection),
analytics, then
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
