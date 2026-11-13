# Architecture

How cti-graph is put together: what each part is for, how data moves
through it, and the rules that hold it together. The README says what the
project does and how to run it; `docs/probe-vm.md` covers the probe VM;
`docs/audit-2026-11.md` records the last full review.

## The parts

```
cti/                    the library
  clusters/             cluster profiles: files, lock, observables, pivots, scans, reports
  core.py               one namespace over cti/clusters/ (re-exports; holds no code)
  membership.py         who belongs to a cluster, in DuckDB
  store/                DuckDB: schema, observations, selectors, scoring, queries
  sources/              third-party data, one module each, over one transport
  probe/                everything that leaves this host toward an indicator
  netwatch/             scheduled re-scans of tracked hosts, and what they find
  tracking/             the daily job's ingest, enrichment, analytics and digest
  report/               threat-report text and indicator extraction
  attack/               the bundled MITRE ATT&CK technique list
  mcp/server.py         the MCP tools (47), thin wrappers over the above
  stix.py               STIX 2.1 export and import
graph/                  the daily pipeline (LangGraph) and its CLI
dashboard/              read-only web UI (Starlette API, Svelte front end)
probe_vm/               probe_helper.py and its installer, deployed to the probe VM
sandbox/                the file-analysis container, built and run on the probe VM
skills/                 agent skills; setup.sh copies them to each harness
scripts/                migrations and backfills, run by hand
```

Three machines are involved:

- **This host** holds all data, runs the pipeline, the MCP server and the
  dashboard, and talks to third-party APIs.
- **The probe VM** is the only machine that connects to adversary
  infrastructure. This host reaches it over SSH with a key pinned to one
  command; the VM cannot connect back.
- **The sensor** (Zeek, read through the SIEM) records the probe VM's
  traffic, which is where passive fingerprints come from.

## Two stores

**Cluster files** (`data/clusters/<slug>.json`, with a rendered `.md`
beside each) hold what an analyst writes and curates: the profile, the
Diamond fields, ATT&CK techniques, the hunt log, gaps, relationships, and
the observables that are members of the cluster. `cti/clusters/storage.py`
owns them. Every change takes one global file lock (`_data_lock`), so two
processes cannot interleave a read-modify-write. The directory is not in
git and is read from `CTI_DATA_DIR` once, at import.

**DuckDB** (`data/tracking/tracking.duckdb`) holds everything measured over
time: daily observations, selectors (the values two hosts can share),
netwatch service snapshots and changes, open-directory listings and sample
verdicts, active-scan history, memberships and candidate scores.
`cti/store/` owns it.

DuckDB allows one writer process at a time, and a writer locks out every
reader in other processes. Three rules follow, and most of the 2026-11
audit's findings were violations of them:

1. Slow work, meaning anything that waits on the network, runs with no
   connection open. Read the work list, close, do the work, reopen to write.
2. Code that only reads uses `store.connect_read()`, which shares the file.
3. Code that writes uses `store.connect_retry(read_only=False)`, which
   waits for a locked database instead of dropping the write.

**Membership is in both stores.** A cluster's members are observables in
its file and rows in the `memberships` table; candidates and rejections
live only in the table. Each change writes the table first and the file
second. `python -m graph doctor` reports any disagreement, and the daily
run does the same check.

Everything else that is state but not a cluster lives under `data/`:
`data/netwatch/` (scan spool, queue, outstanding jobs), `data/hunt_rules/`,
`data/flowcarp/models/`, `data/reports/` (local report files), `data/runs/`
(pipeline traces).

## Where traffic may go

`cti/sources/http.py` is the one transport, and every request names how it
travels:

- `via="probe"` sends it from the probe VM. Anything that names a tracked
  indicator to a third party (RDAP, RIPEstat, DNS) or touches the indicator
  itself goes this way, so this host never originates that traffic and the
  sensor captures all of it.
- `via="direct"` sends it from this host. Queries against a vendor's own
  index go this way: Webamon, HoneyLabs, ThreatFox, Validin, InternetDB,
  passive DNS, and the fetch of an analyst-supplied report URL.

A request that carries a credential never goes through the probe; the
transport refuses it. The probe VM is the least trusted machine in the lab
and holds no API keys.

Two words are defined terms in this project, and the
infrastructure-pivoting skill holds the definitions: **pivoting** asks
third parties and indexes about an indicator; **probing** connects to it.
Probing that is loud (`active_scan`) or that downloads files
(`analyze_opendir_samples`) happens only when an analyst asks for it by
name.

On the probe VM, `probe_helper.py` fetches only `http` and `https` URLs. A
crawl or a download stays on the host and port it was pointed at, and no
redirect may lead to a private or loopback address.

## The cluster code

`cti/clusters/` is layered; each module imports only from those above it.

| Module | Holds |
|---|---|
| `storage` | cluster files, the write lock, the detection registry, the reverse index |
| `profile` | description, techniques, hunt log, detections, relationships, gaps |
| `lifecycle` | active, dormant and retired; how liveness is judged |
| `enrich` | looking an indicator up; network work that never holds the lock |
| `observables` | adding, removing and deciding indicators and candidates |
| `expand` | `pivot_cluster` (the daily sweep) and `pivot_and_expand` |
| `scan` | `active_scan` |
| `reports` | report ingest, STIX import and export |
| `doctor` | the check that the two membership records agree |

Functions that both look things up and file the result are split in two:
an unlocked phase that does the network work, then a locked phase that
re-reads the cluster and writes. A cluster write never waits on a network
call.

`cti.core` re-exports all of it and is what the MCP server, the pipeline,
the dashboard and the scripts import. To patch a function in a test, use
`tests/cluster_patching.py`, which patches every module that holds the
name.

### Members, candidates, links

An indicator a report or an analyst names is a **seed**, and a member. An
indicator the system finds by pivoting is a **candidate**: it is scored
against the cluster's members, shown to the analyst, and becomes a member
only when accepted. A rejection is remembered so the same host is not
filed again.

The score comes from `cti/store/relatedness.py`. Each shared value is a
fact with a class (identity, structural, behavioural, contextual), and
facts about one certificate or one address count once. A fact is worth less
when the two hosts held it at different times, when the value is common
across the internet, when a certificate is a server's default, when an
address answers the same way for every name, or when either end is a CDN
edge.

`cti/store/expand.py` decides which links between indicators the daily
digest calls corroborated. It reads the same score and promotes a link in
the `strong` band. With no discount that is the rule the skill states: one
identity fact, or two independent structural ones.

## The daily pipeline

`python -m graph daily` runs two stages, drawn in `docs/graph-*.mmd`.

**Collect** needs no model:

1. `ingest_inbox` loads report CSV/JSON from the inbox, registers new
   clusters, and ingests any netwatch results still spooled.
2. `sweep` runs once per cluster, in parallel: `pivot_cluster` looks up
   every tracked domain and address and records what changed.
3. `enrich_and_write` enriches addresses that are due (HoneyLabs over its
   hosted MCP server, RDAP, RIPEstat), under a daily budget.
4. `run_analytics` computes the change tables.
5. `corroborate` prices rare selector values and finds links between
   indicators.
6. `expand_coverage` expires stale candidates, re-scores the rest, and once
   a week reverse-pivots each cluster's rare selectors. It ends with the
   membership check.
7. `write_digest` writes the day's digest.

**Analyze** uses the model (`CTI_GRAPH_MODEL`): `rank` picks what is worth
reading, in code, before any token is spent; five specialists run in
parallel, one per family (`infra_change`, `cert_tls`, `hosting`,
`opendir`, `infrastructure`); `persist` stores their findings; `narrate`
writes the day's narrative. A quiet day skips the specialists.

Each phase records its own failure and the run continues. Failed phases
are listed at the top of the digest. Every run is traced to `data/runs/`.

## netwatch

`python -m graph netwatch` re-scans tracked hosts on a schedule and records
what each port answers with.

- `watchlist.py` builds the targets from the cluster files by lifecycle:
  `hot` (hourly, a short port list), `full` (daily, a port sweep), `sweep`
  (discovery).
- `jobs.py` submits every job to the probe, polls them together, and
  spools the results. A job that outlasts the run is collected by the next
  one.
- The probe's worker scans several targets at once and writes a record for
  every port it checked, open or closed.
- `ingest.py` loads the spool: it joins Zeek's passive fingerprints, writes
  `service_snapshots`, diffs each port against its own vantage's last scan
  into `service_changes`, and derives selectors.

Three guards keep bad data out. Ports listed in
`CTI_NETWATCH_INTERCEPTED_PORTS` count as open only with an application
answer behind them. If `CTI_NETWATCH_CONTROL` names a host with known
ports, a job whose scan of it is wrong is set aside in
`spool/quarantine/`. A port sweep that reported an error closes nothing.

Hunt rules, certificate-transparency and neighbourhood discovery, the
Windows-client vantage and FlowCarp labelling are described in the README.

## Probing on request

**`active_scan(target, cluster, tools, ports)`** runs nmap (the top 100
ports, plus any named) and a path and open-directory search from the probe
VM. Ports are added to the observable and diffed. Each open directory is
listed recursively into `opendir_files` and diffed, so a newly dropped file
shows up in the digest. Every run is recorded in `active_scans` with the
Zeek time window its traffic falls in.

**`analyze_opendir_samples(indicator, urls)`** downloads named files on the
probe VM and analyses them in a container with no network and no
capabilities. Only JSON verdicts come back: hash, type, YARA matches, a
strings sample, extracted indicators, archive contents. No sample byte
reaches this host. Verdicts are stored per file URL in `opendir_samples`.

## Reports, ATT&CK, detections, STIX

**Reports.** `ingest_report(source, cluster_name)` reads a report and
extracts hashes, domains, addresses, URLs, emails, CVEs, wallets and
ATT&CK technique IDs by pattern. A URL must be public `http(s)`; a local
file must be in `data/reports/` or a folder named in `CTI_REPORT_DIRS`.
A local PDF needs `pdftotext` installed. `analyze_report` previews the
extraction without writing. Extraction over-matches, and every new domain
and address gets a live lookup, so `exclude` drops values before anything
is sent. A report with no observables and no techniques returns a
`warning`: it usually means the indicators are in a table or an image.

**ATT&CK.** `cti/attack/` bundles a technique list generated from MITRE's
STIX corpus by `scripts/refresh_attack_data.py`. `update_ttp` and report
ingest check each ID and name against it and return a `warning` for an
unknown, revoked or deprecated ID or a mismatched name. The warning never
blocks the write.

**Detections** live in one registry
(`data/clusters/_registry/detections.json`). A `technique`-scoped detection
joins onto every cluster that logs one of its techniques; a
`cluster`-scoped one appears only on the clusters it names. A cluster's
`detections` are joined at read time. `get_technique_usage` is the reverse
view.

**STIX.** `export_stix_bundle` renders a cluster as an Intrusion Set, an
Attack Pattern and a `uses` Relationship per technique, a Relationship per
cross-cluster link, and a Note per hunt log entry. IDs are stable across
exports. `export_stix_ecosystem` walks the relationship graph so every
reference resolves. `import_stix_bundle` creates or merges a cluster. The
JSON is hand-built; run a bundle through `stix2validator` if a consumer
needs strict validation.

## The MCP server and the dashboard

`cti/mcp/server.py` exposes 47 tools over stdio (`.mcp.json`, written by
`setup.sh` with absolute paths). Each is a thin wrapper.

- A tool that changes a cluster replies with what changed and the size of
  each part, not the whole profile. `get_cluster` reads a profile.
- Tools that reply with a dict turn a busy database, an unknown cluster or
  a rejected argument into `{"error": ...}`.
- `query_duckdb` is read-only and cannot reach the filesystem.

The dashboard (`dashboard/server.py`) is read-only and has no login. It
binds to `127.0.0.1` unless `CTI_DASHBOARD_HOST` is set.

## Tests

`pytest` runs about 1,240 tests in a minute and a half. `tests/conftest.py`
points both stores at temporary directories before anything from `cti` is
imported, asserts for every test that the cluster store is not under the
repository's `data/`, blocks real sockets, and blocks the probe transport.
`ruff check .` must pass; `tests/test_lint.py` runs it.

A bug fix lands with a test that fails without it.

## Adding a data source

Add a module under `cti/sources/` that uses `http.fetch` with an explicit
`via`. Read its API key from the environment, never from the repository,
and give it a budget in `cti/sources/budget.py` if it is metered. Call it
from `cti/clusters/enrich.py`, mirror it as a tool in `cti/mcp/server.py`
if an analyst should be able to call it directly, and describe in the
relevant skill what its answers do and do not prove.
