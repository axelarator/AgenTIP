# cti-graph

Threat-cluster tracking as a LangGraph pipeline, over STIX 2.1 and DuckDB.

A fork of [`cti-agent`](../cti-agent) at `096160c`. That repo still works
and still runs its cron; this one is not a drop-in replacement until you
cut over deliberately (see **Cutover**).

```
cti/                    the library
  store/                DuckDB: schema, observations, the change-detector registry
  sources/              external data, one module each, over one transport
  probe/                everything that leaves this host toward an indicator
  core.py               cluster CRUD + enrichment orchestration (still one file)
  report/ attack/ tracking/ mcp/ stix.py
graph/                  the pipeline
  nodes/                rank, the four specialists, collect's Stage A nodes
  prompts/              one prompt per specialist + the shared rules
sandbox/                the analysis container (built and run ON the probe VM)
probe_vm/               probe_helper.py + its bootstrap, deployed to the VM
skills/                 the only committed copy; setup.sh mirrors it per harness
dashboard/              read-only web UI, incl. the per-run node timeline
docs/graph-*.mmd/.png   generated from the graph, not drawn by hand
```

## What changed from cti-agent, and why

### Judgement runs in parallel

Stage B was one `claude -p` pass over a 103-line prompt that encoded
twelve distinct per-attribute judgements, capped at 3 items and 5 tool
calls because that was the only way to bound one serial context.

It is now four specialists running concurrently, each with a ~25-line
prompt covering only the signals it owns, plus a `_common.md` for the
rules that bind all of them:

| Specialist | Owns |
|---|---|
| `infra_change` | `asn`, `ports`, `ptr`, `resolved_ip` |
| `cert_tls` | `cert`, `cert_hash`, `http` |
| `hosting` | `ip_hostnames`, `subdomains`, `webamon_fingerprint`, `infostealer_hits` |
| `opendir` | `opendir_files`, plus sandbox verdicts |

Writes stay centralized in one `persist` node. That is not style: DuckDB's
write lock is process-exclusive and `connect_retry` retries only the
connect, never the body, so four specialists calling `save_correlation`
would surface as "tracking DB busy" rather than queueing.

Stage A is not write-free either, which an earlier version of this README
implied: each cluster's sweep records its own enrichment history at the end.
That is safe because the store serialises read-write connections within a
process (`cti/store/connection.py`), not because sweeps don't write. The
first scheduled run lost a cluster to exactly that assumption.

### Triage happens in code, before any token is spent

`rank` normalizes the digest, scores each row and drops what is provably
noise. On the 2026-09-18 digest it removes 7 of 16 rows — Cloudflare and
AWS addresses listing other tenants' domains, kilobytes each, which the
old single pass paid for in context and then had to reason around.

The ASN list does that work and it has to. The tempting shortcut — "an IP
listing dozens of unrelated domains is shared hosting" — is wrong:
`208.91.112.55` carries 48 hostnames and is STAC4749's own infrastructure
on AS40934, while the Cloudflare and AWS addresses beside it carry 40–50
each. The counts are indistinguishable; the ASNs are not.

### The pipeline is drawable, and runs are recorded

`python -m graph draw` regenerates `docs/graph-{collect,analyze,daily}.{mmd,png}`
from the graph object. It replaces `docs/pipeline.html`, which was good
and had already drifted — drawn against a commit that has since moved,
with a header that disagreed with `setup.sh` about when Stage B runs.

Every run writes `data/runs/<day>.<stage>.jsonl` (`collect`, `analyze` or
`daily`): one record per node, including nodes inside a composed subgraph,
with timings, outputs and errors. `python -m graph trace --date <day>`
prints each stage's timeline; the dashboard's **Pipeline runs** view
renders them together with what the ranker suppressed and why.

One file per stage matters: the first version keyed on the day alone, so
the 06:45 analyze run silently replaced the 06:15 collect run's trace.

Stage A is in the same graph even though no model runs in it. The
question at runtime is "which of these twenty things ran, and which was
slow" — and half of them are collection. Its cluster sweep now fans out;
the old loop swept eight clusters strictly one at a time.

### Open-directory files are analyzed on the probe VM

The VM has always *listed* open directories and never downloaded from
them. `analyze_opendir_samples` fetches named files on the VM and triages
them in a container with `--network=none`, `--read-only`, `--cap-drop=ALL`
and no-new-privileges: sha256, detected type, YARA matches, a strings
sample, extracted URLs and addresses. The staging directory is removed in
a `finally` block.

Only that JSON crosses the SSH channel. **There is no code path on this
host that receives file bytes** — which is the requirement, and also why
the container lives on the VM that did the download rather than here.

It is gated separately from `active_scan`. Listing a directory is
reconnaissance; downloading staged payloads is collection.

### Redundancy

Thirteen confirmed duplications collapsed — most of them documented in
the old repo's own comments, which is how they survived. The ones that
mattered:

- **Ten `_record_*_change` functions and twelve `latest_*_for` queries**
  → ten `AttributeSpec` entries and one driver. Twenty-two functions,
  ~500 lines, expressing ten table rows' worth of difference.
- **Four HTTP transports** → `sources/http.py`, where `via="probe"` vs
  `via="direct"` makes the OPSEC decision a required argument.
- **Three file-backed TTL caches** → `sources/cache.py`, one file per
  key. The pivot cache was an 8.8 MB JSON dict re-read and re-written in
  full on every miss, under a lock, from a six-thread pool.
- **Three separately-counted API budgets** → `sources/budget.py`, which
  reserves under one `flock` before the call. Checking and incrementing
  separately is exactly the race a fan-out exposes.
- **Two ASN normalizers that disagreed** — `lstrip("AS")` takes a
  character set, so `" AS16509"` parsed as `16509` in one and `None` in
  the other.

### The observations table went narrow

52 columns became a five-column spine plus a JSON `payload`, with an
`observations_wide` view projecting the original names so the analytics
SQL, the dashboard and `query_duckdb` are textually unchanged. The old
table needed 36 idempotent `ALTER TABLE`s on every read-write connect,
because each new source added columns and retired ones left theirs behind.

Retired-provider columns are kept: they hold real history (154 Shodan
rows, 20 Cert Spotter rows). So are the five that measure 100% NULL —
`campaign`, `source_url`, `abuse_contact`, `hl_events_7d` and
`infostealer_urls` are all still written or read. Empty today is not the
same as unused.

## Known incomplete

`cti/core.py` is still 2379 lines (from 2774). The store, sources, probe,
report and ATT&CK layers were lifted out of it, and the ten change
detectors it carried are gone — but the cluster-JSON half (CRUD,
observables, the detection registry, the reverse index, markdown
rendering, and the pivot/scan orchestration) has not been split by
concern.

That split is organizational rather than behavioural, and it is not free:
`tests/test_core.py` monkeypatches `core.<attr>` in 134 tests, and a
façade that re-exports from submodules silently breaks that kind of
patching. It is worth doing, with the patch targets moved in the same
change, and it was not worth doing quickly.

## Why this is still Python

The HTTP work was already parallel (`ThreadPoolExecutor` in the cluster
sweep and the fingerprint dispatcher), and nearly all indicator-facing
traffic is not HTTP from this process at all — it is one JSON object over
SSH to the probe VM, multiplexed over a shared ControlMaster. The ceiling
is vendor rate limits (HoneyLabs at 10/min and 400 credits/day, a Webamon
daily quota, RDAP capped at 150/day), not concurrency. Go would have meant
reimplementing `vm_proxy`, `stix.py` and the store across a process
boundary for no measured gain.

## Why the Claude Agent SDK rather than ChatAnthropic

The only LLM call in `cti-agent` was `claude -p`, on a Claude
subscription; there is no `ANTHROPIC_API_KEY` here. `ChatAnthropic` would
need one and would bill per token — which matters when the point is to
run *more* model passes per day. The SDK also speaks MCP natively, so a
specialist gets `query_duckdb` and `get_actor_summary` by naming them,
rather than needing a second definition of each tool to keep in sync.

The cost: nodes are async subprocess turns, so the graph is driven with
`ainvoke`. LangGraph runs async nodes concurrently anyway, which is what
the fan-out needs.

## Quick start

```bash
./setup.sh                      # venv, .mcp.json, skill mirrors
python -m graph draw            # regenerate the diagrams
python -m graph collect         # Stage A  (defaults to today)
python -m graph analyze         # Stage B
python -m graph analyze --dry-run --date 2026-09-18   # no writes
python -m graph trace --date 2026-09-18               # node timings
pytest                          # 409 tests
```

Secrets stay in the environment (`~/.bashrc`, which cron sources):
`WEBAMON_API_KEY`, `HONEYLABS_API_KEY`, `THREATFOX_API_KEY` (optional).
Probe VM: `CTI_PROBE_HOST`, `CTI_PROBE_USER`, `CTI_PROBE_SSH_KEY`,
`CTI_PROBE_KNOWN_HOSTS`, `CTI_PROBE_HELPER_CMD`.

## Cutover

`cti-agent` is untouched and its cron still runs. Two repos must not write
the same DuckDB file — it is process-exclusive for read-write — so
`data/` here is a snapshot, already migrated.

1. Stop the old cron (`crontab -e`) and its dashboard
   (`systemctl --user stop cti-dashboard`).
2. Re-copy `data/` from `cti-agent` and re-run
   `scripts/migrate_schema.py SOURCE DEST --verify`.
3. Deploy the probe VM bootstrap: `probe_vm/setup_probe_vm.sh` (it builds
   the sandbox image and fails if `--network=none` lets a container reach
   the network).
4. Install the cron lines `./setup.sh` prints.
5. Run one day through both pipelines and diff the narratives.

Until then, point this checkout at its own copy with `CTI_DUCKDB_PATH`
and `CTI_DASHBOARD_PORT`.

## Threat cluster tracking, briefly

Unchanged from `cti-agent`. Each cluster is a Diamond-Model JSON record
(adversary, capability, infrastructure, victim) plus STIX profile fields,
an ATT&CK TTP coverage table, a detection inventory, a gaps backlog and an
append-only hunt log. Clusters export as STIX 2.1 bundles (Intrusion Set +
Attack Pattern + Relationship + Note) and can ingest bundles from other
tools. `docs/architecture.md` has the full detail.
