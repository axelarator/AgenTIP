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

### Automating the handoff to a fingerprinting vantage point

Every domain/ip newly filed via `add_observable`, `ingest_report`, or
`import_stix_bundle` is automatically queued for fingerprinting —
nothing to remember to trigger by hand. `list_pending_fingerprints()` /
`cti list-pending-fingerprints` peeks at the queue (read-only);
`pop_pending_fingerprints()` / `cti pop-pending-fingerprints` returns
every queued `{cluster, category, value, queued_at}` entry and clears
it atomically in one step — the one-shot "give me everything waiting"
call a fingerprinting script should make each cycle, so nothing gets
processed twice. Already-tracked domains/ips are never re-queued just
because a later report mentions them again; only genuinely new infra
lands in the queue.

A new value only reaches that queue if it also passes
`core._is_probe_worthy` — extraction is a blind regex over report text
(it'll happily match a version string, a public DNS resolver mentioned
as "the malware checks connectivity against 8.8.8.8", or a vendor's own
site named in passing) and `add_observable` trusts whatever it's handed
verbatim, so without this gate a false match drives a live JARM scan /
SSH round-trip exactly like a real IOC would. The gate rejects
private/reserved/loopback/link-local IPs, a short curated list of
well-known public DNS resolver IPs, and a short curated list of
known-non-actor apex domains (major vendors, CDNs, sinkhole operators —
exact-match only, not subdomains, since a subdomain of e.g. `github.io`
or `amazonaws.com` is routine attacker-controlled shared hosting, not a
false positive). It does **not** affect whether the value gets tracked
as an observable — that stays exactly as permissive as before, it only
gates the active-probing queue. A skip is visible on the caller's
return value (and, for `ingest_report`, persisted on that ingest's
`report_sources` entry) as `fingerprint_queue_skipped`:
`[{category, value, reason}, ...]`. If a skip turns out to be wrong for
a specific case, `requeue_fingerprint()` forces that value back onto
the queue.

That queue only tells you *what* needs probing — moving it to and from
wherever you actually do the probing is outside this tool's scope, but
`mcp-server/scripts/probe_pending_fingerprints.py` +
`mcp-server/scripts/win_probe_helper.py` are a reference implementation
for a specific, common lab shape: a dedicated probe VM sitting inside
an isolated network segment (its own VLAN, its own OPNsense-fronted
LAN) which is deliberately firewalled so it can *never* connect back
out to the host running this tool — one-way access only, into the lab.
That directionality, not "which side is less trusted," is what decides
who initiates: since the lab segment can't reach out regardless, the
cti host always initiates outbound, in — never the reverse.

Generating the probe traffic and reading back what it produced are two
different things happening on two different machines, but as of this
design they're one SSH hop plus one HTTPS query, not two SSH hops.
Earlier versions SSHed into a second VM (the Zeek sensor itself) and
read `ssl.log`/`conn.log` directly off disk there — that's `mcp-server/scripts/zeek_log_query.py`,
still present but **retired from the automated pipeline** (kept only
for manual by-hand troubleshooting directly on a Zeek VM; nothing in
`probe_pending_fingerprints.py` invokes it or the Zeek-VM SSH key
anymore). Two real bugs, found only by testing against real multi-target
runs, drove the move off raw files:

- **Log rotation races.** `logs/current/ssl.log` is periodically rotated
  out from under a reader. A bare `FileNotFoundError` mid-poll used to
  abort that *target's whole Zeek lookup* outright, even though the
  file reappeared moments later — 3 of 14 targets in one real run lost
  their JA4S/JA4L/JA4TS window this way, confirmed by cross-checking
  against an OpenSearch dashboard that showed the same connections
  correctly indexed the whole time. The raw-file reader just couldn't
  reliably see data that unquestionably existed.
- **Recency filtering needing either a fixed-duration guess or a
  cross-host clock comparison.** An even earlier version passed a
  timestamp from the probe VM's own clock across to compare against the
  Zeek VM's log timestamps, which broke once testing showed the two
  VMs' clocks were about an hour apart with nothing keeping them in
  sync (see below) — the fix at the time was a `RECENCY_WINDOW_SECONDS`
  constant measured on the Zeek VM's own clock instead, which works but
  is still just a guess at how long a probe might take.

If your lab already ships Zeek's logs somewhere durable and queryable —
here, an OpenSearch index (`zeek-*`) fed by a separate ingestion
pipeline, already confirmed reliable independent of Zeek's own file
rotation — querying that instead of raw files sidesteps both problems
at the source rather than working around them. And if that queryable
store is reachable directly from wherever this script runs (as
OpenSearch was here, over the same Tailscale/home-LAN routes as the
lab VMs, not proxied through any of them), there's no reason to keep a
second SSH hop just to ask "what did Zeek see" — a plain outbound HTTPS
call does it with one fewer moving part.

- `probe_pending_fingerprints.py` runs on the cti host itself (it
  imports `core.py` directly — no listener, nothing accepts inbound
  connections here). It pops the queue locally, then per entry: SSHes
  into the probe VM piping `{"target": value}` as JSON on stdin
  (avoiding shell-quoting an IOC value that traces back to report
  text), then queries OpenSearch for whatever landed in Zeek's logs for
  the resolved IP, filing whatever comes back from either step with
  `add_observable`.

  The freshness filter for that OpenSearch query is worth calling out
  since it's the fix for the clock-skew bug above, done properly this
  time: right *before* dispatching each target's probe,
  `_current_max_ts()` snapshots the newest `ts` already indexed for
  *anything* in OpenSearch. After the probe returns with a resolved IP,
  `collect_zeek_fingerprints()` only accepts documents for that IP
  newer than that snapshot. Every timestamp compared here came from the
  same clock (Zeek's, via whichever document OpenSearch indexed it as)
  — never a wall-clock reading taken on the cti host or the probe VM.
  That's what actually breaks when you compare across hosts; a fixed
  offset or a bigger window wouldn't have been a real fix, only a
  bigger unreliable guess. Taking the snapshot before the probe fires
  (not right before querying, after the probe already finished) also
  means the window naturally covers the probe's whole actual duration —
  DNS resolution, JARM, the handshake — instead of a fixed guess that
  could be too short for a slow probe.

  The OpenSearch password is deliberately **not** a constant in the
  script — it's read from `CTI_OPENSEARCH_PASSWORD` in the environment.
  This file lives in a git-tracked repo; a plaintext credential written
  into it would land in git history the same way the SSH private keys
  never do (they're referenced by local file path, never embedded). Set
  the env var before running:

      export CTI_OPENSEARCH_PASSWORD='...'
      python3 mcp-server/scripts/probe_pending_fingerprints.py

  Every run validates both the SSH hop and OpenSearch reachability
  before touching the queue (`check_access()`) and aborts if either
  fails — probing/pivoting shouldn't start without confirmed access. If
  you're picking this pipeline up in a fresh session and just want to
  check access without draining the queue, run `python3
  mcp-server/scripts/probe_pending_fingerprints.py --check-access`
  rather than independently `ls`-ing for the SSH key files named above
  or `ping`-ing the lab IPs — that kind of ad hoc discovery (enumerating
  credential files by name, probing internal 10.20.0.x hosts directly)
  is indistinguishable from credential-scanning/lateral-movement recon
  to the auto-mode permission classifier and gets denied outright, even
  though the actual access being checked is this pipeline's own
  pre-authorized keys and credentials against its own lab infrastructure.
  `check_access()` validates the same thing more precisely anyway — it
  round-trips a request through the SSH hop's real forced-command
  channel and makes the exact same OpenSearch query `_current_max_ts()`
  would, rather than inferring reachability from a bare ping or a
  file's presence on disk.
- `win_probe_helper.py` runs on the probe VM (needs nothing from this
  repo — standalone, pure standard library so it doesn't matter if
  it's Windows or Linux). Per target it: resolves the target to an IP
  once (Zeek's logs only ever key on the resolved address, never a
  hostname string) and reuses that same IP for the handshake rather
  than letting the connection call re-resolve it — found live-testing
  against a CDN-fronted domain that a second, separate lookup moments
  later can come back with a different edge IP than the first,
  silently pointing the OpenSearch query at an address nothing was
  ever sent to. Then it runs a JARM scan (the one value nothing passive
  produces) and fires one ordinary TLS handshake — via Python's own
  `ssl`/`socket` modules rather than shelling out to `openssl`, so
  nothing extra needs installing — purely to give the target something
  real to respond to. The handshake's own result is discarded; Zeek's
  log (read back via OpenSearch) is the source of truth for what it
  produced.

`collect_zeek_fingerprints()` takes the most recent *non-empty* value
per field, not just whichever document is chronologically last — a
single probe can produce several `ssl.log` rows for the same target
(JARM's malformed-ClientHello attempts included, which show up with an
empty `ja4s` and an alert like `illegal_parameter`/`handshake_failure`),
so picking blindly by recency can land on an empty JARM-probe row
instead of the one real handshake's actual result. It deliberately does
not attempt ja4/ja4h/ja4t/ja4ssh, for the client-vs-responder reason
above, nor ja4x (needs x509.log, and wasn't computed at all by the
zeek-ja4 build tested against here — confirm against your own build
before assuming otherwise).

Both scripts have environment-specific constants marked for you to
fill in (SSH host/key/known_hosts, JARM CLI path, the OpenSearch
URL/index/username — the exact document field names in your own
OpenSearch index depend on how your ingestion pipeline maps Zeek's
fields, e.g. this lab's pipeline renames `id.resp_h` to a flat `dst_ip`
field, so verify against a real query before trusting the output, the
same way the ja4ts/ja4x gaps here were only found by testing against
this lab's actual data rather than assumed). File results with
`add_observable` citing method + date in `source` as above.

Windows probe VM gotcha worth knowing before you debug it blind: if
the probe VM's account is a member of Administrators, Windows OpenSSH
only honors `C:\ProgramData\ssh\administrators_authorized_keys` (ACLed
to SYSTEM + Administrators only), and only if sshd_config actually has
`Match Group administrators` uncommented — the ordinary per-user
`authorized_keys` is ignored for that account regardless of what's in
it. And the forced `command=` restriction is worthless if a second,
unrestricted line for the same key is sitting above it in that file
(sshd matches the first line, not the most specific one) — if a raw
key was added for initial connectivity testing before the restricted
line was appended, delete it, don't just add the restricted one
alongside it.

## Infrastructure pivoting

Tracked observables are a static record until you actually check
whether they're still live. Three tools cover this, from lightest to
heaviest:

**`pivot_observable(value)`** / `cti pivot-observable <value>` — look a
single hash/domain/ip/url up against free public sources and show the
result, writing nothing. Sources: RDAP registration data; RIPEstat
ASN/network context (IPs); Cert Spotter certificate-transparency
history (domains — sibling subdomains as pivot leads, the keyless
stand-in for crt.sh, which is no longer reachable); Hackertarget
reverse-IP co-hosting (IPs); and VirusTotal reputation + resolution
history if `VT_API_KEY` is set. Reach for it when:

- you want to know if a tracked domain/IP is still active or has been
  sinkholed/taken down (RDAP nameservers/status — a domain suddenly
  pointed at a vendor's sinkhole nameservers, e.g.
  `*.microsoftinternetsafety.net`, means it's dead),
- you want the ASN/network owner behind an IP before deciding it's
  worth its own observable entry vs. shared hosting noise,
- you want sibling infrastructure the same operator stood up (Cert
  Spotter subdomains, VirusTotal resolution history, reverse-IP
  co-hosting) as new pivot leads.

Display-only: nothing is written. If it surfaces something worth
keeping, record it yourself with `append_hunt_log`, `add_gap`, or
`add_observable(name, category, value, source)` — cite the pivot as the
source (e.g. "pivot_observable via VirusTotal resolution history,
checked <date>"), not a report URL.

**`pivot_cluster(name)`** / `cti pivot-cluster <name>` — sweep *every*
tracked domain and IP for a cluster at once and stamp a lifecycle status
onto each: domains become `active` / `dead` / `sinkholed` / `expired` /
`unknown` (RDAP + a live DNS resolution), IPs `routed` / `unrouted` /
`unknown` (RIPEstat). Unlike `pivot_observable`, this **writes** the
status (and when it was checked) back onto the observables, so the
cluster's markdown shows at a glance what's still up. Run it to
re-validate a cluster's infrastructure periodically.

**`pivot_and_expand(value, cluster_name)`** / `cti pivot-and-expand
<value> <cluster_name>` — pivot a domain/IP and **file** the
high-confidence new indicators it surfaces straight onto an existing
cluster, with provenance and a hunt-log entry, instead of copying each
finding back by hand. Files by default: Cert Spotter sibling subdomains
under the queried name (same operator) and VirusTotal historical
resolutions. Reverse-IP co-hosted domains are *not* filed by default
(shared-hosting noise) — they come back in the result's `review` block,
or pass `--include-cohosted` / `include_cohosted=True` to file them too.
Only genuinely new indicators are filed; the `review` block lists
everything left for you to judge. Use this once you trust a pivot
enough to expand from it; use `pivot_observable` first when you just
want to look.

### Pivoting vs. probing — when each runs

"Pivoting" and "probing" name two different operations here and they
run on different triggers — don't conflate them:

- **Pivoting** (`pivot_observable`, `pivot_cluster`, `pivot_and_expand`,
  above) only ever touches free public sources (RDAP, RIPEstat, Cert
  Spotter, Hackertarget, VirusTotal). It's passive from the target's
  perspective — no traffic reaches the adversary's infrastructure.
  **Run it automatically** as part of working through a report: after
  `ingest_report`/`analyze_report` files new domains/IPs onto a
  cluster, pivot them (a `pivot_cluster` sweep for lifecycle status, or
  `pivot_and_expand` on ones worth expanding from) without waiting to
  be asked. There's no reason to gate a public-source lookup behind an
  explicit request.
- **Probing** (JA4+/JARM fingerprinting via the vantage point described
  below) generates *real* network traffic against the target — a live
  TLS handshake or a JARM scan the adversary's infrastructure actually
  receives. **Only run it when explicitly asked** ("probe the
  indicators," "get fingerprints," etc.) — never automatically during
  ingestion or pivoting, and never as a default follow-up to a pivot.
  Always route it through the dedicated vantage point (the Win11 probe
  VM pipeline, see "Automating the handoff" above) — never generate
  probe traffic from wherever this tool itself is running.

If a request says "pivot on infrastructure" but clearly means
fingerprinting (JARM/JA4, a specific VM/vantage point named), treat it
as a probing request, not a call to `pivot_*` — confirm with the user
if genuinely ambiguous rather than guessing from the word alone.

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

Prefer the MCP tools if the harness exposes them: `list_clusters`,
`get_cluster`, `create_cluster`, `update_profile`, `update_ttp`,
`remove_ttp`,
`append_hunt_log`, `add_detection`, `get_technique_usage`,
`add_relationship`, `add_gap`, `update_gap`, `remove_gap`, `export_navigator_layer`,
`export_stix_bundle`, `export_stix_ecosystem`, `import_stix_bundle`,
`get_observables`, `find_observable`, `add_observable`,
`remove_observable`, `list_pending_fingerprints`,
`pop_pending_fingerprints`, `pivot_observable`, `pivot_cluster`,
`pivot_and_expand`, `analyze_report`, `ingest_report`.

If MCP tools are not available in this harness, use the CLI directly via
the shell/bash tool from the `mcp-server` directory (or run `./setup.sh`
once from the repo root first, to create the venv and wire `.mcp.json`):

```
python -m cti_tools.cli list-clusters
python -m cti_tools.cli get-cluster <name>
python -m cti_tools.cli create-cluster <name> --description "..."
python -m cti_tools.cli update-profile <name> --adversary "..." --confidence 60 --aliases "Alias A,Alias B"
python -m cti_tools.cli update-ttp <name> <technique_id> <technique_name> <status> --notes "..."
python -m cti_tools.cli remove-ttp <name> <technique_id>
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
python -m cti_tools.cli add-observable <name> <hashes|domains|ips|urls> <value> <source>
python -m cti_tools.cli remove-observable <name> <category> <value>
python -m cti_tools.cli list-pending-fingerprints
python -m cti_tools.cli pop-pending-fingerprints
python -m cti_tools.cli pivot-observable <value>
python -m cti_tools.cli pivot-cluster <name>
python -m cti_tools.cli pivot-and-expand <value> <cluster_name> [--include-cohosted]
python -m cti_tools.cli analyze-report <url-or-file>
python -m cti_tools.cli ingest-report <url-or-file> [--name "..."] [--no-create]
```

Both paths write to the same JSON store, so the data is identical
regardless of which harness you're running in — this is what makes the
harness comparison meaningful.
