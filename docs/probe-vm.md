# The probe VM

Operator documentation. This is the build, the runbook and the war
stories for the lab's probe VM — how it is provisioned, what the helper
can do, and which failures have already been paid for.

It lived in the old threat-cluster-tracking skill until it was 285 of
that file's 828 lines. It does not belong in a skill: a skill is read by
an agent on every invocation and should say what to *do*, while this says
how the machine is *built*. A human reads this once when something is
broken; an agent was paying for it every time.

The agent-facing rules that used to sit alongside it are now in
`skills/infrastructure-pivoting/SKILL.md` (what a pivot means, and when
probing is allowed at all) and `skills/cluster-bookkeeping/SKILL.md`.

> Some of what follows predates the `observe` pass and the provisioning
> key. Where this file and `probe_vm/setup_probe_vm.sh` disagree, the
> script is what actually runs.

## Deploying a change to the helper

`probe_vm/probe_helper.py` is the VM-side payload. It is installed by
`probe_vm/setup_probe_vm.sh`, which copies the `probe_helper.py` sitting
**beside it** — so deploying a stale copy of the script deploys a stale
helper, silently and with no version to check.

To confirm what is actually running, compare the file the VM has against
the repo's:

```bash
# on this host
sha256sum probe_vm/probe_helper.py
# on the probe VM
sudo sha256sum /opt/cti/probe_helper.py
```

A cheaper smoke test, from this host, is to look at the shape of an
`observe` result. Each of these keys was added by a specific change, so
its absence dates the deployed helper:

| key | added by |
|---|---|
| `responded` | "Record a probed-but-silent host instead of losing it to an empty dict" |
| `ports: null` when nothing scanned | "Stop reporting an unscanned host as having no open ports" |

```python
from cti.probe import vm_proxy
r = vm_proxy.observe("scanme.nmap.org", kind="domain")
sorted(r)            # 'responded' present?
r["ports"]           # None = nobody scanned; [] = scanned, nothing open
```

## Provisioning

Tool installs go through `probe_vm/cti-provision`, pinned to a second
SSH key by a forced command. It deliberately **cannot deploy code**:
there is no verb that writes `probe_helper.py` or a Dockerfile. Helper
and sandbox changes go through `setup_probe_vm.sh`, run by a human who
has read the diff.

---

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
private/reserved/loopback/link-local IPs, IPv6 IPs (the probe VM has no
IPv6 route out — see below), a short curated list of well-known public
DNS resolver IPs, and a short curated list of known-non-actor apex
domains (major vendors, CDNs, sinkhole operators — exact-match only, not
subdomains, since a subdomain of e.g. `github.io` or `amazonaws.com` is
routine attacker-controlled shared hosting, not a false positive). It
does **not** affect whether the value gets tracked as an observable —
that stays exactly as permissive as before, it only gates the
active-probing queue. A skip is visible on the caller's return value
(and, for `ingest_report`, persisted on that ingest's `report_sources`
entry) as `fingerprint_queue_skipped`: `[{category, value, reason}, ...]`.
If a skip turns out to be wrong for a specific case, `requeue_fingerprint()`
forces that value back onto the queue — except for IPv6, which it also
refuses (raises `ValueError`), since that skip is never wrong on this
network.

**Functional rule: ignore IPv6 for pivoting and probing.** The probe VM
has no IPv6 route, so an IPv6 target can only ever time out — confirmed
directly (every IPv6 target in a real probe run failed with `WinError
10051`/"network unreachable", while the same run's IPv4 targets and
DNS-driven pivot lookups worked fine). This is enforced in three places,
not just left to the caller's discipline: `_is_probe_worthy` rejects
IPv6 IPs from the fingerprint queue (as above); `pivot_and_expand`
short-circuits entirely (no expansion lookups at all) when called
directly on an IPv6 target; and
`requeue_fingerprint` refuses to force an IPv6 IP back onto the queue.
`pivot_cluster`'s per-IP RIPEstat lifecycle check is unaffected and still
runs on tracked IPv6 IPs — it's a third-party API query keyed on the IP
as a parameter, not a direct connection to it, so it doesn't hit the
routing problem and stays informative. IPv6 addresses appearing in a
domain's own DNS resolution (e.g. an AAAA record in `pivot_cluster`'s
`resolved` list) are left alone for the same reason — that's descriptive
DNS footprint, not a queued probe/pivot target.

That queue only tells you *what* needs probing — moving it to and from
wherever you actually do the probing is outside this tool's scope, but
`mcp-server/scripts/probe_pending_fingerprints.py` +
`mcp-server/scripts/probe_helper.py` are a reference implementation
for a specific, common lab shape: a dedicated probe VM sitting inside
an isolated network segment (its own VLAN, its own OPNsense-fronted
LAN) which is deliberately firewalled so it can *never* connect back
out to the host running this tool — one-way access only, into the lab.
That directionality, not "which side is less trusted," is what decides
who initiates: since the lab segment can't reach out regardless, the
cti host always initiates outbound, in — never the reverse.

Generating the probe traffic and reading back what it produced are two
different things happening on two different machines, but as of this
design they're one SSH hop plus one HTTP query, not two SSH hops.
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
second SSH hop just to ask "what did Zeek see" — a plain outbound HTTP
call does it with one fewer moving part.

- `probe_pending_fingerprints.py` runs on the cti host itself (it
  imports `core.py` directly — no listener, nothing accepts inbound
  connections here). It pops the queue locally, then for every entry
  looks up every port worth probing (`_lookup_ports` — see below) and
  fans it out into one job per (target, port) pair, since a target with
  more than one known port should get each of them probed, not just the
  first. All of those jobs are then dispatched **concurrently** — a
  `ThreadPoolExecutor` (`PROBE_WORKERS`, same worker-count convention as
  `pivot_cluster`'s `_PIVOT_CLUSTER_WORKERS`) fires the SSH round-trip to
  the probe VM for every job at once, multiplexed over the one shared
  `ControlMaster` connection (`vm_proxy.py`) instead of waiting out one
  job's whole probe before even starting the next one's. Each SSH call
  still pipes `{"target": value, "port": ...}` as JSON on stdin (avoiding
  shell-quoting an IOC value that traces back to report text). Once
  every dispatched job in the batch has returned, one shared OpenSearch
  poll (see below) reads back whatever landed in Zeek's logs for every
  (resolved IP, port) pair at once, and everything found either step is
  filed with `add_observable`. This replaced an earlier version that
  processed the queue one target at a time, one port each — one target's
  JARM scan and Zeek poll had to finish before the next target's SSH
  round-trip even began, despite the targets having no dependency on
  each other; a real 17-target run under that design took close to 15
  minutes.

  `_lookup_ports` returns every port it can find for a target — the
  `ports` list report_ingest._extract_ip_ports stamped onto an IP's own
  observable entry (checked first, since it's the most direct signal a
  report gives about that specific IP), then every tracked URL whose
  host matches the target (the only source for domain targets), falling
  back to `[443]` only if neither source found anything. A genuinely
  multi-port C2 (several listeners on the same IP) now gets each of its
  known ports probed instead of only the first one ever recorded.

  The freshness filter for that OpenSearch query is worth calling out
  since it's the fix for the clock-skew bug above, done properly this
  time: `_current_max_ts()` snapshots the newest `ts` already indexed for
  *anything* in OpenSearch **once, before the whole batch is dispatched**
  — not per job — since every job in the batch fires at essentially the
  same time anyway once dispatch is concurrent, and one snapshot ahead of
  all of them satisfies the same freshness requirement a per-job snapshot
  did. After every dispatched job returns with a resolved IP,
  `collect_zeek_fingerprints_batch()` polls all of those (IP, port) pairs
  in one shared `terms` query per attempt (filtered on IP; the port split
  happens locally against `_DST_PORT_FIELD` — `dst_port`, confirmed
  2026-07-20 by sampling real documents across ssh.log/ssl.log/conn.log/
  dns.log/notice.log/files.log the same way `dst_ip` was, and only
  load-bearing when an IP genuinely has more than one port queued) and
  only accepts documents newer than that snapshot,
  shrinking the set of (IP, port) pairs still being waited on as each
  one's fields fill in. Every timestamp compared here came from the same
  clock (Zeek's, via whichever document OpenSearch indexed it as) — never
  a wall-clock reading taken on the cti host or the probe VM. That's what
  actually breaks when you compare across hosts; a fixed offset or a
  bigger window wouldn't have been a real fix, only a bigger unreliable
  guess. Taking the snapshot before any probe fires (not right before
  querying, after the probes already finished) also means the window
  naturally covers the whole batch's actual duration — DNS resolution,
  JARM, the handshakes — instead of a fixed guess that could be too short
  for a slow probe.

  The OpenSearch queries themselves also reuse one HTTP connection for
  the life of a run (`_opensearch_connection()`, an `http.client.HTTPConnection`
  kept open and only reset on a transport failure) rather than paying a
  fresh TCP handshake per query — previously every one of
  `_current_max_ts()`'s and the poll loop's calls opened its own
  connection, which used to add up across a per-target poll loop into
  dozens of redundant handshakes to the same host in a tight loop. This
  is safe without extra locking because dispatch (concurrent, SSH-only)
  and OpenSearch access (sequential, before and after the dispatch phase)
  never overlap in time within a single run.

  The Arkime VM moved to 10.20.0.18 as of 2026-07-27, and its OpenSearch
  no longer sits behind a login — it's plain HTTP, lab-internal only, no
  credential to set. Just run:

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
- `probe_helper.py` runs on the Linux probe VM (needs nothing from this
  repo — standalone, standard library plus `certifi`, shelling out to
  `dig`/`openssl`/`nmap`/`subfinder`/`dirsearch`/Salesforce `jarm` for
  the actions that need them; it also serves the pivot sources' and the
  enrichment sweep's `http_fetch`/`resolve_dns`/`http_probe`/
  etc. — see its module docstring). For a `jarm_probe` job (one
  target/port pair — see below) it:
  resolves the target to an IP once (Zeek's logs only ever key on the
  resolved address, never a hostname string) and reuses that same IP for
  the handshake rather than letting the connection call re-resolve it —
  found live-testing against a CDN-fronted domain that a second, separate
  lookup moments later can come back with a different edge IP than the
  first, silently pointing the OpenSearch query at an address nothing
  was ever sent to. Then, if `tcp_precheck()` (a bare TCP connect test
  against the resolved IP and requested port, a few seconds' timeout)
  finds something actually listening, it runs a JARM scan (the one value
  nothing passive produces) and fires one ordinary TLS handshake — via
  Python's own `ssl`/`socket` modules rather than shelling out to
  `openssl`, so nothing extra needs installing — purely to give the
  target something real to respond to. The handshake's own result is
  discarded; Zeek's log (read back via OpenSearch) is the source of
  truth for what it produced.

  The pre-check exists because a wrong port guess is not a rare edge
  case here — `_lookup_ports` (below) falls back to 443 whenever a
  target's real port isn't recorded, and that guess is simply wrong for
  any C2 on a nonstandard port. Before the pre-check, a wrong guess paid
  JARM's full multi-attempt timeout budget (each of its ~10
  malformed-ClientHello attempts independently re-discovering that the
  same port refuses connections) before giving up; now a closed/filtered
  port fails in `TCP_PRECHECK_TIMEOUT` seconds and both the JARM scan and
  the throwaway handshake are skipped outright, with `error` explaining
  why. This is the main reason a real run's total time is sensitive to
  how many of its targets have a confirmed port versus a blind 443
  fallback — get the port right (see `_lookup_ports`) and this pre-check
  barely matters; get it wrong across many targets and it's what keeps a
  batch of dead guesses from each burning JARM's full budget.

  Probing more than one port for the same target — a target with
  several recorded ports (see `_lookup_ports` below) — means more than
  one request to this script, each independently resolving, pre-checking,
  and (if reachable) JARM-scanning + handshaking its own port. Nothing in
  this script needs to know a target has other ports in flight; each
  request is self-contained.

`collect_zeek_fingerprints_batch()` takes the most recent *non-empty*
value per field, not just whichever document is chronologically last — a
single probe can produce several `ssl.log` rows for the same target
(JARM's malformed-ClientHello attempts included, which show up with an
empty `ja4s` and an alert like `illegal_parameter`/`handshake_failure`),
so picking blindly by recency can land on an empty JARM-probe row
instead of the one real handshake's actual result. It deliberately does
not attempt ja4/ja4h/ja4t/ja4ssh, for the client-vs-responder reason
above, nor ja4x (needs x509.log, and wasn't computed at all by the
zeek-ja4 build tested against here — confirm against your own build
before assuming otherwise).

The SSH hop is configured from the environment (`CTI_PROBE_HOST`/
`CTI_PROBE_USER`/`CTI_PROBE_SSH_KEY`/`CTI_PROBE_KNOWN_HOSTS`/
`CTI_PROBE_HELPER_CMD`, read by `cti_tools/vm_proxy.py`); the remaining
environment-specific constants are marked for you to fill in at the top
of each script (tool/JARM CLI paths in `probe_helper.py`, the OpenSearch
URL/index in `probe_pending_fingerprints.py` — the exact document field names in your own
OpenSearch index depend on how your ingestion pipeline maps Zeek's
fields, e.g. this lab's pipeline renames `id.resp_h` to a flat `dst_ip`
field, so verify against a real query before trusting the output, the
same way the ja4ts/ja4x gaps here were only found by testing against
this lab's actual data rather than assumed). File results with
`add_observable` citing method + date in `source` as above.

Pin the probe VM's `authorized_keys` entry for this key to the helper
with a forced command, so the key can do nothing else:
`command="python3 /opt/cti/probe_helper.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...`
(full build checklist: "Probe VM build" in `mcp-server/README.md`).
The forced `command=` restriction is worthless if a second,
unrestricted line for the same key is sitting above it in that file
(sshd matches the first line, not the most specific one) — if a raw
key was added for initial connectivity testing before the restricted
line was appended, delete it, don't just add the restricted one
alongside it. (The lab previously used a Windows probe VM; if you ever
go back to one, Windows OpenSSH ignores the per-user `authorized_keys`
for Administrators-group accounts and only honors
`C:\ProgramData\ssh\administrators_authorized_keys`.)

