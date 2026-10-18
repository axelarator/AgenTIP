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

### What gets scanned, and what never is

netwatch's watchlist (`cti/netwatch/watchlist.py`) decides what the probe
scans: every cluster member, plus candidates at `CTI_CANDIDATE_SCAN_BAND`
(default `weak`) or better, tiered by lifecycle. A newly filed domain or IP
is picked up on the next hourly pass - there is nothing to trigger by hand.

Nothing that fails `core._is_probe_worthy` is scanned. Extraction is a
blind regex over report text (it will happily match a version string, a
public DNS resolver named as "the malware checks connectivity against
8.8.8.8", or a vendor's own site named in passing) and `add_observable`
trusts what it is handed, so without this gate a false match would draw a
live scan exactly like a real IOC. The gate rejects private, reserved,
loopback and link-local IPs; IPv6 (below); a short curated list of public
DNS resolvers; and a short curated list of known non-actor apex domains
(major vendors, CDNs, sinkhole operators - exact match only, since a
subdomain of `github.io` or `amazonaws.com` is routine attacker-controlled
shared hosting). It does **not** affect whether a value is tracked - only
whether our probe touches it. A skip is reported on the caller's return
value (and, for `ingest_report`, persisted on that ingest's
`report_sources` entry) as `scan_skipped`: `[{category, value, reason}, ...]`.

**Functional rule: ignore IPv6 for pivoting and probing.** The probe VM
has no IPv6 route, so an IPv6 target can only ever time out - confirmed
directly, every IPv6 target in a real probe run failed with "network
unreachable" while the same run's IPv4 targets worked. It is enforced in
two places: the scan gate above, and `pivot_and_expand`, which
short-circuits on an IPv6 target. `pivot_cluster`'s RIPEstat lifecycle
check still runs on tracked IPv6 addresses - it is a third-party API query
keyed on the address, not a connection to it - and AAAA records in a
domain's own resolution are left alone as descriptive DNS footprint.

### Where JA4+ and JARM come from

| Value | Source |
|---|---|
| JARM | httpx `-jarm`, in every netwatch scan and the daily observe pass |
| JA4S, JA4X* | Zeek's ssl.log for the session **tlsx** opened (pinned - a server answers each client hello differently) |
| JA4TS, JA4L | Zeek's conn.log for that same session |
| JA4, JA4H, JA4T, JA4SSH | client fingerprints of the malware - from reports, never from our own probing |

\* Zeek does not emit JA4X; see the cluster-tracking notes for its status.

### The fingerprint queue (retired 2026-10-17)

Filing a new domain or IP used to queue it, and
`scripts/probe_pending_fingerprints.py` drained the queue by hand: a
reference JARM scan plus one Python TLS handshake from the probe, then a
Zeek lookup. netwatch replaced both halves - its httpx JARM agreed with the
reference tool on every host measured at the same time, and its pinned
tlsx session gives JA4S from one consistent client, where the queue's
Python handshake was a different client again. The queue was never on a
schedule, so it was also quietly piling up. Its full description is in
this file's git history.

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

