# Hunt rules

A hunt rule is a saved signature of what a tracked operator's infrastructure
looks like. It is our own Censys-style query, run against our own snapshots
and against the Certificate Transparency stream, instead of a vendor's.

Each `*.yaml` file here holds one rule (or a list of rules). A rule is only
matched when `enabled: true`. Drafts start disabled — a human reads the
evidence and turns it on. Nothing in the pipeline enables a rule for you.

## Format

```yaml
id: clusterX-sliver-https        # required, unique
cluster: clusterX                # optional owner; required to FILE candidates
enabled: false                   # only true rules are ever matched
note: >                          # why this rule exists; shown in the hunt log
  Sliver C2 over HTTPS: the framework's default JARM plus the kit's header
  order, seen on 4 clusterX hosts. Drafted 2026-10-15.
where:
  all:                           # every term must match (AND)
    - tls.jarm: "29d3fd00029d29d00042d43d00041d5de67cc7f44f9c5bd6c3f5dd2a7f6b3b"
    - http.header_order: "server,content-length,content-type"
  any:                           # at least one must match (OR), optional
    - tls.subject_cn: "^internal\\.[a-z0-9-]+\\.net$"
  ports: [443, 8443]             # restrict to hosts with these ports open
scope: [snapshots, ct]           # where it runs
action: candidate                # candidate (file for review) or alert
```

### Terms

Every term is a single `selector_type: value` pair. The selector types are
the ones in `cti/store/selectors.py` (`tls.jarm`, `tls.cert_sha256`,
`http.header_order`, `tls.ja4s`, `tls.san`, `dns.apex`, …). An unknown type
is logged and never matches.

* **In `snapshots` scope** a value is matched **exactly** (after the same
  normalization selectors use). This is the right form for a JARM, a cert
  hash, a header-order digest — a fixed fingerprint.
* **In `ct` scope** a value is treated as a **regex** (`tls.san`,
  `tls.subject_cn`, `tls.issuer`) or an apex suffix (`dns.apex`), because a
  certificate names things that vary. An exact string is a valid regex that
  matches itself, so a rule can carry both scopes if its values suit both.
  Only cert-expressible terms are checked against CT; the rest are confirmed
  by the scan the CT hit triggers.

### Scope, action and corroboration

* `scope: [snapshots]` compiles to SQL over the `selectors` table joined with
  `service_snapshots` (for the port constraint) and returns matching hosts.
* `scope: [ct]` matches streaming certificates in memory and queues the
  resolved names as `hot` scan targets.
* `action: candidate` files a matching host as a cluster **candidate** — it
  shows in the digest and must be `accept_candidate`-ed before it exports. A
  rule is a human-approved signature, so a rule hit is filed on the rule's
  authority; a plain pivot (Webamon, passive DNS) still has to clear the
  corroboration rule first.
* `action: alert` only reports; it files nothing.

## Drafting a rule

`cti.netwatch.rules.suggest(con, indicators, cluster=...)` proposes a rule
from the selectors several of a cluster's hosts share and that are rare. It
returns a disabled draft plus the supporting evidence. Review it, tighten
the terms, give it a real `id` and `note`, set `enabled: true`, and drop it
here. `example-disabled.yaml` is a non-matching template to copy.
