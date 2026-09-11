Daily actor-tracking analysis. Read the pre-computed digest at
{{DIGEST}} - it is the complete, bounded summary of everything Stage A
found today; you do not need to re-derive it.

Rules (token budget is the point of this design - stay inside it):
- Pick at most 3 noteworthy items from the digest.
- Across the whole session, make at most 5 tool calls total from
  query_duckdb / get_actor_summary, each targeted at one of those
  items. Never run broad queries over raw observations (no
  `SELECT * FROM observations`, no unfiltered scans).
- For each finding worth keeping, persist it with save_correlation
  (correlation_type one of: asn_pivot, port_pattern, temporal_cluster,
  new_infrastructure; include the supporting IPs as indicators).
  Deliberately out of scope: Zeek/OpenSearch/Arkime cross-referencing -
  the digest never includes it (that's a separate, on-demand,
  post-probe capability, not part of this routine daily narrative) -
  so never suggest an OpenSearch/Arkime query as a follow-up, and never
  use correlation_type=zeek_hit.
- What to weigh: an ASN change on actor infrastructure is a pivot
  candidate, but heavy HoneyLabs event counts mean mass-scanner noise,
  not dedicated C2 - say so instead of over-claiming.
- A port change in the "Indicator attribute changes" table (Shodan
  InternetDB's open-port diff on tracked infra, NOT the separate "Port
  scan patterns" table below it - that one is HoneyLabs scan-pattern
  telemetry, a different thing) can mean a C2 listener redeployed or a
  service was added/removed - weigh a medium-confidence port change as
  a pivot candidate similar to an ASN change, but Shodan's snapshot
  reflects whatever last scanned the host and can flap day to day, so a
  low-confidence one (stale baseline) is background noise, not a lead.
- A certificate change in that same table only ever appears when the
  issuer changed or new sibling hostnames showed up on the cert -
  routine same-issuer renewals are filtered out before they reach you.
  An issuer change is the stronger signal (often an infrastructure
  refresh); new sibling hostnames on an existing cert are worth a
  new_infrastructure-flavored look, not an ASN-style pivot correlation.
- attribute=ptr (change_type=ptr_changed): a tracked IP's reverse-DNS
  (PTR) record changed, or first appeared/disappeared. Weigh this by
  what kind of IP it is: a PTR flip on a shared-hosting/CDN/big-cloud
  IP (see the "Cross-actor ASN overlap" note on shared-hosting ASNs, or
  a hostname that itself looks like a CDN/accelerator name) is often
  routine churn, not a signal; a PTR flip on infrastructure that's been
  stable and dedicated to this actor is a stronger signal worth a pivot
  look. A None value on either side means "confirmed no PTR record",
  not a lookup failure - still worth a mention if it's a change from or
  to having one.
- attribute=resolved_ip (change_type=resolved_ip_changed): a tracked
  domain's current resolved IP(s) changed since the last check (the
  same lifecycle lookup that also classifies the domain
  active/dead/sinkholed). An empty new_value can mean the domain went
  dead OR got sinkholed - this table alone can't tell those apart, so
  check the cluster's own status via get_actor_summary before calling
  it "dead". Moving to an IP that looks like different infrastructure
  (different ASN/hosting provider than before) is a stronger pivot
  candidate than moving to another address inside the same CDN/cloud
  range - if the digest alone doesn't tell you which, a query_duckdb
  lookup on the new IP's own observations is a reasonable use of one of
  your 5 tool calls rather than guessing.
- One more attribute type can appear in "Indicator attribute changes",
  an exception to the "never call an attribute-change row newly-
  discovered infrastructure" rule below (it genuinely is a first-ever
  discovery, not a changed value on already-known infra):
  attribute=cert_hash (change_type=cert_new): a tracked domain's
  certificate rotated to a new SHA256 - already auto-filed onto the
  cluster's own hash list as `cert-sha256:<hash>`, so just note it's
  now tracked/pivotable. Flag prominently if `revoked` is true.
- Only call something "new" if it's in the digest's "New unattributed
  IPs in known-actor ASNs" table, or the cert_hash exception above -
  those are already filtered to first-observation-ever-in-window.
  Never describe an indicator from the "Cross-actor ASN overlap" table as new:
  everything there is a pre-existing, already-attributed indicator whose
  ASN happens to overlap a different actor's known ASNs - note it as a
  lead or drop it, never as newly-discovered infrastructure. Same rule
  for every OTHER "Indicator attribute changes" row (asn, ports, cert,
  cert_hash, ptr, resolved_ip): each is a change on an already-tracked
  indicator (first-ever-check baselines are excluded before the digest
  is built) - never call one newly-discovered infrastructure either.
- Only use correlation_type=new_infrastructure for indicators the
  digest itself marks first-seen-in-window (the "New unattributed
  IPs" table, ingested reports, or pivot_and_expand discoveries) -
  never for an indicator that already has prior observations or
  existing cluster provenance, even if it's newly co-located with a
  tracked actor's ASN.
- Finish with a short markdown narrative (your stdout is saved as the
  day's narrative file): what happened, what you saved, and 1-3
  recommended follow-up queries for tomorrow. Keep it under ~40 lines.
- If the digest shows nothing genuinely noteworthy, write two lines
  saying so and stop - no tool calls, no filler.
