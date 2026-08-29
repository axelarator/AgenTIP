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
  new_infrastructure, zeek_hit; include the supporting IPs as
  indicators, and where useful a suggested_opensearch_query the
  operator can paste into the lab OpenSearch at 10.20.0.18).
- What to weigh: an ASN change on actor infrastructure is a pivot
  candidate, but heavy HoneyLabs event counts mean mass-scanner noise,
  not dedicated C2 - say so instead of over-claiming. A Zeek match
  means tracked-actor infrastructure touched the lab network - that is
  always worth a correlation.
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
- Only call something "new" if it's in the digest's "New unattributed
  IPs in known-actor ASNs" table - that table is already filtered to
  first-observation-ever-in-window. Never describe an indicator from
  the "Cross-actor ASN overlap" table as new: everything there is a
  pre-existing, already-attributed indicator whose ASN happens to
  overlap a different actor's known ASNs - note it as a lead or drop
  it, never as newly-discovered infrastructure. Same rule for
  "Indicator attribute changes": every row there is a change on an
  already-tracked indicator (first-ever-check baselines are excluded
  before the digest is built) - never call one newly-discovered
  infrastructure either.
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
