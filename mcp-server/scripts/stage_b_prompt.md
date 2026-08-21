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
- Finish with a short markdown narrative (your stdout is saved as the
  day's narrative file): what happened, what you saved, and 1-3
  recommended follow-up queries for tomorrow. Keep it under ~40 lines.
- If the digest shows nothing genuinely noteworthy, write two lines
  saying so and stop - no tool calls, no filler.
