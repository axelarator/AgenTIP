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
- Three more attribute types can appear in "Indicator attribute changes",
  each an exception to the "never call an attribute-change row newly-
  discovered infrastructure" rule below (they genuinely are first-ever
  discoveries, not a changed value on already-known infra):
  - attribute=hostnames: a new domain (Shodan InternetDB + Hackertarget
    reverse-IP, free/keyless - no VT passive-DNS is used for this) was
    seen pointed at a tracked IP. The hostname itself is NOT auto-filed
    as a tracked observable - treat it as a candidate lead
    (new_infrastructure-flavored) and, in the narrative, suggest
    pivot_and_expand or add_observable if it's worth tracking. If the
    row's `certs` field carries a cert_sha256 for that hostname, quote
    it - that's a ready-made pivot value.
  - attribute=cert_hash (change_type=cert_new): a tracked domain's
    certificate rotated to a new SHA256 - already auto-filed onto the
    cluster's own hash list as `cert-sha256:<hash>`, so just note it's
    now tracked/pivotable. Flag prominently if `revoked` is true.
  - attribute=vt_files (change_type=new_file_hash): a VirusTotal
    communicating/downloaded-file relationship on a tracked IP that
    wasn't previously known. Never dismiss one of these as routine or a
    baseline - unlike ASN/ports/cert, this row is never a "first check"
    artifact (see core.py's _record_vt_file_hashes), so every row here
    is itself the notable event. Include the filenames, SHA256, and
    malicious-engine count in the narrative and in save_correlation's
    indicators/narrative fields - that's the record of the finding.
    Deliberately do NOT suggest add_observable or otherwise recommend
    filing the file hash as a tracked observable on the cluster: a
    single IP's communicating-files list is often a large, unvetted
    pile (dozens of generically-labeled samples), and listing one as a
    cluster IOC without manual review risks mis-attributing unrelated
    malware to this actor. Note the finding; leave filing it to the
    operator's own judgment, done by hand later if ever.
- Only call something "new" if it's in the digest's "New unattributed
  IPs in known-actor ASNs" table, or one of the three attribute types
  above - those are already filtered to first-observation-ever-in-window
  (or, for vt_files, are inherently first-observation by design). Never
  describe an indicator from the "Cross-actor ASN overlap" table as new:
  everything there is a pre-existing, already-attributed indicator whose
  ASN happens to overlap a different actor's known ASNs - note it as a
  lead or drop it, never as newly-discovered infrastructure. Same rule
  for every OTHER "Indicator attribute changes" row (asn, ports, cert,
  cert_hash): each is a change on an already-tracked indicator (first-
  ever-check baselines are excluded before the digest is built) - never
  call one newly-discovered infrastructure either.
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
