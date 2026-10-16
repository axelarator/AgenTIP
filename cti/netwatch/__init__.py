"""Self-owned network-observable tracking.

We re-scan known-bad hosts from our own probe on a schedule, diff each
service against its last scan, and derive the same selectors the observe
pass does - so a port opening, a certificate swap or a JARM change on a
tracked host is our own signal, not a vendor's. The probe sits on the
mirrored bridge, so Zeek fingerprints every session we open and the
passive half (ja4s/ja4ts/ja4l) is joined back in during ingest.

- watchlist: which hosts to scan, and how hard, from the cluster files.
- jobs: push a scan batch to the probe, poll, pull the results.
- ingest: load the results, diff them, derive selectors, record changes.
"""
