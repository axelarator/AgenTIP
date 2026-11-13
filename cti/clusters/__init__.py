"""Threat-cluster tracking: the profiles under data/clusters/ and everything
that reads, enriches and files into them.

One module per concern, layered so that each imports only from those above
it in this list:

    storage       cluster files, the write lock, the registries
    profile       description, techniques, hunt log, detections, gaps
    lifecycle     active / dormant / retired, and liveness
    enrich        looking an indicator up (network; never holds the lock)
    observables   adding, removing and deciding indicators and candidates
    expand        pivot_cluster and pivot_and_expand
    scan          active_scan
    reports       report ingest, STIX import and export

`cti.core` re-exports all of it, and is what callers outside this package
import. To patch a function in a test, patch it in the module that defines
it, or use `tests/cluster_patching.py`, which patches every module that
holds the name.
"""
