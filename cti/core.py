"""Cluster tracking, as one namespace.

The code lives in `cti/clusters/`, split by concern; see that package's
docstring for the layout. This module re-exports every name from it, so
`from cti import core; core.add_observable(...)` keeps working for the MCP
server, the pipeline nodes, the dashboard and the scripts.

It is a view, not a place to put code. A name assigned here (a test
patching `core.load_cluster`, say) changes this module only: the functions
in `cti/clusters/` look names up in their own modules.
"""
# ruff: noqa: F401
from __future__ import annotations

# Modules and helpers that callers and tests reach through this namespace.
from . import membership
from . import store as tracking_store
from .clusters_render import write_markdown
from .probe import vm_proxy
from .report import ingest as report_ingest
from .sources import passive, pivot, webamon
from .tracking.analytics import SHARED_HOSTING_ASNS
from .tracking.history import (
    _log_cluster_enrichment_history, _log_observation, _record_opendir,
)
from .util import now_iso

from .clusters.doctor import membership_drift
from .clusters.storage import (
    log, _REPO_ROOT, DATA_DIR, OBSERVABLE_CATEGORIES, ClusterNotFound, _slug, _path,
    _lock_state, _data_lock, _synchronized, _new_cluster, _migrate, load_cluster,
    save_cluster, list_clusters, create_cluster, get_cluster, _registry_path,
    _load_detection_registry, _save_detection_registry, _index_path,
    _index_signature, _build_reverse_index, _reverse_index, DETECTION_SCOPES,
    _detection_scope, _detections_for_cluster,
)
from .clusters.profile import (
    STATUS_COLORS, STATUS_LABELS, update_profile, update_ttp, remove_ttp,
    append_hunt_log, add_detection, get_technique_usage, add_relationship, add_gap,
    update_gap, remove_gap, export_navigator_layer,
)
from .clusters.lifecycle import (
    _without_inactive, _find_entry, member_values, LIFECYCLE_STATES,
    INACTIVE_LIFECYCLES, _DORMANT_DAYS_DEFAULT, _RETIRED_DAYS_DEFAULT, _env_days,
    dormant_days, retired_days, lifecycle_of, _is_live, _age_lifecycle,
    sweep_targets,
)
from .clusters.enrich import (
    _FINGERPRINTABLE_CATEGORIES, FINGERPRINTABLE_CATEGORIES,
    _KNOWN_NON_ACTOR_DOMAINS, _KNOWN_NON_ACTOR_IPS, _is_ipv4, _is_probe_worthy,
    _PIVOT_CACHE_TTL_ENV, _PIVOT_CACHE_TTL_DEFAULT, _cached_pivot, _observe,
    _tls_from_observe, _live_http, _webamon_domain, _webamon_ip,
    _webamon_infostealers, _internetdb, _pdns, _subdomains_for, pivot_observable,
    honeylabs_context, summarize_honeylabs, _PIVOT_CLUSTER_WORKERS,
    _threatfox_enrichment, _run_sources, _domain_lifecycle, _ip_lifecycle,
    _sweep_lifecycle, _new_values, _stamp_webamon_summary,
    _apply_enrichment_snapshot, _record_enrichment,
)
from .clusters.observables import (
    get_observables, find_observable, add_observable, _add_observable_locked,
    remove_observable, CANDIDATE_QUIET_DAYS, file_candidate, accept_candidate,
    reject_candidate, _set_role_analyst, _reject, expire_candidates,
    _merge_observables, _merge_ttps,
)
from .clusters.expand import (
    pivot_cluster, pivot_and_expand, _pivot_and_expand_ipv6_skip,
    _pivot_and_expand_merge,
)
from .clusters.scan import (
    _ACTIVE_SCAN_TOOLS, _opensearch_max_ts, _ts_to_dt, _MAX_EXTRA_DIRSEARCH,
    _TLS_SERVICES, active_scan, _active_scan_file,
)
from .clusters.reports import (
    _EXTRACTION_EMPTY_WARNING, _nothing_extracted, _REPORT_CACHE_TTL_ENV,
    _REPORT_CACHE_TTL_DEFAULT, _fetch_report_text, analyze_report, ingest_report,
    _apply_exclusions, _ingest_report_phase1, _ingest_report_phase2,
    export_stix_bundle, export_stix_ecosystem, import_stix_bundle,
)
