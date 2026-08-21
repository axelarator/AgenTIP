"""Inbox ingestion for threat-report indicators, plus the one-time
bridge that seeds actors from the JSON cluster store.

Input contract: drop files into data/tracking/inbox/ as either
  *.csv  - header: ip,actor,campaign,date_observed,source_url
  *.json - a list of objects with those same keys
Rows with an unparseable IP or a missing actor are skipped and counted,
never abort the file. Processed files are archived (renamed) so a
re-run of Stage A can't double-ingest.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any

import duckdb

from . import store

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _inbox_dir() -> Path:
    return Path(os.environ.get("CTI_TRACKING_INBOX",
                               _REPO_ROOT / "data" / "tracking" / "inbox"))


def _archive_dir() -> Path:
    return Path(os.environ.get("CTI_TRACKING_ARCHIVE",
                               _REPO_ROOT / "data" / "tracking" / "archive"))


def _parse_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text())
        if not isinstance(data, list):
            raise ValueError("JSON inbox file must be a list of objects")
        return [r for r in data if isinstance(r, dict)]
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _parse_row(row: dict[str, Any]) -> dict[str, Any] | None:
    ip_raw = str(row.get("ip") or "").strip()
    actor = str(row.get("actor") or "").strip()
    if not ip_raw or not actor:
        return None
    try:
        addr = ipaddress.ip_address(ip_raw)
    except ValueError:
        return None
    observed = str(row.get("date_observed") or "").strip()
    try:
        observed_at = datetime.fromisoformat(observed) if observed else None
    except ValueError:
        observed_at = None
    if observed_at is None:
        observed_at = datetime.combine(date.today(), datetime.min.time())
    return {
        "ip": str(addr),
        "indicator_type": f"ipv{addr.version}",
        "actor": actor,
        "campaign": str(row.get("campaign") or "").strip() or None,
        "observed_at": observed_at,
        "source_url": str(row.get("source_url") or "").strip() or None,
    }


def ingest_inbox(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """Parse and upsert every inbox file, then archive it. Returns a
    per-file summary for the digest."""
    inbox = _inbox_dir()
    archive = _archive_dir()
    files: list[dict[str, Any]] = []
    new_ips: set[str] = set()
    if not inbox.is_dir():
        return {"files": files, "rows_ingested": 0, "rows_skipped": 0,
                "new_ips": []}
    for path in sorted(inbox.iterdir()):
        if path.suffix.lower() not in (".csv", ".json") or not path.is_file():
            continue
        summary = {"file": path.name, "ingested": 0, "skipped": 0}
        try:
            rows = _parse_rows(path)
        except (ValueError, OSError, UnicodeDecodeError) as e:
            summary["error"] = str(e)
            files.append(summary)
            continue
        for raw in rows:
            parsed = _parse_row(raw)
            if parsed is None:
                summary["skipped"] += 1
                continue
            store.upsert_observation(
                con, observed_at=parsed["observed_at"],
                indicator_value=parsed["ip"], source=f"report:{path.name}",
                indicator_type=parsed["indicator_type"], actor=parsed["actor"],
                campaign=parsed["campaign"], source_url=parsed["source_url"])
            store.upsert_actor(con, parsed["actor"], parsed["observed_at"])
            new_ips.add(parsed["ip"])
            summary["ingested"] += 1
        archive.mkdir(parents=True, exist_ok=True)
        path.rename(archive / f"{date.today().isoformat()}-{path.name}")
        files.append(summary)
    return {
        "files": files,
        "rows_ingested": sum(f["ingested"] for f in files),
        "rows_skipped": sum(f["skipped"] for f in files),
        "new_ips": sorted(new_ips),
    }


def seed_from_clusters(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """One-time bridge: import ipv4/ipv6 observables from the JSON
    cluster store as observations, creating one tracked actor per
    cluster with cluster_slug set. That slug string is the entire
    actor<->cluster linkage; the JSON store stays canonical for
    cluster/TTP/diamond data and there is no reverse sync."""
    from .. import core  # deferred: pulls in the whole cluster stack

    today = datetime.combine(date.today(), datetime.min.time())
    seeded: dict[str, int] = {}
    for slug in core.list_clusters():
        cluster = core.load_cluster(slug)
        name = cluster.get("name") or slug
        entries = (cluster.get("observables") or {}).get("ips") or []
        count = 0
        for entry in entries:
            value = entry.get("value")
            if not value:
                continue
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            store.upsert_observation(
                con, observed_at=today, indicator_value=str(addr),
                source=f"cluster:{slug}", indicator_type=f"ipv{addr.version}",
                actor=name,
                metadata={"cluster_sources": entry.get("sources", [])[:5]})
            count += 1
        store.upsert_actor(con, name, today, cluster_slug=slug)
        seeded[name] = count
    return {"actors_seeded": len(seeded), "ips_by_actor": seeded}
