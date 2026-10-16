"""Rebuild cluster membership from seeds: the redesign's cutover.

Every observable in every cluster JSON is classified by where it came from:

  seed       a report (URL or ingested file) or analyst-supplied
  candidate  surfaced by a pivot, a scan or a note - re-scored, not kept
  selector   a property of a host rather than an indicator: auto-filed
             certificate hashes and the JARM / JA4S / JA4TS / JA4X entries,
             which become dated selectors on the host they were measured on
  dropped    JA4L - a latency measurement, which links nothing

plus each cluster's deny list, which becomes `rejected` memberships.

Then every candidate is scored against its cluster's seeds, and the result
is printed and written to a JSON report for review.

The default is a dry run against a COPY of the database, so it touches
nothing live. `--apply` backs up every cluster JSON and the database, writes
the memberships into the live store, and rewrites each cluster JSON so its
observables hold only seeds (plus report-sourced client fingerprints such as
JA4/JA4H, which describe the malware and stay observables). The deny list
moves to the store as `rejected`, and the hunt log records what moved.

    .venv/bin/python scripts/rebuild_from_seeds.py [--cluster jadeprox] \\
        [--report PATH] [--apply]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.membership import (MEMBER_CATEGORIES, SERVER_FINGERPRINTS,  # noqa: E402
                            fingerprint_selector)

SEED = "seed"
CANDIDATE = "candidate"
SELECTOR = "selector"
DROPPED = "dropped"

_REPORT_FILE = re.compile(r"\.(pdf|txt|html?|md|docx?)$", re.I)
_TLS_GRAB = re.compile(r"^live TLS grab for (?P<host>\S+?)(?:, seen (?P<when>\S+))?$")


def classify(category: str, entry: dict[str, Any]) -> tuple[str, str]:
    """(verdict, why) for one cluster-JSON observable."""
    first = ((entry.get("sources") or [""])[0] or "").strip()
    if category == "ja4l":
        return DROPPED, "JA4L is a latency measurement, not a selector"
    if category in SERVER_FINGERPRINTS:
        return SELECTOR, f"{category} measured on a host"
    if category == "hashes" and entry["value"].lower().startswith("cert-sha256:"):
        return SELECTOR, "certificate digest of a tracked host"
    if first.startswith(("http://", "https://")):
        return SEED, "report URL"
    if first.startswith("/") or _REPORT_FILE.search(first):
        return SEED, "ingested report file"
    if first.lower().startswith("analyst-supplied"):
        return SEED, "analyst-supplied"
    return CANDIDATE, f"derived: {first[:80]}"


def _fingerprint_rows(category: str, entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Dated selectors from a fingerprint entry's source strings."""
    out = []
    for source in entry.get("sources") or []:
        row = fingerprint_selector(category, entry["value"], source)
        if row:
            row["source"] = f"migration:{category}"
            out.append(row)
    return out


def _cert_rows(entry: dict[str, Any]) -> list[dict[str, Any]]:
    digest = entry["value"].split(":", 1)[1]
    hosts = {entry.get("cert_for")} if entry.get("cert_for") else set()
    for source in entry.get("sources") or []:
        m = _TLS_GRAB.match(source)
        if m:
            hosts.add(m["host"])
    return [{"indicator": host.lower().rstrip("."), "selector_type": "tls.cert_sha256",
             "value": digest, "first": entry.get("first_seen"),
             "last": entry.get("last_seen") or entry.get("first_seen"),
             "source": "migration:cert", "vantage": "probe"}
            for host in sorted(h for h in hosts if h)]


def plan_cluster(data: dict[str, Any]) -> dict[str, Any]:
    seeds, candidates, selectors, dropped = [], [], [], Counter()
    keep: dict[str, list[str]] = {}
    for category, entries in (data.get("observables") or {}).items():
        for entry in entries:
            verdict, why = classify(category, entry)
            origin = (entry.get("sources") or [None])[0]
            if verdict == SEED:
                keep.setdefault(category, []).append(entry["value"])
                if category in MEMBER_CATEGORIES:
                    seeds.append({"value": entry["value"], "category": category,
                                  "why": why, "origin": origin})
            elif verdict == CANDIDATE:
                candidates.append({"value": entry["value"], "category": category,
                                   "why": why, "origin": origin})
            elif verdict == SELECTOR:
                rows = (_cert_rows(entry) if category == "hashes"
                        else _fingerprint_rows(category, entry))
                selectors.extend(rows)
                if not rows:
                    dropped[f"{category}: no parseable source"] += 1
            else:
                dropped[why] += 1
    rejected = [{"value": d["value"], "reason": d.get("reason") or "migrated deny list"}
                for d in data.get("denylist") or []]
    return {"seeds": seeds, "candidates": candidates, "selectors": selectors,
            "rejected": rejected, "dropped": dict(dropped), "keep": keep}


def execute(con, cluster: str, plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Write one cluster's plan into a store and score its candidates."""
    from cti.store import entities as E
    from cti.store import relatedness as R
    from cti.store import selectors as S

    for row in plan["selectors"]:
        S.record(con, indicator_value=row["indicator"], selector_type=row["selector_type"],
                 selector_value=row["value"], observed_at=row.get("when") or row.get("last"),
                 first_seen=row.get("first"), last_seen=row.get("last"),
                 indicator_type=E.entity_type(row["indicator"]), actor=cluster,
                 source=row["source"], vantage=row["vantage"])
    for seed in plan["seeds"]:
        E.set_role(con, cluster, seed["value"], "seed", decided_by="migration",
                   origin=seed["origin"], reason=seed["why"])
    for rej in plan["rejected"]:
        E.set_role(con, cluster, rej["value"], "rejected", decided_by="migration",
                   origin="denylist", reason=rej["reason"])
    for cand in plan["candidates"]:
        E.file_candidate(con, cluster, cand["value"], origin=cand["origin"],
                         decided_by="migration", reason=cand["why"])
    return [r.to_dict() for r in R.rescore_cluster(con, cluster)]


def rewrite_json(slug: str, plan: dict[str, Any], scores: list[dict[str, Any]]) -> None:
    """Cut a cluster's JSON down to its seeds and record what moved."""
    from cti import core
    from cti.util import now_iso

    with core._data_lock():
        data = core.load_cluster(slug)
        for category, entries in data["observables"].items():
            kept = set(plan["keep"].get(category, []))
            data["observables"][category] = [e for e in entries if e["value"] in kept]
        data["denylist"] = []
        bands = Counter(s["band"] for s in scores)
        data["hunt_log"].append({"date": now_iso(), "entry": (
            f"rebuilt from seeds (membership moved to the store): {len(plan['seeds'])} seeds "
            f"kept; {len(plan['candidates'])} pivot/scan-derived indicators re-filed as scored "
            f"candidates ({', '.join(f'{b} {n}' for b, n in bands.most_common()) or 'none'}); "
            f"{len(plan['selectors'])} certificate/fingerprint entries converted to dated "
            f"selectors on their hosts; {len(plan['rejected'])} deny-list entries now "
            f"rejected memberships"
            + (f"; dropped {sum(plan['dropped'].values())} JA4L latency readings"
               if plan["dropped"] else ""))})
        core.save_cluster(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cluster", help="only this cluster slug")
    parser.add_argument("--report", type=Path, help="write the full JSON report here")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    from cti import store
    from cti.util import data_dir

    clusters = sorted(data_dir().glob("*.json"))
    if args.cluster:
        clusters = [p for p in clusters if p.stem == args.cluster]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scratch = Path(tempfile.mkdtemp(prefix="rebuild-"))
    live = store.db_path()
    with store.connect(read_only=False) as con:
        con.execute("CHECKPOINT")
    if args.apply:
        backup_dir = data_dir() / f"_backup-{stamp}-pre-rebuild"
        backup_dir.mkdir()
        for path in clusters:
            shutil.copy2(path, backup_dir / path.name)
        shutil.copy2(live, live.with_name(f"{live.name}.bak-{stamp}-pre-rebuild"))
        print(f"backed up cluster JSON to {backup_dir} and the store beside {live}")
    else:
        copy = scratch / live.name
        shutil.copy2(live, copy)
        os.environ["CTI_DUCKDB_PATH"] = str(copy)

    report: dict[str, Any] = {"dry_run": not args.apply, "clusters": {}}
    for path in clusters:
        data = json.loads(path.read_text())
        name = data.get("name") or path.stem
        plan = plan_cluster(data)
        with store.connect(read_only=False) as con:
            scores = execute(con, path.stem, plan)
        if args.apply:
            rewrite_json(path.stem, plan, scores)
        report["clusters"][path.stem] = {"name": name, **plan, "scores": scores}

        bands = Counter(s["band"] for s in scores)
        print(f"\n== {name}: {len(plan['seeds'])} seeds, {len(plan['candidates'])} "
              f"candidates ({', '.join(f'{b} {n}' for b, n in bands.most_common()) or 'none'}), "
              f"{len(plan['selectors'])} selectors converted, "
              f"{len(plan['rejected'])} rejected"
              + (f", dropped {plan['dropped']}" if plan["dropped"] else ""))
        for s in scores:
            top = ", ".join(f"{k} {v}" for k, v in list(s["artefacts"].items())[:3])
            print(f"   {s['band']:9} {s['score']:.3f}  {s['entity']:40} {top}")

    target = args.report or scratch / "rebuild_report.json"
    target.write_text(json.dumps(report, indent=1, default=str))
    print(f"\nfull report: {target}")
    if not args.apply:
        print("(dry run: the live store and cluster JSON were not touched)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
