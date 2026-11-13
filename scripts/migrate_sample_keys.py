#!/usr/bin/env python3
"""Re-key `opendir_samples` rows written before 2026-11-13.

    python scripts/migrate_sample_keys.py [DB]            # show what would change
    python scripts/migrate_sample_keys.py [DB] --apply    # back up, then change

A sample verdict used to be stored under (host, URL of the first file in the
batch, staged filename). Two things were wrong with that: files with the
same name in different folders overwrote each other, and the staged name had
lost its leading dots and unusual characters (`.bash_history` was stored as
`bash_history`). New rows are stored under the file's own URL with the name
the server gave it.

Old rows are matched to the listing in `opendir_files` (which holds each
file's full URL) by host and by filename, allowing for the two changes the
staging made. A row is rewritten only if exactly one listed file matches;
anything else is reported and left alone. Running it twice changes nothing
the second time.

--apply copies the database to `<name>.bak-<timestamp>` first. Stop anything
that writes to the database (the cron jobs, the MCP server) before running
it, or it will fail to get the write lock.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.store import db_path  # noqa: E402


def _name(file_url: str) -> str:
    tail = urllib.parse.unquote(urllib.parse.urlsplit(file_url).path).rsplit("/", 1)[-1]
    return "".join(c for c in tail if c.isprintable())[:255]


def _staged(name: str) -> str:
    """What the probe's staging did to a filename before 2026-11-13."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80].lstrip(".")


def plan(con: duckdb.DuckDBPyConnection) -> dict[str, list[dict]]:
    """{"update": [...], "unmatched": [...], "done": [...]} without writing."""
    listed: dict[str, list[str]] = {}
    for host, file_url in con.execute(
            "SELECT indicator_value, path FROM opendir_files WHERE NOT is_dir").fetchall():
        listed.setdefault(host, []).append(file_url)

    out: dict[str, list[dict]] = {"update": [], "unmatched": [], "done": []}
    for host, url, path in con.execute(
            "SELECT indicator_value, url, path FROM opendir_samples "
            "ORDER BY indicator_value, url, path").fetchall():
        row = {"indicator_value": host, "url": url, "path": path}
        if _name(url) == path:
            out["done"].append(row)          # already under its own URL
            continue
        matches = sorted({f for f in listed.get(host, [])
                          if path in (_name(f), _staged(_name(f)))})
        if len(matches) != 1:
            out["unmatched"].append({**row, "candidates": matches})
            continue
        out["update"].append({**row, "new_url": matches[0],
                              "new_path": _name(matches[0])})
    return out


def apply(con: duckdb.DuckDBPyConnection, changes: list[dict]) -> int:
    con.execute("BEGIN")
    try:
        for c in changes:
            # A row already at the new key was analysed again since; it is
            # the newer verdict, so the old row gives way to it.
            con.execute(
                "DELETE FROM opendir_samples WHERE indicator_value = ? AND url = ? "
                "AND path = ? AND EXISTS (SELECT 1 FROM opendir_samples "
                "WHERE indicator_value = ? AND url = ? AND path = ?)",
                [c["indicator_value"], c["url"], c["path"],
                 c["indicator_value"], c["new_url"], c["new_path"]])
            con.execute(
                "UPDATE opendir_samples SET url = ?, path = ? "
                "WHERE indicator_value = ? AND url = ? AND path = ?",
                [c["new_url"], c["new_path"],
                 c["indicator_value"], c["url"], c["path"]])
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return len(changes)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db", nargs="?", default=str(db_path()))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--no-backup", action="store_true")
    args = ap.parse_args(argv)
    db = Path(args.db)

    con = duckdb.connect(str(db), read_only=not args.apply)
    try:
        found = plan(con)
        print(f"{db}: {len(found['update'])} to re-key, "
              f"{len(found['done'])} already done, "
              f"{len(found['unmatched'])} with no single match (left alone)")
        for c in found["update"]:
            print(f"  {c['indicator_value']}  {c['path']!r} -> {c['new_url']}")
        for c in found["unmatched"]:
            print(f"  no match: {c['indicator_value']} {c['path']!r} "
                  f"({len(c['candidates'])} candidates)")
        if not args.apply:
            print("dry run; pass --apply to make the change")
            return 0
        if not found["update"]:
            return 0
    finally:
        if not args.apply:
            con.close()

    if not args.no_backup:
        con.close()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = db.with_name(f"{db.name}.bak-{stamp}")
        shutil.copy2(db, backup)
        print(f"backed up to {backup}")
        con = duckdb.connect(str(db))
    try:
        print(f"re-keyed {apply(con, found['update'])} row(s)")
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
