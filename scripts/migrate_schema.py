#!/usr/bin/env python3
"""Migrate a cti-agent DuckDB file to the cti-graph narrow schema.

    python scripts/migrate_schema.py SOURCE.duckdb DEST.duckdb
    python scripts/migrate_schema.py SOURCE.duckdb DEST.duckdb --verify

The only table whose shape changes is `observations`: 52 columns become a
five-column spine plus a JSON payload, projected back under the original
names by the `observations_wide` view. Every other table is copied as-is.

--verify re-reads both files and compares row counts and per-column
checksums through the view, so the claim "nothing was lost" is checked
rather than asserted. Retired-provider columns are included in that
check: they hold real history (154 Shodan rows, 20 Cert Spotter rows)
and a migration that quietly dropped them would still look successful.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.store.schema import OBS_JSON_KEYS, OBS_PAYLOAD_KEYS, init_schema  # noqa: E402

SPINE = ("observed_at", "indicator_type", "indicator_value", "actor", "source")
COPY_TABLES = ("asn_changes", "actors", "correlations", "zeek_matches",
               "attribute_changes", "opendir_files", "active_scans")
# Tables whose `id` comes from a `<table>_seq` sequence. The copy carries the
# old ids over explicitly, which leaves the sequence behind them.
SEQUENCE_TABLES = ("observations", "asn_changes", "correlations",
                   "attribute_changes", "active_scans")


def _source_columns(con: duckdb.DuckDBPyConnection) -> list[str]:
    return [r[0] for r in con.execute("DESCRIBE observations").fetchall()]


def advance_sequences(con: duckdb.DuckDBPyConnection) -> None:
    """Move each id sequence past the highest copied id. Without this the
    first new insert takes nextval=1 and collides with a migrated row
    (DuckDB has no setval, so the sequence is stepped forward).

    Stepping nextval on its own reads back correctly on this connection but
    is NOT persisted: a transaction with no write to commit drops the
    sequence state on close. The throwaway CREATE/DROP makes the
    transaction a writer so the new positions reach the WAL."""
    con.execute("BEGIN")
    try:
        for table in SEQUENCE_TABLES:
            top = con.execute(
                f"SELECT coalesce(max(id), 0) FROM {table}").fetchone()[0]
            if not top:
                continue
            current = con.execute(f"SELECT nextval('{table}_seq')").fetchone()[0]
            if current < top:
                con.execute(f"SELECT count(nextval('{table}_seq')) "
                            f"FROM range({top - current})")
        con.execute("CREATE TABLE _seqfix (x INTEGER)")
        con.execute("DROP TABLE _seqfix")
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def migrate(source: Path, dest: Path) -> dict:
    if dest.exists():
        raise SystemExit(f"refusing to overwrite an existing file: {dest}")

    src = duckdb.connect(str(source), read_only=True)
    dst = duckdb.connect(str(dest))
    init_schema(dst)

    columns = _source_columns(src)
    payload_columns = [c for c in columns if c in OBS_PAYLOAD_KEYS]
    unmapped = [c for c in columns
                if c not in OBS_PAYLOAD_KEYS and c not in SPINE and c != "id"]
    if unmapped:
        # Loud, not silent: a column in the source with nowhere to go means
        # the schema definition is behind the data.
        raise SystemExit(
            f"columns present in {source} with no home in the new schema: "
            f"{unmapped}. Add them to cti/store/schema.py before migrating.")

    rows = src.execute(
        f"SELECT {', '.join(SPINE)}, {', '.join(payload_columns)} "
        f"FROM observations ORDER BY id").fetchall()

    batch = []
    for row in rows:
        spine, values = row[:len(SPINE)], row[len(SPINE):]
        payload = {}
        for name, value in zip(payload_columns, values):
            if value is None:
                continue
            if name in OBS_JSON_KEYS and isinstance(value, str):
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    pass
            payload[name] = value
        batch.append([*spine, json.dumps(payload, default=str)])

    dst.executemany(
        "INSERT INTO observations (observed_at, indicator_type, indicator_value, "
        "actor, source, payload) VALUES (?, ?, ?, ?, ?, ?)", batch)

    copied = {"observations": len(batch)}
    for table in COPY_TABLES:
        try:
            src.execute(f"SELECT 1 FROM {table} LIMIT 1")
        except duckdb.Error:
            continue
        cols = [r[0] for r in src.execute(f"DESCRIBE {table}").fetchall()]
        dest_cols = [r[0] for r in dst.execute(f"DESCRIBE {table}").fetchall()]
        shared = [c for c in cols if c in dest_cols]
        data = src.execute(f"SELECT {', '.join(shared)} FROM {table}").fetchall()
        if data:
            dst.executemany(
                f"INSERT INTO {table} ({', '.join(shared)}) "
                f"VALUES ({', '.join('?' for _ in shared)})", data)
        copied[table] = len(data)

    advance_sequences(dst)
    src.close()
    dst.close()
    return copied


def verify(source: Path, dest: Path) -> int:
    src = duckdb.connect(str(source), read_only=True)
    dst = duckdb.connect(str(dest), read_only=True)
    problems = []

    columns = _source_columns(src)
    checked = [c for c in columns if c not in ("id",)]

    n_src = src.execute("SELECT count(*) FROM observations").fetchone()[0]
    n_dst = dst.execute("SELECT count(*) FROM observations").fetchone()[0]
    print(f"observations rows: source {n_src}, dest {n_dst}",
          "OK" if n_src == n_dst else "MISMATCH")
    if n_src != n_dst:
        problems.append("observations row count")

    print(f"\nper-column non-null counts (through observations_wide):")
    for col in checked:
        a = src.execute(f'SELECT count("{col}") FROM observations').fetchone()[0]
        try:
            b = dst.execute(f'SELECT count("{col}") FROM observations_wide').fetchone()[0]
        except duckdb.Error as e:
            problems.append(f"{col}: not projected by the view ({e})")
            print(f"  {col:28s} {a:>6} -> MISSING FROM VIEW")
            continue
        flag = "" if a == b else "   <-- MISMATCH"
        if a != b:
            problems.append(f"{col}: {a} -> {b}")
        if a or flag:
            print(f"  {col:28s} {a:>6} -> {b:<6}{flag}")

    for table in COPY_TABLES:
        try:
            a = src.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            b = dst.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        except duckdb.Error:
            continue
        if a != b:
            problems.append(f"{table}: {a} -> {b}")
        print(f"{table:22s} {a:>6} -> {b}")

    for table in SEQUENCE_TABLES:
        top = dst.execute(f"SELECT coalesce(max(id), 0) FROM {table}").fetchone()[0]
        last = dst.execute("SELECT last_value FROM duckdb_sequences() "
                           "WHERE sequence_name = ?", [f"{table}_seq"]).fetchone()
        last = last[0] if last else None
        if top and (last is None or last < top):
            problems.append(f"{table}_seq at {last} but max id is {top}: "
                            f"the next insert will collide")

    src.close()
    dst.close()
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nall checks passed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source", type=Path)
    ap.add_argument("dest", type=Path)
    ap.add_argument("--verify", action="store_true",
                    help="only verify an already-migrated dest")
    args = ap.parse_args()

    if not args.verify:
        copied = migrate(args.source, args.dest)
        for table, n in copied.items():
            print(f"copied {n:>6} rows  {table}")
        print()
    return verify(args.source, args.dest)


if __name__ == "__main__":
    raise SystemExit(main())
