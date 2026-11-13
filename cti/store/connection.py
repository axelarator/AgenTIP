"""DuckDB connections.

Concurrency model, unchanged from the old tree because it is correct:
DuckDB's file lock is process-exclusive for read-write, so every
connection here is short-lived (open, work, close) and the slow parts of
the pipeline - network enrichment - run with no connection held. That
constraint is also why the LangGraph collect subgraph fans out over
clusters but funnels every write into a single `write_batch` node.
"""
from __future__ import annotations

import os
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator

import duckdb

from ..errors import TrackingBusy
from ..util import repo_root

_REPO_ROOT = repo_root()


# Two races, both first seen on the graph's first scheduled run
# (fox-tempest, 2026-09-19), and both invisible before the fan-out because
# nothing ever opened two read-write connections at once.
#
# 1. Schema DDL. init_schema ends in CREATE OR REPLACE VIEW, which is
#    catalog DDL, and DuckDB raises "Catalog write-write conflict" when two
#    connections issue it together. It now runs once per database FILE per
#    process instead of on every connect. Reproduced with eight threads:
#    81 of 160 connects failed.
#
# 2. Connect/close. With the DDL gone, the same reproduction still failed on
#    "Unique file handle conflict: ... already attached": one thread opening
#    a connection while another closes its own. The DDL errors had been
#    masking it.
#
# The fix for the second is to make explicit what this module's docstring
# already says - DuckDB is single-writer per process - by serialising
# read-write connections with a process-wide lock held from open to close.
# That is cheap because every read-write connection here is short by
# design (the slow network phases run with no connection held). It is an
# RLock so a helper that opens a connection inside another's context, in
# the same thread, does not deadlock. Read-only connections are left alone:
# they never take the write lock and concurrent readers are fine.
#
# What this does NOT permit: spawning threads inside a read-write context
# whose workers open their own read-write connections. That deadlocks. No
# caller does; keep it that way.
_writer_lock = threading.RLock()

# The cache is only a hint. A hit is confirmed by asking the database
# whether its tables are really there (_schema_present), because a key made
# of path and inode was not enough: delete a database and recreate it at
# the same path - a re-migration, which a long-lived process like the MCP
# server would then survive - and filesystems routinely hand the new file
# the SAME inode number. The first version trusted that key and left the
# recreated file with no tables; a test caught it.
_schema_ready: set[tuple[str, int]] = set()
# Read-write connections this process has open. Changed only while holding
# _writer_lock; a list so the context managers can mutate it in place.
_open_writes = [0]

_CORE_TABLES = ("observations", "observations_wide")


def _schema_present(con: duckdb.DuckDBPyConnection) -> bool:
    n = con.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_name IN (?, ?)",
        list(_CORE_TABLES)).fetchone()[0]
    return n == len(_CORE_TABLES)


def _ensure_schema(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    """Initialise the schema once per database file per process.

    Only ever called with _writer_lock held, so no second lock is needed.
    """
    from .schema import init_schema

    try:
        key = (str(path), os.stat(path).st_ino)
    except OSError:
        key = None
    if key is not None and key in _schema_ready and _schema_present(con):
        return
    init_schema(con)
    try:
        _schema_ready.add((str(path), os.stat(path).st_ino))
    except OSError:
        pass


def db_path() -> Path:
    """Read lazily so a monkeypatched CTI_DUCKDB_PATH takes effect per-test."""
    return Path(os.environ.get("CTI_DUCKDB_PATH",
                               _REPO_ROOT / "data" / "tracking" / "tracking.duckdb"))


@contextmanager
def connect(read_only: bool = False) -> Iterator[duckdb.DuckDBPyConnection]:
    """Short-lived connection; rw connections initialize the schema."""
    path = db_path()
    if read_only:
        con = duckdb.connect(str(path), read_only=True)
        try:
            yield con
        finally:
            con.close()
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    with _writer_lock:
        con = duckdb.connect(str(path), read_only=False)
        _open_writes[0] += 1
        try:
            _ensure_schema(con, path)
            yield con
        finally:
            _open_writes[0] -= 1
            con.close()


@contextmanager
def connect_retry(read_only: bool, attempts: int = 4,
                  backoff: float = 0.5) -> Iterator[duckdb.DuckDBPyConnection]:
    """connect() with backoff on the process-exclusive file lock.

    Only the connect itself is retried - never the caller's body, so a
    mid-transaction failure can't replay non-idempotent writes. Raises
    TrackingBusy after the last attempt; MCP wrappers turn that into an
    error dict rather than letting it propagate to the agent.
    """
    path = db_path()
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.exists():
        # A missing file can't be lock contention - fail fast instead of
        # sleeping through the whole backoff schedule.
        raise duckdb.IOException(f"tracking DB not initialized ({path})")
    with ExitStack() as stack:
        # Same single-writer rule as connect(). The lock is held across the
        # backoff sleeps too: another in-process writer would only be
        # waiting on the same file lock anyway.
        if not read_only:
            stack.enter_context(_writer_lock)
        delay = backoff
        con = None
        for attempt in range(attempts):
            try:
                con = duckdb.connect(str(path), read_only=read_only)
                break
            except duckdb.IOException as e:
                if attempt == attempts - 1:
                    raise TrackingBusy(str(e)) from e
                time.sleep(delay)
                delay *= 2
        if not read_only:
            _open_writes[0] += 1
        try:
            if not read_only:
                _ensure_schema(con, path)
            yield con
        finally:
            if not read_only:
                _open_writes[0] -= 1
            con.close()


def _schema_known(path: Path) -> bool:
    try:
        return (str(path), os.stat(path).st_ino) in _schema_ready
    except OSError:
        return False


@contextmanager
def connect_read(attempts: int = 4,
                 backoff: float = 0.5) -> Iterator[duckdb.DuckDBPyConnection]:
    """A connection for code that only reads.

    A read-write open takes the database file's exclusive lock, so it fails
    while any other process has the file open at all - the dashboard, an
    analyst's MCP session - and locks them out while it is held. Reads that
    opened read-write did both, once per cluster, every hour. A read-only
    open shares the file with other readers.

    Two cases still open read-write, because they must:
    - this process has not yet seen the schema on this file (new database,
      or new code with a table to add), so there may be nothing to read;
    - this thread already holds a write connection. DuckDB refuses a
      read-only open of a file the process has open read-write.

    It holds the writer lock throughout, for the second reason: a write
    opened by another thread while this read is open would be refused the
    same way.
    """
    path = db_path()
    with _writer_lock:
        if _open_writes[0] or not _schema_known(path):
            with connect_retry(read_only=False, attempts=attempts,
                               backoff=backoff) as con:
                yield con
            return
        with connect_retry(read_only=True, attempts=attempts,
                           backoff=backoff) as con:
            yield con
