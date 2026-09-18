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
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import duckdb

from ..errors import TrackingBusy

_REPO_ROOT = Path(__file__).resolve().parents[2]


def db_path() -> Path:
    """Read lazily so a monkeypatched CTI_DUCKDB_PATH takes effect per-test."""
    return Path(os.environ.get("CTI_DUCKDB_PATH",
                               _REPO_ROOT / "data" / "tracking" / "tracking.duckdb"))


@contextmanager
def connect(read_only: bool = False) -> Iterator[duckdb.DuckDBPyConnection]:
    """Short-lived connection; rw connections initialize the schema."""
    from .schema import init_schema

    path = db_path()
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path), read_only=read_only)
    try:
        if not read_only:
            init_schema(con)
        yield con
    finally:
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
    from .schema import init_schema

    path = db_path()
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.exists():
        # A missing file can't be lock contention - fail fast instead of
        # sleeping through the whole backoff schedule.
        raise duckdb.IOException(f"tracking DB not initialized ({path})")
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
    try:
        if not read_only:
            init_schema(con)
        yield con
    finally:
        con.close()
