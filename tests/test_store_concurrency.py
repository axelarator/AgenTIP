"""The store under the graph's fan-out.

Nothing opened two read-write connections at once in the old sequential
daily loop, so none of this was ever exercised. The graph's per-cluster
sweeps do it, and the first scheduled run lost a cluster to it
(fox-tempest, 2026-09-19). These reproduce that failure rather than
describe it: against the pre-fix connection module, the hammer test failed
81 of 160 connects with "Catalog write-write conflict", and once that was
fixed, on "Unique file handle conflict" - a second race the first had been
masking.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime

import duckdb
import pytest

from cti import core, store
from cti.store import connection, schema


def _hammer(open_ctx, threads: int = 8, rounds: int = 20) -> list[str]:
    errors: list[str] = []
    barrier = threading.Barrier(threads)

    def work(n: int):
        barrier.wait()
        for _ in range(rounds):
            try:
                with open_ctx(n):
                    pass
            except Exception as e:                      # noqa: BLE001
                errors.append(f"{type(e).__name__}: {str(e)[:100]}")

    pool = [threading.Thread(target=work, args=(i,)) for i in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return errors


def test_concurrent_read_write_connects_do_not_conflict():
    errors = _hammer(lambda n: store.connect(read_only=False))
    assert errors == []


def test_concurrent_connect_and_connect_retry_do_not_conflict():
    """Both entry points share one writer lock; using only one of them in
    the test would leave the other's bypass undetected."""
    errors = _hammer(lambda n: (store.connect(read_only=False) if n % 2
                                else store.connect_retry(read_only=False)))
    assert errors == []


def test_schema_is_initialised_once_per_database_file(monkeypatch):
    calls = []
    real = schema.init_schema
    monkeypatch.setattr(schema, "init_schema", lambda con: (calls.append(1), real(con)))
    for _ in range(5):
        with store.connect(read_only=False):
            pass
    assert len(calls) == 1


def test_a_recreated_database_file_is_initialised_again(monkeypatch):
    """Keyed on inode as well as path. Without that, a database deleted and
    recreated at the same path - a re-migration - would be trusted from the
    cache and left with no tables."""
    with store.connect(read_only=False):
        pass
    connection.db_path().unlink()
    with store.connect(read_only=False) as con:
        tables = {r[0] for r in con.execute(
            "SELECT table_name FROM information_schema.tables").fetchall()}
    assert "observations" in tables


def test_a_second_writer_waits_for_the_first_to_finish():
    """The lock is held from open to close, so writers are serialised - the
    single-writer-per-process rule made explicit."""
    order: list[str] = []
    first_in = threading.Event()

    def first():
        with store.connect(read_only=False):
            order.append("first-open")
            first_in.set()
            time.sleep(0.3)
            order.append("first-close")

    def second():
        first_in.wait()
        with store.connect(read_only=False):
            order.append("second-open")

    a, b = threading.Thread(target=first), threading.Thread(target=second)
    a.start(); b.start(); a.join(); b.join()
    assert order == ["first-open", "first-close", "second-open"]


def test_read_only_connections_do_not_take_the_writer_lock():
    """Concurrent readers are fine and must stay concurrent."""
    with store.connect(read_only=False):
        pass
    with connection._writer_lock:
        got = []
        t = threading.Thread(target=lambda: got.append(
            store.connect(read_only=True).__enter__()))
        t.start(); t.join(timeout=5)
        assert not t.is_alive() and got, "a read-only connect blocked on the writer lock"
        got[0].close()


def test_nested_read_write_connects_in_one_thread_do_not_deadlock():
    with store.connect(read_only=False):
        with store.connect(read_only=False):
            pass


# --------------------------------------------------------------------------- #
# The history write is best-effort - and now says so out loud
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("exc", [
    duckdb.TransactionException("Catalog write-write conflict on alter"),
    duckdb.IOException("Could not set lock on file"),
    duckdb.BinderException("Referenced column not found"),
])
def test_history_failures_become_a_note_not_a_failed_sweep(monkeypatch, exc):
    """It caught only IOException, so the TransactionException that hit
    fox-tempest escaped, failed the whole sweep, and reported a cluster as
    unswept whose cluster JSON had in fact been written."""
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(core.tracking_store, "connect", boom)
    note = core._log_cluster_enrichment_history("A", datetime(2026, 9, 19), {})
    assert note and note.startswith("enrichment history not recorded:")
    assert type(exc).__name__ in note


def test_active_scan_history_failures_are_also_a_note(monkeypatch):
    """Same clause, second site (core.active_scan)."""
    import inspect
    source = inspect.getsource(core.active_scan)
    assert "duckdb.Error" in source and "duckdb.IOException" not in source
