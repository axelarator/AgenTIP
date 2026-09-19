"""scripts/migrate_schema.py.

The first migration copied rows with their old ids and left the id
sequences at 1, so the first new insert after cutover took an id a migrated
row already held. That is the "Duplicate key id: 28" that failed four
cluster sweeps on 2026-09-19. The migration's own --verify passed, because
it compared row counts and nothing else - so the check that would have
caught it is tested here too.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("migrate_schema", REPO / "scripts" / "migrate_schema.py")
migrate_schema = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate_schema)


def _old_db(path: Path, asn_ids=(5, 474), attr_ids=(7, 2407)) -> Path:
    """A minimal database in the OLD shape: a wide observations table and
    side tables whose ids are sparse, like the live one (29 rows, max id 474,
    because ON CONFLICT DO UPDATE burns sequence values)."""
    con = duckdb.connect(str(path))
    con.execute("""CREATE TABLE observations (
        id BIGINT, observed_at TIMESTAMP, indicator_type TEXT, indicator_value TEXT,
        actor TEXT, source TEXT, hl_events BIGINT, asn BIGINT)""")
    con.execute("INSERT INTO observations VALUES (1, ?, 'ipv4', '1.2.3.4', 'A', 'rdap', NULL, 16509)",
                [datetime(2026, 9, 1)])
    con.execute("""CREATE TABLE asn_changes (id BIGINT, detected_at TIMESTAMP,
        indicator_value TEXT, actor TEXT, old_asn BIGINT, old_netname TEXT,
        new_asn BIGINT, new_netname TEXT, change_type TEXT, confidence TEXT)""")
    for i in asn_ids:
        con.execute("INSERT INTO asn_changes VALUES (?, ?, ?, 'A', 1, 'x', 2, 'y', 'asn_change', 'medium')",
                    [i, datetime(2026, 9, 1), f"10.0.0.{i % 250}"])
    con.execute("""CREATE TABLE attribute_changes (id BIGINT, detected_at TIMESTAMP,
        indicator_value TEXT, actor TEXT, attribute TEXT, change_type TEXT,
        old_value JSON, new_value JSON, confidence TEXT)""")
    for i in attr_ids:
        con.execute("INSERT INTO attribute_changes VALUES (?, ?, ?, 'A', 'ports', 'ports_changed', NULL, NULL, 'medium')",
                    [i, datetime(2026, 9, 1), f"10.1.0.{i % 250}"])
    con.close()
    return path


def test_new_inserts_after_migration_do_not_collide_with_migrated_ids(tmp_path):
    src = _old_db(tmp_path / "old.duckdb")
    dest = tmp_path / "new.duckdb"
    migrate_schema.migrate(src, dest)

    # A brand-new connection, the way the next cron run opens it. The
    # sequence position has to have been PERSISTED, not just advanced on the
    # migrating connection - the script's own comments explain that a
    # transaction with nothing to commit drops it on close.
    con = duckdb.connect(str(dest))
    con.execute("INSERT INTO asn_changes (detected_at, indicator_value, change_type) "
                "VALUES (?, '9.9.9.9', 'asn_change')", [datetime(2026, 9, 19)])
    new_id = con.execute("SELECT id FROM asn_changes WHERE indicator_value = '9.9.9.9'").fetchone()[0]
    assert new_id > 474

    con.execute("INSERT INTO attribute_changes (detected_at, indicator_value, attribute, change_type) "
                "VALUES (?, '9.9.9.9', 'ports', 'ports_changed')", [datetime(2026, 9, 19)])
    assert con.execute("SELECT id FROM attribute_changes WHERE indicator_value = '9.9.9.9'"
                       ).fetchone()[0] > 2407
    con.close()


def test_verify_passes_on_a_correct_migration(tmp_path):
    src = _old_db(tmp_path / "old.duckdb")
    dest = tmp_path / "new.duckdb"
    migrate_schema.migrate(src, dest)
    assert migrate_schema.verify(src, dest) == 0


def test_verify_catches_a_sequence_left_behind_the_data(tmp_path, capsys):
    """The check that was missing. Rebuild the original bug: rows copied with
    explicit ids, sequence never advanced."""
    from cti.store.schema import init_schema

    src = _old_db(tmp_path / "old.duckdb")
    dest = tmp_path / "broken.duckdb"
    con = duckdb.connect(str(dest))
    init_schema(con)
    con.execute("INSERT INTO observations (observed_at, indicator_type, indicator_value, actor, source, payload) "
                "VALUES (?, 'ipv4', '1.2.3.4', 'A', 'rdap', '{\"asn\": 16509}')", [datetime(2026, 9, 1)])
    for i in (5, 474):
        con.execute("INSERT INTO asn_changes (id, detected_at, indicator_value, change_type) "
                    "VALUES (?, ?, ?, 'asn_change')", [i, datetime(2026, 9, 1), f"10.0.0.{i % 250}"])
    for i in (7, 2407):
        con.execute("INSERT INTO attribute_changes (id, detected_at, indicator_value, attribute, change_type) "
                    "VALUES (?, ?, ?, 'ports', 'ports_changed')", [i, datetime(2026, 9, 1), f"10.1.0.{i % 250}"])
    con.close()

    assert migrate_schema.verify(src, dest) == 1
    out = capsys.readouterr().out
    assert "asn_changes_seq" in out and "collide" in out


def test_migration_refuses_to_overwrite_an_existing_destination(tmp_path):
    src = _old_db(tmp_path / "old.duckdb")
    dest = tmp_path / "exists.duckdb"
    dest.write_text("")
    with pytest.raises(SystemExit):
        migrate_schema.migrate(src, dest)
