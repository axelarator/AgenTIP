"""scripts/probe_pending_fingerprints.py, which drains the fingerprint queue.

It had no tests, and it was broken for weeks without anyone knowing: the
restructure into cti/ removed the local probe_win() wrapper and left one
bare call to it, so every probe raised NameError. Nothing exercised the
script, and the failure mode made it worse - the queue is popped before any
probing starts, per-target exceptions are logged and swallowed, and the
script exited 0. The first real run failed all 112 targets in under a
second and left the queue empty.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

from cti import core
from cti.probe import vm_proxy

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "probe_pending_fingerprints.py"


@pytest.fixture
def script(monkeypatch):
    spec = importlib.util.spec_from_file_location("probe_pending_fingerprints", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "check_access", lambda: [])
    monkeypatch.setattr(mod, "_current_max_ts", lambda: 0)
    monkeypatch.setattr(mod, "_lookup_ports", lambda cluster, target: [443])
    monkeypatch.setattr(mod, "collect_zeek_fingerprints_batch", lambda *a, **k: {})
    monkeypatch.setattr(mod, "_enrich_with_honeylabs", lambda pairs: None)
    monkeypatch.setattr("sys.argv", ["probe_pending_fingerprints.py"])
    return mod


_QUEUE = [{"cluster": "C", "category": "domains", "value": f"h{i}.example",
           "queued_at": "2026-09-22T00:00:00+00:00"} for i in range(4)]


def test_a_probe_goes_through_vm_proxy(script, monkeypatch):
    """The regression. A bare probe_win() name raised NameError on every
    call; the swallowed exception turned it into "probe failed" for every
    target."""
    calls = []
    monkeypatch.setattr(vm_proxy, "probe_win",
                        lambda target, port: calls.append((target, port)) or
                        {"jarm": "j" * 62, "resolved_ip": "203.0.113.9"})
    out = script._dispatch_one({"cluster": "C", "target": "x.example", "port": 443})
    assert calls == [("x.example", 443)]
    assert out["probe_error"] is None
    assert out["probe_result"]["jarm"] == "j" * 62


def test_no_bare_probe_win_call_remains_in_the_script():
    """The specific shape of the original bug, checked by text because it
    only fails at call time."""
    import re
    src = SCRIPT.read_text()
    bare = [l for l in src.splitlines()
            if re.search(r"(?<![\w.])probe_win\(", l) and not l.lstrip().startswith("#")]
    assert bare == []


def test_a_batch_where_every_probe_fails_puts_the_queue_back(script, monkeypatch):
    """A batch that fails completely is a broken script or a dead vantage
    point, not 112 dead hosts. The queue was popped before probing, so
    carrying on discards it."""
    monkeypatch.setattr(core, "pop_pending_fingerprints", lambda: list(_QUEUE))
    requeued = []
    monkeypatch.setattr(core, "requeue_fingerprint",
                        lambda name, cat, value: requeued.append((name, cat, value)) or [])

    def boom(target, port):
        raise RuntimeError("the helper is broken")

    monkeypatch.setattr(vm_proxy, "probe_win", boom)
    with pytest.raises(SystemExit) as exc:
        script.main()
    assert "every one of 4 probes failed" in str(exc.value)
    assert "4/4 entries put back" in str(exc.value)
    assert sorted(v for _, _, v in requeued) == sorted(e["value"] for e in _QUEUE)


def test_a_partial_failure_is_left_alone(script, monkeypatch):
    """Some targets genuinely are dead. Requeueing those forever would make
    the queue a treadmill."""
    monkeypatch.setattr(core, "pop_pending_fingerprints", lambda: list(_QUEUE))
    requeued = []
    monkeypatch.setattr(core, "requeue_fingerprint",
                        lambda *a: requeued.append(a) or [])
    filed = []
    monkeypatch.setattr(core, "add_observable", lambda *a, **k: filed.append(a))

    def flaky(target, port):
        if target == "h0.example":
            raise RuntimeError("connection refused")
        return {"jarm": "j" * 62, "resolved_ip": None}

    monkeypatch.setattr(vm_proxy, "probe_win", flaky)
    script.main()                                     # must not exit
    assert requeued == []
    assert len(filed) == 3, "the three that worked were filed"


def test_an_empty_queue_is_a_quiet_no_op(script, monkeypatch):
    monkeypatch.setattr(core, "pop_pending_fingerprints", lambda: [])
    called = []
    monkeypatch.setattr(vm_proxy, "probe_win", lambda *a: called.append(a))
    script.main()
    assert called == []
