"""Recording what actually ran.

The static drawing shows the pipeline. This shows the run: which nodes
fired, in what order, how long each took, what each produced. That is the
question the old design could not answer at all - Stage B was one opaque
`claude -p` whose only artifact was the finished narrative.

One JSONL file per STAGE per day under data/runs/, named
`<day>.<stage>.jsonl`. JSONL because a run is appended to as it happens, so
a crashed run still leaves everything up to the crash, which is exactly
when you want it.

Per stage, not per day, because the first version keyed on the day alone
and opened the file in write mode: the 06:45 analyze run silently replaced
the 06:15 collect run's trace, so the day's record held no collect nodes
and the fan-out timing it was built to show was gone. Files written that
way (`<day>.jsonl`, no stage) are still readable and are reported as the
stage "legacy".
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, AsyncIterator


def runs_dir() -> Path:
    base = os.environ.get("CTI_RUNS_DIR")
    return Path(base) if base else Path(__file__).resolve().parents[1] / "data" / "runs"


def _plain(value: Any, depth: int = 0) -> Any:
    """Make a node's output JSON-safe and bounded.

    Bounded matters: a sweep result carries a whole cluster record, and a
    trace nobody can open is a trace nobody reads.
    """
    # Deep enough to keep the ranker's family -> items -> fields
    # nesting legible; a trace that elides the indicator values is a
    # trace you cannot use to answer "why did it pick that?".
    if depth > 8:
        return "..."
    if is_dataclass(value) and not isinstance(value, type):
        return _plain(asdict(value), depth + 1)
    if isinstance(value, dict):
        return {k: _plain(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [_plain(v, depth + 1) for v in value[:40]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 2000:
            return value[:2000] + f"... [{len(value)} chars]"
        return value
    return str(value)


STAGES = ("collect", "analyze", "daily", "legacy")
_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:\.([a-z]+))?\.jsonl$")


def run_path(day: str, stage: str) -> Path:
    return runs_dir() / f"{day}.{stage}.jsonl"


def run_files(day: str) -> list[tuple[str, Path]]:
    """Every recorded stage for a day, in pipeline order."""
    found = []
    rdir = runs_dir()
    if not rdir.is_dir():
        return found
    for path in rdir.glob(f"{day}*.jsonl"):
        m = _FILE_RE.match(path.name)
        if m and m.group(1) == day:
            found.append((m.group(2) or "legacy", path))
    order = {name: i for i, name in enumerate(STAGES)}
    return sorted(found, key=lambda item: order.get(item[0], len(order)))


def run_days() -> list[str]:
    """Days with at least one recorded stage, newest first."""
    rdir = runs_dir()
    if not rdir.is_dir():
        return []
    days = {m.group(1) for p in rdir.glob("*.jsonl") if (m := _FILE_RE.match(p.name))}
    return sorted(days, reverse=True)


class Trace:
    """Consumes a LangGraph update stream and writes the run record."""

    def __init__(self, day: str, stage: str = "run", path: Path | None = None):
        self.day = day
        self.stage = stage
        self.path = path or run_path(day, stage)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.started = time.time()
        self._fh = self.path.open("w")
        self._write({"event": "run_start", "day": day, "stage": stage,
                     "ts": self.started})

    def _write(self, record: dict) -> None:
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()   # a crashed run should still leave its trace

    def node(self, name: str, output: Any, elapsed: float,
             started: float | None = None, error: str | None = None) -> None:
        record = {"event": "node", "node": name, "elapsed_s": round(elapsed, 3)}
        if started is not None:
            record["started_s"] = round(started - self.started, 3)
        if error:
            record["error"] = error
        record["output"] = _plain(output)
        self._write(record)

    def close(self, final_state: Any = None) -> Path:
        self._write({"event": "run_end", "elapsed_s": round(time.time() - self.started, 3),
                     "state": _plain(final_state) if final_state is not None else None})
        self._fh.close()
        return self.path


def _label(namespace: tuple[str, ...], node: str) -> str:
    """`collect:sweep` for a node inside the `collect` subgraph.

    LangGraph namespaces look like ("collect:<task-uuid>",); the uuid is
    noise for a reader and different every run.
    """
    parents = [part.split(":", 1)[0] for part in namespace]
    return ":".join([*parents, node])


async def run_traced(compiled, state: dict, *, day: str, stage: str,
                     path: Path | None = None) -> tuple[dict, Path]:
    """Run a compiled graph, writing a trace and returning the final state.

    Timing comes from `stream_mode="tasks"`, which emits an event when each
    task starts and another when it finishes, keyed by task id. The first
    version timed a node as the gap since the previous "updates" event.
    That is only a duration when nodes run one at a time: the nine
    parallel sweeps each got "the time since the last cluster finished",
    so the trace drew a parallel fan-out as a serial chain and put
    famoussparrow at 1s when it had run for 13 minutes.

    `subgraphs=True` makes that include nodes inside a composed subgraph;
    without it a `daily` run records two events, `collect` and `analyze`,
    and nothing about what happened inside either. "updates" is still
    consumed, for the final state only.
    """
    trace = Trace(day, stage, path)
    final: dict = dict(state)
    started: dict[str, float] = {}
    try:
        async for namespace, mode, chunk in compiled.astream(
                state, stream_mode=["updates", "tasks"], subgraphs=True):
            now = time.time()
            if mode == "tasks":
                if "result" not in chunk:           # a task starting
                    started[chunk["id"]] = now
                    continue
                t0 = started.pop(chunk["id"], now)
                error = chunk.get("error")
                trace.node(_label(namespace, chunk["name"]), chunk["result"],
                           now - t0, started=t0,
                           error=str(error) if error else None)
                continue
            # Only top-level updates are the graph's own state. A subgraph's
            # node outputs are a subset of what the subgraph returns to its
            # parent as one top-level update at the end.
            if not namespace:
                for output in chunk.values():
                    if isinstance(output, dict):
                        final.update(output)
    finally:
        trace.close(final)
    return final, trace.path


def read(path: Path) -> list[dict]:
    """Read a trace back. Used by the dashboard's run view."""
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def summarize(path: Path) -> dict:
    """Per-node timings and the run total for one stage's file."""
    records = read(path)
    nodes = [r for r in records if r.get("event") == "node"]
    start = next((r for r in records if r.get("event") == "run_start"), {})
    end = next((r for r in records if r.get("event") == "run_end"), {})
    return {
        "day": start.get("day"),
        "stage": start.get("stage") or "legacy",
        "total_s": end.get("elapsed_s"),
        "nodes": [{"node": n["node"], "elapsed_s": n["elapsed_s"]} for n in nodes],
        "slowest": max(nodes, key=lambda n: n["elapsed_s"])["node"] if nodes else None,
    }
