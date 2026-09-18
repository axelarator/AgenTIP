"""Recording what actually ran.

The static drawing shows the pipeline. This shows the run: which nodes
fired, in what order, how long each took, what each produced. That is the
question the old design could not answer at all - Stage B was one opaque
`claude -p` whose only artifact was the finished narrative.

One JSONL file per run under data/runs/. JSONL because a run is appended
to as it happens, so a crashed run still leaves everything up to the
crash, which is exactly when you want it.
"""
from __future__ import annotations

import json
import os
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


class Trace:
    """Consumes a LangGraph update stream and writes the run record."""

    def __init__(self, day: str, path: Path | None = None):
        self.day = day
        self.path = path or (runs_dir() / f"{day}.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.started = time.time()
        self._fh = self.path.open("w")
        self._write({"event": "run_start", "day": day, "ts": self.started})

    def _write(self, record: dict) -> None:
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()   # a crashed run should still leave its trace

    def node(self, name: str, output: Any, elapsed: float) -> None:
        self._write({"event": "node", "node": name, "elapsed_s": round(elapsed, 3),
                     "output": _plain(output)})

    def close(self, final_state: Any = None) -> Path:
        self._write({"event": "run_end", "elapsed_s": round(time.time() - self.started, 3),
                     "state": _plain(final_state) if final_state is not None else None})
        self._fh.close()
        return self.path


async def run_traced(compiled, state: dict, *, day: str,
                     path: Path | None = None) -> tuple[dict, Path]:
    """Run a compiled graph, writing a trace and returning the final state.

    `stream_mode="updates"` gives one event per node as it finishes,
    which is what makes the per-node timing real rather than inferred.
    """
    trace = Trace(day, path)
    final: dict = dict(state)
    last = time.time()
    try:
        async for chunk in compiled.astream(state, stream_mode="updates"):
            now = time.time()
            for node_name, output in chunk.items():
                trace.node(node_name, output, now - last)
                if isinstance(output, dict):
                    final.update(output)
            last = now
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
    """Per-node timings and the run total - the shape the dashboard renders."""
    records = read(path)
    nodes = [r for r in records if r.get("event") == "node"]
    start = next((r for r in records if r.get("event") == "run_start"), {})
    end = next((r for r in records if r.get("event") == "run_end"), {})
    return {
        "day": start.get("day"),
        "total_s": end.get("elapsed_s"),
        "nodes": [{"node": n["node"], "elapsed_s": n["elapsed_s"]} for n in nodes],
        "slowest": max(nodes, key=lambda n: n["elapsed_s"])["node"] if nodes else None,
    }
