"""Drawing the graph.

Replaces docs/pipeline.html's hand-drawn diagrams. Those were good, and
they were already drifting - they were drawn against a commit that has
since moved, and the header disagreed with setup.sh about when Stage B
runs. A diagram generated from the graph object cannot drift.
"""
from __future__ import annotations

from pathlib import Path


def mermaid(compiled) -> str:
    return compiled.get_graph(xray=True).draw_mermaid()


def write_png(compiled, path: Path) -> Path | None:
    """PNG rendering needs either graphviz or a network round-trip to
    mermaid.ink. Neither is guaranteed here, and neither is worth failing
    a run over - the mermaid source is the artifact that matters."""
    try:
        png = compiled.get_graph(xray=True).draw_mermaid_png()
    except Exception:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)
    return path


def write_all(out_dir: Path) -> dict[str, str]:
    from .build import build_analyze, build_collect, build_daily

    out_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, compiled in (("collect", build_collect()),
                           ("analyze", build_analyze()),
                           ("daily", build_daily())):
        src = mermaid(compiled)
        target = out_dir / f"graph-{name}.mmd"
        target.write_text(src)
        written[name] = str(target)
        png = write_png(compiled, out_dir / f"graph-{name}.png")
        if png:
            written[f"{name}_png"] = str(png)
    return written
