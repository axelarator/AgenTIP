"""Assembling the graph.

Two subgraphs, one drawing. `collect` is Stage A - deterministic
collection, no model. `analyze` is Stage B - the judgement that used to
be a single `claude -p` pass over a 103-line prompt.

Keeping both in one graph is the point of the visualization request:
the interesting question at runtime is not "what did the model do", it is
"which of these twenty things ran, in what order, and which one was
slow" - and half of those things are collection.
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes import analyze, collect, rank
from .state import FAMILY_ATTRIBUTES, CTIState


def build_collect():
    """Stage A: ingest -> register -> fan out over clusters -> write."""
    g = StateGraph(CTIState)
    g.add_node("ingest_inbox", collect.ingest_inbox)
    g.add_node("sweep", collect.sweep)
    g.add_node("enrich_and_write", collect.enrich_and_write)
    g.add_node("run_analytics", collect.run_analytics)
    g.add_node("write_digest", collect.write_digest)

    g.add_edge(START, "ingest_inbox")
    # One `sweep` per cluster, all dispatched together. This is the loop
    # that used to be strictly sequential across eight clusters.
    g.add_conditional_edges("ingest_inbox", collect.fan_out_clusters, ["sweep"])
    g.add_edge("sweep", "enrich_and_write")
    g.add_edge("enrich_and_write", "run_analytics")
    g.add_edge("run_analytics", "write_digest")
    g.add_edge("write_digest", END)
    return g.compile()


def build_analyze():
    """Stage B: rank -> four specialists in parallel -> persist -> narrate."""
    g = StateGraph(CTIState)
    g.add_node("rank", rank.rank)
    for family in FAMILY_ATTRIBUTES:
        g.add_node(family, analyze.make_specialist(family))
    g.add_node("persist", analyze.persist)
    g.add_node("narrate", analyze.narrate)

    g.add_edge(START, "rank")
    # Every specialist is wired unconditionally and returns immediately
    # when it has no items. Routing around them instead would make the
    # drawn graph depend on the day's data, and the drawing is supposed
    # to show the pipeline, not one run of it.
    for family in FAMILY_ATTRIBUTES:
        g.add_edge("rank", family)
        g.add_edge(family, "persist")
    g.add_edge("persist", "narrate")
    g.add_edge("narrate", END)
    return g.compile()


def build_daily():
    """The whole pipeline: collect, then analyze what it produced.

    The subgraphs are added as compiled graphs rather than wrapped in
    adapter functions, so `draw_mermaid(xray=True)` renders every node
    inside them. An adapter would draw as three boxes - which is the view
    that was already unhelpful.
    """
    g = StateGraph(CTIState)
    g.add_node("collect", build_collect())
    g.add_node("analyze", build_analyze())
    g.add_edge(START, "collect")
    g.add_edge("collect", "analyze")
    g.add_edge("analyze", END)
    return g.compile()
