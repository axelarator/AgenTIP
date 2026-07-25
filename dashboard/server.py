"""Read-only web dashboard for the CTI cluster store.

A thin Starlette API in front of cti_tools.core (the same module the MCP
server and CLI use), plus a static frontend. Deliberately read-only: all
writes to cluster data go through the MCP tools / CLI, which hold the
on-disk lock this module never needs to touch.

Run with the mcp-server venv, which already has cti_tools installed and
starlette/uvicorn as transitive deps of the `mcp` package:

    mcp-server/.venv/bin/python dashboard/server.py
"""
from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from cti_tools import core

STATIC_DIR = Path(__file__).parent / "static"


def _cluster_summary(name: str) -> dict:
    data = core.load_cluster(name)
    return {
        "slug": name,
        "name": data["name"],
        "aliases": data["aliases"],
        "description": data["description"],
        "confidence": data["confidence"],
        "first_seen": data["first_seen"],
        "last_seen": data["last_seen"],
        "ttp_count": len(data["ttps"]),
        "observable_count": sum(len(v) for v in data["observables"].values()),
        "gap_count": len(data["gaps"]),
        "detection_count": len(data["detections"]),
        "relationship_count": len(data.get("relationships", [])),
    }


async def list_clusters(request):
    summaries = [_cluster_summary(n) for n in core.list_clusters()]
    summaries.sort(key=lambda c: c["last_seen"] or "", reverse=True)
    return JSONResponse(summaries)


async def get_cluster(request):
    name = request.path_params["name"]
    try:
        data = core.get_cluster(name)
    except core.ClusterNotFound:
        return JSONResponse({"error": f"cluster {name!r} not found"}, status_code=404)
    return JSONResponse(data)


async def stats(request):
    names = core.list_clusters()
    totals = {"observable_count": 0, "ttp_count": 0, "gap_count": 0, "detection_count": 0}
    activity = []
    for n in names:
        data = core.load_cluster(n)
        totals["observable_count"] += sum(len(v) for v in data["observables"].values())
        totals["ttp_count"] += len(data["ttps"])
        totals["gap_count"] += len(data["gaps"])
        totals["detection_count"] += len(data["detections"])
        for entry in data["hunt_log"]:
            activity.append({"cluster": data["name"], "slug": n, **entry})
    activity.sort(key=lambda e: e["date"], reverse=True)
    return JSONResponse({
        "cluster_count": len(names),
        "pending_fingerprint_count": len(core.list_pending_fingerprints()),
        "recent_activity": activity[:20],
        **totals,
    })


async def techniques(request):
    return JSONResponse(core.get_technique_usage())


async def technique_detail(request):
    return JSONResponse(core.get_technique_usage(request.path_params["technique_id"]))


async def observable_search(request):
    q = request.query_params.get("q", "").strip()
    if not q:
        return JSONResponse({"query": q, "exact": [], "partial": []})

    exact = core.find_observable(q)["matches"]
    partial: list[dict] = []
    needle = q.lower()
    if len(needle) >= 3:
        exact_keys = {(m["cluster"], m["category"], m["value"].lower()) for m in exact}
        for name in core.list_clusters():
            data = core.load_cluster(name)
            for category, items in data["observables"].items():
                for o in items:
                    key = (data["name"], category, o["value"].lower())
                    if needle in o["value"].lower() and key not in exact_keys:
                        partial.append({
                            "cluster": data["name"], "category": category, "value": o["value"],
                            "sources": o["sources"], "first_seen": o["first_seen"],
                            "last_seen": o["last_seen"],
                        })
    return JSONResponse({"query": q, "exact": exact, "partial": partial[:200]})


async def pending_fingerprints(request):
    return JSONResponse(core.list_pending_fingerprints())


routes = [
    Route("/api/stats", stats),
    Route("/api/clusters", list_clusters),
    Route("/api/clusters/{name}", get_cluster),
    Route("/api/techniques", techniques),
    Route("/api/techniques/{technique_id}", technique_detail),
    Route("/api/observables/search", observable_search),
    Route("/api/pending-fingerprints", pending_fingerprints),
    Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True), name="static"),
]

app = Starlette(routes=routes)


if __name__ == "__main__":
    import uvicorn
    # Headless lab VM — bind all interfaces so the dashboard is reachable by
    # the VM's LAN IP, not just from a shell on the box itself.
    uvicorn.run(app, host="0.0.0.0", port=8420)
