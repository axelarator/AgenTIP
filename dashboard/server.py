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

import re
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from cti_tools import core
from cti_tools.tracking import digest as tracking_digest
from cti_tools.tracking import store as tracking_store

STATIC_DIR = Path(__file__).parent / "static"
_NARRATIVE_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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


async def tracking_observables(request):
    result = tracking_store.tracked_observables()
    if "error" in result:
        return JSONResponse(result, status_code=503)
    return JSONResponse(result)


async def tracking_observable_detail(request):
    result = tracking_store.observable_history(request.path_params["ip"])
    if "error" in result:
        return JSONResponse(result, status_code=503)
    return JSONResponse(result)


async def tracking_narratives(request):
    ndir = tracking_digest.narrative_dir()
    if not ndir.is_dir():
        return JSONResponse({"dates": []})
    dates = sorted((p.stem for p in ndir.glob("*.md") if _NARRATIVE_DATE_RE.match(p.stem)),
                   reverse=True)
    return JSONResponse({"dates": dates})


async def tracking_narrative_detail(request):
    day = request.path_params["date"]
    if not _NARRATIVE_DATE_RE.match(day):
        return JSONResponse({"error": "invalid date"}, status_code=400)
    path = tracking_digest.narrative_dir() / f"{day}.md"
    if not path.is_file():
        return JSONResponse({"error": f"no narrative for {day}"}, status_code=404)
    return JSONResponse({"date": day, "content": path.read_text()})


routes = [
    Route("/api/stats", stats),
    Route("/api/clusters", list_clusters),
    Route("/api/clusters/{name}", get_cluster),
    Route("/api/techniques", techniques),
    Route("/api/techniques/{technique_id}", technique_detail),
    Route("/api/observables/search", observable_search),
    Route("/api/pending-fingerprints", pending_fingerprints),
    Route("/api/tracking/observables", tracking_observables),
    Route("/api/tracking/observables/{ip}", tracking_observable_detail),
    Route("/api/tracking/narratives", tracking_narratives),
    Route("/api/tracking/narratives/{date}", tracking_narrative_detail),
    Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True), name="static"),
]

app = Starlette(routes=routes)


if __name__ == "__main__":
    import uvicorn
    # Headless lab VM — bind all interfaces so the dashboard is reachable by
    # the VM's LAN IP, not just from a shell on the box itself.
    uvicorn.run(app, host="0.0.0.0", port=8420)
