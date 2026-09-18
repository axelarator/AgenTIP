"""Host side of the probe VM's analysis container.

The division of labour matters more than the code: the VM downloads and
analyzes, this host only ever sees JSON. `cti-graph` never contains a
sample, never writes one to disk, and cannot - there is no code path here
that receives file bytes.

That is why the container runs on the probe VM rather than here. The VM
already has the network position (VPN egress, mirrored to Zeek/Arkime), it
already did the download that found the directory, and it is the machine
this lab is willing to point at adversary infrastructure. Shipping the
bytes back to analyze them would have undone all of that for no gain.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..errors import VMProxyError
from ..store import connect, upsert_opendir_samples
from . import vm_proxy

log = logging.getLogger("cti.probe.sandbox")

# Caps applied on this side as well as the VM's own. Two independent
# limits because they answer different questions: the VM's protect the VM,
# these protect the analyst's budget and attention.
MAX_FILES = 20
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def analyze_urls(urls: list[str], *, indicator: str, actor: str | None = None,
                 url_base: str | None = None,
                 max_files: int = MAX_FILES,
                 max_total_bytes: int = MAX_TOTAL_BYTES,
                 persist: bool = True) -> dict[str, Any]:
    """Analyze specific open-directory files and record the verdicts.

    `urls` is an explicit list. There is deliberately no "analyze
    everything in this directory" convenience: downloading an adversary's
    staged payloads is a decision per file, and a helper that made it in
    bulk would get used by accident.
    """
    if not urls:
        return {"error": "no urls given", "results": []}

    try:
        response = vm_proxy.fetch_and_analyze(
            urls[:max_files], max_files=max_files, max_total_bytes=max_total_bytes)
    except VMProxyError as e:
        return {"error": f"probe VM unreachable: {e}", "results": []}

    if response.get("error"):
        return {"error": str(response["error"]),
                "results": response.get("results") or [],
                "fetched": response.get("fetched", 0)}

    results = response.get("results") or []
    if persist and results:
        analyzed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        try:
            with connect(read_only=False) as con:
                upsert_opendir_samples(
                    con, indicator_value=indicator,
                    url=url_base or (results[0].get("url") or ""),
                    results=results, analyzed_at=analyzed_at, actor=actor)
        except Exception as e:                  # noqa: BLE001
            # The analysis succeeded; losing the write is worth a note, not
            # a discarded result the analyst then has to re-collect loudly.
            log.warning("sandbox verdicts not persisted: %s", e)
            response["persist_error"] = str(e)

    response["notable"] = [r for r in results if r.get("verdict") == "notable"]
    return response


def summarize(response: dict[str, Any]) -> str:
    """A compact human/agent-readable rendering of a sandbox run."""
    if response.get("error"):
        return f"sandbox failed: {response['error']}"
    results = response.get("results") or []
    if not results:
        return "sandbox ran but analyzed nothing"
    lines = [f"analyzed {len(results)} file(s), "
             f"{len(response.get('notable') or [])} notable"]
    for r in sorted(results, key=lambda r: r.get("verdict") != "notable"):
        hits = ", ".join(h.get("rule", "") for h in (r.get("yara_hits") or []))
        flags = []
        if r.get("type_mismatch"):
            flags.append("type mismatch")
        if hits:
            flags.append(hits)
        lines.append(f"  [{r.get('verdict','?'):12s}] {r.get('path')}  "
                     f"{r.get('sha256','')[:16]}  {r.get('magic') or '-'}"
                     + (f"  ({'; '.join(flags)})" if flags else ""))
    return "\n".join(lines)
