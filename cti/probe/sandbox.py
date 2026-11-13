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
from ..store import connect_retry, upsert_opendir_samples
from . import vm_proxy

log = logging.getLogger("cti.probe.sandbox")

# Caps applied on this side as well as the VM's own. Two independent
# limits because they answer different questions: the VM's protect the VM,
# these protect the analyst's budget and attention.
MAX_FILES = 20
MAX_TOTAL_BYTES = 64 * 1024 * 1024
# How much of each file's strings sample and extracted lists a compact
# reply carries. The stored row keeps all of it.
REPLY_STRINGS = 8
REPLY_EXTRACTED = 15


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
            with connect_retry(read_only=False) as con:
                upsert_opendir_samples(
                    con, indicator_value=indicator,
                    url=url_base or (results[0].get("url") or ""),
                    results=results, analyzed_at=analyzed_at, actor=actor)
        except Exception as e:                  # noqa: BLE001
            # The analysis succeeded; losing the write is worth a note, not
            # a discarded result the analyst then has to re-collect loudly.
            log.warning("sandbox verdicts not persisted: %s", e)
            response["persist_error"] = str(e)

    # Paths, not the results again: every notable result is already in
    # `results`, and repeating them doubled the size of the reply.
    response["notable"] = [r.get("path") for r in results
                           if r.get("verdict") == "notable"]
    # A request past the cap used to be cut to it without a word, so the
    # caller believed every file had been looked at.
    response["not_fetched"] = urls[max_files:]
    return response


def compact(response: dict[str, Any], *, strings: int | None = None,
            extracted: int | None = None) -> dict[str, Any]:
    """The same response sized for a caller with a result limit.

    A full batch is 20 files of 60 strings each plus every extracted URL,
    which overflowed the MCP result limit. The verdict fields are kept
    whole; the strings sample and the extracted lists are cut to the first
    few, with a `_total` beside each so the cut is visible. Nothing is lost:
    analyze_urls has already stored the full results, and
    get_opendir_samples reads them back.
    """
    strings = REPLY_STRINGS if strings is None else strings
    extracted = REPLY_EXTRACTED if extracted is None else extracted
    rows = []
    for r in response.get("results") or []:
        sample = r.get("strings_sample") or []
        found = {}
        for key, values in (r.get("extracted") or {}).items():
            values = values or []
            found[key] = values[:extracted]
            if len(values) > extracted:
                found[f"{key}_total"] = len(values)
        row = {**r, "strings_sample": sample[:strings], "extracted": found}
        if len(sample) > strings:
            row["strings_total"] = len(sample)
        rows.append(row)
    out = {**response, "results": rows, "summary": summarize(response)}
    if rows:
        out["full_results"] = "get_opendir_samples(indicator, sha256)"
    return out


def summarize(response: dict[str, Any]) -> str:
    """A compact human/agent-readable rendering of a sandbox run."""
    if response.get("error"):
        return f"sandbox failed: {response['error']}"
    results = response.get("results") or []
    if not results:
        return "sandbox ran but analyzed nothing"
    skipped = response.get("not_fetched") or []
    lines = [f"analyzed {len(results)} file(s), "
             f"{len(response.get('notable') or [])} notable"
             + (f"; {len(skipped)} url(s) past the {MAX_FILES}-file limit "
                "were not fetched" if skipped else "")]
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
