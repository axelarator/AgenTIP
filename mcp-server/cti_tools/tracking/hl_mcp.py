"""HoneyLabs lookups over their hosted MCP server (mcp.honeylabs.net)
instead of the plain lookup API.

Why this exists alongside pivot.honeylabs_lookup: pivot routes every
call through the Win11 VM SSH hop and looks IPs up one at a time, so a
300-IP batch took half an hour and a single transient 429 used to end
telemetry for the day. The MCP endpoint authenticates with the same
HONEYLABS_API_KEY and answers in ~0.6s per call over one session.

OPSEC note: these calls go straight from this host, NOT via the Win11
VM. That is a deliberate exception to pivot.py's "nothing originates
from this host" rule: HoneyLabs is a threat-intel provider we already
authenticate to (and query interactively over this same MCP endpoint),
not candidate adversary infrastructure. Registry lookups (RIPEstat,
RDAP) keep riding the VM hop.

Both surfaces share the plan's limits (free tier: 500 credits/day, 10
calls/min - confirmed against the docs and empirically 2026-08-21), so
the speedup comes from spending calls better, not calling faster:
`prefilter` checks a whole chunk of IPs as a /32 cidr_set in ONE call
(the response's per_range counts are doc-guaranteed observed absences
when 0), and only IPs with events get the full per-IP `lookup`. Most
tracked infrastructure is quiet on any given day, so a 300-IP batch
collapses to ~10 prefilter calls plus a handful of full lookups.

Results are normalized to exactly the dict shape pivot.honeylabs_lookup
returns, so downstream storage/digest code is agnostic about which
surface fetched the data. Fields the MCP tool does not expose
(events_24h/7d, malware) come back None.
"""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, AsyncIterator

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from ..pivot import PivotError

HL_MCP_URL = os.environ.get("CTI_HL_MCP_URL", "https://mcp.honeylabs.net/mcp")
CALL_TIMEOUT_SECS = 60.0


@asynccontextmanager
async def open_session(api_key: str) -> AsyncIterator[ClientSession]:
    """One initialized MCP session for a whole batch of lookups."""
    try:
        async with streamablehttp_client(
                HL_MCP_URL,
                headers={"Authorization": f"Bearer {api_key}"}) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    except PivotError:
        raise
    except Exception as e:
        raise PivotError(f"honeylabs mcp session failed: "
                         f"{type(e).__name__}: {e}") from e


async def prefilter(session: ClientSession, ips: list[str]) -> dict[str, int]:
    """One cidr_set call over the chunk as /32s -> {ip: event_count}.
    A count of 0 is a real observed absence (per the tool contract), so
    the caller can record it without a per-IP lookup. IPs the response
    doesn't cover are simply missing from the dict - callers should
    fall back to a full lookup for those."""
    data = await _call(session, ", ".join(f"{ip}/32" for ip in ips))
    per_range = data.get("per_range")
    if not isinstance(per_range, list):
        raise PivotError("honeylabs mcp prefilter: response has no per_range "
                         f"(query_type={data.get('query_type')!r})")
    counts: dict[str, int] = {}
    for row in per_range:
        if isinstance(row, dict) and isinstance(row.get("range"), str):
            counts[row["range"].split("/")[0]] = int(row.get("events") or 0)
    return counts


def not_observed() -> dict[str, Any]:
    """The normalized record for an IP a prefilter showed as absent -
    identical to what a full lookup of an unobserved IP normalizes to."""
    return normalize({"total_events": 0})


async def lookup(session: ClientSession, ip: str) -> dict[str, Any]:
    """ioc_lookup_tool for one IP, normalized to the
    pivot.honeylabs_lookup shape."""
    return normalize(await _call(session, ip))


async def _call(session: ClientSession, ioc: str) -> dict[str, Any]:
    """One ioc_lookup_tool call, decoded to a dict. Raises PivotError on
    tool errors or an unparseable result; rate/quota errors keep their
    status text so callers can string-match 402/429 the same way as on
    the direct API."""
    try:
        result = await session.call_tool(
            "ioc_lookup_tool", {"ioc": ioc},
            read_timeout_seconds=timedelta(seconds=CALL_TIMEOUT_SECS))
    except Exception as e:
        raise PivotError(f"honeylabs mcp call failed for {ioc}: "
                         f"{type(e).__name__}: {e}") from e
    if result.isError:
        text = result.content[0].text if result.content else "unknown tool error"
        raise PivotError(f"honeylabs mcp error for {ioc}: {text}")
    data = result.structuredContent
    if data is None:
        try:
            data = json.loads(result.content[0].text)
        except (IndexError, AttributeError, ValueError) as e:
            raise PivotError(f"honeylabs mcp returned an unparseable "
                             f"result for {ioc}: {e}") from e
    if not isinstance(data, dict):
        raise PivotError(f"unexpected HoneyLabs MCP response shape for {ioc}")
    return data


def is_rate_or_budget(msg: str) -> tuple[bool, bool]:
    """(rate_limited, budget_exhausted) from an error message. Shapes
    confirmed on the direct API; the MCP endpoint fronts the same
    backend so match both numeric statuses and the words."""
    low = msg.lower()
    rate = "429" in msg or "rate limit" in low or "rate-limit" in low
    budget = ("402" in msg or "quota" in low or "credit" in low
              or "payment" in low)
    return rate, budget


def normalize(data: dict[str, Any]) -> dict[str, Any]:
    """MCP ioc_lookup_tool response -> pivot.honeylabs_lookup shape.

    Response shape confirmed against the live endpoint (2026-08-21):
    flat fields (total_events, asn_number/asn_org, ports_targeted as
    bare ints, verdict as the human sentence with verdict_key as the
    stable value, single `scanner`, cve_probes). An unobserved IP is
    total_events 0 with epoch-sentinel first/last_seen and zero/empty
    placeholders, so everything but the zero event count maps to None
    then - matching what the direct API's compact not-observed response
    normalized to."""
    observed = bool(data.get("total_events"))
    scanner = data.get("scanner")
    return {
        "events": data.get("total_events"),
        "events_24h": None,   # not exposed by the MCP tool
        "events_7d": None,    # not exposed by the MCP tool
        "first_seen": data.get("first_seen") if observed else None,
        "last_seen": data.get("last_seen") if observed else None,
        "country": data.get("country_code") or None,
        "asn": data.get("asn_number") or None,
        "as_org": data.get("asn_org") or None,
        "verdict": (data.get("verdict_key") if observed else None),
        "verdict_label": (data.get("verdict") if observed else None),
        "verdict_detail": "; ".join(data.get("verdict_why") or []) or None,
        "verdict_confidence": data.get("verdict_confidence"),
        "known_scanners": [scanner] if scanner else None,
        "ports": data.get("ports_targeted") or None,
        "fingerprints": {
            "ja4": data.get("top_ja4_fingerprints"),
            "ja3": data.get("top_ja3_fingerprints"),
            "hassh": data.get("top_hassh_fingerprints"),
        } if observed else None,
        "cves": data.get("cve_probes") or None,
        "malware": None,      # not exposed by the MCP tool
    }
