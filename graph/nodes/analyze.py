"""The specialist nodes, and the reducer that follows them.

Four specialists run concurrently, each with its own short prompt and a
read-only tool budget. They write only to `findings` and `errors`, which
are the graph's two reducer fields - that is what makes running them at
the same time safe without a lock.

Writes are centralized in `persist`, deliberately. DuckDB's write lock is
process-exclusive and `connect_retry` retries only the connect, never the
body, so four nodes each calling save_correlation would surface as
"tracking DB busy" rather than queueing. One writer, at the end.
"""
from __future__ import annotations

import json
from typing import Any

from cti.store import CORRELATION_TYPES, save_correlation

from ..sdk import load_prompt, parse_findings, run_turn
from ..state import CTIState, Family, Finding, Item

# Read-only. A specialist that could write could also write something no
# other specialist saw, which is exactly the coordination problem the
# single-writer design avoids.
SPECIALIST_TOOLS = ["query_duckdb", "get_actor_summary"]

MAX_TURNS = 4


def _render_items(items: list[Item]) -> str:
    """What the specialist actually reads.

    Values are truncated hard. A single ip_hostnames row in the real
    digest is several kilobytes of unrelated tenant domains; the old
    single pass paid for all of it in context and then had to reason
    around it.
    """
    lines = []
    for n, item in enumerate(items, 1):
        lines.append(f"### Item {n}")
        lines.append(f"- actor: {item.actor or 'unattributed'}")
        lines.append(f"- indicator: {item.indicator}")
        lines.append(f"- attribute: {item.attribute}  (change: {item.change_type})")
        lines.append(f"- detected: {item.detected_at}")
        lines.append(f"- stored confidence: {item.confidence}")
        lines.append(f"- old: {_trim(item.old_value)}")
        lines.append(f"- new: {_trim(item.new_value)}")
        lines.append("")
    return "\n".join(lines)


def _trim(value: Any, limit: int = 600) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if text is None:
        return "null"
    return text if len(text) <= limit else text[:limit] + f"... [{len(text)} chars total]"


def make_specialist(family: Family):
    """Build the node function for one specialist family."""

    async def node(state: CTIState) -> dict:
        items = (state.get("ranked") or {}).get(family) or []
        if not items:
            return {}

        result = await run_turn(
            system=load_prompt(family),
            prompt=(f"Day: {state.get('day')}\n\n"
                    f"Items for you ({len(items)}):\n\n{_render_items(items)}"),
            allowed_tools=SPECIALIST_TOOLS,
            max_turns=MAX_TURNS,
        )
        if result.error:
            return {"errors": [f"{family}: {result.error}"]}

        parsed, parse_error = parse_findings(result.text)
        if parse_error:
            return {"errors": [f"{family}: {parse_error}"]}

        by_indicator = {i.indicator: i.actor for i in items}

        findings = []
        for raw in parsed:
            correlation_type = raw.get("correlation_type")
            if correlation_type not in CORRELATION_TYPES:
                # Not an error: null is the documented way to say "worth
                # reporting, not worth storing". An unrecognized value is
                # treated the same way rather than rejected, because a
                # finding with a bad label is still a finding.
                correlation_type = None
            indicators = [str(i) for i in (raw.get("indicators") or [])]
            findings.append(Finding(
                family=family,
                actor=_resolve_actor(raw.get("actor"), indicators, by_indicator),
                headline=str(raw.get("headline") or "").strip(),
                detail=str(raw.get("detail") or "").strip(),
                indicators=indicators,
                correlation_type=correlation_type,
                confidence=str(raw.get("confidence") or "medium"),
            ))
        return {"findings": [f for f in findings if f.headline]}

    node.__name__ = family
    return node


def _resolve_actor(claimed: Any, indicators: list[str],
                   by_indicator: dict[str, str | None]) -> str | None:
    """Which actor a finding belongs to.

    The first version of this defaulted to `items[0].actor` whenever the
    model did not name one. That is wrong the moment a specialist holds
    items from more than one actor, which is the normal case - and it
    showed up immediately: a finding about a DragonForce domain was
    stamped JadeProx, and one about a Teams Gets Turnt domain was stamped
    JadeProx too. persist() writes this field into save_correlation, so
    the consequence is a durable correlation filed against the wrong
    threat actor - worse than no correlation at all.

    The finding's own indicators are the authority, because the ranker
    already knows which actor each one is tracked under. A model-supplied
    actor is only trusted when it agrees, and a finding spanning two
    actors gets no actor at all rather than an arbitrary one.
    """
    from_items = {by_indicator.get(i) for i in indicators if by_indicator.get(i)}
    if len(from_items) == 1:
        return from_items.pop()
    if from_items:
        return None   # genuinely spans actors - let persist skip it
    return str(claimed) if claimed else None


def persist(state: CTIState) -> dict:
    """The only writer in the analyze subgraph.

    `zeek_hit` is excluded on purpose: Zeek cross-referencing is a
    separate on-demand capability that never feeds this digest, so a
    correlation claiming a Zeek hit here would be unfounded by
    construction.
    """
    if state.get("dry_run"):
        return {"correlations": [f.to_dict() for f in state.get("findings") or []
                                 if f.correlation_type]}

    saved = []
    errors = []

    # Every finding, before the correlation filter below. The two are not
    # the same set and the difference is the point: on 2026-09-21, 1 of 5
    # findings carried a correlation_type, and the other four - a cert
    # rotation, a workers.dev link, a PTR loss - existed nowhere but the
    # run trace afterwards. The leads worth clicking are usually among the
    # ones not worth filing.
    findings = state.get("findings") or []
    if findings:
        try:
            from datetime import date as _date

            from cti.store import connect, record_findings
            day = state.get("day")
            with connect(read_only=False) as con:
                record_findings(con,
                                day=_date.fromisoformat(day) if isinstance(day, str) else day,
                                findings=[f.to_dict() for f in findings])
        except Exception as e:                  # noqa: BLE001
            # Best-effort, like the enrichment history write: a store
            # hiccup must not cost the day's analysis.
            errors.append(f"persist findings: {type(e).__name__}: {e}")

    for finding in findings:
        if not finding.correlation_type or finding.correlation_type == "zeek_hit":
            continue
        if not finding.actor or not finding.indicators:
            continue
        result = save_correlation(
            actor=finding.actor,
            correlation_type=finding.correlation_type,
            indicators=finding.indicators,
            narrative=f"{finding.headline}\n\n{finding.detail}",
            confidence=finding.confidence,
        )
        if isinstance(result, dict) and result.get("error"):
            errors.append(f"persist: {result['error']}")
        else:
            saved.append(finding.to_dict())
    return {"correlations": saved, "errors": errors}


async def narrate(state: CTIState) -> dict:
    """Turn the findings into the day's narrative file."""
    findings = state.get("findings") or []
    if not findings:
        return {"narrative": _quiet_day(state)}

    payload = {
        "day": state.get("day"),
        "findings": [f.to_dict() for f in findings],
        "saved_as_correlations": [c.get("headline") for c in state.get("correlations") or []],
        "specialist_errors": state.get("errors") or [],
    }
    result = await run_turn(
        system=load_prompt("narrate", with_common=False),
        prompt=json.dumps(payload, indent=2, default=str),
        allowed_tools=[],
        max_turns=1,
        mcp=False,
    )
    if result.error or not result.text:
        # Falling back to a mechanical rendering beats losing the day's
        # work because the last node failed.
        return {"narrative": _fallback_narrative(state),
                "errors": [f"narrate: {result.error or 'empty reply'}"]}
    return {"narrative": result.text}


def _quiet_day(state: CTIState) -> str:
    items = state.get("items") or []
    suppressed = sum(1 for i in items if i.suppressed)
    return (f"# {state.get('day')}\n\n"
            f"Nothing noteworthy. {len(items)} digest rows reviewed, "
            f"{suppressed} suppressed as routine before analysis.\n")


def _fallback_narrative(state: CTIState) -> str:
    lines = [f"# {state.get('day')}", "",
             "_Narrative node failed; findings rendered mechanically._", ""]
    for f in state.get("findings") or []:
        lines.append(f"## {f.headline}")
        lines.append(f"{f.detail}")
        if f.indicators:
            lines.append(f"Indicators: {', '.join(f.indicators)}")
        lines.append("")
    return "\n".join(lines)
