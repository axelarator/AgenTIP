"""Running a Claude Agent SDK turn as a LangGraph node.

## Why the Agent SDK rather than ChatAnthropic

Two reasons, and the first is the decisive one.

**Auth.** The pipeline this replaced made its one LLM call with
`claude -p`, on the operator's Claude subscription, and the SDK uses the
same login. There is no ANTHROPIC_API_KEY in this environment. A LangChain `ChatAnthropic` node would need one, and would
bill per token - which matters when the point of this change is to run
*more* model passes per day, in parallel.

**Tools.** The tool surface the specialists need already exists as an MCP
server, wired by .mcp.json, with the read-only subset
already allow-listed. The SDK speaks MCP natively, so a specialist gets
`query_duckdb` and `get_actor_summary` by naming them. Re-exposing them
as LangChain tools would mean a second definition of each to keep in sync.

The cost is that a node is an async subprocess turn rather than an
in-process call, so nodes are async and the graph is driven with
`ainvoke`. LangGraph runs async nodes concurrently on one event loop,
which is what the fan-out needs anyway.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from claude_agent_sdk import (AssistantMessage, ClaudeAgentOptions, ResultMessage,
                              TextBlock, ToolUseBlock, query)

PROMPTS = Path(__file__).parent / "prompts"
REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MODEL = os.environ.get("CTI_GRAPH_MODEL", "claude-sonnet-5")

log = logging.getLogger(__name__)

# A turn is one model response; each tool call costs one. At 4 a specialist
# had three lookups and its answer, and the fourth lookup aborted it with
# nothing kept - 5 of 112 runs before 2026-10-17, two of four that day.
#
# It lives here, not beside the specialists, because the shared prompt
# states it: the prompt said "at most two tool calls" while this allowed
# five, and a specialist that believed the prompt and one that did not were
# both within the rules.
SPECIALIST_MAX_TURNS = 6


def selector_taxonomy() -> str:
    """The selector taxonomy, rendered from the code that enforces it.

    The prompt must not carry its own copy. `selectors.py` decides what a
    shared value proves and `expand.py` applies that decision; a prompt
    that restated it in prose would drift the first time a type was
    reclassed, and the model would then be arguing with the rule that
    already ran. whois.registrar was reclassed structural -> behavioural
    during this work, which is exactly the edit a hand-written table would
    have missed.

    Only the classes that can promote are listed in full. Behavioural and
    contextual types are named but not explained, because the one thing the
    specialist needs to know about them is that they cannot make a link.
    """
    from cti.store.selectors import CLASS_ORDER, TYPES

    by_class: dict[str, list] = {c: [] for c in CLASS_ORDER}
    for spec in TYPES.values():
        by_class[spec.cls].append(spec)

    lines: list[str] = []
    for cls in ("identity", "structural"):
        lines.append(f"### {cls} - {'promotes alone' if cls == 'identity' else 'two independent ones promote'}")
        lines.append("")
        for spec in sorted(by_class[cls], key=lambda s: s.name):
            lines.append(f"- **`{spec.name}`** - {spec.means}.")
            if spec.never:
                lines.append(f"  Never: {spec.never}.")
        lines.append("")
    for cls in ("behavioural", "contextual"):
        names = ", ".join(f"`{s.name}`" for s in sorted(by_class[cls], key=lambda s: s.name))
        note = ("corroborate a link, never make one" if cls == "behavioural"
                else "describe a finding; structurally unable to promote one")
        lines.append(f"### {cls} - {note}")
        lines.append("")
        lines.append(names)
        lines.append("")
    return "\n".join(lines).strip()


def load_prompt(name: str, *, with_common: bool = True) -> str:
    """A specialist's prompt is its own file plus the shared rules.

    Splitting them this way is the point of the decomposition: the rules
    every specialist needs (the "never call it new" rule, the
    Zeek-is-out-of-scope rule, the output shape) live once in _common.md,
    and each specialist's file holds only what is actually its own. The
    original single prompt had all of it inline, which is why adding a
    signal type meant editing a 103-line block that four unrelated
    judgements also depended on.
    """
    body = (PROMPTS / f"{name}.md").read_text()
    # A prompt may ask for a table the code owns rather than restating it.
    if "{{SELECTOR_TAXONOMY}}" in body:
        body = body.replace("{{SELECTOR_TAXONOMY}}", selector_taxonomy())
    if not with_common:
        return body
    common = (PROMPTS / "_common.md").read_text().replace(
        "{{MAX_LOOKUPS}}", str(SPECIALIST_MAX_TURNS - 1))
    return common + "\n\n---\n\n" + body


def mcp_config() -> dict[str, Any]:
    """The cti-tools MCP server, launched from this checkout's venv."""
    return {
        "cti-tools": {
            "type": "stdio",
            "command": str(REPO_ROOT / ".venv" / "bin" / "python"),
            "args": ["-m", "cti.mcp.server"],
            "cwd": str(REPO_ROOT),
        }
    }


@dataclass
class TurnResult:
    text: str
    tool_calls: list[str] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# --- waiting out a usage limit ---------------------------------------------
#
# The pipeline runs on the operator's subscription, which the operator also
# uses by hand. When the two meet, every model call of the 06:15 run fails
# at once with "You've hit your session limit - resets 7:30am (UTC)", and
# the day's narrative used to be written from nothing. On 2026-11-12 and
# 2026-11-13 the analysis had to be re-run by hand.
#
# The limit says when it ends, so the call waits until then and tries
# again. Waiting here, inside the call, means the rest of the run needs no
# second pass: the specialists that were refused all sleep to the same
# minute, then answer, and persist and narrate run once, as on any day.

_LIMIT = re.compile(r"\b(?:session|usage|weekly|rate)[ -]limit\b|\bhit your limit\b",
                    re.IGNORECASE)
_RESETS = re.compile(r"resets\s+(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)\s*\(UTC\)",
                     re.IGNORECASE)
# After the stated reset, before trying: the clocks need not agree.
RESET_MARGIN = timedelta(minutes=3)
# When the message names no time this code can read.
BLIND_WAIT = timedelta(minutes=30)


def limit_wait_hours() -> float:
    """How long a run may spend waiting for a usage limit to lift, in all.
    `CTI_LIMIT_WAIT_HOURS`, default 8; 0 turns the waiting off, which is
    what a run started by hand to see the error wants."""
    try:
        return max(0.0, float(os.environ.get("CTI_LIMIT_WAIT_HOURS", "8")))
    except ValueError:
        return 8.0


def is_usage_limit(error: str | None) -> bool:
    return bool(error and _LIMIT.search(error))


def limit_resets_at(error: str, now: datetime) -> datetime | None:
    """When the limit in this message lifts: the next time the clock reads
    what the message says. None if it names no UTC time."""
    m = _RESETS.search(error or "")
    if not m:
        return None
    hour, minute = int(m.group(1)) % 12, int(m.group(2) or 0)
    if m.group(3).lower() == "pm":
        hour += 12
    if hour > 23 or minute > 59:
        return None
    at = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return at if at > now else at + timedelta(days=1)


async def run_turn(*, system: str, prompt: str, allowed_tools: list[str],
                   max_turns: int = 4, model: str = DEFAULT_MODEL,
                   mcp: bool = True) -> TurnResult:
    """One bounded agent turn. Never raises - a specialist that fails is
    a gap in the day's narrative, not a failed run.

    A turn refused for a usage limit is tried again once the limit lifts,
    for as long as `limit_wait_hours` allows. A turn that fails any other
    way is returned as it is."""
    give_up = datetime.now(timezone.utc) + timedelta(hours=limit_wait_hours())
    while True:
        result = await _one_turn(system=system, prompt=prompt,
                                 allowed_tools=allowed_tools, max_turns=max_turns,
                                 model=model, mcp=mcp)
        if not is_usage_limit(result.error):
            return result
        now = datetime.now(timezone.utc)
        resets = limit_resets_at(result.error, now)
        retry_at = resets + RESET_MARGIN if resets else now + BLIND_WAIT
        if retry_at > give_up:
            # Said plainly, so the log shows a wait that was declined and
            # not one that was never considered.
            log.warning("usage limit; not waiting (next attempt %s is past the "
                        "%.1f h allowed)", f"{retry_at:%Y-%m-%d %H:%M} UTC",
                        limit_wait_hours())
            return result
        log.warning("usage limit; waiting until %s to try again",
                    f"{retry_at:%Y-%m-%d %H:%M} UTC")
        await asyncio.sleep((retry_at - now).total_seconds())


async def _one_turn(*, system: str, prompt: str, allowed_tools: list[str],
                    max_turns: int, model: str, mcp: bool) -> TurnResult:
    options = ClaudeAgentOptions(
        system_prompt=system,
        allowed_tools=[f"mcp__cti-tools__{t}" for t in allowed_tools],
        mcp_servers=mcp_config() if mcp else {},
        max_turns=max_turns,
        model=model,
        permission_mode="default",
    )

    chunks: list[str] = []
    tool_calls: list[str] = []
    usage: dict[str, Any] = {}
    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        chunks.append(block.text)
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block.name)
            elif isinstance(message, ResultMessage):
                usage = {"turns": getattr(message, "num_turns", None),
                         "cost_usd": getattr(message, "total_cost_usd", None),
                         "duration_ms": getattr(message, "duration_ms", None)}
    except Exception as e:                      # noqa: BLE001 - see docstring
        return TurnResult(text="", tool_calls=tool_calls, usage=usage,
                          error=f"{type(e).__name__}: {e}")

    return TurnResult(text="\n".join(chunks).strip(), tool_calls=tool_calls, usage=usage)


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_findings(text: str) -> tuple[list[dict[str, Any]], str | None]:
    """Pull the JSON array out of a reply.

    Models wrap JSON in a fence more often than not, and sometimes add a
    sentence either side. Rather than forbid that in the prompt and hope,
    accept both shapes. Returns (findings, error).
    """
    if not text:
        return [], None
    candidates = _FENCE.findall(text) or []
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])
    # A single finding sometimes comes back as a bare object rather than a
    # one-element array. That is a correct answer in the wrong shape, not a
    # failure, so try the whole reply too.
    candidates.append(text)

    for candidate in candidates:
        try:
            parsed = json.loads(candidate.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, list):
            return [p for p in parsed if isinstance(p, dict)], None
        if isinstance(parsed, dict):
            return [parsed], None
    return [], f"no JSON array in reply: {text[:200]!r}"
