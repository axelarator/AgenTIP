"""Running a Claude Agent SDK turn as a LangGraph node.

## Why the Agent SDK rather than ChatAnthropic

Two reasons, and the first is the decisive one.

**Auth.** The pipeline's only LLM call today is `claude -p`, which uses
the operator's Claude subscription. There is no ANTHROPIC_API_KEY in this
environment. A LangChain `ChatAnthropic` node would need one, and would
bill per token - which matters when the point of this change is to run
*more* model passes per day, in parallel.

**Tools.** The tool surface the specialists need already exists as an MCP
server with 33 tools, wired by .mcp.json, with the read-only subset
already allow-listed. The SDK speaks MCP natively, so a specialist gets
`query_duckdb` and `get_actor_summary` by naming them. Re-exposing them
as LangChain tools would mean a second definition of each to keep in sync.

The cost is that a node is an async subprocess turn rather than an
in-process call, so nodes are async and the graph is driven with
`ainvoke`. LangGraph runs async nodes concurrently on one event loop,
which is what the fan-out needs anyway.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_agent_sdk import (AssistantMessage, ClaudeAgentOptions, ResultMessage,
                              TextBlock, ToolUseBlock, query)

PROMPTS = Path(__file__).parent / "prompts"
REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MODEL = os.environ.get("CTI_GRAPH_MODEL", "claude-sonnet-5")


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
    if not with_common:
        return body
    return (PROMPTS / "_common.md").read_text() + "\n\n---\n\n" + body


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


async def run_turn(*, system: str, prompt: str, allowed_tools: list[str],
                   max_turns: int = 4, model: str = DEFAULT_MODEL,
                   mcp: bool = True) -> TurnResult:
    """One bounded agent turn. Never raises - a specialist that fails is
    a gap in the day's narrative, not a failed run."""
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
