# cti-agent

Portable capabilities for cross-harness testing (Claude Code, GitHub
Copilot, Pi), split the way the harnesses expect:

```
skills/threat-cluster-tracking/SKILL.md   # procedural knowledge, portable as-is
.pi/skills/threat-cluster-tracking/       # same skill, mirrored for Pi's skill loader
mcp-server/                               # tools: core logic + MCP + CLI surfaces
  cti_tools/core.py                       # source of truth, no protocol code
  cti_tools/stix.py                       # STIX 2.1 bundle (de)serialization
  cti_tools/server.py                     # MCP surface (Claude Code, Copilot)
  cti_tools/cli.py                        # CLI surface (Pi via Bash, or any harness)
  tests/                                  # pytest against core.py
data/clusters/                            # local JSON + generated markdown, gitignored
setup.sh                                  # creates the venv, wires .mcp.json
```

## Quick start

```bash
./setup.sh
```

This creates `mcp-server/.venv`, installs `cti_tools` into it, and
rewrites `.mcp.json` with absolute paths for your checkout (MCP stdio
configs need real paths — see `mcp-server/README.md` for why
`${workspaceFolder}`-style variables aren't relied on here). Re-run it
after cloning to a new machine or moving the repo.

Then, per harness:

- **Claude Code / GitHub Copilot** — native MCP support. `.mcp.json` is
  already wired by `setup.sh`; put `skills/threat-cluster-tracking/`
  wherever your harness reads Agent Skills from (Claude Code:
  `.claude/skills/`).
- **Pi** — no built-in MCP client in the core loop, so the skill drives
  `cti_tools/cli.py` through the Bash tool instead.
  `.pi/skills/threat-cluster-tracking/` is already in place.

See `mcp-server/README.md` for full install/wiring details, provider
notes (Ollama / Anthropic subscription), and how clustering maps onto
STIX 2.1 for sharing outside this tool.

## Threat cluster tracking, briefly

Each cluster is a Diamond-Model-shaped JSON record (adversary,
capability, infrastructure, victim) plus STIX-flavored profile fields
(aliases, confidence, first/last seen), an ATT&CK TTP coverage table, a
detection inventory, a gaps backlog, and an append-only hunt log. A
markdown view is regenerated alongside the JSON on every write — don't
hand-edit the `.md`, it's derived.

Clusters export as STIX 2.1 bundles (Intrusion Set + Attack Pattern +
Relationship + Note) and can ingest bundles from other tools, so a
cluster tracked here is portable to any STIX-consuming platform without
a bespoke converter.

Clusters can also be populated directly from a threat report (URL or
local file): `ingest_report` extracts hashes/domains/IPs/URLs/TTPs and
files them into an existing or new cluster (inferring the cluster name
from the report text when not given explicitly), and `get_observables`
lists everything gathered for a cluster so far. See
`mcp-server/README.md` for the extraction/attribution caveats.
