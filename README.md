# cti-agent

Portable capabilities for cross-harness testing (Claude Code, GitHub
Copilot, Pi), split the way the harnesses expect:

```
skills/threat-cluster-tracking/SKILL.md   # procedural knowledge, portable as-is
.pi/skills/threat-cluster-tracking/       # same skill, mirrored for Pi's skill loader
mcp-server/                               # tools: core logic + MCP + CLI surfaces
  cti_tools/core.py                       # source of truth, no protocol code
  cti_tools/stix.py                       # STIX 2.1 bundle (de)serialization
  cti_tools/server.py                     # MCP surface (Claude Code, Copilot, Pi)
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

Optional API keys, passed through as env vars (missing keys degrade to
a skip note, never an error): `VT_API_KEY` (VirusTotal pivots) and
`HONEYLABS_API_KEY` (HoneyLabs honeypot telemetry — both the per-IP
pivot enrichment and the `honeylabs` remote MCP server that `.mcp.json`
wires up).

Then, per harness:

- **Claude Code** — native MCP support. `.mcp.json` and
  `.claude/skills/threat-cluster-tracking/` are both already wired by
  `setup.sh` (the latter is a mirror of `skills/threat-cluster-tracking/`,
  refreshed on every run).
- **GitHub Copilot** — native MCP support via `.mcp.json` (already
  wired by `setup.sh`); put `skills/threat-cluster-tracking/` wherever
  its own Agent Skills loader reads from.
- **Pi** — MCP support via the `pi-mcp-adapter` package
  (https://pi.dev/packages/pi-mcp-adapter), wired up through
  `.pi/mcp.json` (already written by `setup.sh`).
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
