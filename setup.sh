#!/usr/bin/env bash
# One-shot setup: creates the mcp-server venv, installs cti_tools into it,
# and (re)writes .mcp.json with absolute paths for this checkout.
#
# MCP stdio configs generally need a real, resolvable command path — not
# every harness expands ${workspaceFolder}-style variables the same way
# (or at all), so this script bakes in absolute paths instead of hoping
# for the best. Re-run it any time you move or clone the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/mcp-server"

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -e '.[test]'

cat > "$ROOT/.mcp.json" <<EOF
{
  "mcpServers": {
    "cti-tools": {
      "type": "stdio",
      "command": "$ROOT/mcp-server/.venv/bin/python",
      "args": ["-m", "cti_tools.server"],
      "cwd": "$ROOT/mcp-server",
      "env": {"VT_API_KEY": "\${VT_API_KEY}",
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}",
              "THREATFOX_API_KEY": "\${THREATFOX_API_KEY}"}
    },
    "honeylabs": {
      "type": "http",
      "url": "https://mcp.honeylabs.net/mcp",
      "headers": {"Authorization": "Bearer \${HONEYLABS_API_KEY}"}
    }
  }
}
EOF

# .pi/mcp.json is the same server, wired for Pi's pi-mcp-adapter
# package (https://pi.dev/packages/pi-mcp-adapter), which gives Pi a
# native MCP client — keep it in sync with .mcp.json above so it
# doesn't go stale/lose the API-key passthroughs on a clone or move.
# (In practice pi-mcp-adapter also reads .mcp.json directly, so the
# remote honeylabs server there is picked up without needing to be
# mirrored here — this file just keeps stdio config explicit for Pi.)
cat > "$ROOT/.pi/mcp.json" <<EOF
{
  "mcpServers": {
    "cti-tools": {
      "transport": "stdio",
      "command": "$ROOT/mcp-server/.venv/bin/python",
      "args": ["-m", "cti_tools.server"],
      "cwd": "$ROOT/mcp-server",
      "env": {"VT_API_KEY": "\${VT_API_KEY}",
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}",
              "THREATFOX_API_KEY": "\${THREATFOX_API_KEY}"},
      "lifecycle": "lazy"
    }
  }
}
EOF

mkdir -p "$ROOT"/data/tracking/{inbox,archive,digests,narratives,logs}
touch "$ROOT"/data/tracking/.gitkeep

# Claude Code reads Agent Skills from .claude/skills/ - mirror the
# canonical copy there the same way .pi/skills/ already mirrors it for
# Pi, so a fresh clone doesn't silently run without the skill (in
# particular, its "pivoting vs. probing" section - the one place the
# distinction between a passive lookup and an active JARM/JA4 probe via
# the Win11 VM is actually written down). Plain copy, not a symlink -
# same convention as .pi/skills/, and avoids relying on every harness
# following symlinks the same way.
mkdir -p "$ROOT"/.claude/skills/threat-cluster-tracking
cp "$ROOT"/skills/threat-cluster-tracking/SKILL.md "$ROOT"/.claude/skills/threat-cluster-tracking/SKILL.md

echo "Installed cti_tools into $ROOT/mcp-server/.venv"
echo "Wrote $ROOT/.mcp.json and $ROOT/.pi/mcp.json"
echo "Mirrored skills/threat-cluster-tracking/ into .claude/skills/ (Claude Code) and .pi/skills/ (Pi)"
echo
echo "Sanity check:"
python -c "from cti_tools import core; print(core.list_clusters())"
echo
echo "Next: point GitHub Copilot at skills/threat-cluster-tracking/ (wherever"
echo "its own Agent Skills loader reads from) and at .mcp.json."
echo "See mcp-server/README.md."
echo
echo "Daily actor-tracking loop (skills/actor-tracking/): add to crontab -e:"
echo "  15 6 * * * cd $ROOT && mcp-server/.venv/bin/python mcp-server/scripts/daily_tracking.py >> data/tracking/logs/stage_a.log 2>&1"
echo "  45 6 * * * cd $ROOT && bash mcp-server/scripts/daily_narrative.sh >> data/tracking/logs/stage_b.log 2>&1"
echo "Tunables (env): CTI_DUCKDB_PATH (default data/tracking/tracking.duckdb),"
echo "  CTI_HL_BUDGET (HoneyLabs lookups/day, default 400)."
echo "One-time seed from the cluster store:"
echo "  mcp-server/.venv/bin/python mcp-server/scripts/daily_tracking.py --seed"
