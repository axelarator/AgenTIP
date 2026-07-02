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
      "env": {}
    }
  }
}
EOF

echo "Installed cti_tools into $ROOT/mcp-server/.venv"
echo "Wrote $ROOT/.mcp.json"
echo
echo "Sanity check:"
python -m cti_tools.cli list-clusters
echo
echo "Next: point your harness at skills/threat-cluster-tracking/ and,"
echo "for MCP-capable harnesses, at .mcp.json. See mcp-server/README.md."
