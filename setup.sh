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
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}"}
    },
    "honeylabs": {
      "type": "http",
      "url": "https://mcp.honeylabs.net/mcp",
      "headers": {"Authorization": "Bearer \${HONEYLABS_API_KEY}"}
    }
  }
}
EOF

# .pi/mcp.json is the same server, wired for MCP-capable Pi forks
# (oh-my-pi etc.) — keep it in sync with .mcp.json above so it doesn't
# go stale/lose the API-key passthroughs on a clone or move. The remote
# honeylabs server is deliberately NOT mirrored here: remote-HTTP MCP
# support in the Pi forks is unverified — add it once confirmed.
cat > "$ROOT/.pi/mcp.json" <<EOF
{
  "mcpServers": {
    "cti-tools": {
      "transport": "stdio",
      "command": "$ROOT/mcp-server/.venv/bin/python",
      "args": ["-m", "cti_tools.server"],
      "cwd": "$ROOT/mcp-server",
      "env": {"VT_API_KEY": "\${VT_API_KEY}",
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}"},
      "lifecycle": "lazy"
    }
  }
}
EOF

echo "Installed cti_tools into $ROOT/mcp-server/.venv"
echo "Wrote $ROOT/.mcp.json and $ROOT/.pi/mcp.json"
echo
echo "Sanity check:"
python -m cti_tools.cli list-clusters
echo
echo "Next: point your harness at skills/threat-cluster-tracking/ and,"
echo "for MCP-capable harnesses, at .mcp.json (or .pi/mcp.json for Pi)."
echo "See mcp-server/README.md."
