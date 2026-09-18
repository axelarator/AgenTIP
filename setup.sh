#!/usr/bin/env bash
# One-shot setup: creates the venv, installs cti into it, and (re)writes
# .mcp.json with absolute paths for this checkout.
#
# MCP stdio configs generally need a real, resolvable command path — not
# every harness expands ${workspaceFolder}-style variables the same way
# (or at all), so this script bakes in absolute paths instead of hoping
# for the best. Re-run it any time you move or clone the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

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
      "command": "$ROOT/.venv/bin/python",
      "args": ["-m", "cti.mcp.server"],
      "cwd": "$ROOT",
      "env": {"WEBAMON_API_KEY": "\${WEBAMON_API_KEY}",
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}",
              "THREATFOX_API_KEY": "\${THREATFOX_API_KEY}",
              "CTI_PROBE_HOST": "\${CTI_PROBE_HOST}",
              "CTI_PROBE_USER": "\${CTI_PROBE_USER}",
              "CTI_PROBE_SSH_KEY": "\${CTI_PROBE_SSH_KEY}",
              "CTI_PROBE_KNOWN_HOSTS": "\${CTI_PROBE_KNOWN_HOSTS}",
              "CTI_PROBE_HELPER_CMD": "\${CTI_PROBE_HELPER_CMD}"}
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
      "command": "$ROOT/.venv/bin/python",
      "args": ["-m", "cti.mcp.server"],
      "cwd": "$ROOT",
      "env": {"WEBAMON_API_KEY": "\${WEBAMON_API_KEY}",
              "HONEYLABS_API_KEY": "\${HONEYLABS_API_KEY}",
              "THREATFOX_API_KEY": "\${THREATFOX_API_KEY}",
              "CTI_PROBE_HOST": "\${CTI_PROBE_HOST}",
              "CTI_PROBE_USER": "\${CTI_PROBE_USER}",
              "CTI_PROBE_SSH_KEY": "\${CTI_PROBE_SSH_KEY}",
              "CTI_PROBE_KNOWN_HOSTS": "\${CTI_PROBE_KNOWN_HOSTS}",
              "CTI_PROBE_HELPER_CMD": "\${CTI_PROBE_HELPER_CMD}"},
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
# distinction between a passive lookup and an active JARM/JA4/nmap/
# dirsearch probe via the lab probe VM is actually written down). Plain
# copy, not a symlink -
# same convention as .pi/skills/, and avoids relying on every harness
# following symlinks the same way.
# Both skills, not just one: actor-tracking was never mirrored here, so
# Claude Code loaded the cluster-tracking rules and never the time-series
# ones - the DuckDB layer's vocabulary, budgets and query discipline were
# reachable only through tool descriptions. The mirrors are generated and
# gitignored now; skills/ is the only copy under version control, because
# three committed copies drift.
for skill in "$ROOT"/skills/*/; do
    name=$(basename "$skill")
    for target in "$ROOT/.claude/skills" "$ROOT/.pi/skills"; do
        mkdir -p "$target/$name"
        cp "$skill/SKILL.md" "$target/$name/SKILL.md"
    done
done

echo "Installed cti + graph into $ROOT/.venv"
echo "Wrote $ROOT/.mcp.json and $ROOT/.pi/mcp.json"
echo "Mirrored every skills/*/ into .claude/skills/ (Claude Code) and .pi/skills/ (Pi)"
echo
echo "Sanity check:"
python -c "from cti import core; print(core.list_clusters())"
echo
echo "Next: point GitHub Copilot at skills/threat-cluster-tracking/ (wherever"
echo "its own Agent Skills loader reads from) and at .mcp.json."
echo "See docs/architecture.md."
echo
echo "Daily actor-tracking loop (skills/actor-tracking/): add to crontab -e:"
echo "  15 6 * * * cd $ROOT && .venv/bin/python -m graph collect >> data/tracking/logs/stage_a.log 2>&1"
echo "  45 6 * * * cd $ROOT && .venv/bin/python -m graph analyze >> data/tracking/logs/stage_b.log 2>&1"
echo "  (both default to today, so no date arithmetic in the crontab;"
echo "   one line for both: .venv/bin/python -m graph daily)"
echo "Secrets (env, e.g. in ~/.bashrc - never committed): WEBAMON_API_KEY,"
echo "  HONEYLABS_API_KEY, THREATFOX_API_KEY (optional)."
echo "Probe VM (env): CTI_PROBE_HOST/USER/SSH_KEY/KNOWN_HOSTS/HELPER_CMD"
echo "  (default helper: python3 /opt/cti/probe_helper.py on the Linux probe VM)."
echo "Tunables (env): CTI_DUCKDB_PATH (default data/tracking/tracking.duckdb),"
echo "  CTI_HL_BUDGET (HoneyLabs lookups/day, default 400),"
echo "  CTI_WEBAMON_DAILY_BUDGET (default 1000), CTI_WEBAMON_RESCAN_DAYS (default 7)."
echo "One-time seed from the cluster store:"
echo "  .venv/bin/python scripts/daily_tracking.py --seed"
echo
echo "Pipeline diagrams (regenerate after changing the graph):"
echo "  .venv/bin/python -m graph draw"
echo "Per-run node timings:"
echo "  .venv/bin/python -m graph trace --date YYYY-MM-DD"
