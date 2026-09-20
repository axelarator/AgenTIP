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
# Pi, so a fresh clone doesn't silently run without the skills. Plain
# copy, not a symlink - same convention as .pi/skills/, and avoids
# relying on every harness following symlinks the same way.
#
# Every skills/*/, not a hand-listed set: actor-tracking was never
# mirrored here, so Claude Code loaded the cluster-tracking rules and
# never the time-series ones - the DuckDB layer's vocabulary, budgets and
# query discipline were reachable only through tool descriptions. The
# mirrors are generated and gitignored; skills/ is the only copy under
# version control, because three committed copies drift.
#
# The mirrors are rebuilt from scratch rather than copied over. Copying
# into an existing directory only ever ADDS, so a skill that was renamed
# or split left its old copy behind and every harness kept loading it -
# which is exactly what happened when threat-cluster-tracking became
# cluster-bookkeeping and infrastructure-pivoting.
for target in "$ROOT/.claude/skills" "$ROOT/.pi/skills"; do
    rm -rf "$target"
    mkdir -p "$target"
done
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
echo "Next: point GitHub Copilot at skills/cluster-bookkeeping/ (wherever"
echo "its own Agent Skills loader reads from) and at .mcp.json."
echo "See docs/architecture.md."
echo
echo "Daily actor-tracking loop (skills/actor-tracking/): add to crontab -e:"
# The `. $HOME/.bashrc &&` prefix is not optional. Every API key and every
# CTI_PROBE_* setting lives in ~/.bashrc, and cron starts with an empty
# environment. An earlier version of these lines left it off; the first
# scheduled run then went to a default probe address that is not this lab's
# VM, collected nothing, and overwrote cluster statuses with "unknown".
#
# ONE line, not two. Collect and analyze were separate jobs half an hour
# apart, which is a guess about how long collect takes: on 2026-09-20 it
# took 21 minutes with an EMPTY enrich worklist, and it has since grown a
# corroborate stage. When it overruns, analyze exits with "no digest for
# <today>" and the day's analysis is simply lost. `daily` starts analyze
# when collect finishes.
echo "  15 6 * * * . \$HOME/.bashrc && cd $ROOT && .venv/bin/python -m graph daily >> data/tracking/logs/daily.log 2>&1"
echo "  (defaults to today. The stages can still be run separately by hand:"
echo "   -m graph collect, then -m graph analyze.)"
echo "  Verify cron's view of the environment before trusting it:"
echo "    env -i HOME=\$HOME SHELL=/bin/bash PATH=/usr/bin:/bin bash -c '. \$HOME/.bashrc; echo \$CTI_PROBE_HOST'"
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
