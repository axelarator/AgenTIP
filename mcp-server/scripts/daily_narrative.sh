#!/usr/bin/env bash
# Stage B of the daily actor-tracking loop: one headless claude -p pass
# over the Stage A digest. Run from cron ~30min after daily_tracking.py
# (see setup.sh output). Exits 0 silently when there's nothing to do,
# so quiet days cost zero tokens.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

DAY="${1:-$(date +%F)}"
DIGEST="data/tracking/digests/${DAY}.md"
NARRATIVE_DIR="data/tracking/narratives"
PROMPT_TEMPLATE="mcp-server/scripts/stage_b_prompt.md"

[ -f "$DIGEST" ] || exit 0
grep -q '^NO ACTIVITY$' "$DIGEST" && exit 0

mkdir -p "$NARRATIVE_DIR"
claude -p "$(sed "s|{{DIGEST}}|$DIGEST|" "$PROMPT_TEMPLATE")" \
  --model claude-sonnet-5 \
  --allowedTools "Read,mcp__cti-tools__query_duckdb,mcp__cti-tools__save_correlation,mcp__cti-tools__get_actor_summary" \
  --max-turns 15 > "$NARRATIVE_DIR/${DAY}.md"

echo "narrative written: $NARRATIVE_DIR/${DAY}.md"
