#!/usr/bin/env bash
# Copy the Windows-client runner to win116. Connection details come from the
# same environment win_proxy.py reads; nothing about the lab is in this file.
#
#   CTI_WIN_HOST, CTI_WIN_USER, CTI_WIN_SSH_KEY, CTI_WIN_KNOWN_HOSTS
#   CTI_WIN_RUNNER  (default C:\tools\cti\win_runner.ps1)
set -euo pipefail
: "${CTI_WIN_HOST:?set CTI_WIN_HOST}" "${CTI_WIN_USER:?set CTI_WIN_USER}"
KEY="${CTI_WIN_SSH_KEY:-$HOME/.ssh/id_ed25519_win_probe}"
KNOWN="${CTI_WIN_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_win_probe}"
RUNNER="${CTI_WIN_RUNNER:-C:\\tools\\cti\\win_runner.ps1}"
DIR="${RUNNER%\\*}"
SSH=(-i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$KNOWN")
HERE="$(cd "$(dirname "$0")" && pwd)"

ssh "${SSH[@]}" "$CTI_WIN_USER@$CTI_WIN_HOST" "if not exist \"$DIR\" mkdir \"$DIR\""
scp "${SSH[@]}" "$HERE/win_runner.ps1" "$CTI_WIN_USER@$CTI_WIN_HOST:${RUNNER//\\//}"
echo '{"action":"check"}' | ssh "${SSH[@]}" "$CTI_WIN_USER@$CTI_WIN_HOST" \
    "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"$RUNNER\""
echo
