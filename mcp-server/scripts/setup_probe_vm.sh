#!/usr/bin/env bash
# Bootstrap the lab probe VM (Debian/Ubuntu) for cti-agent: installs the
# tools probe_helper.py shells out to, installs the helper, and creates the
# SSH user whose key is pinned to it with a forced command. Idempotent.
#
# Run as root ON THE PROBE VM, with probe_helper.py beside this script:
#   sudo bash setup_probe_vm.sh --pubkey id_ed25519_probe.pub [--user detonate]
#
# Network placement (VPN egress, NIC on the mirrored bridge so Zeek/Arkime
# see its traffic, firewall blocking connections back to the cti host) is
# NOT done here - see "Probe VM build" in mcp-server/README.md.
set -euo pipefail

PROBE_USER=detonate            # matches vm_proxy.py's CTI_PROBE_USER default
PUBKEY=""
HELPER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probe_helper.py"
SUBFINDER_VERSION="${SUBFINDER_VERSION:-2.6.6}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --user)   PROBE_USER="$2"; shift 2 ;;
    --helper) HELPER_SRC="$2"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- validate everything before changing anything -------------------------
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "this script targets Debian/Ubuntu (apt)" >&2; exit 1; }
[[ -f "$HELPER_SRC" ]] || { echo "probe_helper.py not found at $HELPER_SRC (use --helper)" >&2; exit 1; }
[[ -f "$PUBKEY" ]] || { echo "--pubkey <file> required (the cti host's probe public key)" >&2; exit 1; }
KEY_LINE=$(grep -v '^[[:space:]]*#' "$PUBKEY" | grep -m1 . || true)
[[ $KEY_LINE == ssh-* || $KEY_LINE == ecdsa-* ]] \
  || { echo "$PUBKEY doesn't look like an OpenSSH public key" >&2; exit 1; }

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-certifi dnsutils openssl curl nmap \
  git unzip pipx openssh-server
systemctl enable --now ssh >/dev/null 2>&1 || true

echo "== subfinder"
if ! command -v subfinder >/dev/null; then
  if ! apt-get install -y -q subfinder >/dev/null 2>&1; then
    arch=$(dpkg --print-architecture)            # amd64 | arm64
    base="https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}"
    zip="subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/$zip" "$base/$zip"
    curl -fsSL -o "$tmp/sums" "$base/subfinder_${SUBFINDER_VERSION}_checksums.txt"
    (cd "$tmp" && grep " ${zip}\$" sums | sha256sum -c -)
    unzip -o -q "$tmp/$zip" subfinder -d /usr/local/bin
    chmod 0755 /usr/local/bin/subfinder
    rm -rf "$tmp"
  fi
fi

echo "== dirsearch"
if ! command -v dirsearch >/dev/null; then
  PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install dirsearch
fi

echo "== jarm (salesforce/jarm -> /opt/jarm, probe_helper.JARM_CMD)"
if [[ -d /opt/jarm/.git ]]; then
  git -C /opt/jarm pull -q --ff-only || echo "   (jarm update skipped)"
else
  git clone -q https://github.com/salesforce/jarm /opt/jarm
fi

echo "== helper -> /opt/cti/probe_helper.py"
# Root-owned so the probe user (whose key is forced to run it) can't edit it.
install -d -m 0755 -o root -g root /opt/cti
install -m 0755 -o root -g root "$HELPER_SRC" /opt/cti/probe_helper.py

echo "== user $PROBE_USER"
if ! id "$PROBE_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$PROBE_USER"
fi
usermod -p '*' "$PROBE_USER"                     # no password; key-only, not "locked"
home=$(getent passwd "$PROBE_USER" | cut -d: -f6)
install -d -m 0700 -o "$PROBE_USER" -g "$PROBE_USER" "$home/.ssh"
# Written from scratch, not appended: sshd uses the FIRST line matching a
# key, so a leftover unrestricted line for the same key would void the
# forced command. This user exists only for the probe key.
opts='command="python3 /opt/cti/probe_helper.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty'
printf '%s %s\n' "$opts" "$KEY_LINE" > "$home/.ssh/authorized_keys"
chown "$PROBE_USER:$PROBE_USER" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"

echo "== self-check (as $PROBE_USER)"
runuser -u "$PROBE_USER" -- python3 /opt/cti/probe_helper.py --check-access; echo
dirsearch --help >/dev/null 2>&1 || echo "WARNING: dirsearch is installed but won't run - check its Python deps"

ip=$(hostname -I | awk '{print $1}')
cat <<EOF

Done. On the cti host:
  1. Append this VM's host key to the CTI_PROBE_KNOWN_HOSTS file:
       $ip $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
  2. In ~/.bashrc (cron sources it):
       export CTI_PROBE_HOST=$ip
       export CTI_PROBE_USER=$PROBE_USER
       export CTI_PROBE_SSH_KEY=~/.ssh/id_ed25519_probe
       export CTI_PROBE_KNOWN_HOSTS=~/.ssh/known_hosts_probe
  3. Re-run ./setup.sh, restart the harness, then:
       mcp-server/.venv/bin/python mcp-server/scripts/probe_pending_fingerprints.py --check-access
EOF
