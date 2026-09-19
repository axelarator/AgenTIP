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
SANDBOX_SRC="${SANDBOX_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandbox}"
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

echo "== observation tools (ProjectDiscovery + whois)"
# These are what the `observe` action runs. All are single static binaries or
# apt packages, all free, none needs an API key - which is the point: capture
# as much as possible with CLI tools before reaching for a vendor API.
#
# httpx alone replaces several hand-rolled probes and adds two things this
# pipeline never had: a response-body SHA-256 (the rotation-proof link) and a
# favicon mmh3 hash. tlsx adds the certificate serial and SPKI digest. whois
# parses the registrar and registrant fields RDAP buries in vcardArray.
apt-get install -y -q whois || echo "   WARNING: whois unavailable from apt"

PD_TOOLS="httpx tlsx dnsx naabu cdncheck asnmap"
if command -v go >/dev/null 2>&1; then
  for tool in $PD_TOOLS; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "   $tool already present"
      continue
    fi
    echo "   installing $tool"
    GOBIN=/usr/local/bin go install -v \
      "github.com/projectdiscovery/$tool/cmd/$tool@latest" >/dev/null 2>&1 \
      || echo "   WARNING: $tool failed to install"
  done
else
  echo "   WARNING: go not installed - skipping $PD_TOOLS"
  echo "   install golang-go, or drop the binaries into /usr/local/bin by hand."
  echo "   The observe action degrades to what is present and reports the rest."
fi

# naabu needs raw sockets for SYN scanning; without the capability it falls
# back to connect() scans, which work but are slower and noisier.
if command -v naabu >/dev/null 2>&1; then
  setcap cap_net_raw+eip "$(command -v naabu)" 2>/dev/null \
    || echo "   note: naabu lacks cap_net_raw, will use connect() scans"
fi

echo "== docker + the analysis sandbox image"
# The sandbox runs HERE, on the probe VM, not on the cti host. This VM
# already did the download that found the open directory and already has
# the network position we are willing to point at adversary
# infrastructure; shipping samples back to analyze them would undo that.
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y -q docker.io
fi
systemctl enable --now docker >/dev/null 2>&1 || true

if [[ -d "$SANDBOX_SRC" ]]; then
  docker build -q -t cti-sbx:latest "$SANDBOX_SRC" >/dev/null
  echo "   built cti-sbx:latest"
  # Prove the isolation flags actually isolate. A sandbox that can reach
  # the network is not a sandbox, and the failure would be silent.
  if docker run --rm --network=none --cap-drop=ALL \
       --security-opt=no-new-privileges --entrypoint python cti-sbx:latest \
       -c "import socket; socket.create_connection(('1.1.1.1',53),2)" 2>/dev/null; then
    echo "   ERROR: the sandbox container reached the network with --network=none" >&2
    exit 1
  fi
  echo "   verified: --network=none blocks egress"
else
  echo "   WARNING: $SANDBOX_SRC not found - copy sandbox/ next to this script"
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
# Needed for fetch_and_analyze. Note this is effectively root-equivalent on
# this VM - which is why the probe VM is disposable, isolated on its own
# VLAN, and unable to initiate a connection back to the cti host.
getent group docker >/dev/null && usermod -aG docker "$PROBE_USER"
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
runuser -u "$PROBE_USER" -- docker info >/dev/null 2>&1 \
  || echo "WARNING: $PROBE_USER cannot run docker - fetch_and_analyze will fail"

# Report the observe toolchain explicitly. A half-provisioned VM that silently
# collects less is worse than one that says what is missing.
echo "   observe toolchain:"
for tool in httpx tlsx dnsx naabu cdncheck whois; do
  if runuser -u "$PROBE_USER" -- command -v "$tool" >/dev/null 2>&1; then
    printf "     %-10s ok\n" "$tool"
  else
    printf "     %-10s MISSING - observe will skip it and say so\n" "$tool"
  fi
done

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
       .venv/bin/python scripts/probe_pending_fingerprints.py --check-access
EOF
