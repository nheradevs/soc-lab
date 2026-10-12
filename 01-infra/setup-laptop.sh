#!/usr/bin/env bash
# Bootstrap Machine A (soc-lab, always-on server) on a fresh Ubuntu 24.04 install.
# Usage: sudo bash 01-infra/setup-laptop.sh
set -euo pipefail

echo "=== 1. Sanity checks ==="
# Root and the exact target release are required before any mutation.
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: run as root: sudo bash $0" >&2
  exit 1
fi
. /etc/os-release
if [ "$ID" != "ubuntu" ] || [ "$VERSION_ID" != "24.04" ]; then
  echo "WARNING: targets Ubuntu 24.04 but detected '$ID $VERSION_ID', aborting." >&2
  exit 1
fi
if [ -d /opt/wazuh-docker ]; then
  echo "already provisioned, nothing to do"
  exit 0
fi

echo "=== 2. RAM profile ==="
MEM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
MEM_GB=$((MEM_KB / 1048576))
if [ "$MEM_GB" -ge 15 ]; then
  PROFILE=full
else
  PROFILE=slim
fi
echo "Detected RAM: ${MEM_GB} GB (${MEM_KB} KB)"
echo "Profile: ${PROFILE} (full adds Grafana + Prometheus + node_exporter)"

echo "=== 3. Always-on: no sleep/suspend, lid ignored ==="
# The machine is an always-on server; it must survive lid close and unplug.
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
sed -i 's/#HandleLidSwitch=ignore/HandleLidSwitch=ignore/' /etc/systemd/logind.conf
systemctl restart systemd-logind
powerprofilesctl set performance || true

echo "=== 4. Swap: 6 GB file (headroom for OpenSearch) ==="
SWAP_ACTIVE=$(swapon --show=NAME 2>/dev/null || true)
if printf '%s\n' "$SWAP_ACTIVE" | grep -qx '/swapfile'; then
  echo "/swapfile already active, skipping."
else
  fallocate -l 6G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  # Guard the fstab append so re-runs never duplicate the entry.
  if ! grep -q '^/swapfile[[:space:]]' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
fi

echo "=== 5. sysctl: vm.max_map_count for the Wazuh indexer/OpenSearch ==="
# OpenSearch refuses to start with the kernel default of 65530.
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-wazuh.conf
sysctl --system

echo "=== 6. Packages ==="
apt-get update && apt-get -y upgrade
apt-get install -y docker.io docker-compose-v2 git htop ufw openssh-server

echo "=== 7. Firewall: SSH + tailscale0 only ==="
ufw allow OpenSSH
# tailscale0 may not exist yet; it appears after 'tailscale up'.
ufw allow in on tailscale0 || true
ufw --force enable

echo "=== 8. Tailscale via apt repo (no blind curl|sh as root - AGENTS.md §2.5) ==="
if ! command -v tailscale >/dev/null 2>&1; then
  CODENAME=$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:?unsupported release}")
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${CODENAME}.noarmor.gpg" -o /tmp/tailscale.gpg
  echo "Signing key fingerprints (compare against https://tailscale.com/kb/1312/keys):"
  gpg --show-keys --with-colons /tmp/tailscale.gpg | awk -F: '/^fpr:/{print "  " $10}'
  read -r -p "Fingerprints match the published Tailscale signing key? [y/N] " REPLY
  if [ "$REPLY" != "y" ]; then
    echo "ABORT: unverified signing key." >&2
    rm -f /tmp/tailscale.gpg
    exit 1
  fi
  install -m 0644 /tmp/tailscale.gpg /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${CODENAME}.tailscale-keyring.list" -o /etc/apt/sources.list.d/tailscale.list
  apt-get update
  apt-get install -y tailscale
  rm -f /tmp/tailscale.gpg
fi
echo "NEXT (manual): run 'tailscale up' on this machine."

echo "=== 9. Wazuh single-node: indexer + manager + dashboard ==="
# Pinned to the stack version (AGENTS.md §4): never a floating HEAD clone.
git clone --branch v4.14.7 --depth 1 https://github.com/wazuh/wazuh-docker /opt/wazuh-docker
cd /opt/wazuh-docker/wazuh-docker
docker compose -f single-node.yaml --env-file .env.local up -d

echo "Polling OpenSearch cluster health (up to 12 minutes; first boot is slow)..."
HEALTH=""
for ((i = 1; i <= 36; i++)); do
  sleep 20
  HEALTH=$(curl -sk https://localhost:9200/_cluster/health 2>/dev/null || true)
  if printf '%s' "$HEALTH" | grep -Eq '"status":"(green|yellow)"'; then
    echo "Cluster is up after attempt ${i}/36."
    break
  fi
  echo "  attempt ${i}/36: not green/yellow yet."
done
if ! printf '%s' "$HEALTH" | grep -Eq '"status":"(green|yellow)"'; then
  # First boot can be slow: warn instead of failing so the rest of the setup is visible.
  echo "WARNING: cluster not green/yellow after 12 minutes. Last health output:"
  printf '%s\n' "$HEALTH"
  echo "Inspect with: docker compose -f single-node.yaml logs indexer"
fi

echo "=== 10. Observability: canonical loopback-only stack ==="
if [ "$PROFILE" = "full" ]; then
  # Single source of truth: copy the hardened stack versioned in this repo.
  # The old inline compose bound 3000/9090/9100 to 0.0.0.0 (Docker's iptables
  # bypass UFW) and left Grafana on its default admin credential. Never rebuild
  # a second variant inline.
  SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  MONITORING_SRC="$SCRIPT_DIR/../05-visualizacion/monitoring"
  if [ ! -d "$MONITORING_SRC" ]; then
    echo "ERROR: $MONITORING_SRC not found; run this script from a repo checkout." >&2
    exit 1
  fi
  mkdir -p /opt/soc-lab
  cp -a "$MONITORING_SRC" /opt/soc-lab/monitoring
  cd /opt/soc-lab/monitoring
  # Secrets are generated straight into the 0600 file, never echoed (AGENTS.md §2.1).
  if [ ! -f .env ]; then
    umask 077
    {
      printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 16)"
      printf 'TELEGRAM_BOT_TOKEN=<PASTE-from-BotFather>\n'
      printf 'TELEGRAM_CHAT_ID=<PASTE>\n'
      printf 'DRY_RUN=true\n'
    } > .env
    echo "Created /opt/soc-lab/monitoring/.env (mode 0600) with a generated Grafana admin password."
    echo "Paste the Telegram values there, then flip DRY_RUN=false to enable real sends."
  fi
  docker compose up -d
  echo "All monitoring ports bind 127.0.0.1 only. Access Grafana via tunnel:"
  echo "  ssh -N -L 3000:localhost:3000 <this-host>"
  echo "Grafana admin password: in /opt/soc-lab/monitoring/.env (not printed anywhere)."
  echo "OpenSearch datasource: https://localhost:9200 (self-signed: pin the indexer CA), pattern 'wazuh-*'."
else
  echo "Profile 'slim': Grafana/Prometheus skipped to protect RAM."
  echo "The Wazuh dashboard is the console for now."
fi

echo "=== 11. Summary ==="
HOST_IP=$(hostname -I | awk '{print $1}')
[ -n "$HOST_IP" ] || HOST_IP=$(hostname)
echo "Wazuh dashboard: https://${HOST_IP}"
echo "Dashboard credentials live in /opt/wazuh-docker/wazuh-docker/.env.local. Change the password."
echo "Profile in use: ${PROFILE}"
echo "Next manual steps:"
echo "  1) tailscale up   (on this laptop)"
echo "  2) run 01-infra/setup-vps.sh on the GCP VPS (after 'tailscale up' there)"
