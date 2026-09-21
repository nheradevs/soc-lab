#!/usr/bin/env bash
# Bootstrap Machine B (GCP honeypot) on a fresh Ubuntu 22.04/24.04.
# Usage: fill the config block, then sudo bash 01-infra/setup-vps.sh
set -euo pipefail

# --- Configuration: fill all three before running ------------------------------
WAZUH_MANAGER_IP=""    # Tailscale IP of Machine A, from 'tailscale ip -4' on the always-on server.
WAZUH_AUTH_PASSWORD="" # Wazuh agent enrollment password, from Machine A's /opt/wazuh-docker/wazuh-docker/.env.local.
HOME_IP=""             # Your home public IP, used to block self from hitting the honeypot.

echo "=== 1. Sanity and configuration check ==="
# Never run half-configured: every value is required before any mutation happens.
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: run as root: sudo bash $0" >&2
  exit 1
fi
MISSING=()
[ -n "$WAZUH_MANAGER_IP" ] || MISSING+=("WAZUH_MANAGER_IP: Tailscale IP of Machine A, from 'tailscale ip -4' on the always-on server")
[ -n "$WAZUH_AUTH_PASSWORD" ] || MISSING+=("WAZUH_AUTH_PASSWORD: Wazuh agent enrollment password, from Machine A's /opt/wazuh-docker/wazuh-docker/.env.local")
[ -n "$HOME_IP" ] || MISSING+=("HOME_IP: your home public IP, used to keep your own scans off the honeypot")
if [ "${#MISSING[@]}" -gt 0 ]; then
  echo "ERROR: missing configuration:" >&2
  for m in "${MISSING[@]}"; do
    echo "  - $m" >&2
  done
  echo "Edit the config block at the top of this script and re-run." >&2
  exit 1
fi

echo "=== 2. Move real SSH to 2222 ==="
# sshd honors the first uncommented Port directive, so replace instead of append.
if grep -Eq '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config; then
  sed -i -E 's/^[[:space:]]*Port[[:space:]].*/Port 2222/' /etc/ssh/sshd_config
else
  echo 'Port 2222' >> /etc/ssh/sshd_config
fi
# Validate the config before restarting so a typo cannot lock us out.
sshd -t
echo "WARNING: SSH moves to port 2222 on the next line. Reconnect with 'ssh -p 2222 user@host' before closing this session. The restart will drop this one."
systemctl restart ssh

echo "=== 3. ufw: default deny, honeypot ports open to the world ==="
ufw default deny incoming
ufw default allow outgoing
# ufw is first-match-wins: the self-deny must be added before the per-port allows.
ufw deny from "$HOME_IP" to any port 22,23,80,445,3389,3306
# Fake honeypot services: these SHOULD be reachable by the world.
ufw allow 22/tcp
ufw allow 23/tcp
ufw allow 80/tcp
ufw allow 445/tcp
ufw allow 3389/tcp
ufw allow 3306/tcp
# Management SSH: restrict to the operator IP only (defense in depth; also
# restrict it in the GCP VPC firewall). If your public IP is dynamic, keep 2222
# reachable via Tailscale instead of widening this, or you will lock yourself out.
ufw allow from "$HOME_IP" to any port 2222
# NEVER allow the Wazuh ports (9200/55000/11300/1514/1515) here, tailnet-only by design.
ufw --force enable

echo "=== 4. (fail2ban intentionally omitted) ==="
# No fail2ban on a honeypot: its job is to LOG attacker behaviour, not to ban
# it. Worse, its iptables/nftables ban rules conflict with ufw and broke access
# in the lab (ufw default-deny + fail2ban = every port dropped). The management
# SSH on 2222 is protected instead by the ufw allow above (operator IP only).

echo "=== 5. Docker + Tailscale (install only; 'up' is interactive) ==="
apt-get update
apt-get install -y docker.io docker-compose-v2 git
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi
echo "NEXT (manual): run 'tailscale up' on this VPS, same tailnet as the always-on server."

echo "=== 6. Cowrie honeypot ==="
mkdir -p /opt/honeypot/cowrie
# Canonical compose file, also kept at 02-honeypot/docker-compose.yaml in this repo.
cat > /opt/honeypot/cowrie/docker-compose.yaml <<'EOF'
# Cowrie honeypot: low-interaction SSH and Telnet trap.
# Ports here are INTENTIONALLY exposed to the internet: that is the product.
# The image serves SSH on 2222 and Telnet on 2223 internally, so the
# mappings publish them on the standard ports 22 and 23.
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: always
    ports:
      - "22:2222"
      - "23:2223"
    volumes:
      - cowrie-data:/cowrie/cowrie-git/var:z
volumes:
  cowrie-data:
EOF
cd /opt/honeypot/cowrie
docker compose up -d
echo "Fake SSH and Telnet are live on 22/23."
echo "Logs land in the 'cowrie-data' docker volume at log/cowrie/cowrie.json."

echo "=== 7. Manual next steps ==="
cat <<EOF
1) Run 'tailscale up' on this VPS and on the always-on server (same tailnet).
2) Install the Wazuh agent (adjust 4.14 to the Wazuh version in use):
   curl -sO https://packages.wazuh.com/4.14/wazuh-agent/latest/wazuh-agent.deb \\
     && dpkg -i ./wazuh-agent.deb \\
     && /var/ossec/bin/agent-authd -t $WAZUH_MANAGER_IP -p $WAZUH_AUTH_PASSWORD -A honeypot-vps
 3) Once the agent is active, add a localfile to the agent config pointing at the
    Cowrie JSON log in the 'cowrie-data' docker volume
    (/var/lib/docker/volumes/cowrie-data/_data/log/cowrie/cowrie.json) and check the
    built-in Wazuh Cowrie decoders; if the event format does not match, author a
   custom decoder + rule in 03-siem/rules (that becomes 04-detecciones material).
4) Plant canarytokens (canarytokens.org, manual): a fake AWS credentials file and
   a fake credential doc reachable by the honeypot, alerts to email.
EOF
