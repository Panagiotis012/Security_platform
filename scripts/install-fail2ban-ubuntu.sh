#!/usr/bin/env bash
set -euo pipefail

# Install and configure fail2ban on Ubuntu for:
#  - sshd brute force protection
#  - basic nginx abuse protection (botsearch + auth)
#
# Usage (on the VM):
#   sudo bash scripts/install-fail2ban-ubuntu.sh
#
# Optional env:
#   NGINX_ACCESS_LOG=/var/log/nginx/access.log
#   IGNORE_IPS="127.0.0.1/8 ::1 203.0.113.4"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: This script is for Linux hosts only." >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root (use sudo)." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: This script expects apt-get (Ubuntu/Debian)." >&2
  exit 1
fi

echo "==> Installing fail2ban..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban

NGINX_ACCESS_LOG="${NGINX_ACCESS_LOG:-/var/log/nginx/access.log}"
if [[ ! -f "$NGINX_ACCESS_LOG" ]]; then
  # Best-effort discovery
  found="$(ls -1 /var/log/nginx/*access*.log 2>/dev/null | head -n 1 || true)"
  if [[ -n "${found//[[:space:]]/}" ]]; then
    NGINX_ACCESS_LOG="$found"
  fi
fi

IGNORE_IPS="${IGNORE_IPS:-127.0.0.1/8 ::1}"

echo "==> Writing jail config..."
mkdir -p /etc/fail2ban/jail.d
cat >/etc/fail2ban/jail.d/security-platform.conf <<EOF
[DEFAULT]
backend = systemd
banaction = ufw
ignoreip = ${IGNORE_IPS}
findtime = 10m
bantime = 1h
maxretry = 6

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
port = http,https
logpath = ${NGINX_ACCESS_LOG}
maxretry = 3

[nginx-botsearch]
enabled = true
port = http,https
logpath = ${NGINX_ACCESS_LOG}
maxretry = 2

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 7d
findtime = 1d
maxretry = 5
EOF

echo "==> Enabling + restarting fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban

echo ""
echo "==> fail2ban status:"
for _ in $(seq 1 10); do
  if fail2ban-client ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
fail2ban-client status || true
