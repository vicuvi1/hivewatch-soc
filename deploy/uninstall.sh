#!/usr/bin/env bash
# Stop HiveWatch and give port 22 back to the real sshd.
#   sudo bash deploy/uninstall.sh            keep captured data
#   sudo bash deploy/uninstall.sh --purge    also delete the data volume
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash deploy/uninstall.sh" >&2; exit 1; }
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--purge" ]]; then
  docker compose down -v
else
  docker compose down
fi

# Real sshd listens on 22 AND the admin port again, so no session is lost.
ADMIN_PORT="$(grep -oP '^Port \K\d+' /etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf 2>/dev/null || echo 22222)"
cat > /etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf <<EOF
Port 22
Port ${ADMIN_PORT}
EOF
if [[ -f /etc/systemd/system/ssh.socket.d/hivewatch.conf ]]; then
  rm /etc/systemd/system/ssh.socket.d/hivewatch.conf
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
sshd -t && { systemctl restart ssh 2>/dev/null || systemctl restart sshd; }

echo "HiveWatch stopped. sshd listens on 22 and ${ADMIN_PORT} again."
echo "Once you have confirmed 'ssh -p 22' works, you may delete"
echo "/etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf to drop port ${ADMIN_PORT}."
