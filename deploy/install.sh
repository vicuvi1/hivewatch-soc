#!/usr/bin/env bash
# HiveWatch SOC — one-command installer for a fresh Ubuntu/Debian VPS.
#
#   curl -fsSLO https://raw.githubusercontent.com/vicuvi1/hivewatch-soc/main/deploy/install.sh
#   less install.sh          # always read a script before running it as root
#   sudo bash install.sh
#
# What it does (safely, in this order):
#   1. installs Docker + git + a firewall
#   2. adds your REAL sshd on port 22222 *alongside* 22
#   3. asks you to prove you can log in on 22222 from a second terminal
#   4. only then frees port 22 and starts the honeypot on it
#   5. prints how to open the (private) dashboard through an SSH tunnel
set -euo pipefail

REPO_URL="${HW_REPO_URL:-https://github.com/vicuvi1/hivewatch-soc.git}"
INSTALL_DIR="${HW_INSTALL_DIR:-/opt/hivewatch-soc}"
ADMIN_SSH_PORT="${HW_ADMIN_SSH_PORT:-22222}"
HONEYPOT_PORTS=(22 23 80 3389 5900 3306 6379 9200)

c_cyan=$'\e[36m'; c_green=$'\e[32m'; c_yellow=$'\e[33m'; c_red=$'\e[31m'; c_off=$'\e[0m'
step() { echo; echo "${c_cyan}==> $*${c_off}"; }
ok()   { echo "${c_green}  ✓ $*${c_off}"; }
warn() { echo "${c_yellow}  ! $*${c_off}"; }
die()  { echo "${c_red}  ✗ $*${c_off}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root:  sudo bash install.sh"
command -v apt-get >/dev/null || die "this installer supports Ubuntu/Debian (apt) only"

# --------------------------------------------------------------------------- 1. packages
step "Installing Docker, git and firewall tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl openssl ca-certificates >/dev/null
if ! command -v docker >/dev/null; then
  apt-get install -y -qq docker.io >/dev/null
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 \
    || apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 \
    || die "could not install the docker compose plugin"
fi
systemctl enable --now docker >/dev/null
ok "docker $(docker --version | awk '{print $3}' | tr -d ,) / $(docker compose version --short)"

# --------------------------------------------------------------------------- 2. firewall
open_port() {
  local port=$1
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${port}/tcp" >/dev/null
  fi
  # Oracle Cloud & some images ship a default-deny iptables INPUT chain
  if iptables -S INPUT 2>/dev/null | grep -qE -- "-j (REJECT|DROP)"; then
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
  fi
}
step "Opening firewall ports (admin SSH ${ADMIN_SSH_PORT} + honeypot ports)"
open_port "$ADMIN_SSH_PORT"
for p in "${HONEYPOT_PORTS[@]}"; do open_port "$p"; done
if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi
ok "host firewall updated"
warn "Cloud firewalls are separate! Also allow TCP ${ADMIN_SSH_PORT},$(IFS=,; echo "${HONEYPOT_PORTS[*]}") in your"
warn "provider's panel (Oracle: VCN Security List · AWS: Security Group · Hetzner: Firewall)."

# --------------------------------------------------------------------------- 3. move real sshd
step "Adding your real SSH on port ${ADMIN_SSH_PORT} (port 22 stays open for now)"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf <<EOF
# Added by HiveWatch: real admin SSH. Port 22 is handed to the honeypot.
Port 22
Port ${ADMIN_SSH_PORT}
EOF
uses_socket=false
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
  uses_socket=true   # Ubuntu 22.10+ uses socket activation: ports live in the socket unit
  mkdir -p /etc/systemd/system/ssh.socket.d
  cat > /etc/systemd/system/ssh.socket.d/hivewatch.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:22
ListenStream=[::]:22
ListenStream=0.0.0.0:${ADMIN_SSH_PORT}
ListenStream=[::]:${ADMIN_SSH_PORT}
EOF
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
sshd -t || die "sshd config test failed — nothing was restarted"
systemctl restart ssh 2>/dev/null || systemctl restart sshd
ok "sshd now listens on 22 and ${ADMIN_SSH_PORT}"

PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')"
ADMIN_USER="${SUDO_USER:-root}"
echo
echo "${c_yellow}  >>> IMPORTANT: open a NEW terminal on your computer and run:${c_off}"
echo
echo "        ssh -p ${ADMIN_SSH_PORT} ${ADMIN_USER}@${PUBLIC_IP}"
echo
echo "${c_yellow}  Keep THIS session open. Only continue once that login works.${c_off}"
read -r -p "  Did the login on port ${ADMIN_SSH_PORT} work? Type 'yes' to continue: " answer </dev/tty
[[ "$answer" == "yes" ]] || die "aborted — port 22 is still your SSH port, nothing else changed"

step "Freeing port 22 for the honeypot"
# An explicit 'Port 22' in the main config would keep sshd on 22 -> comment it out (backup kept)
if grep -qE '^\s*Port\s+' /etc/ssh/sshd_config; then
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.hivewatch"
  sed -i -E 's/^\s*Port\s+/# (hivewatch) Port /' /etc/ssh/sshd_config
  warn "commented out Port in /etc/ssh/sshd_config (backup: sshd_config.bak.hivewatch)"
fi
cat > /etc/ssh/sshd_config.d/00-hivewatch-admin-port.conf <<EOF
# Added by HiveWatch: real admin SSH. Port 22 is handed to the honeypot.
Port ${ADMIN_SSH_PORT}
EOF
if $uses_socket; then
  cat > /etc/systemd/system/ssh.socket.d/hivewatch.conf <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${ADMIN_SSH_PORT}
ListenStream=[::]:${ADMIN_SSH_PORT}
EOF
  systemctl daemon-reload
  systemctl restart ssh.socket
fi
sshd -t && { systemctl restart ssh 2>/dev/null || systemctl restart sshd; }
ok "real SSH is now only on ${ADMIN_SSH_PORT}"

# --------------------------------------------------------------------------- 4. app
step "Installing HiveWatch into ${INSTALL_DIR}"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" pull --ff-only -q
else
  git clone -q "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

if [[ ! -f .env ]]; then
  cp .env.example .env
  TOKEN="$(openssl rand -hex 24)"
  sed -i "s/^HW_DASH_TOKEN=.*/HW_DASH_TOKEN=${TOKEN}/" .env
  sed -i "s/^HW_MODE=.*/HW_MODE=live/" .env
  # place the honeypot at the server's real location on the globe
  if geo="$(curl -fsS --max-time 5 "http://ip-api.com/line/${PUBLIC_IP}?fields=city,countryCode,lat,lon")"; then
    mapfile -t g <<<"$geo"
    if [[ ${#g[@]} -ge 4 ]]; then
      sed -i "s/^HW_SENSOR_LABEL=.*/HW_SENSOR_LABEL=${g[0]}, ${g[1]}/" .env
      sed -i "s/^HW_SENSOR_LAT=.*/HW_SENSOR_LAT=${g[2]}/" .env
      sed -i "s/^HW_SENSOR_LON=.*/HW_SENSOR_LON=${g[3]}/" .env
    fi
  fi
  chmod 600 .env
  ok "created .env with a random dashboard token"
else
  ok "keeping existing .env"
fi
TOKEN="$(grep '^HW_DASH_TOKEN=' .env | cut -d= -f2)"

step "Building and starting the containers"
docker compose up -d --build
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:8000/healthz" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "http://127.0.0.1:8000/healthz" >/dev/null || die "dashboard did not come up — check: docker compose logs"
ok "HiveWatch is running"

# --------------------------------------------------------------------------- 5. done
cat <<EOF

${c_green}  ██  HiveWatch is live and waiting for attackers  ██${c_off}

  Open the dashboard from YOUR computer (it is never exposed to the internet):

      ssh -N -L 8000:localhost:8000 -p ${ADMIN_SSH_PORT} ${ADMIN_USER}@${PUBLIC_IP}

  then browse to:

      http://localhost:8000/?token=${TOKEN}

  Useful commands (on the server, in ${INSTALL_DIR}):
      docker compose logs -f        live logs
      docker compose restart        restart
      bash deploy/update.sh         pull the latest version
      sudo bash deploy/uninstall.sh remove everything, give port 22 back to sshd

  Optional: add ABUSEIPDB_API_KEY / TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID to .env,
  then run:  docker compose up -d

  First SSH brute-force attempts usually arrive within minutes. Happy hunting!
EOF
