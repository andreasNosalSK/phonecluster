#!/usr/bin/env bash
# 06_ubuntu_touch_node_setup.sh — Run inside Ubuntu Touch (UBports) on each phone
# Safe for Ubuntu Touch's read-only rootfs (no `apt` required!).
# Configures:
#   1. SSH server + ~/.ssh key permissions
#   2. Docker via Snap (`docker:home` plug, `docker` group, socket access, ~/phonecluster/docker-data)
#   3. Persistent `systemd --user` service + lingering + `/snap/bin` PATH wrapper
#
# Usage:
#   bash scripts/06_ubuntu_touch_node_setup.sh --node-id node0 --master
#   bash scripts/06_ubuntu_touch_node_setup.sh --node-id node1
set -euo pipefail

NODE_ID=""
REPO_DIR="${HOME}/phonecluster"
IS_MASTER=0
BOOT_ONLY=0
NO_DOCKER_FIX=0

usage() {
  cat <<'EOF'
Usage: bash scripts/06_ubuntu_touch_node_setup.sh [options]

Options:
  --node-id <id>     Node ID in config/cluster.json (default: node0 for Master, node1 for Worker)
  --repo-dir <path>  Path to PhoneCluster checkout (default: ~/phonecluster)
  --master           Also install systemd --user service for Master Web Dashboard (:8080)
  --boot-only        Only update wrappers & systemd --user unit (offline-safe, used by `pc join`)
  --no-docker-fix    Skip automatic Snap Docker group/interface checks
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-id)
      [[ $# -ge 2 ]] || { echo "Error: --node-id requires a value" >&2; usage; exit 2; }
      NODE_ID="$2"; shift 2 ;;
    --repo-dir)
      [[ $# -ge 2 ]] || { echo "Error: --repo-dir requires a path" >&2; usage; exit 2; }
      REPO_DIR="$2"; shift 2 ;;
    --master) IS_MASTER=1; shift ;;
    --boot-only) BOOT_ONLY=1; shift ;;
    --no-docker-fix) NO_DOCKER_FIX=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${NODE_ID}" ]]; then
  if [[ "${IS_MASTER}" -eq 1 ]]; then NODE_ID="node0"; else NODE_ID="node1"; fi
fi

if [[ ! "${NODE_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$ ]]; then
  echo "Error: Invalid --node-id '${NODE_ID}' (must start with alphanumeric and contain only A-Za-z0-9._-, max 40 chars)." >&2
  exit 2
fi

case "${REPO_DIR}" in
  '~') REPO_DIR="${HOME}" ;;
  '~/'*) REPO_DIR="${HOME}/${REPO_DIR#??}" ;;
  /*) ;;
  *) REPO_DIR="${PWD}/${REPO_DIR#./}" ;;
esac

if [[ "${REPO_DIR}" == *$'\n'* || "${REPO_DIR}" == *'"'* || "${REPO_DIR}" == *'$'* || "${REPO_DIR}" == *'`'* || "${REPO_DIR}" == *'\'* || "${REPO_DIR}" == *'}'* || "${REPO_DIR}" == *'%'* ]]; then
  echo "Error: Unsupported special characters in --repo-dir '${REPO_DIR}'." >&2
  exit 2
fi

export PATH="/snap/bin:${HOME}/.local/bin:${PATH}"

echo "=== PhoneCluster Ubuntu Touch + Snap Docker Setup (${NODE_ID}) ==="

# 1. SSH & ~/.ssh permissions (read-only rootfs safe)
if [[ "${BOOT_ONLY}" -eq 0 ]]; then
  echo "[1/4] Checking SSH server & key permissions..."
  mkdir -p "${HOME}/.ssh"
  chmod 700 "${HOME}/.ssh"
  if [[ ! -f "${HOME}/.ssh/authorized_keys" ]]; then
    (umask 077 && : > "${HOME}/.ssh/authorized_keys")
  else
    chmod 600 "${HOME}/.ssh/authorized_keys"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet ssh 2>/dev/null && ! systemctl is-active --quiet ssh.socket 2>/dev/null; then
      echo "  Enabling SSH service (may prompt for sudo/PIN password)..."
      sudo systemctl enable --now ssh 2>/dev/null || sudo systemctl enable --now ssh.socket 2>/dev/null || true
    fi
  elif command -v android-gadget-service >/dev/null 2>&1; then
    android-gadget-service enable ssh 2>/dev/null || true
  fi
fi

# 2. Snap Docker confinement & group setup
DOCKER_DATA_DIR="${REPO_DIR}/docker-data"
mkdir -p "${DOCKER_DATA_DIR}" "${REPO_DIR}/logs" "${REPO_DIR}/config"

if [[ "${BOOT_ONLY}" -eq 0 && "${NO_DOCKER_FIX}" -eq 0 ]]; then
  echo "[2/4] Checking Docker (Snap) runtime & permissions..."
  if [[ -x "/snap/bin/docker" ]] || command -v docker >/dev/null 2>&1; then
    if [[ -x "/snap/bin/docker" ]] && command -v snap >/dev/null 2>&1; then
      echo "  Detected Docker via Snap (/snap/bin/docker)."
      # Connect :home so Snap Docker can bind-mount volumes under $HOME/phonecluster/docker-data
      if ! snap connections docker 2>/dev/null | grep -q "docker:home.*:home"; then
        echo "  Connecting Snap interface docker:home..."
        sudo snap connect docker:home 2>/dev/null || echo "  (Run manually if needed: sudo snap connect docker:home)"
      fi

      NEED_RESTART=0
      if [[ ! -r /var/run/docker.sock || ! -w /var/run/docker.sock ]]; then
        echo "  Configuring 'docker' group for user '${USER}'..."
        sudo addgroup --system docker 2>/dev/null || sudo groupadd -r docker 2>/dev/null || true
        sudo adduser "${USER}" docker 2>/dev/null || sudo usermod -aG docker "${USER}" 2>/dev/null || true
        NEED_RESTART=1
      fi

      if [[ -d "${HOME}/.docker" && "$(stat -c '%u' "${HOME}/.docker" 2>/dev/null || echo 1)" -eq 0 && "$(id -u)" -ne 0 ]]; then
        echo "  Fixing root-owned ~/.docker directory permissions..."
        sudo chown -R "${USER}:${USER}" "${HOME}/.docker" 2>/dev/null || true
      fi

      if [[ "${NEED_RESTART}" -eq 1 || ! -S /var/run/docker.sock ]]; then
        echo "  Restarting Snap Docker so group & socket permissions take effect..."
        sudo snap disable docker 2>/dev/null && sudo snap enable docker 2>/dev/null || sudo snap restart docker 2>/dev/null || true
      fi
    fi
    echo "  Snap-safe Docker volume directory: ${DOCKER_DATA_DIR}"
    echo "  (Tip: Snap Docker bind mounts MUST live under \$HOME, never /tmp or /opt.)"
  else
    echo "  Docker not found yet. Install via Snap with:"
    echo "    sudo snap install docker"
    echo "  Then re-run this script to configure docker:home and group access."
  fi
fi

# 3. Install ~/.local/bin wrappers with /snap/bin on PATH
echo "[3/4] Installing ~/.local/bin/phonecluster & pc wrappers (with /snap/bin PATH)..."
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"
cat > "${BIN_DIR}/phonecluster" <<EOF
#!/usr/bin/env sh
export PATH="/snap/bin:${HOME}/.local/bin:\${PATH}"
export PHONECLUSTER_CONFIG="\${PHONECLUSTER_CONFIG:-${REPO_DIR}/config/cluster.json}"
exec python3 "${REPO_DIR}/phonecluster_cli.py" "\$@"
EOF
chmod +x "${BIN_DIR}/phonecluster"
ln -sf "${BIN_DIR}/phonecluster" "${BIN_DIR}/pc"

# 4. Install persistent systemd --user unit(s) (works on Ubuntu Touch read-only rootfs!)
echo "[4/4] Installing persistent systemd --user service(s)..."
UNIT_DIR="${HOME}/.config/systemd/user"
mkdir -p "${UNIT_DIR}"

cat > "${UNIT_DIR}/phonecluster-worker.service" <<EOF
[Unit]
Description=PhoneCluster Worker Daemon (${NODE_ID})
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${REPO_DIR}
Environment="PATH=/snap/bin:${HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PHONECLUSTER_CONFIG=${REPO_DIR}/config/cluster.json"
ExecStart=/usr/bin/env python3 "${REPO_DIR}/phonecluster_cli.py" --config "${REPO_DIR}/config/cluster.json" worker --node-id ${NODE_ID}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

if [[ "${IS_MASTER}" -eq 1 ]]; then
  cat > "${UNIT_DIR}/phonecluster-dashboard.service" <<EOF
[Unit]
Description=PhoneCluster Master Web Dashboard (${NODE_ID})
After=network-online.target phonecluster-worker.service

[Service]
Type=simple
WorkingDirectory=${REPO_DIR}
Environment="PATH=/snap/bin:${HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PHONECLUSTER_CONFIG=${REPO_DIR}/config/cluster.json"
ExecStart=/usr/bin/env python3 "${REPO_DIR}/phonecluster_cli.py" --config "${REPO_DIR}/config/cluster.json" dashboard --bind 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
fi

# Populate XDG_RUNTIME_DIR for SSH sessions so `systemctl --user` connects cleanly
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
  systemctl --user daemon-reload
  units=(phonecluster-worker.service)
  if [[ "${IS_MASTER}" -eq 1 ]]; then
    units+=(phonecluster-dashboard.service)
  fi
  systemctl --user enable "${units[@]}"
  if [[ -f "${REPO_DIR}/config/cluster.json" ]]; then
    systemctl --user restart "${units[@]}"
  else
    echo "  After creating config/cluster.json, run: systemctl --user start ${units[*]}"
  fi
else
  echo "  Note: systemd --user bus not active in this shell; unit written to ${UNIT_DIR}/phonecluster-worker.service."
fi

if [[ "${BOOT_ONLY}" -eq 0 ]] && command -v loginctl >/dev/null 2>&1; then
  loginctl enable-linger "${USER}" 2>/dev/null || sudo loginctl enable-linger "${USER}" 2>/dev/null || true
fi

echo
echo "=== Ubuntu Touch Setup Complete ==="
echo "  User / SSH   : ${USER} (port 22)"
echo "  Docker Data  : ${DOCKER_DATA_DIR} (Snap-safe bind-mount root)"
echo "  Wake-Lock    : Automatically held by worker daemon via repowerd-cli / powerd-cli"
echo "  Systemd Unit : ${UNIT_DIR}/phonecluster-worker.service"
echo
if [[ "${IS_MASTER}" -eq 1 ]]; then
  echo "Next steps on this Ubuntu Touch MASTER phone:"
  echo "  1. Create config:  pc wizard --master-id ${NODE_ID}   (if you have not configured the cluster yet)"
  echo "  2. Pair phone #2:  pc pair     (then run 'pc join' on your second Ubuntu Touch phone)"
  echo "  3. Check Docker :  pc docker status"
  echo "  4. Optional Swarm: pc docker swarm-init"
else
  echo "Next steps on this Ubuntu Touch WORKER phone:"
  echo "  1. On Master phone, open Pairing:  pc pair  (or Dashboard Tab 6)"
  echo "  2. On THIS phone, run:             pc join"
fi
