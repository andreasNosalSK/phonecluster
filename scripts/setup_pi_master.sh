#!/usr/bin/env bash
# ==============================================================================
# PhoneCluster — Raspberry Pi / Pi Zero 2 W / Debian 13 Hardened Master Setup
# ==============================================================================
# Turns a Raspberry Pi Zero 2 W (~€15, 512 MB RAM, 1-2 W) or any Debian 13 host
# into a 24/7 battery-free PhoneCluster Master + optional Native AdGuard Home
# (single ~12 MB Go binary — NO Docker required!) + optional nftables firewall.
#
# Usage:
#   sudo bash scripts/setup_pi_master.sh
#   sudo bash scripts/setup_pi_master.sh --with-adguard
#   sudo bash scripts/setup_pi_master.sh --with-adguard --with-firewall --lan-subnet 192.168.1.0/24
# ==============================================================================
set -euo pipefail

WITH_ADGUARD=0
WITH_FIREWALL=0
ENABLE_GATEWAY=0
LAN_SUBNET=""
LAN_SUBNET_EXPLICIT=0
RUN_USER="${SUDO_USER:-$(whoami)}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-adguard) WITH_ADGUARD=1; shift ;;
    --with-firewall) WITH_FIREWALL=1; shift ;;
    --enable-gateway) ENABLE_GATEWAY=1; shift ;;
    --lan-subnet)
      [[ $# -ge 2 ]] || { echo "Error: --lan-subnet requires a CIDR value (e.g. 192.168.1.0/24)" >&2; exit 2; }
      LAN_SUBNET="$2"; LAN_SUBNET_EXPLICIT=1; shift 2 ;;
    --user)
      [[ $# -ge 2 ]] || { echo "Error: --user requires a username" >&2; exit 2; }
      RUN_USER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,15p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "${RUN_USER}" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "Error: Invalid --user '${RUN_USER}'." >&2
  exit 2
fi

if [[ "${REPO_DIR}" == *$'\n'* || "${REPO_DIR}" == *'"'* || "${REPO_DIR}" == *'$'* || "${REPO_DIR}" == *'`'* || "${REPO_DIR}" == *'\'* || "${REPO_DIR}" == *'%'* || "${REPO_DIR}" == *'}'* ]]; then
  echo "Error: Unsupported special characters in repo directory '${REPO_DIR}'." >&2
  exit 2
fi

if [[ -n "${LAN_SUBNET}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c 'import ipaddress, sys; ipaddress.ip_network(sys.argv[1], strict=False)' "${LAN_SUBNET}" 2>/dev/null; then
      echo "Error: Invalid --lan-subnet CIDR '${LAN_SUBNET}' (example: 192.168.1.0/24)." >&2
      exit 2
    fi
  elif [[ ! "${LAN_SUBNET}" =~ ^[0-9A-Fa-f.:]+/[0-9]{1,3}$ ]]; then
    echo "Error: Invalid --lan-subnet CIDR '${LAN_SUBNET}' (example: 192.168.1.0/24)." >&2
    exit 2
  fi
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run with sudo: sudo bash $0 $*" >&2
  exit 1
fi

if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  echo "Error: System user '${RUN_USER}' does not exist." >&2
  exit 2
fi

USER_HOME="$(getent passwd "${RUN_USER}" | cut -d: -f6 || echo "/home/${RUN_USER}")"
MASTER_IP="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i !~ /^127\./) {print $i; exit}}' || true)"
MASTER_IP="${MASTER_IP:-192.168.1.200}"
if [[ -z "${LAN_SUBNET}" ]]; then
  LAN_SUBNET="$(echo "${MASTER_IP}" | awk -F. '{print $1"."$2"."$3".0/24"}')"
fi

BOARD="Debian / Linux"
if [[ -r /proc/device-tree/model ]]; then
  BOARD="$(tr -d '\0' </proc/device-tree/model)"
fi

echo "============================================================"
echo "  PhoneCluster Master Setup — ${BOARD}"
echo "============================================================"
echo "  User        : ${RUN_USER} (${USER_HOME})"
echo "  Repo Dir    : ${REPO_DIR}"
echo "  Master IP   : ${MASTER_IP} (LAN: ${LAN_SUBNET})"
echo "  AdGuard     : $([[ "${WITH_ADGUARD}" -eq 1 ]] && echo "YES (Native binary, NO Docker)" || echo "Skip (pass --with-adguard to add)")"
echo "  Firewall    : $([[ "${WITH_FIREWALL}" -eq 1 ]] && echo "YES (nftables LAN-only)" || echo "Skip (pass --with-firewall to add)")"
echo "============================================================"

# 1. Core packages (lightweight, zero Docker bloat)
apt-get update -qq
PKGS=(python3 openssh-client curl ca-certificates)
if [[ "${WITH_FIREWALL}" -eq 1 ]]; then
  PKGS+=(nftables)
fi
apt-get install -y -qq "${PKGS[@]}"

# 2. Global `pc` & `phonecluster` CLI wrapper
cat > /usr/local/bin/phonecluster <<EOF
#!/usr/bin/env bash
export PHONECLUSTER_CONFIG="\${PHONECLUSTER_CONFIG:-${REPO_DIR}/config/cluster.json}"
exec python3 "${REPO_DIR}/phonecluster_cli.py" "\$@"
EOF
chmod 0755 /usr/local/bin/phonecluster
ln -sf /usr/local/bin/phonecluster /usr/local/bin/pc

run_as_user() {
  if [[ "${RUN_USER}" == "root" ]]; then
    "$@"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "${RUN_USER}" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "${RUN_USER}" -- "$@"
  else
    su -s /bin/sh "${RUN_USER}" -c 'exec "$@"' _ "$@"
  fi
}

# Re-validate --lan-subnet now that python3 is guaranteed installed (before passing it to CLI!)
if ! python3 -c 'import ipaddress, sys; ipaddress.ip_network(sys.argv[1], strict=False)' "${LAN_SUBNET}" 2>/dev/null; then
  echo "Error: Invalid --lan-subnet CIDR '${LAN_SUBNET}' (example: 192.168.1.0/24)." >&2
  exit 2
fi

# 3. Ensure cluster.json exists (owned by RUN_USER, 0600, with Linux SSH port 22!)
CFG_PATH="${REPO_DIR}/config/cluster.json"
CONFIG_CREATED=0
if [[ ! -f "${CFG_PATH}" ]]; then
  run_as_user python3 "${REPO_DIR}/phonecluster_cli.py" init-config \
    --name "pi-phonecluster" \
    --master-host "${MASTER_IP}" \
    --workers "" \
    --ssh-user "${RUN_USER}" \
    --ssh-port 22 \
    --output "${CFG_PATH}"
  CONFIG_CREATED=1
fi

# Persist chosen LAN subnet on first creation or when explicitly passed via --lan-subnet
if [[ "${CONFIG_CREATED}" -eq 1 || "${LAN_SUBNET_EXPLICIT}" -eq 1 ]]; then
  run_as_user python3 "${REPO_DIR}/phonecluster_cli.py" \
    --config "${CFG_PATH}" net-audit --lan-subnet "${LAN_SUBNET}" --json >/dev/null
fi

if [[ "${ENABLE_GATEWAY}" -eq 1 ]]; then
  run_as_user python3 "${REPO_DIR}/phonecluster_cli.py" \
    --config "${CFG_PATH}" gateway --enable --mode allowlist
fi

# Detect Master node ID from cluster.json (supports pre-existing custom Master node IDs)
MASTER_NODE_ID="$(python3 -c 'import json, sys; c=json.load(open(sys.argv[1], encoding="utf-8")); n=next((x for x in c["nodes"] if x.get("role")=="master"), c["nodes"][0]); print(n["id"])' "${CFG_PATH}" 2>/dev/null || echo "node0")"
if [[ ! "${MASTER_NODE_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$ ]]; then
  MASTER_NODE_ID="node0"
fi

# 4. Install systemd services for Master Dashboard (+ optional Network Guard) AND local Master Worker
cat > /etc/systemd/system/phonecluster-worker.service <<EOF
[Unit]
Description=PhoneCluster Master Local Worker Agent (${MASTER_NODE_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO_DIR}
ExecStart=/usr/bin/python3 "${REPO_DIR}/phonecluster_cli.py" --config "${CFG_PATH}" worker --node-id ${MASTER_NODE_ID} --bind 0.0.0.0
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/phonecluster-master.service <<EOF
[Unit]
Description=PhoneCluster Master Control Center & Optional Network Guard
After=network-online.target phonecluster-worker.service
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO_DIR}
ExecStart=/usr/bin/python3 "${REPO_DIR}/phonecluster_cli.py" --config "${CFG_PATH}" dashboard --bind 0.0.0.0
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phonecluster-worker.service phonecluster-master.service
systemctl restart phonecluster-worker.service phonecluster-master.service
echo "[OK] Installed & restarted phonecluster-worker.service + phonecluster-master.service (http://${MASTER_IP}:8080)"

# 5. Optional: Native AdGuard Home (NO Docker required — single ~12 MB Go binary!)
if [[ "${WITH_ADGUARD}" -eq 1 ]]; then
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
    echo "[OK] Native AdGuard Home already installed at /opt/AdGuardHome/AdGuardHome"
  else
    echo "Installing native AdGuard Home (no Docker)..."
    curl -fsSL https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
  fi
  echo "[OK] Open AdGuard Home setup wizard at: http://${MASTER_IP}:3000"
  echo "     Then paste DNS rewrites from: pc net-audit --adguard"
fi

# 6. Optional: Hardened LAN-only nftables firewall (persisted to /etc/nftables.conf so rules survive reboot)
if [[ "${WITH_FIREWALL}" -eq 1 ]]; then
  echo "Applying hardened LAN-only nftables rules (${LAN_SUBNET})..."
  run_as_user python3 "${REPO_DIR}/phonecluster_cli.py" \
    --config "${CFG_PATH}" net-audit --firewall > /etc/nftables.phonecluster.conf
  if ! nft -c -f /etc/nftables.phonecluster.conf; then
    echo "Error: Generated nftables rules failed syntax check; leaving existing /etc/nftables.conf untouched." >&2
    exit 1
  fi
  if [[ -f /etc/nftables.conf && ! -f /etc/nftables.conf.pre-phonecluster.bak ]]; then
    cp /etc/nftables.conf /etc/nftables.conf.pre-phonecluster.bak
  fi
  cp /etc/nftables.phonecluster.conf /etc/nftables.conf
  nft -f /etc/nftables.conf
  systemctl enable nftables || true
  echo "[OK] Hardened nftables rules active & persisted in /etc/nftables.conf (backup: /etc/nftables.conf.pre-phonecluster.bak)."
fi

echo
echo "============================================================"
echo "  Raspberry Pi / Debian Master Ready!"
echo "============================================================"
echo "  Web Control Center : http://${MASTER_IP}:8080"
echo "  Show Unlock Token  : pc token"
echo "  Pair Phone Workers : pc pair   (then run 'pc join' on each phone)"
echo "  Network Audit      : pc net-audit"
echo "============================================================"
