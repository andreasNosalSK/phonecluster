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
RUN_USER="${SUDO_USER:-$(whoami)}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-adguard) WITH_ADGUARD=1; shift ;;
    --with-firewall) WITH_FIREWALL=1; shift ;;
    --enable-gateway) ENABLE_GATEWAY=1; shift ;;
    --lan-subnet) LAN_SUBNET="$2"; shift 2 ;;
    --user) RUN_USER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,15p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run with sudo: sudo bash $0 $*" >&2
  exit 1
fi

USER_HOME="$(getent passwd "${RUN_USER}" | cut -d: -f6 || echo "/home/${RUN_USER}")"
MASTER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
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
exec python3 "${REPO_DIR}/phonecluster_cli.py" "\$@"
EOF
chmod 0755 /usr/local/bin/phonecluster
ln -sf /usr/local/bin/phonecluster /usr/local/bin/pc

# 3. Ensure cluster.json exists (owned by RUN_USER, 0600)
CFG_PATH="${REPO_DIR}/config/cluster.json"
if [[ ! -f "${CFG_PATH}" ]]; then
  sudo -u "${RUN_USER}" python3 "${REPO_DIR}/phonecluster_cli.py" init-config \
    --name "pi-phonecluster" \
    --master-host "${MASTER_IP}" \
    --workers "" \
    --ssh-user "${RUN_USER}" \
    --output "${CFG_PATH}"
fi

if [[ "${ENABLE_GATEWAY}" -eq 1 ]]; then
  sudo -u "${RUN_USER}" python3 "${REPO_DIR}/phonecluster_cli.py" \
    --config "${CFG_PATH}" gateway --enable --mode allowlist
fi

# 4. Install systemd service for PhoneCluster Master Dashboard (+ optional Network Guard)
cat > /etc/systemd/system/phonecluster-master.service <<EOF
[Unit]
Description=PhoneCluster Master Control Center & Optional Network Guard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO_DIR}
ExecStart=/usr/bin/python3 ${REPO_DIR}/phonecluster_cli.py --config ${CFG_PATH} dashboard --bind 0.0.0.0
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now phonecluster-master.service
echo "[OK] Installed & started phonecluster-master.service (http://${MASTER_IP}:8080)"

# 5. Optional: Native AdGuard Home (NO Docker required — single ~12 MB Go binary!)
if [[ "${WITH_ADGUARD}" -eq 1 ]]; then
  if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
    echo "[OK] Native AdGuard Home already installed at /opt/AdGuardHome/AdGuardHome"
  else
    echo "Installing native AdGuard Home (no Docker)..."
    curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
  fi
  echo "[OK] Open AdGuard Home setup wizard at: http://${MASTER_IP}:3000"
  echo "     Then paste DNS rewrites from: pc net-audit --adguard"
fi

# 6. Optional: Hardened LAN-only nftables firewall
if [[ "${WITH_FIREWALL}" -eq 1 ]]; then
  echo "Applying hardened LAN-only nftables rules (${LAN_SUBNET})..."
  sudo -u "${RUN_USER}" python3 "${REPO_DIR}/phonecluster_cli.py" \
    --config "${CFG_PATH}" net-audit --firewall > /etc/nftables.phonecluster.conf
  nft -f /etc/nftables.phonecluster.conf
  systemctl enable nftables || true
  echo "[OK] Hardened nftables rules active (saved to /etc/nftables.phonecluster.conf)."
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
