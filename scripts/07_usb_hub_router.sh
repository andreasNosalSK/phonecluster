#!/usr/bin/env bash
# 07_usb_hub_router.sh — Zero-Wi-Fi USB 3.0 Hub Router for 2–6+ Phones
# Connects multiple phones plugged into one POWERED USB 3.0 hub attached to a
# Master Host (Raspberry Pi / Linux PC / SBC) so phones communicate with Master
# and directly with EACH OTHER with Wi-Fi completely turned OFF.
#
# Supports:
#   - Mode 1 (`setup-adb`):   Zero-root ADB hub forwarding + phone-to-phone peer mesh
#   - Mode 2 (`setup-rndis`): True Layer-3 IP-over-USB `/30` subnets (`10.77.<k>.0/30`),
#                             eliminating Ubuntu Touch `10.15.19.82` & Android `192.168.42.x`
#                             subnet collisions (ideal for Ubuntu Touch + Snap Docker Swarm!)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD="${1:-help}"
shift || true

PREFIX="10.77"
CONFIG_PATH="${PHONECLUSTER_CONFIG:-${REPO_ROOT}/config/cluster.json}"
DRY_RUN=0
NAT_WAN=0
WAN_IFACE=""
PEER_MESH=1
GW_PORT="8888"
PHONE_IFACE="auto"

usage() {
  cat <<'EOF'
PhoneCluster USB 3.0 Hub Router (Zero-Wi-Fi Multi-Phone Mode)

Usage:
  bash scripts/07_usb_hub_router.sh scan
  bash scripts/07_usb_hub_router.sh setup-adb [--config <path>] [--no-peer-mesh] [--gateway-port 8888]
  sudo bash scripts/07_usb_hub_router.sh setup-rndis [--prefix 10.77] [--nat-wan --wan-iface <if>] [--dry-run]
  sudo bash scripts/07_usb_hub_router.sh phone-setup <index 1..62> [--prefix 10.77] [--iface auto|rndis0|usb0]
  sudo bash scripts/07_usb_hub_router.sh teardown [--prefix 10.77]

Hardware Note:
  USB is Host-Device (not peer-to-peer). Plug your 2-6 phones into a POWERED
  USB 3.0 hub (12V/3A-5A PSU), and connect the hub's upstream cable to your
  Master Host (Raspberry Pi 4/5 / Pi Zero 2 W / Linux PC).
EOF
}

validate_prefix() {
  local p="$1"
  if [[ ! "${p}" =~ ^(10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)$ ]]; then
    echo "Error: Invalid RFC1918 /16 prefix '${p}' (use e.g. 10.77, 172.30, or 192.168)." >&2
    exit 2
  fi
}

validate_iface() {
  local ifc="$1"
  if [[ -z "${ifc}" || "${ifc}" == -* || ! "${ifc}" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]]; then
    echo "Error: Invalid network interface name '${ifc}'." >&2
    exit 2
  fi
}

run_cmd() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

case "${CMD}" in
  scan)
    exec python3 "${REPO_ROOT}/phonecluster_cli.py" --config "${CONFIG_PATH}" usb-hub scan
    ;;

  setup-adb)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -c|--config)
          [[ $# -ge 2 ]] || { echo "Error: $1 requires a path" >&2; exit 2; }
          CONFIG_PATH="$2"; shift 2 ;;
        --no-peer-mesh) PEER_MESH=0; shift ;;
        --peer-mesh) PEER_MESH=1; shift ;;
        --gateway-port)
          [[ $# -ge 2 ]] || { echo "Error: --gateway-port requires a port" >&2; exit 2; }
          GW_PORT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
      esac
    done
    ARGS=(--config "${CONFIG_PATH}" usb-hub setup --mode adb --gateway-port "${GW_PORT}" --write-config)
    [[ "${PEER_MESH}" -eq 0 ]] && ARGS+=(--no-peer-mesh)
    exec python3 "${REPO_ROOT}/phonecluster_cli.py" "${ARGS[@]}"
    ;;

  setup-rndis)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --prefix)
          [[ $# -ge 2 ]] || { echo "Error: --prefix requires a value (e.g. 10.77)" >&2; exit 2; }
          PREFIX="$2"; shift 2 ;;
        --nat-wan) NAT_WAN=1; shift ;;
        --wan-iface)
          [[ $# -ge 2 ]] || { echo "Error: --wan-iface requires an interface name" >&2; exit 2; }
          WAN_IFACE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
      esac
    done
    validate_prefix "${PREFIX}"
    if [[ -n "${WAN_IFACE}" ]]; then
      validate_iface "${WAN_IFACE}"
    fi
    if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
      echo "Error: setup-rndis requires root privileges (run with sudo, or pass --dry-run)." >&2
      exit 1
    fi

    # Discover USB-Ethernet interfaces sorted stably by MAC address
    IFACE_ROWS="$(python3 - "${REPO_ROOT}" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from phonecluster.usbhub import list_usb_net_interfaces
for idx, it in enumerate(list_usb_net_interfaces(include_ips=False), start=1):
    print(f"{idx}|{it['iface']}|{it['mac'] or 'unknown'}|{it['driver']}")
PY
)"
    if [[ -z "${IFACE_ROWS}" ]]; then
      echo "No USB-Ethernet / RNDIS phone interfaces found." >&2
      echo "Tip: Connect your phones to a powered USB 3.0 hub and enable USB Tethering (Android) or plug in Ubuntu Touch (usb0/rndis0 is enabled by default)." >&2
      exit 1
    fi

    CLUSTER_CIDR="${PREFIX}.0.0/16"
    echo "=== Configuring Layer-3 USB 3.0 Hub Router (${CLUSTER_CIDR}) ==="
    run_cmd sysctl -w net.ipv4.ip_forward=1 >/dev/null

    while IFS='|' read -r IDX IFACE MAC DRV; do
      [[ -z "${IFACE}" ]] && continue
      validate_iface "${IFACE}"
      HOST_IP="${PREFIX}.${IDX}.1"
      PHONE_IP="${PREFIX}.${IDX}.2"
      echo "  [usb${IDX}] ${IFACE} (mac=${MAC}, driver=${DRV}) -> Host ${HOST_IP}/30 <-> Phone ${PHONE_IP}/30"
      if command -v nmcli >/dev/null 2>&1; then
        run_cmd nmcli dev set "${IFACE}" managed no 2>/dev/null || true
      fi
      run_cmd ip addr flush dev "${IFACE}"
      run_cmd ip addr add "${HOST_IP}/30" dev "${IFACE}"
      run_cmd ip link set "${IFACE}" up
    done <<< "${IFACE_ROWS}"

    if command -v iptables >/dev/null 2>&1; then
      if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] iptables -I FORWARD 1 -s ${CLUSTER_CIDR} -d ${CLUSTER_CIDR} -j ACCEPT"
      else
        iptables -C FORWARD -s "${CLUSTER_CIDR}" -d "${CLUSTER_CIDR}" -j ACCEPT 2>/dev/null \
          || iptables -I FORWARD 1 -s "${CLUSTER_CIDR}" -d "${CLUSTER_CIDR}" -j ACCEPT
      fi
      if [[ "${NAT_WAN}" -eq 1 ]]; then
        if [[ -z "${WAN_IFACE}" ]]; then
          WAN_IFACE="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
        fi
        if [[ -n "${WAN_IFACE}" ]]; then
          validate_iface "${WAN_IFACE}"
          echo "  Enabling optional WAN NAT via ${WAN_IFACE} for ${CLUSTER_CIDR}..."
          if [[ "${DRY_RUN}" -eq 1 ]]; then
            echo "[dry-run] iptables -t nat -A POSTROUTING -s ${CLUSTER_CIDR} -o ${WAN_IFACE} -j MASQUERADE"
            echo "[dry-run] iptables -I FORWARD 2 -s ${CLUSTER_CIDR} -o ${WAN_IFACE} -j ACCEPT"
            echo "[dry-run] iptables -I FORWARD 3 -i ${WAN_IFACE} -d ${CLUSTER_CIDR} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
          else
            iptables -t nat -C POSTROUTING -s "${CLUSTER_CIDR}" -o "${WAN_IFACE}" -j MASQUERADE 2>/dev/null \
              || iptables -t nat -A POSTROUTING -s "${CLUSTER_CIDR}" -o "${WAN_IFACE}" -j MASQUERADE
            iptables -C FORWARD -s "${CLUSTER_CIDR}" -o "${WAN_IFACE}" -j ACCEPT 2>/dev/null \
              || iptables -I FORWARD 2 -s "${CLUSTER_CIDR}" -o "${WAN_IFACE}" -j ACCEPT
            iptables -C FORWARD -i "${WAN_IFACE}" -d "${CLUSTER_CIDR}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
              || iptables -I FORWARD 3 -i "${WAN_IFACE}" -d "${CLUSTER_CIDR}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
          fi
        else
          echo "Warning: Could not detect default WAN interface; pass --wan-iface <if>." >&2
        fi
      else
        echo "  WAN isolation: Phones can talk to Master & each other (${CLUSTER_CIDR}), air-gapped from WAN."
      fi
    fi

    echo
    echo "Next: Run the matching phone-side command on each Ubuntu Touch / Linux phone:"
    while IFS='|' read -r IDX IFACE MAC DRV; do
      [[ -z "${IFACE}" ]] && continue
      echo "  Phone ${IDX} (${IFACE}, mac=${MAC}):  sudo bash ~/phonecluster/scripts/07_usb_hub_router.sh phone-setup ${IDX} --prefix ${PREFIX}"
    done <<< "${IFACE_ROWS}"
    echo
    echo "Then save all USB phones into config/cluster.json with:"
    echo "  pc usb-hub setup --mode rndis --subnet-prefix ${PREFIX} --write-config"
    ;;

  phone-setup)
    [[ $# -ge 1 ]] || { echo "Error: phone-setup requires a phone index (1..62)" >&2; usage; exit 2; }
    IDX="$1"; shift
    if [[ ! "${IDX}" =~ ^[0-9]+$ ]] || (( IDX < 1 || IDX > 62 )); then
      echo "Error: phone index must be an integer between 1 and 62 (got '${IDX}')." >&2
      exit 2
    fi
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --prefix)
          [[ $# -ge 2 ]] || { echo "Error: --prefix requires a value" >&2; exit 2; }
          PREFIX="$2"; shift 2 ;;
        --iface)
          [[ $# -ge 2 ]] || { echo "Error: --iface requires an interface name" >&2; exit 2; }
          PHONE_IFACE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
      esac
    done
    validate_prefix "${PREFIX}"
    if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
      echo "Error: phone-setup requires root privileges (run with sudo, or pass --dry-run)." >&2
      exit 1
    fi

    if [[ "${PHONE_IFACE}" == "auto" ]]; then
      for CAND in rndis0 usb0 ncm0; do
        if [[ -d "/sys/class/net/${CAND}" ]]; then
          PHONE_IFACE="${CAND}"
          break
        fi
      done
    fi
    if [[ "${PHONE_IFACE}" == "auto" ]]; then
      echo "Error: Could not find rndis0/usb0/ncm0 gadget interface on this phone (pass --iface <name>)." >&2
      exit 1
    fi
    validate_iface "${PHONE_IFACE}"

    HOST_IP="${PREFIX}.${IDX}.1"
    PHONE_IP="${PREFIX}.${IDX}.2"
    CLUSTER_CIDR="${PREFIX}.0.0/16"

    echo "=== Configuring Phone #${IDX} on ${PHONE_IFACE} (${PHONE_IP}/30 -> Hub ${HOST_IP}) ==="
    if command -v nmcli >/dev/null 2>&1; then
      run_cmd nmcli dev set "${PHONE_IFACE}" managed no 2>/dev/null || true
    fi
    run_cmd ip addr flush dev "${PHONE_IFACE}"
    run_cmd ip addr add "${PHONE_IP}/30" dev "${PHONE_IFACE}"
    run_cmd ip link set "${PHONE_IFACE}" up
    run_cmd ip route replace "${CLUSTER_CIDR}" via "${HOST_IP}" dev "${PHONE_IFACE}"
    echo "Ready! This phone is ${PHONE_IP} and can reach Master (${HOST_IP}) and all sibling USB phones (${CLUSTER_CIDR}) with Wi-Fi OFF."
    ;;

  teardown)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --prefix)
          [[ $# -ge 2 ]] || { echo "Error: --prefix requires a value" >&2; exit 2; }
          PREFIX="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
      esac
    done
    validate_prefix "${PREFIX}"
    if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
      echo "Error: teardown requires root privileges (run with sudo, or pass --dry-run)." >&2
      exit 1
    fi
    CLUSTER_CIDR="${PREFIX}.0.0/16"
    if command -v iptables >/dev/null 2>&1; then
      if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] iptables -D FORWARD -s ${CLUSTER_CIDR} -d ${CLUSTER_CIDR} -j ACCEPT"
      else
        iptables -D FORWARD -s "${CLUSTER_CIDR}" -d "${CLUSTER_CIDR}" -j ACCEPT 2>/dev/null || true
      fi
    fi
    echo "Removed USB hub forwarding rules for ${CLUSTER_CIDR}."
    ;;

  help|-h|--help)
    usage
    ;;

  *)
    echo "Error: Unknown subcommand '${CMD}'." >&2
    usage >&2
    exit 2
    ;;
esac
