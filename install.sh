#!/usr/bin/env bash
# PhoneCluster Universal One-Command Installer & Updater
# Works on: Android Termux (unrooted), Debian 13 ARM64 chroot, and Linux/macOS PCs.
#
# True one-line remote install:
#   curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash
#
# Local install / flags:
#   bash install.sh --master --with-compute
#   bash install.sh --worker --node-id node1 --with-compute
set -euo pipefail

ROLE=""
NODE_ID=""
WITH_COMPUTE=0
NON_INTERACTIVE=0
INSTALL_DIR="${PHONECLUSTER_DIR:-${HOME}/phonecluster}"
REPO_URL="${PHONECLUSTER_REPO_URL:-https://github.com/andreasNosalSK/phonecluster.git}"

usage() {
  cat <<'EOF'
PhoneCluster Easy Installer & Updater

Usage: bash install.sh [options]

Options:
  --master            Configure this device as the Master phone (node0 + Web Dashboard)
  --worker            Configure this device as a Worker phone
  --node-id <id>      Node ID (e.g. node0, node1, node2)
  --with-compute      Also install clang, cmake, distcc, openmpi, htop
  --dir <path>        Install directory (default: ~/phonecluster)
  --non-interactive   Skip prompts and use flags/defaults
  -h, --help          Show this help
EOF
}

# Read safely from /dev/tty even when invoked via `curl ... | bash`
ask() {
  local prompt="$1"
  local default_val="$2"
  local reply=""
  if [[ -r /dev/tty ]]; then
    read -r -p "${prompt}" reply < /dev/tty || reply=""
  elif [[ -t 0 ]]; then
    read -r -p "${prompt}" reply || reply=""
  fi
  printf '%s' "${reply:-${default_val}}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master) ROLE="master"; shift ;;
    --worker) ROLE="worker"; shift ;;
    --node-id)
      [[ $# -ge 2 ]] || { echo "Error: --node-id requires a value" >&2; usage; exit 2; }
      NODE_ID="$2"; shift 2 ;;
    --with-compute) WITH_COMPUTE=1; shift ;;
    --dir)
      [[ $# -ge 2 ]] || { echo "Error: --dir requires a path" >&2; usage; exit 2; }
      INSTALL_DIR="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -n "${NODE_ID}" && ! "${NODE_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$ ]]; then
  echo "Error: Invalid --node-id '${NODE_ID}' (must start with alphanumeric and contain only A-Za-z0-9._-, max 40 chars)." >&2
  exit 2
fi

if [[ "${INSTALL_DIR}" == *$'\n'* || "${INSTALL_DIR}" == *'"'* || "${INSTALL_DIR}" == *'$'* || "${INSTALL_DIR}" == *'`'* ]]; then
  echo "Error: Unsupported special characters in --dir '${INSTALL_DIR}'." >&2
  exit 2
fi

IS_TERMUX=0
if [[ "${PREFIX:-}" == *"com.termux"* ]] || [[ -n "${TERMUX_VERSION:-}" ]]; then
  IS_TERMUX=1
fi

echo "============================================================"
echo "  PhoneCluster Easy Installer"
echo "============================================================"

# Locate source directory if running from inside a cloned repo
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/phonecluster_cli.py" ]]; then
  INSTALL_DIR="${SCRIPT_DIR}"
else
  if ! command -v git >/dev/null 2>&1; then
    if [[ "${IS_TERMUX}" -eq 1 ]]; then
      echo "Installing git in Termux..."
      pkg update -y && pkg install -y git
    else
      echo "Error: 'git' is required to download PhoneCluster from ${REPO_URL}." >&2
      exit 1
    fi
  fi
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo "Existing installation found at ${INSTALL_DIR} — updating..."
    git -C "${INSTALL_DIR}" pull --ff-only || echo "Warning: git pull skipped (local changes?)."
  else
    echo "Cloning PhoneCluster into ${INSTALL_DIR}..."
    git clone "${REPO_URL}" "${INSTALL_DIR}"
  fi
fi

echo "Install path : ${INSTALL_DIR}"
echo "Environment  : $([[ "${IS_TERMUX}" -eq 1 ]] && echo "Android Termux" || echo "Standard Linux / Debian")"
echo

# 1. Install OS packages cleanly
if [[ "${IS_TERMUX}" -eq 1 ]]; then
  echo "[1/4] Installing Termux packages (openssh, termux-api, python, jq, tmux, git)..."
  pkg update -y
  pkg install -y openssh termux-api python jq tmux git
  if [[ "${WITH_COMPUTE}" -eq 1 ]]; then
    echo "[1b/4] Installing native ARM64 compute & compiler tools..."
    pkg install -y clang cmake make distcc openmpi htop
  fi
else
  echo "[1/4] Checking Python 3..."
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found. Install it first (e.g. sudo apt install -y python3 openssh-server)." >&2
    exit 1
  fi
fi

# 2. Install global CLI wrappers `phonecluster` and short alias `pc`
echo "[2/4] Creating global commands: 'phonecluster' and 'pc'..."
if [[ "${IS_TERMUX}" -eq 1 ]]; then
  BIN_DIR="${PREFIX}/bin"
else
  BIN_DIR="${HOME}/.local/bin"
fi
mkdir -p "${BIN_DIR}"

cat > "${BIN_DIR}/phonecluster" <<EOF
#!/usr/bin/env sh
export PHONECLUSTER_CONFIG="\${PHONECLUSTER_CONFIG:-${INSTALL_DIR}/config/cluster.json}"
exec python3 "${INSTALL_DIR}/phonecluster_cli.py" "\$@"
EOF
chmod +x "${BIN_DIR}/phonecluster"
ln -sf "${BIN_DIR}/phonecluster" "${BIN_DIR}/pc"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "  Note: Add ${BIN_DIR} to your PATH (e.g. export PATH=\"${BIN_DIR}:\$PATH\")."
fi

# 3. Interactive role selection if not provided via flags
if [[ -z "${ROLE}" && "${NON_INTERACTIVE}" -eq 0 ]]; then
  echo
  echo "[3/4] What role will this device play?"
  echo "  1) Master phone (Controls the cluster + runs Web Dashboard + runs jobs)"
  echo "  2) Worker phone (Joins the cluster and runs jobs)"
  echo "  3) Just install CLI tools (configure later)"
  CHOICE="$(ask "Choose [1/2/3] (default 1): " "1")"
  case "${CHOICE}" in
    1) ROLE="master" ;;
    2) ROLE="worker" ;;
    *) ROLE="cli-only" ;;
  esac
fi

if [[ "${ROLE}" == "master" && -z "${NODE_ID}" ]]; then
  NODE_ID="node0"
elif [[ "${ROLE}" == "worker" && -z "${NODE_ID}" ]]; then
  if [[ "${NON_INTERACTIVE}" -eq 0 ]]; then
    NODE_ID="$(ask "Enter Worker node ID [node1]: " "node1")"
  fi
  NODE_ID="${NODE_ID:-node1}"
fi

# 4. Termux boot + SSH setup
if [[ "${IS_TERMUX}" -eq 1 && "${ROLE}" != "cli-only" && -n "${ROLE}" ]]; then
  echo "[4/4] Setting up Termux SSH + Termux:Boot auto-start for '${NODE_ID}' (${ROLE})..."
  EXTRA_ARGS=(--node-id "${NODE_ID}" --repo-dir "${INSTALL_DIR}")
  [[ "${ROLE}" == "master" ]] && EXTRA_ARGS+=(--master)
  [[ "${WITH_COMPUTE}" -eq 1 ]] && EXTRA_ARGS+=(--with-compute)
  bash "${INSTALL_DIR}/scripts/02_termux_node_setup.sh" "${EXTRA_ARGS[@]}"
else
  echo "[4/4] Skipping Termux:Boot (not running inside Termux or cli-only mode)."
fi

echo
echo "============================================================"
echo "  PhoneCluster Installed!"
echo "============================================================"
echo "Commands ready anywhere:"
echo "  pc                  -> Open friendly interactive menu"
echo "  pc top              -> Pretty multi-device shared btop Terminal UI"
echo "  pc dashboard        -> Accessible Web Control Center + Web Terminal (:8080)"
echo "  pc pair             -> (Master) Open temporary 2-min encrypted Pairing Window"
echo "  pc join             -> (New phone) Auto-find Master on Wi-Fi & join with 6-digit PIN"
echo "  pc doctor           -> Health, security & 24/7 battery safety check"
echo "  pc token            -> Print unlock token for the Web UI"
echo "  pc sync             -> Push code & scoped configs to all worker phones"
echo

if [[ "${ROLE}" == "master" && "${NON_INTERACTIVE}" -eq 0 && ! -f "${INSTALL_DIR}/config/cluster.json" ]]; then
  RUN_WIZ="$(ask "Launch the Guided Setup Wizard right now? [Y/n]: " "y")"
  if [[ "${RUN_WIZ,,}" == "y" || "${RUN_WIZ,,}" == "yes" ]]; then
    if [[ -r /dev/tty ]]; then
      "${BIN_DIR}/phonecluster" wizard < /dev/tty
    else
      "${BIN_DIR}/phonecluster" wizard
    fi
  fi
elif [[ "${ROLE}" == "worker" && "${NON_INTERACTIVE}" -eq 0 && ! -f "${INSTALL_DIR}/config/cluster.json" ]]; then
  echo "Ready to join your cluster securely!"
  echo "  -> On your Master phone, open Pairing first (Web UI Tab 6 or run: pc pair)"
  RUN_JOIN="$(ask "Auto-search Wi-Fi for your Master phone and pair now? [Y/n]: " "y")"
  if [[ "${RUN_JOIN,,}" == "y" || "${RUN_JOIN,,}" == "yes" ]]; then
    if [[ -r /dev/tty ]]; then
      "${BIN_DIR}/phonecluster" join < /dev/tty
    else
      "${BIN_DIR}/phonecluster" join
    fi
  fi
fi
