#!/usr/bin/env bash
# PhoneCluster Universal One-Command Installer
# Works on: Android Termux (unrooted), Debian 13 ARM64 chroot, and Linux/macOS PCs.
#
# Quick run:
#   bash install.sh
#   bash install.sh --master --with-compute
#   bash install.sh --worker --node-id node1 --with-compute
set -euo pipefail

ROLE=""
NODE_ID=""
WITH_COMPUTE=0
NON_INTERACTIVE=0
INSTALL_DIR="${PHONECLUSTER_DIR:-${HOME}/phonecluster}"
REPO_URL="${PHONECLUSTER_REPO_URL:-}"

usage() {
  cat <<'EOF'
PhoneCluster Easy Installer

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master) ROLE="master"; shift ;;
    --worker) ROLE="worker"; shift ;;
    --node-id) NODE_ID="$2"; shift 2 ;;
    --with-compute) WITH_COMPUTE=1; shift ;;
    --dir) INSTALL_DIR="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

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
elif [[ ! -f "${INSTALL_DIR}/phonecluster_cli.py" ]]; then
  if [[ -z "${REPO_URL}" ]]; then
    echo "Error: Run install.sh from the cloned repo folder, or set PHONECLUSTER_REPO_URL=<git-url>." >&2
    exit 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    if [[ "${IS_TERMUX}" -eq 1 ]]; then
      pkg update -y && pkg install -y git
    else
      echo "Error: 'git' is required to clone ${REPO_URL}." >&2
      exit 1
    fi
  fi
  echo "Cloning PhoneCluster into ${INSTALL_DIR}..."
  git clone "${REPO_URL}" "${INSTALL_DIR}"
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
  read -r -p "Choose [1/2/3] (default 1): " CHOICE || CHOICE="1"
  case "${CHOICE:-1}" in
    1) ROLE="master" ;;
    2) ROLE="worker" ;;
    *) ROLE="cli-only" ;;
  esac
fi

if [[ "${ROLE}" == "master" && -z "${NODE_ID}" ]]; then
  NODE_ID="node0"
elif [[ "${ROLE}" == "worker" && -z "${NODE_ID}" ]]; then
  if [[ "${NON_INTERACTIVE}" -eq 0 ]]; then
    read -r -p "Enter Worker node ID [node1]: " NODE_ID || NODE_ID="node1"
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
echo "  pc wizard           -> Guided setup wizard (auto-discovers phones on Wi-Fi)"
echo "  pc status           -> Unified 'one PC' cluster view"
echo "  pc doctor           -> Health, SSH & 24/7 battery safety check"
echo "  pc dashboard        -> Accessible Web Control Center (port 8080)"
echo

if [[ "${ROLE}" == "master" && "${NON_INTERACTIVE}" -eq 0 && ! -f "${INSTALL_DIR}/config/cluster.json" ]]; then
  read -r -p "Launch the Guided Setup Wizard right now? [Y/n]: " RUN_WIZ || RUN_WIZ="y"
  if [[ -z "${RUN_WIZ}" || "${RUN_WIZ,,}" == "y" || "${RUN_WIZ,,}" == "yes" ]]; then
    "${BIN_DIR}/phonecluster" wizard
  fi
fi
