#!/usr/bin/env bash
# 03_sync_cluster.sh — Run from the Master phone (or PC) to sync PhoneCluster code +
# config/cluster.json to every node over SSH and restart the worker daemon.
set -euo pipefail

CONFIG_PATH="${PHONECLUSTER_CONFIG:-config/cluster.json}"
REMOTE_DIR="~/phonecluster"
SETUP_KEYS=0
SKIP_LOCAL=""

usage() {
  cat <<'EOF'
Usage: ./scripts/03_sync_cluster.sh [options]

Options:
  -c, --config <path>   Path to cluster.json (default: config/cluster.json)
  --setup-keys          Run ssh-copy-id for each node before syncing
  --skip-node <id>      Skip syncing a specific node (e.g. node0 if running on Master)
  --remote-dir <path>   Destination folder on remote nodes (default: ~/phonecluster)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config) CONFIG_PATH="$2"; shift 2 ;;
    --setup-keys) SETUP_KEYS=1; shift ;;
    --skip-node) SKIP_LOCAL="$2"; shift 2 ;;
    --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Error: Config not found at '${CONFIG_PATH}'. Run: python3 phonecluster_cli.py init-config" >&2
  exit 1
fi

if [[ "${SETUP_KEYS}" -eq 1 && ! -f "${HOME}/.ssh/id_ed25519" ]]; then
  echo "Generating SSH key (~/.ssh/id_ed25519)..."
  mkdir -p "${HOME}/.ssh"
  ssh-keygen -t ed25519 -N "" -f "${HOME}/.ssh/id_ed25519"
fi

# Extract node list cleanly via stdlib Python (no jq required)
NODES_TSV="$(python3 - "${CONFIG_PATH}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    cfg = json.load(fh)
for n in cfg["nodes"]:
    print(f"{n['id']}\t{n['host']}\t{n.get('ssh_port', 8022)}\t{n.get('ssh_user', '')}\t{n.get('role', 'worker')}")
PY
)"

while IFS=$'\t' read -r NODE_ID HOST SSH_PORT SSH_USER ROLE; do
  [[ -z "${NODE_ID}" ]] && continue
  if [[ "${NODE_ID}" == "${SKIP_LOCAL}" ]]; then
    echo "--- Skipping local node '${NODE_ID}' (${HOST}) ---"
    continue
  fi

  TARGET="${HOST}"
  [[ -n "${SSH_USER}" ]] && TARGET="${SSH_USER}@${HOST}"

  echo "=== Syncing '${NODE_ID}' (${ROLE}) -> ${TARGET}:${SSH_PORT} ==="

  if [[ "${SETUP_KEYS}" -eq 1 ]]; then
    ssh-copy-id -p "${SSH_PORT}" "${TARGET}"
  fi

  # Stream project files via tar over SSH (works cleanly without rsync)
  tar -cf - \
    phonecluster \
    phonecluster_cli.py \
    scripts \
    examples \
    "${CONFIG_PATH}" \
    | ssh -p "${SSH_PORT}" "${TARGET}" \
      "mkdir -p ${REMOTE_DIR}/config ${REMOTE_DIR}/logs && tar -xf - -C ${REMOTE_DIR} && cp -f ${REMOTE_DIR}/${CONFIG_PATH} ${REMOTE_DIR}/config/cluster.json 2>/dev/null || true"

  # Restart worker daemon cleanly on remote node
  ssh -p "${SSH_PORT}" "${TARGET}" bash -s -- "${NODE_ID}" "${REMOTE_DIR}" <<'REMOTE'
set -euo pipefail
NODE_ID="$1"
REMOTE_DIR="${2/#\~/$HOME}"
LOG_DIR="${REMOTE_DIR}/logs"
PID_FILE="${LOG_DIR}/worker-${NODE_ID}.pid"
mkdir -p "${LOG_DIR}"

if [[ -f "${PID_FILE}" ]]; then
  OLD_PID="$(cat "${PID_FILE}")"
  if [[ -n "${OLD_PID}" ]] && kill -0 "${OLD_PID}" 2>/dev/null; then
    kill "${OLD_PID}" || true
    sleep 1
  fi
fi

cd "${REMOTE_DIR}"
nohup python3 "${REMOTE_DIR}/phonecluster_cli.py" \
  --config "${REMOTE_DIR}/config/cluster.json" \
  worker --node-id "${NODE_ID}" \
  >> "${LOG_DIR}/worker-${NODE_ID}.log" 2>&1 < /dev/null &
echo $! > "${PID_FILE}"
echo "Started worker '${NODE_ID}' (PID $(cat "${PID_FILE}"))"
REMOTE
done <<< "${NODES_TSV}"

echo
echo "Sync complete! Verify the whole cluster with:"
echo "  python3 phonecluster_cli.py --config ${CONFIG_PATH} status"
