#!/usr/bin/env bash
# 03_sync_cluster.sh — Run from the Master phone (or PC) to sync PhoneCluster code +
# config/cluster.json to every node over SSH and restart the worker daemon.
set -euo pipefail

CONFIG_PATH="${PHONECLUSTER_CONFIG:-config/cluster.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

  # Stream project code via tar over SSH (without shipping Master's full cluster.json to workers)
  tar -C "${REPO_ROOT}" -cf - \
    phonecluster \
    phonecluster_cli.py \
    scripts \
    examples \
    | ssh -p "${SSH_PORT}" "${TARGET}" \
      "mkdir -p ${REMOTE_DIR}/config ${REMOTE_DIR}/logs && tar -xf - -C ${REMOTE_DIR}"

  # Push least-privilege scoped config (workers ONLY receive their own node token, never Master's admin token)
  python3 - "${CONFIG_PATH}" "${NODE_ID}" "${ROLE}" <<'PY' \
    | ssh -p "${SSH_PORT}" "${TARGET}" \
      "umask 077 && cat > ${REMOTE_DIR}/config/cluster.json && chmod 600 ${REMOTE_DIR}/config/cluster.json"
import json, socket, sys
cfg_path, node_id, role = sys.argv[1], sys.argv[2], sys.argv[3]
with open(cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)
if role == "master":
    out = cfg
else:
    node = next(n for n in cfg["nodes"] if n["id"] == node_id)
    master = next((n for n in cfg["nodes"] if n.get("role") == "master"), cfg["nodes"][0])
    tok = node.get("auth_token") or cfg["auth_token"]
    scoped_node = dict(node)
    scoped_node["auth_token"] = tok
    net_cfg = dict(cfg.get("network") or {})
    allowed_masters = [str(x).strip() for x in (net_cfg.get("allowed_master_ips") or []) if str(x).strip()]
    m_host = str(master.get("host") or "").strip()
    if m_host and m_host not in allowed_masters:
        allowed_masters.append(m_host)
    # Also include the local source IP that routes to this worker (handles loopback master_host or multi-homed Pi)
    w_host = str(node.get("host") or "").strip().strip("[]")
    if w_host:
        try:
            fam = socket.AF_INET6 if ":" in w_host else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            try:
                s.connect((w_host, 80))
                src_ip = s.getsockname()[0]
                if src_ip and src_ip not in allowed_masters:
                    allowed_masters.append(src_ip)
            finally:
                s.close()
        except OSError:
            pass
    out = {
        "cluster_name": cfg.get("cluster_name", "phonecluster"),
        "auth_token": tok,
        "safety": cfg.get("safety", {}),
        "network": {
            "enforce_worker_source_ip": bool(net_cfg.get("enforce_worker_source_ip", False)),
            "allowed_master_ips": allowed_masters,
        },
        "nodes": [scoped_node],
    }
print(json.dumps(out, indent=2))
PY

  # Restart worker daemon cleanly on remote node
  ssh -p "${SSH_PORT}" "${TARGET}" bash -s -- "${NODE_ID}" "${REMOTE_DIR}" <<'REMOTE'
set -euo pipefail
NODE_ID="$1"
REMOTE_DIR="${2/#\~/$HOME}"
LOG_DIR="${REMOTE_DIR}/logs"
PID_FILE="${LOG_DIR}/worker-${NODE_ID}.pid"
mkdir -p "${LOG_DIR}"

if [[ -f "${PID_FILE}" ]]; then
  OLD_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ -n "${OLD_PID}" ]] && kill -0 "${OLD_PID}" 2>/dev/null; then
    kill "${OLD_PID}" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "${OLD_PID}" 2>/dev/null || break
      sleep 0.3
    done
    if kill -0 "${OLD_PID}" 2>/dev/null; then
      kill -9 "${OLD_PID}" 2>/dev/null || true
      sleep 0.2
    fi
  fi
fi

# Also clean up any orphaned worker for the same node_id started outside PID file
if command -v pkill >/dev/null 2>&1; then
  pkill -f "phonecluster_cli\.py.*worker --node-id ${NODE_ID}(\$| )" 2>/dev/null || true
  sleep 0.2
fi

cd "${REMOTE_DIR}"
nohup python3 "${REMOTE_DIR}/phonecluster_cli.py" \
  --config "${REMOTE_DIR}/config/cluster.json" \
  worker --node-id "${NODE_ID}" \
  >> "${LOG_DIR}/worker-${NODE_ID}.log" 2>&1 < /dev/null &
NEW_PID=$!
echo "${NEW_PID}" > "${PID_FILE}"
sleep 0.4
if ! kill -0 "${NEW_PID}" 2>/dev/null; then
  echo "ERROR: Worker '${NODE_ID}' exited immediately! Recent log:" >&2
  tail -n 12 "${LOG_DIR}/worker-${NODE_ID}.log" >&2 || true
  exit 1
fi
echo "Started worker '${NODE_ID}' (PID ${NEW_PID})"
REMOTE
done <<< "${NODES_TSV}"

echo
echo "Sync complete! Verify the whole cluster with:"
echo "  python3 phonecluster_cli.py --config ${CONFIG_PATH} status"
