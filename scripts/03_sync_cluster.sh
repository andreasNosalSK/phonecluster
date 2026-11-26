#!/usr/bin/env bash
# 03_sync_cluster.sh — Run from the Master phone (or PC) to sync PhoneCluster code +
# config/cluster.json to every node over SSH and restart the worker daemon.
set -euo pipefail

CONFIG_PATH="${PHONECLUSTER_CONFIG:-config/cluster.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_ROOT="${PHONECLUSTER_MODULE_ROOT:-${REPO_ROOT}}"
REMOTE_DIR="~/phonecluster"
SETUP_KEYS=0
SKIP_LOCAL=""
DRY_RUN=0
SELECTED_NODES=()

usage() {
  cat <<'EOF'
Usage: ./scripts/03_sync_cluster.sh [options]

Options:
  -c, --config <path>   Path to cluster.json (default: config/cluster.json)
  --setup-keys          Run ssh-copy-id for each node before syncing
  --skip-node <id>      Skip syncing a specific node (e.g. node0 if running on Master)
  --node-id <id>        Sync only this node (repeat for multiple nodes)
  --dry-run             Preview the selected nodes without SSH or key setup
  --remote-dir <path>   Destination folder on remote nodes (default: ~/phonecluster)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config)
      [[ $# -ge 2 ]] || { echo "Error: $1 requires a path" >&2; exit 2; }
      CONFIG_PATH="$2"; shift 2 ;;
    --setup-keys) SETUP_KEYS=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --node-id)
      [[ $# -ge 2 ]] || { echo "Error: --node-id requires a node id" >&2; exit 2; }
      SELECTED_NODES+=("$2"); shift 2 ;;
    --skip-node)
      [[ $# -ge 2 ]] || { echo "Error: --skip-node requires a node id" >&2; exit 2; }
      SKIP_LOCAL="$2"; shift 2 ;;
    --remote-dir)
      [[ $# -ge 2 ]] || { echo "Error: --remote-dir requires a path" >&2; exit 2; }
      REMOTE_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Error: Config not found at '${CONFIG_PATH}'. Run: python3 phonecluster_cli.py init-config" >&2
  exit 1
fi

# Extract & strictly validate node list via phonecluster.config (blocks SSH option injection & normalizes role casing)
NODES_PSV="$(python3 - "${CONFIG_PATH}" "${MODULE_ROOT}" "${SKIP_LOCAL}" ${SELECTED_NODES[@]+"${SELECTED_NODES[@]}"} <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
from phonecluster.config import load_config

cfg = load_config(sys.argv[1])
skip_id, *requested = sys.argv[3:]
known = {n.id for n in cfg.nodes}
missing = set(requested) - known
if missing:
    raise SystemExit("Unknown sync node ID(s): " + ", ".join(sorted(missing)))
if skip_id and skip_id not in known:
    raise SystemExit(f"Unknown --skip-node ID: {skip_id}")
if skip_id in requested:
    raise SystemExit(f"Node {skip_id} was both selected and skipped.")
nodes = [n for n in cfg.nodes if n.id != skip_id and (not requested or n.id in requested)]
selected_ids = {n.id for n in nodes}
repairs = [n for n in cfg.workers_needing_tokens() if n.id in selected_ids]
if repairs:
    node_ids = ", ".join(n.id for n in repairs)
    raise SystemExit(f"Workers need individual credentials: {node_ids}. On the Master, run pc token --rotate with this config, then retry sync.")
legacy_adb = [n.id for n in nodes if "usb-mode:adb" in n.tags and n.adb is None]
if legacy_adb:
    raise SystemExit("Run pc usb-hub setup --mode adb --write-config to record the device listener ports for: " + ", ".join(legacy_adb))
for n in nodes:
    fields = [
        n.id,
        n.host,
        str(n.ssh_port),
        n.ssh_user,
        n.role,
    ]
    if any("|" in f or "\n" in f or "\r" in f for f in fields):
        raise SystemExit(f"Invalid control/delimiter character in node entry: {n.id}")
    print("|".join(fields))
PY
)"

if [[ -z "${NODES_PSV}" ]]; then
  echo "No nodes selected for sync."
  exit 0
fi

ARCHIVE_HASH_CODE='import hashlib, sys
digest = hashlib.sha256()
with open(sys.argv[1], "rb") as archive:
    for chunk in iter(lambda: archive.read(65536), b""):
        digest.update(chunk)
print(digest.hexdigest())'
if [[ "${DRY_RUN}" -eq 0 ]]; then
  SYNC_ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/phonecluster-sync.XXXXXX")"
  trap 'rm -f -- "${SYNC_ARCHIVE}"' EXIT
  tar --exclude='__pycache__' --exclude='*.pyc' -cf "${SYNC_ARCHIVE}" -C "${MODULE_ROOT}" phonecluster \
    -C "${REPO_ROOT}" phonecluster_cli.py scripts examples
  ARCHIVE_SHA="$(python3 -c "${ARCHIVE_HASH_CODE}" "${SYNC_ARCHIVE}")"
fi

if [[ "${DRY_RUN}" -eq 0 && "${SETUP_KEYS}" -eq 1 && ! -f "${HOME}/.ssh/id_ed25519" ]]; then
  echo "Generating SSH key (~/.ssh/id_ed25519)..."
  mkdir -p -m 700 "${HOME}/.ssh"
  chmod 700 "${HOME}/.ssh"
  ssh-keygen -t ed25519 -N "" -f "${HOME}/.ssh/id_ed25519"
fi

while IFS='|' read -r NODE_ID HOST SSH_PORT SSH_USER ROLE <&3; do
  [[ -z "${NODE_ID}" ]] && continue
  TARGET="${HOST}"
  [[ -n "${SSH_USER}" ]] && TARGET="${SSH_USER}@${HOST}"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "Would transfer code and config, then restart '${NODE_ID}' (${ROLE}) at ${TARGET}:${SSH_PORT}"
    continue
  fi

  echo "=== Syncing '${NODE_ID}' (${ROLE}) -> ${TARGET}:${SSH_PORT} ==="

  if [[ "${SETUP_KEYS}" -eq 1 ]]; then
    ssh-copy-id -p "${SSH_PORT}" -- "${TARGET}"
  fi

  # POSIX-safe single-quote escaping via Python shlex.quote (immune to spaces/metacharacters/quotes)
  SQ_RDIR="$(python3 -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "${REMOTE_DIR}")"
  SQ_NID="$(python3 -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "${NODE_ID}")"

  # Use POSIX shell syntax for the remote command, including Termux and Ubuntu Touch shells.
  REMOTE_PATH="set -eu; RDIR=${SQ_RDIR}; case \"\$RDIR\" in '~') RDIR=\"\$HOME\" ;; '~/'*) RDIR=\"\$HOME/\${RDIR#??}\" ;; esac"
ARCHIVE_SAFE_CHECK='import os, pathlib, sys, tarfile
archive, dest = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]).resolve()
if dest.is_symlink():
    raise SystemExit("Sync destination cannot be a symlink.")
with tarfile.open(archive, "r") as tf:
    for m in tf.getmembers():
        if m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
            raise SystemExit(f"Unsafe tar member type rejected: {m.name}")
        p = pathlib.PurePosixPath(m.name)
        if p.is_absolute() or ".." in p.parts:
            raise SystemExit(f"Unsafe tar member path rejected: {m.name}")
        cur = dest
        for part in p.parts:
            cur = cur / part
            if cur.is_symlink():
                raise SystemExit(f"Refusing to extract through symlink: {cur}")'
  REMOTE_UNPACK="${REMOTE_PATH}
mkdir -p \"\$RDIR/config\" \"\$RDIR/logs\"
ARCHIVE=\$(mktemp \"\$RDIR/.phonecluster-sync.XXXXXX\")
trap 'rm -f -- \"\$ARCHIVE\"' 0
cat > \"\$ARCHIVE\"
CHECKSUM=\$(python3 -c '${ARCHIVE_HASH_CODE}' \"\$ARCHIVE\")
if [ \"\$CHECKSUM\" != '${ARCHIVE_SHA}' ]; then
    echo 'Sync archive checksum mismatch. Code was not extracted.' >&2
    exit 1
fi
python3 -c '${ARCHIVE_SAFE_CHECK}' \"\$ARCHIVE\" \"\$RDIR\"
tar -xf \"\$ARCHIVE\" -C \"\$RDIR\"
cd \"\$RDIR\"
python3 -m phonecluster.config_transfer config/cluster.json"
  REMOTE_REVISION="$(
    ssh -p "${SSH_PORT}" -- "${TARGET}" "${REMOTE_UNPACK}" < "${SYNC_ARCHIVE}"
  )"
  if [[ -n "${REMOTE_REVISION}" && ! "${REMOTE_REVISION}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: Invalid config revision returned by '${NODE_ID}'." >&2
    exit 1
  fi

  # Build scoped config locally FIRST so a Python failure NEVER truncates remote config/cluster.json to 0 bytes
  SCOPED_CFG="$(python3 - "${CONFIG_PATH}" "${MODULE_ROOT}" "${NODE_ID}" "${ROLE}" "${HOST}" "${SSH_PORT}" "${SSH_USER}" <<'PY'
import json, socket, sys
cfg_path, module_root, node_id, role, host, ssh_port, ssh_user = sys.argv[1:]
sys.path.insert(0, module_root)
from phonecluster.config import ClusterConfig

with open(cfg_path, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)
cluster = ClusterConfig.from_dict(cfg)
target = cluster.get_node(node_id)
if (target.role, target.host, str(target.ssh_port), target.ssh_user) != (role, host, ssh_port, ssh_user):
    raise SystemExit(f"Destination for {node_id} changed during sync. Retry with the updated config.")
if role == "master":
    out = cfg
else:
    if target in cluster.workers_needing_tokens():
        raise SystemExit(f"Worker {node_id} needs an individual token. On the Master, run pc token --rotate with this config, then retry sync.")
    node = next(n for n in cfg["nodes"] if n["id"].strip() == node_id)
    master = next((n for n in cfg["nodes"] if str(n.get("role") or "").strip().lower() == "master"), cfg["nodes"][0])
    tok = target.auth_token
    scoped_node = dict(node)
    scoped_node["auth_token"] = tok
    if target.adb is not None:
        scoped_node["worker_port"] = target.adb.remote_worker_port
        scoped_node["ssh_port"] = target.adb.remote_ssh_port
        scoped_node.pop("adb", None)
        scoped_node["tags"] = [
            tag for tag in target.tags if tag != "usb-mode:adb" and not tag.startswith("usb-serial:")
        ]
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
            "require_signed_requests": bool(net_cfg.get("require_signed_requests", False)),
            "allowed_master_ips": allowed_masters,
        },
        "nodes": [scoped_node],
    }
print(json.dumps(out, indent=2))
PY
)"
  if [[ -z "${SCOPED_CFG}" ]]; then
    echo "Error: Failed to build scoped config for '${NODE_ID}'." >&2
    exit 1
  fi
  printf '%s\n' "${SCOPED_CFG}" \
    | ssh -p "${SSH_PORT}" -- "${TARGET}" \
      "${REMOTE_PATH}; cd \"\$RDIR\"; python3 -m phonecluster.config_transfer config/cluster.json --expect '${REMOTE_REVISION}'"

  # Restart worker daemon cleanly on remote node (arguments pre-quoted via shlex.quote so spaces/metachars stay literal)
  ssh -p "${SSH_PORT}" -- "${TARGET}" "bash -s -- ${SQ_NID} ${SQ_RDIR}" <<'REMOTE'
set -euo pipefail
NODE_ID="$1"
case "$2" in
  '~') REMOTE_DIR="$HOME" ;;
  '~/'*) REMOTE_DIR="$HOME/${2#??}" ;;
  *) REMOTE_DIR="$2" ;;
esac
if [[ -d "/snap/bin" ]]; then
  export PATH="/snap/bin:${HOME}/.local/bin:${PATH}"
fi
LOG_DIR="${REMOTE_DIR}/logs"
PID_FILE="${LOG_DIR}/worker-${NODE_ID}.pid"
mkdir -p "${LOG_DIR}"

# Prefer systemd --user unit on Ubuntu Touch / systemd nodes if already enabled so systemd never fights nohup
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
UT_UNIT="${HOME}/.config/systemd/user/phonecluster-worker.service"
if [[ -f "${UT_UNIT}" ]] && command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  if ! grep -Fq -- "--node-id ${NODE_ID}" "${UT_UNIT}" 2>/dev/null; then
    if [[ -f "${REMOTE_DIR}/scripts/06_ubuntu_touch_node_setup.sh" ]]; then
      bash "${REMOTE_DIR}/scripts/06_ubuntu_touch_node_setup.sh" --boot-only --node-id "${NODE_ID}" --repo-dir "${REMOTE_DIR}" >/dev/null 2>&1 || true
    fi
  fi
  if grep -Fq -- "--node-id ${NODE_ID}" "${UT_UNIT}" 2>/dev/null; then
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    systemctl --user restart phonecluster-worker.service
    echo "Restarted systemd --user phonecluster-worker.service for '${NODE_ID}'"
    exit 0
  fi
fi

if [[ -f "${PID_FILE}" ]]; then
  OLD_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
  if [[ "${OLD_PID}" =~ ^[0-9]+$ ]] && (( OLD_PID > 1 )) && kill -0 "${OLD_PID}" 2>/dev/null; then
    SHOULD_KILL=1
    if [[ -d /proc ]]; then
      if [[ -r "/proc/${OLD_PID}/cmdline" ]]; then
        OLD_CMDLINE="$(tr '\0' ' ' < "/proc/${OLD_PID}/cmdline" 2>/dev/null || true)"
        [[ "${OLD_CMDLINE}" == *"phonecluster"* ]] || SHOULD_KILL=0
      else
        SHOULD_KILL=0
      fi
    fi
    if [[ "${SHOULD_KILL}" -eq 1 ]]; then
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
fi

# Also clean up any orphaned worker for the same node_id started outside PID file
if command -v pkill >/dev/null 2>&1; then
  NODE_ID_RE="${NODE_ID//./\\.}"
  pkill -f "phonecluster_cli\.py.*worker --node-id ${NODE_ID_RE}(\$| )" 2>/dev/null || true
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
done 3<<< "${NODES_PSV}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  exit 0
fi

echo
echo "Sync complete! Verify the whole cluster with:"
echo "  python3 phonecluster_cli.py --config ${CONFIG_PATH} status"
