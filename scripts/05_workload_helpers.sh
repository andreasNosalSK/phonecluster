#!/usr/bin/env bash
# 05_workload_helpers.sh — Start/stop distributed compute & Docker cluster daemons on cluster phones
# (Compiler farm via distccd, Distributed AI via llama.cpp rpc-server, Docker / Snap Docker Swarm).
set -euo pipefail

if [[ -d "/snap/bin" ]]; then
  export PATH="/snap/bin:${HOME}/.local/bin:${PATH}"
fi

CMD="${1:-help}"
shift || true

case "${CMD}" in
  distcc-start)
    ALLOW_CIDR="${1:-192.168.1.0/24}"
    JOBS="${2:-$(nproc 2>/dev/null || echo 4)}"
    if [[ "${ALLOW_CIDR}" == -* || "${ALLOW_CIDR}" =~ [[:space:]] ]]; then
      echo "Error: Invalid allow CIDR '${ALLOW_CIDR}'." >&2
      exit 2
    fi
    if [[ ! "${JOBS}" =~ ^[0-9]+$ ]] || (( JOBS < 1 || JOBS > 128 )); then
      echo "Error: Invalid jobs count '${JOBS}' (expected 1..128)." >&2
      exit 2
    fi
    if ! command -v distccd >/dev/null 2>&1; then
      echo "Error: distccd not installed. Run: pkg install distcc (Termux) or apt install distcc (Debian 13)" >&2
      exit 1
    fi
    pkill -x distccd 2>/dev/null || true
    sleep 0.2
    EXTRA_USER_ARGS=()
    if [[ "$(id -u)" -eq 0 ]]; then
      if id distccd >/dev/null 2>&1; then
        EXTRA_USER_ARGS=(--user distccd)
      else
        EXTRA_USER_ARGS=(--user nobody)
      fi
    fi
    LISTEN_ADDR="0.0.0.0"
    [[ "${ALLOW_CIDR}" == *:* ]] && LISTEN_ADDR="::"
    distccd --daemon --allow "${ALLOW_CIDR}" --jobs "${JOBS}" --listen "${LISTEN_ADDR}" --port 3632 ${EXTRA_USER_ARGS[@]+"${EXTRA_USER_ARGS[@]}"} </dev/null >/dev/null 2>&1
    echo "Started distccd (allow=${ALLOW_CIDR}, jobs=${JOBS}, listen=${LISTEN_ADDR}, port=3632)"
    ;;

  distcc-stop)
    pkill -x distccd 2>/dev/null && echo "Stopped distccd" || echo "distccd was not running"
    ;;

  llama-rpc-start)
    LLAMA_DIR="${1:-${HOME}/llama.cpp}"
    PORT="${2:-50052}"
    if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
      echo "Error: Invalid port '${PORT}' (expected 1..65535)." >&2
      exit 2
    fi
    BIN=""
    for CAND in "${LLAMA_DIR}/build/bin/rpc-server" "${LLAMA_DIR}/rpc-server" "$(command -v rpc-server 2>/dev/null || true)"; do
      if [[ -n "${CAND}" && -x "${CAND}" ]]; then
        BIN="${CAND}"
        break
      fi
    done
    if [[ -z "${BIN}" ]]; then
      echo "Error: rpc-server binary not found (checked '${LLAMA_DIR}/build/bin/rpc-server' and PATH)." >&2
      echo "Build llama.cpp with:" >&2
      echo "  git clone https://github.com/ggml-org/llama.cpp ${LLAMA_DIR}" >&2
      echo "  cmake -S ${LLAMA_DIR} -B ${LLAMA_DIR}/build -DGGML_RPC=ON && cmake --build ${LLAMA_DIR}/build -j" >&2
      exit 1
    fi
    LOG_DIR="${HOME}/phonecluster/logs"
    mkdir -p "${LOG_DIR}" 2>/dev/null || LOG_DIR="${TMPDIR:-/tmp}"
    PID_FILE="${LOG_DIR}/llama-rpc-${PORT}.pid"
    if [[ -f "${PID_FILE}" ]]; then
      OLD_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
      if [[ "${OLD_PID}" =~ ^[0-9]+$ ]] && (( OLD_PID > 1 )) && kill -0 "${OLD_PID}" 2>/dev/null; then
        SHOULD_KILL=1
        if [[ -d /proc ]]; then
          if [[ -r "/proc/${OLD_PID}/cmdline" ]]; then
            OLD_CMDLINE="$(tr '\0' ' ' < "/proc/${OLD_PID}/cmdline" 2>/dev/null || true)"
            [[ "${OLD_CMDLINE}" == *"rpc-server"* ]] || SHOULD_KILL=0
          else
            SHOULD_KILL=0
          fi
        fi
        if [[ "${SHOULD_KILL}" -eq 1 ]]; then
          kill "${OLD_PID}" 2>/dev/null || true
        fi
      fi
    fi
    pkill -x rpc-server 2>/dev/null || true
    sleep 0.2
    nohup "${BIN}" -H 0.0.0.0 -p "${PORT}" >> "${LOG_DIR}/llama-rpc.log" 2>&1 < /dev/null &
    NEW_PID=$!
    echo "${NEW_PID}" > "${PID_FILE}"
    sleep 0.3
    if ! kill -0 "${NEW_PID}" 2>/dev/null; then
      echo "Error: llama.cpp rpc-server exited immediately. Log:" >&2
      tail -n 10 "${LOG_DIR}/llama-rpc.log" >&2 || true
      exit 1
    fi
    echo "Started llama.cpp rpc-server on 0.0.0.0:${PORT} (PID ${NEW_PID}, bin=${BIN})"
    ;;

  llama-rpc-stop)
    STOPPED=0
    for PF in "${HOME}/phonecluster/logs"/llama-rpc-*.pid "${TMPDIR:-/tmp}"/llama-rpc-*.pid; do
      if [[ -f "${PF}" ]]; then
        OLD_PID="$(cat "${PF}" 2>/dev/null || true)"
        if [[ "${OLD_PID}" =~ ^[0-9]+$ ]] && (( OLD_PID > 1 )) && kill -0 "${OLD_PID}" 2>/dev/null; then
          SHOULD_KILL=1
          if [[ -d /proc ]]; then
            if [[ -r "/proc/${OLD_PID}/cmdline" ]]; then
              OLD_CMDLINE="$(tr '\0' ' ' < "/proc/${OLD_PID}/cmdline" 2>/dev/null || true)"
              [[ "${OLD_CMDLINE}" == *"rpc-server"* ]] || SHOULD_KILL=0
            else
              SHOULD_KILL=0
            fi
          fi
          if [[ "${SHOULD_KILL}" -eq 1 ]]; then
            kill "${OLD_PID}" 2>/dev/null && STOPPED=1 || true
          fi
        fi
        rm -f "${PF}"
      fi
    done
    if pkill -x rpc-server 2>/dev/null; then
      STOPPED=1
    fi
    if [[ "${STOPPED}" -eq 1 ]]; then
      echo "Stopped llama.cpp rpc-server"
    else
      echo "rpc-server was not running"
    fi
    ;;

  docker-status)
    DK_BIN="$(command -v docker 2>/dev/null || true)"
    [[ -z "${DK_BIN}" && -x "/snap/bin/docker" ]] && DK_BIN="/snap/bin/docker"
    if [[ -z "${DK_BIN}" ]]; then
      echo "Error: docker binary not found (checked PATH and /snap/bin/docker)." >&2
      exit 1
    fi
    IS_SNAP="no"
    [[ "${DK_BIN}" == /snap/* || -d "/var/snap/docker" ]] && IS_SNAP="yes"
    echo "Docker binary : ${DK_BIN} (snap=${IS_SNAP})"
    echo "Volume root   : ${HOME}/phonecluster/docker-data"
    "${DK_BIN}" info --format 'Server: {{.ServerVersion}} | Swarm: {{.Swarm.LocalNodeState}} (manager={{.Swarm.ControlAvailable}}, nodes={{.Swarm.Nodes}}) | Running: {{.ContainersRunning}}/{{.Containers}}'
    "${DK_BIN}" ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
    ;;

  docker-swarm-init)
    ADV_ADDR="${1:-}"
    if [[ -n "${ADV_ADDR}" ]] && [[ "${ADV_ADDR}" == -* || "${ADV_ADDR}" =~ [[:space:]] ]]; then
      echo "Error: Invalid advertise address '${ADV_ADDR}'." >&2
      exit 2
    fi
    DK_BIN="$(command -v docker 2>/dev/null || true)"
    [[ -z "${DK_BIN}" && -x "/snap/bin/docker" ]] && DK_BIN="/snap/bin/docker"
    if [[ -z "${DK_BIN}" ]]; then
      echo "Error: docker binary not found (install via: sudo snap install docker)." >&2
      exit 1
    fi
    SW_STATE="$("${DK_BIN}" info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo inactive)"
    if [[ "${SW_STATE}" == "active" ]]; then
      echo "Docker Swarm is already active on this node."
    else
      if [[ -n "${ADV_ADDR}" ]]; then
        "${DK_BIN}" swarm init --advertise-addr "${ADV_ADDR}"
      else
        "${DK_BIN}" swarm init
      fi
    fi
    ;;

  docker-swarm-join)
    MGR_ADDR="${1:-}"
    if [[ -z "${MGR_ADDR}" || "${MGR_ADDR}" == -* || "${MGR_ADDR}" =~ [[:space:]] ]]; then
      echo "Error: Usage: docker-swarm-join <manager_ip:2377> (pass token in PHONECLUSTER_SWARM_TOKEN env var)" >&2
      exit 2
    fi
    if [[ -z "${PHONECLUSTER_SWARM_TOKEN:-}" ]]; then
      echo "Error: PHONECLUSTER_SWARM_TOKEN environment variable is required (never pass secrets in CLI args)." >&2
      exit 2
    fi
    DK_BIN="$(command -v docker 2>/dev/null || true)"
    [[ -z "${DK_BIN}" && -x "/snap/bin/docker" ]] && DK_BIN="/snap/bin/docker"
    if [[ -z "${DK_BIN}" ]]; then
      echo "Error: docker binary not found." >&2
      exit 1
    fi
    SW_STATE="$("${DK_BIN}" info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo inactive)"
    if [[ "${SW_STATE}" == "active" ]]; then
      echo "Already part of an active Docker Swarm."
    else
      "${DK_BIN}" swarm join --token "${PHONECLUSTER_SWARM_TOKEN}" "${MGR_ADDR}"
    fi
    ;;

  docker-swarm-leave)
    DK_BIN="$(command -v docker 2>/dev/null || true)"
    [[ -z "${DK_BIN}" && -x "/snap/bin/docker" ]] && DK_BIN="/snap/bin/docker"
    if [[ -z "${DK_BIN}" ]]; then
      echo "Error: docker binary not found." >&2
      exit 1
    fi
    "${DK_BIN}" swarm leave --force
    ;;

  help|-h|--help)
    cat <<'EOF'
Usage: bash scripts/05_workload_helpers.sh <subcommand> [args]

Subcommands:
  distcc-start [cidr] [jobs]       Start distccd compiler worker (default: 192.168.1.0/24)
  distcc-stop                      Stop distccd
  llama-rpc-start [dir] [port]     Start llama.cpp rpc-server (default: ~/llama.cpp, port 50052)
  llama-rpc-stop                   Stop llama.cpp rpc-server
  docker-status                    Show Docker / Snap Docker version, Swarm state, and running containers
  docker-swarm-init [adv_ip]       Initialize Docker Swarm manager on this phone
  docker-swarm-join <mgr:2377>     Join Docker Swarm (reads token from PHONECLUSTER_SWARM_TOKEN env var)
  docker-swarm-leave               Leave Docker Swarm on this phone

Tip: Run across all phones from your Master phone in one command:
  python3 phonecluster_cli.py run --target all "bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start 192.168.1.0/24"
  python3 phonecluster_cli.py docker status
  python3 phonecluster_cli.py docker swarm-init
EOF
    ;;

  *)
    echo "Error: Unknown subcommand '${CMD}'. Run with --help for usage." >&2
    exit 2
    ;;
esac
