#!/usr/bin/env bash
# 05_workload_helpers.sh — Start/stop distributed compute daemons on cluster phones
# (Compiler farm via distccd, Distributed AI via llama.cpp rpc-server).
set -euo pipefail

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

  help|-h|--help)
    cat <<'EOF'
Usage: bash scripts/05_workload_helpers.sh <subcommand> [args]

Subcommands:
  distcc-start [cidr] [jobs]       Start distccd compiler worker (default: 192.168.1.0/24)
  distcc-stop                      Stop distccd
  llama-rpc-start [dir] [port]     Start llama.cpp rpc-server (default: ~/llama.cpp, port 50052)
  llama-rpc-stop                   Stop llama.cpp rpc-server

Tip: Run across all phones from your Master phone in one command:
  python3 phonecluster_cli.py run --target all "bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start 192.168.1.0/24"
  eval "$(python3 phonecluster_cli.py distcc-env)"
EOF
    ;;

  *)
    echo "Error: Unknown subcommand '${CMD}'. Run with --help for usage." >&2
    exit 2
    ;;
esac
