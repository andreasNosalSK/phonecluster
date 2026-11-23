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
    if ! command -v distccd >/dev/null 2>&1; then
      echo "Error: distccd not installed. Run: pkg install distcc (Termux) or apt install distcc (Debian 13)" >&2
      exit 1
    fi
    pkill -x distccd 2>/dev/null || true
    distccd --daemon --allow "${ALLOW_CIDR}" --jobs "${JOBS}" --listen 0.0.0.0 --port 3632
    echo "Started distccd (allow=${ALLOW_CIDR}, jobs=${JOBS}, port=3632)"
    ;;

  distcc-stop)
    pkill -x distccd 2>/dev/null && echo "Stopped distccd" || echo "distccd was not running"
    ;;

  llama-rpc-start)
    LLAMA_DIR="${1:-${HOME}/llama.cpp}"
    PORT="${2:-50052}"
    BIN="${LLAMA_DIR}/build/bin/rpc-server"
    if [[ ! -x "${BIN}" ]]; then
      echo "Error: rpc-server binary not found at '${BIN}'." >&2
      echo "Build llama.cpp with:" >&2
      echo "  git clone https://github.com/ggml-org/llama.cpp ${LLAMA_DIR}" >&2
      echo "  cmake -S ${LLAMA_DIR} -B ${LLAMA_DIR}/build -DGGML_RPC=ON && cmake --build ${LLAMA_DIR}/build -j" >&2
      exit 1
    fi
    pkill -f "rpc-server.*-p ${PORT}" 2>/dev/null || true
    mkdir -p "${HOME}/phonecluster/logs"
    nohup "${BIN}" -H 0.0.0.0 -p "${PORT}" >> "${HOME}/phonecluster/logs/llama-rpc.log" 2>&1 < /dev/null &
    echo "Started llama.cpp rpc-server on 0.0.0.0:${PORT} (PID $!)"
    ;;

  llama-rpc-stop)
    pkill -f "rpc-server" 2>/dev/null && echo "Stopped llama.cpp rpc-server" || echo "rpc-server was not running"
    ;;

  help|-h|--help|*)
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
esac
