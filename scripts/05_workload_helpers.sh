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
    ALLOW_CIDR="$(python3 - "${ALLOW_CIDR}" <<'PY_CIDR'
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    raise SystemExit(f"Error: Invalid allow CIDR {sys.argv[1]!r}.")
min_prefix = 8 if isinstance(net, ipaddress.IPv4Network) else 48
if net.prefixlen < min_prefix:
    raise SystemExit(f"Error: CIDR {sys.argv[1]!r} is too broad for unauthenticated distccd (prefix must be >= /{min_prefix}).")
print(str(net))
PY_CIDR
)" || exit 2
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

  llama-rpc-start|llama-rpc-stop)
    exec python3 - "$CMD" "$@" <<'PY_RPC'
import fcntl
import ipaddress
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

BINARIES = ("ggml-rpc-server", "rpc-server")
LOG_DIR = Path.home() / "phonecluster" / "logs"


def parse_port(value):
    if not value.isascii() or not value.isdecimal() or len(value) > 5 or not 1 <= int(value) <= 65535:
        raise ValueError(f"Invalid port {value!r} (expected 1..65535).")
    return int(value)


def parse_bind_host(value):
    clean = str(value or "0.0.0.0").strip().strip("[]")
    try:
        return str(ipaddress.ip_address(clean))
    except ValueError as exc:
        raise ValueError(f"Invalid RPC bind host IP {value!r}.") from exc


def process_start(pid, port):
    if pid <= 1:
        return None
    proc = Path("/proc") / str(pid)
    try:
        executable = Path(os.readlink(proc / "exe").removesuffix(" (deleted)"))
        args = (proc / "cmdline").read_bytes().rstrip(b"\x00").split(b"\x00")
        fields = (proc / "stat").read_text(encoding="utf-8", errors="replace").rsplit(") ", 1)[1].split()
        if executable.name in BINARIES and args[-2:] == [b"-p", str(port).encode()] and fields[0] != "Z":
            return fields[19]
    except (OSError, IndexError):
        pass
    return None


def owned_session(file, port):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(file, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            return None
        raw = os.read(fd, 128).decode("ascii", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)
    try:
        fields = raw.split()
        pid = int(fields[0])
    except (IndexError, ValueError):
        return None
    started = process_start(pid, port)
    if started and (len(fields) == 1 or fields == [str(pid), started]):
        return pid, started
    return None


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def start_rpc(directory, port, bind_host="0.0.0.0"):
    session = LOG_DIR / f"llama-rpc-{port}.pid"
    owned = owned_session(session, port)
    if owned:
        if not listening(port):
            raise RuntimeError(f"Managed RPC process exists on port {port}, but its listener is unavailable.")
        print(f"Managed RPC server already running on port {port}.")
        return

    for name in BINARIES:
        candidates = [directory / "build" / "bin" / name, directory / name, shutil.which(name)]
        binary = next((path for path in candidates if path and Path(path).is_file() and os.access(path, os.X_OK)), None)
        if binary is not None:
            break
    else:
        raise RuntimeError(f"Neither ggml-rpc-server nor rpc-server was found under {directory} or on PATH.")

    if listening(port):
        raise RuntimeError(f"Port {port} is already in use.")
    log_path = LOG_DIR / f"llama-rpc-{port}.log"
    with log_path.open("ab") as log:
        process = subprocess.Popen(
            [str(Path(binary).resolve()), "-H", bind_host, "-p", str(port)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
        )
    written = False
    try:
        for _ in range(50):
            if process.poll() is not None:
                break
            started = process_start(process.pid, port)
            if started and not written:
                with tempfile.NamedTemporaryFile(mode="w", dir=LOG_DIR, delete=False, encoding="ascii") as stream:
                    temp = Path(stream.name)
                    stream.write(f"{process.pid} {started}\n")
                try:
                    temp.replace(session)
                finally:
                    temp.unlink(missing_ok=True)
                written = True
            if written and started and listening(port):
                print(f"Started {Path(binary).name} on port {port}.")
                return
            time.sleep(0.1)
        raise RuntimeError(f"RPC listener on port {port} did not become ready. See {log_path}.")
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if written:
            session.unlink(missing_ok=True)
        raise


def stop_rpc():
    stopped = []
    errors = []
    directories = dict.fromkeys((LOG_DIR, Path(tempfile.gettempdir())))
    for directory in directories:
        for file in directory.glob("llama-rpc-*.pid"):
            if file.is_symlink() or not file.is_file() or file.stat().st_uid != os.getuid():
                continue
            try:
                port = parse_port(file.stem.removeprefix("llama-rpc-"))
            except ValueError:
                continue
            identity = owned_session(file, port)
            if identity:
                pid, started = identity
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                stopped.append((file, pid, port, started))
            else:
                file.unlink(missing_ok=True)

    deadline = time.monotonic() + 3
    for file, pid, port, started in stopped:
        while process_start(pid, port) == started and time.monotonic() < deadline:
            time.sleep(0.05)
        if process_start(pid, port) == started:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            kill_deadline = time.monotonic() + 1.0
            while process_start(pid, port) == started and time.monotonic() < kill_deadline:
                time.sleep(0.05)
        if process_start(pid, port) == started:
            errors.append(str(port))
        else:
            file.unlink(missing_ok=True)
    if errors:
        raise RuntimeError("RPC shutdown unconfirmed on ports " + ", ".join(errors) + ".")
    print(f"Stopped {len(stopped)} managed RPC server(s)." if stopped else "No managed RPC servers were running.")


try:
    command, *args = sys.argv[1:]
    if command == "llama-rpc-start":
        directory = Path(args[0]).expanduser() if args else Path.home() / "llama.cpp"
        port = parse_port(args[1] if len(args) > 1 else "50052")
        bind_host = parse_bind_host(args[2] if len(args) > 2 else "0.0.0.0")
    LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(LOG_DIR, 0o700)
    except OSError:
        pass
    with (LOG_DIR / "llama-rpc.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if command == "llama-rpc-start":
            start_rpc(directory, port, bind_host=bind_host)
        else:
            stop_rpc()
except (OSError, RuntimeError, ValueError) as exc:
    print(f"Error: {exc}", file=sys.stderr)
    sys.exit(2 if isinstance(exc, ValueError) else 1)
PY_RPC
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
      if ! JOIN_OUT="$("${DK_BIN}" swarm join --token "${PHONECLUSTER_SWARM_TOKEN}" "${MGR_ADDR}" 2>&1)"; then
        echo "${JOIN_OUT//"${PHONECLUSTER_SWARM_TOKEN}"/[redacted]}" >&2
        exit 1
      fi
      echo "${JOIN_OUT//"${PHONECLUSTER_SWARM_TOKEN}"/[redacted]}"
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
  llama-rpc-start [dir] [port]     Start ggml-rpc-server or rpc-server (default: ~/llama.cpp, port 50052)
  llama-rpc-stop                   Stop PhoneCluster-managed llama.cpp RPC processes
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
