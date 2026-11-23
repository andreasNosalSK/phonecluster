"""PhoneCluster Worker HTTP daemon with thermal gating and 24/7 battery guard."""

from __future__ import annotations

import collections
import json
import logging
import os
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .auth import verify_token
from .config import SafetyConfig
from .discovery import DISCOVERY_PORT, DiscoveryResponder
from .telemetry import ThermalGate, collect_node_health

LOG = logging.getLogger("phonecluster.worker")

MAX_OUTPUT_BYTES = 512 * 1024  # 512 KiB per stream to protect 4 GB phones from OOM
MAX_REQUEST_BYTES = 2 * 1024 * 1024  # 2 MiB max JSON payload (allows inline scripts)


@dataclass
class ActiveJob:
    """Tracks a currently running subprocess on this worker."""

    job_id: str
    command_preview: str
    started_at: float
    process: subprocess.Popen[bytes] | None = None
    cancelled: bool = False


@dataclass
class WorkerState:
    """Shared state across HTTP worker threads and background safety monitor."""

    node_id: str
    role: str
    auth_token: str
    safety: SafetyConfig
    max_concurrency: int = 2
    workdir: Path = field(default_factory=lambda: Path.cwd())
    health_provider: Callable[[], dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir).resolve()
        self.thermal_gate = ThermalGate(
            max_temp_c=self.safety.max_temp_c,
            resume_temp_c=self.safety.resume_temp_c,
        )
        self.lock = threading.Lock()
        self.active_jobs: dict[str, ActiveJob] = {}
        self.recent_jobs: collections.deque[dict[str, Any]] = collections.deque(maxlen=50)
        self.recent_alerts: collections.deque[dict[str, Any]] = collections.deque(maxlen=25)
        self._last_alert_ts: dict[str, float] = {}

    def get_health(self) -> dict[str, Any]:
        """Collect current node health and active job counts."""
        with self.lock:
            active_count = len(self.active_jobs)
        if self.health_provider is not None:
            health = dict(self.health_provider())
            health.setdefault("node_id", self.node_id)
            health.setdefault("role", self.role)
            health["active_jobs"] = active_count
            health["max_concurrency"] = self.max_concurrency
            if active_count >= self.max_concurrency:
                health["ready_for_jobs"] = False
                reasons = list(health.get("not_ready_reasons", []))
                reasons.append(f"busy ({active_count}/{self.max_concurrency})")
                health["not_ready_reasons"] = reasons
            return health
        return collect_node_health(
            node_id=self.node_id,
            role=self.role,
            safety=self.safety,
            thermal_gate=self.thermal_gate,
            active_jobs=active_count,
            max_concurrency=self.max_concurrency,
            workdir=self.workdir,
        )

    def try_reserve_slot(
        self, job_id: str, preview: str, force: bool = False
    ) -> tuple[bool, dict[str, Any]]:
        """Atomically check capacity & thermal safety, then reserve a job slot."""
        with self.lock:
            active_count = len(self.active_jobs)
            if active_count >= self.max_concurrency:
                return (
                    False,
                    {
                        "error": "node_busy",
                        "reasons": [f"busy ({active_count}/{self.max_concurrency})"],
                    },
                )
            # Reserve immediately so concurrent requests cannot overshoot max_concurrency
            self.active_jobs[job_id] = ActiveJob(
                job_id=job_id,
                command_preview=preview,
                started_at=time.time(),
            )

        if not force:
            # Evaluate thermal/RAM health outside the lock (may invoke termux-battery-status)
            health = self.get_health()
            # Exclude our own newly reserved slot when checking busy state
            non_busy_reasons = [
                r for r in health.get("not_ready_reasons", []) if not r.startswith("busy")
            ]
            if non_busy_reasons:
                with self.lock:
                    self.active_jobs.pop(job_id, None)
                return (
                    False,
                    {
                        "error": "node_not_ready",
                        "reasons": non_busy_reasons,
                        "health": health,
                    },
                )
        return True, {}

    def attach_process(self, job_id: str, proc: subprocess.Popen[bytes]) -> None:
        with self.lock:
            job = self.active_jobs.get(job_id)
            if job is not None:
                job.process = proc

    def finish_job(self, job_id: str, record: dict[str, Any]) -> None:
        with self.lock:
            self.active_jobs.pop(job_id, None)
            self.recent_jobs.appendleft(record)

    def cancel_job(self, job_id: str) -> bool:
        with self.lock:
            job = self.active_jobs.get(job_id)
            if job is None:
                return False
            job.cancelled = True
            proc = job.process
        if proc is not None and proc.poll() is None:
            _terminate_process_group(proc)
        return True

    def is_cancelled(self, job_id: str) -> bool:
        with self.lock:
            job = self.active_jobs.get(job_id)
            return bool(job and job.cancelled)

    def list_jobs(self) -> dict[str, Any]:
        with self.lock:
            active = [
                {
                    "job_id": j.job_id,
                    "command": j.command_preview,
                    "running_sec": round(time.time() - j.started_at, 2),
                }
                for j in self.active_jobs.values()
            ]
            recent = list(self.recent_jobs)
        return {"active": active, "recent": recent}

    def record_safety_event(self, event: str, message: str, health: dict[str, Any]) -> bool:
        """Record a battery/thermal safety event respecting cooldown, and fire webhook."""
        now = time.time()
        with self.lock:
            last = self._last_alert_ts.get(event, 0.0)
            if now - last < self.safety.webhook_cooldown_sec:
                return False
            self._last_alert_ts[event] = now
            payload = {
                "event": event,
                "node_id": self.node_id,
                "message": message,
                "battery_pct": health.get("battery_pct"),
                "battery_status": health.get("battery_status"),
                "temp_c": health.get("temp_c"),
                "timestamp": int(now),
            }
            self.recent_alerts.appendleft(payload)

        LOG.warning("[%s] %s: %s", self.node_id, event, message)
        if self.safety.battery_webhook_url:
            _post_webhook(self.safety.battery_webhook_url, payload)
        return True


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Safely terminate a subprocess and all of its children."""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            return
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass


def _post_webhook(url: str, payload: dict[str, Any], timeout: float = 5.0) -> None:
    """Send a best-effort JSON webhook (e.g., Home Assistant, ntfy, smart plug bridge)."""
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    except (urllib.error.URLError, OSError, ValueError) as exc:
        LOG.warning("Safety webhook POST to %s failed: %s", url, exc)


def _decode_capped(data: bytes | None, limit: int = MAX_OUTPUT_BYTES) -> str:
    if not data:
        return ""
    if len(data) <= limit:
        return data.decode("utf-8", errors="replace")
    kept = data[:limit].decode("utf-8", errors="replace")
    return f"{kept}\n...[truncated {len(data) - limit} bytes]"


def _execute_job_payload(state: WorkerState, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Run a shell command or staged inline script with timeout and cancellation."""
    job_id = str(payload.get("job_id") or uuid.uuid4().hex[:12])
    command = payload.get("command")
    script_content = payload.get("script_content")
    if not command and not script_content:
        return HTTPStatus.BAD_REQUEST, {
            "error": "Provide either 'command' or 'script_content'."
        }

    timeout_sec = float(payload.get("timeout_sec", 600))
    if timeout_sec <= 0:
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be > 0"}

    force = bool(payload.get("force", False))
    extra_env = payload.get("env") or {}
    if not isinstance(extra_env, dict):
        return HTTPStatus.BAD_REQUEST, {"error": "'env' must be a JSON object"}

    req_workdir = payload.get("workdir")
    cwd = Path(req_workdir).expanduser() if req_workdir else state.workdir
    if not cwd.exists() or not cwd.is_dir():
        return HTTPStatus.BAD_REQUEST, {"error": f"workdir does not exist: {cwd}"}

    preview = (
        str(command).strip()[:120]
        if command
        else f"script:{payload.get('script_name', 'inline')}"
    )

    reserved, reject_info = state.try_reserve_slot(job_id, preview, force=force)
    if not reserved:
        return HTTPStatus.SERVICE_UNAVAILABLE, reject_info

    started = time.monotonic()
    temp_script_path: Path | None = None
    timed_out = False
    returncode = -1
    stdout_text = ""
    stderr_text = ""

    try:
        env = os.environ.copy()
        for k, v in extra_env.items():
            env[str(k)] = str(v)
        env["PHONECLUSTER_NODE_ID"] = state.node_id
        env["PHONECLUSTER_JOB_ID"] = job_id

        if script_content is not None:
            script_name = Path(str(payload.get("script_name") or "job.py")).name
            suffix = Path(script_name).suffix or ".py"
            interpreter = payload.get("interpreter")
            if not interpreter:
                interpreter = "python3" if suffix == ".py" else "sh"
            raw_args = payload.get("args") or []
            if isinstance(raw_args, str):
                args = shlex.split(raw_args)
            elif isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
            else:
                args = []

            fd, tmp_name = tempfile.mkstemp(
                prefix=f"pc_{job_id}_", suffix=suffix, dir=str(cwd)
            )
            temp_script_path = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(str(script_content))
            os.chmod(temp_script_path, 0o700)

            cmd_list = shlex.split(str(interpreter)) + [str(temp_script_path)] + args
            proc = subprocess.Popen(
                cmd_list,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        else:
            proc = subprocess.Popen(
                str(command),
                shell=True,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

        state.attach_process(job_id, proc)
        try:
            out_bytes, err_bytes = proc.communicate(timeout=timeout_sec)
            returncode = proc.returncode
            stdout_text = _decode_capped(out_bytes)
            stderr_text = _decode_capped(err_bytes)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(proc)
            try:
                out_bytes, err_bytes = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                out_bytes, err_bytes = b"", b""
            returncode = -9
            stdout_text = _decode_capped(out_bytes)
            stderr_text = _decode_capped(err_bytes) + f"\n[Job timed out after {timeout_sec}s]"
    except OSError as exc:
        stderr_text = f"Execution error: {exc}"
        returncode = 127
    finally:
        if temp_script_path is not None:
            try:
                temp_script_path.unlink(missing_ok=True)
            except OSError:
                pass
        cancelled = state.is_cancelled(job_id)
        duration = round(time.monotonic() - started, 3)
        summary = {
            "job_id": job_id,
            "node_id": state.node_id,
            "command": preview,
            "returncode": returncode,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "duration_sec": duration,
            "finished_at": int(time.time()),
        }
        state.finish_job(job_id, summary)

    result = {
        "job_id": job_id,
        "node_id": state.node_id,
        "returncode": returncode,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "duration_sec": duration,
        "stdout": stdout_text,
        "stderr": stderr_text,
    }
    return HTTPStatus.OK, result


class BatteryGuardLoop(threading.Thread):
    """Periodically checks battery level and temperature for 24/7 unrooted safety."""

    def __init__(self, state: WorkerState, stop_event: threading.Event) -> None:
        super().__init__(name="battery-guard", daemon=True)
        self.state = state
        self.stop_event = stop_event

    def check_once(self) -> None:
        health = self.state.get_health()
        safety = self.state.safety
        pct = health.get("battery_pct")
        status = str(health.get("battery_status", "UNKNOWN")).upper()
        temp_c = health.get("temp_c")

        if health.get("overheated"):
            self.state.record_safety_event(
                "thermal_throttle",
                f"Temperature {temp_c}C reached limit {safety.max_temp_c}C; pausing new jobs.",
                health,
            )

        if pct is not None:
            if pct >= safety.battery_high_pct and status in {"CHARGING", "FULL"}:
                self.state.record_safety_event(
                    "charge_off",
                    (
                        f"Battery at {pct}% ({status}) >= {safety.battery_high_pct}%. "
                        "Cut charger power (smart plug / unplug) to prevent Li-Po swelling."
                    ),
                    health,
                )
            elif pct <= safety.battery_low_pct and status in {"DISCHARGING", "NOT_CHARGING"}:
                self.state.record_safety_event(
                    "charge_on",
                    (
                        f"Battery at {pct}% ({status}) <= {safety.battery_low_pct}%. "
                        "Restore charger power."
                    ),
                    health,
                )

    def run(self) -> None:
        interval = max(5, int(self.state.safety.battery_poll_sec))
        while not self.stop_event.is_set():
            try:
                self.check_once()
            except Exception as exc:  # pragma: no cover - guard loop resilience
                LOG.exception("Battery guard check failed: %s", exc)
            self.stop_event.wait(interval)


class WorkerHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying a WorkerState reference."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: WorkerState,
    ) -> None:
        self.state = state
        super().__init__(server_address, WorkerRequestHandler)


class WorkerRequestHandler(BaseHTTPRequestHandler):
    """HTTP JSON API for PhoneCluster workers."""

    server: WorkerHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        LOG.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _check_auth(self) -> bool:
        if not verify_token(self.headers, self.server.state.auth_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return False
        return True

    def _read_json_body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid Content-Length"})
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": f"payload exceeds {MAX_REQUEST_BYTES} bytes"},
            )
            return None
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
            return None
        if not isinstance(parsed, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"})
            return None
        return parsed

    def do_GET(self) -> None:  # noqa: N802
        if not self._check_auth():
            return
        path = self.path.split("?", 1)[0]
        if path == "/health":
            health = self.server.state.get_health()
            with self.server.state.lock:
                health["recent_alerts"] = list(self.server.state.recent_alerts)[:5]
            self._send_json(HTTPStatus.OK, health)
        elif path == "/jobs":
            self._send_json(HTTPStatus.OK, self.server.state.list_jobs())
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._check_auth():
            return
        path = self.path.split("?", 1)[0]
        payload = self._read_json_body()
        if payload is None:
            return
        if path == "/exec":
            status, body = _execute_job_payload(self.server.state, payload)
            self._send_json(status, body)
        elif path == "/cancel":
            job_id = str(payload.get("job_id", "")).strip()
            if not job_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing job_id"})
                return
            cancelled = self.server.state.cancel_job(job_id)
            if cancelled:
                self._send_json(HTTPStatus.OK, {"job_id": job_id, "cancelled": True})
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"job '{job_id}' not active"})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})


def create_worker_server(
    bind_host: str,
    port: int,
    state: WorkerState,
) -> tuple[WorkerHTTPServer, BatteryGuardLoop, threading.Event]:
    """Instantiate the worker server and its background battery/thermal guard."""
    server = WorkerHTTPServer((bind_host, port), state)
    stop_event = threading.Event()
    guard = BatteryGuardLoop(state, stop_event)
    return server, guard, stop_event


def serve_worker(
    bind_host: str,
    port: int,
    state: WorkerState,
    ssh_port: int = 8022,
    ssh_user: str = "",
    enable_discovery: bool = True,
    discovery_port: int = DISCOVERY_PORT,
) -> None:
    """Run the worker HTTP daemon (plus optional UDP LAN discovery) until interrupted."""
    server, guard, stop_event = create_worker_server(bind_host, port, state)
    guard.start()

    responder: DiscoveryResponder | None = None
    if enable_discovery:
        responder = DiscoveryResponder(
            node_id=state.node_id,
            role=state.role,
            worker_port=server.server_address[1],
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            listen_host=bind_host,
            discovery_port=discovery_port,
        )
        if responder.bind():
            responder.start()
        else:
            responder = None

    def _handle_sigterm(signum: int, _frame: Any) -> None:
        LOG.info("Received signal %s; shutting down worker '%s'...", signum, state.node_id)
        stop_event.set()
        if responder is not None:
            responder.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, _handle_sigterm)
    except ValueError:
        pass  # Not on main thread

    LOG.info(
        "PhoneCluster worker '%s' (%s) listening on http://%s:%d (max_concurrency=%d, max_temp=%.1fC)",
        state.node_id,
        state.role,
        bind_host,
        server.server_address[1],
        state.max_concurrency,
        state.safety.max_temp_c,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        if responder is not None:
            responder.stop()
        server.server_close()
