"""PhoneCluster Worker HTTP daemon with thermal gating and 24/7 battery guard."""

from __future__ import annotations

import collections
import ipaddress
import json
import logging
import math
import os
import re
import shlex
import signal
import socket
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

from .auth import AuthRateLimiter, verify_token
from .config import (
    NetworkHardeningConfig,
    SafetyConfig,
    load_config,
    normalize_host,
    save_config,
)
from .discovery import DISCOVERY_PORT, DiscoveryResponder
from .telemetry import CpuSampler, NetSampler, ThermalGate, collect_node_health

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
    allowed_client_ips: set[str] = field(default_factory=set)
    config_path: Path | None = None

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir).resolve()
        self.thermal_gate = ThermalGate(
            max_temp_c=self.safety.max_temp_c,
            resume_temp_c=self.safety.resume_temp_c,
        )
        self.cpu_sampler = CpuSampler()
        self.net_sampler = NetSampler()
        self.rate_limiter = AuthRateLimiter(max_failures=10, window_sec=60.0, block_sec=60.0)
        self.lock = threading.Lock()
        self.active_jobs: dict[str, ActiveJob] = {}
        self.recent_jobs: collections.deque[dict[str, Any]] = collections.deque(maxlen=50)
        self.recent_alerts: collections.deque[dict[str, Any]] = collections.deque(maxlen=25)
        self._last_alert_ts: dict[str, float] = {}
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allowed_exact_ips: set[str] = set()
        exact, nets = self._build_allowed_clients(self.allowed_client_ips)
        self._allowed_exact_ips = exact
        self._allowed_networks = nets

    @staticmethod
    def _build_allowed_clients(
        raw_entries: set[str] | list[str],
    ) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        """Compile exact IPs, CIDRs, and best-effort hostnames WITHOUT holding `self.lock`."""
        exact_ips: set[str] = set()
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in raw_entries:
            entry = normalize_host(raw)
            if not entry:
                continue
            if "/" in entry:
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                    continue
                except ValueError:
                    pass
            try:
                addr = ipaddress.ip_address(entry)
                if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                    exact_ips.add(str(addr.ipv4_mapped))
                exact_ips.add(str(addr))
                continue
            except ValueError:
                pass
            # Best-effort hostname resolution (e.g. `raspberrypi.local`, Tailscale MagicDNS)
            exact_ips.add(entry)
            try:
                for _fam, _st, _pr, _cn, sa in socket.getaddrinfo(entry, None, type=socket.SOCK_STREAM):
                    exact_ips.add(normalize_host(str(sa[0])))
            except OSError:
                pass
        return exact_ips, networks

    def _compile_allowed_clients(self) -> None:
        """Expand configured `allowed_client_ips` (exact IPs, CIDRs, or hostnames) cleanly."""
        with self.lock:
            raw_copy = set(self.allowed_client_ips)
        exact, nets = self._build_allowed_clients(raw_copy)
        with self.lock:
            self._allowed_exact_ips = exact
            self._allowed_networks = nets

    def is_client_ip_allowed(self, client_ip: str) -> bool:
        """Return True if `client_ip` satisfies the optional Master source-IP allowlist."""
        with self.lock:
            if not self.allowed_client_ips:
                return True
            exact_ips = self._allowed_exact_ips
            networks = self._allowed_networks
        norm = normalize_host(client_ip)
        if norm in exact_ips or client_ip in exact_ips:
            return True
        try:
            addr = ipaddress.ip_address(norm)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            if str(addr) in exact_ips:
                return True
            for net in networks:
                if addr.version == net.version and addr in net:
                    return True
        except ValueError:
            pass
        return False

    def get_health(self) -> dict[str, Any]:
        """Collect current node health and active job details."""
        with self.lock:
            now = time.time()
            active_list = [
                {
                    "job_id": j.job_id,
                    "command": j.command_preview,
                    "running_sec": round(now - j.started_at, 1),
                }
                for j in self.active_jobs.values()
            ]
            active_count = len(active_list)
        if self.health_provider is not None:
            health = dict(self.health_provider())
            health.setdefault("node_id", self.node_id)
            health.setdefault("role", self.role)
            health["active_jobs"] = active_count
            health["active_job_list"] = active_list
            health["max_concurrency"] = self.max_concurrency
            health["source_ip_allowlist_active"] = bool(self.allowed_client_ips)
            if active_count >= self.max_concurrency:
                health["ready_for_jobs"] = False
                reasons = list(health.get("not_ready_reasons", []))
                reasons.append(f"busy ({active_count}/{self.max_concurrency})")
                health["not_ready_reasons"] = reasons
            return health
        health = collect_node_health(
            node_id=self.node_id,
            role=self.role,
            safety=self.safety,
            thermal_gate=self.thermal_gate,
            active_jobs=active_count,
            max_concurrency=self.max_concurrency,
            workdir=self.workdir,
            cpu_sampler=self.cpu_sampler,
            net_sampler=self.net_sampler,
            active_job_list=active_list,
        )
        health["source_ip_allowlist_active"] = bool(self.allowed_client_ips)
        return health

    def try_reserve_slot(
        self, job_id: str, preview: str, force: bool = False
    ) -> tuple[bool, dict[str, Any]]:
        """Atomically check capacity & thermal safety, then reserve a job slot."""
        with self.lock:
            if job_id in self.active_jobs:
                return (
                    False,
                    {
                        "error": "duplicate_job_id",
                        "reasons": [f"job '{job_id}' is already running on '{self.node_id}'"],
                    },
                )
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
            # Evaluate thermal/RAM safety outside the lock (fast path skips `ps`/port probes/CPU sampler!)
            if self.health_provider is not None:
                health = self.get_health()
            else:
                with self.lock:
                    cur_active = len(self.active_jobs)
                health = collect_node_health(
                    node_id=self.node_id,
                    role=self.role,
                    safety=self.safety,
                    thermal_gate=self.thermal_gate,
                    active_jobs=cur_active,
                    max_concurrency=self.max_concurrency,
                    workdir=self.workdir,
                    safety_only=True,
                )
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
        already_cancelled = False
        with self.lock:
            job = self.active_jobs.get(job_id)
            if job is not None:
                job.process = proc
                already_cancelled = job.cancelled
        if already_cancelled and proc.poll() is None:
            _terminate_process_group(proc)

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

    def cancel_all_jobs(self) -> int:
        """Terminate all running child process groups cleanly (called on worker shutdown)."""
        procs: list[subprocess.Popen[bytes]] = []
        with self.lock:
            for job in self.active_jobs.values():
                job.cancelled = True
                if job.process is not None and job.process.poll() is None:
                    procs.append(job.process)
        for proc in procs:
            _terminate_process_group(proc)
        return len(procs)

    def apply_live_config(
        self, payload: dict[str, Any], requester_ip: str = ""
    ) -> tuple[int, dict[str, Any]]:
        """Apply live policy updates pushed by Master (safety, max_concurrency, source-IP lock).

        Never modifies `auth_token` or `node_id`. When enabling `enforce_worker_source_ip`,
        always includes the authenticated Master's current source IP + loopback so Master
        cannot lock itself out. Persists atomically to `self.config_path` when available.
        """
        target_id = str(payload.get("target_node_id") or "").strip()
        if target_id and target_id != self.node_id:
            return HTTPStatus.CONFLICT, {
                "error": f"node_id mismatch (expected '{self.node_id}', got '{target_id}') — check for DHCP IP swap"
            }

        new_safety: SafetyConfig | None = None
        if "safety" in payload:
            raw_s = payload.get("safety")
            if not isinstance(raw_s, dict):
                return HTTPStatus.BAD_REQUEST, {"error": "'safety' must be a JSON object"}
            try:
                cur_s = self.safety
                merged_s = {
                    "max_temp_c": raw_s.get("max_temp_c", cur_s.max_temp_c),
                    "resume_temp_c": raw_s.get("resume_temp_c", cur_s.resume_temp_c),
                    "min_free_ram_mb": raw_s.get("min_free_ram_mb", cur_s.min_free_ram_mb),
                    "battery_low_pct": raw_s.get("battery_low_pct", cur_s.battery_low_pct),
                    "battery_high_pct": raw_s.get("battery_high_pct", cur_s.battery_high_pct),
                    "battery_poll_sec": raw_s.get("battery_poll_sec", cur_s.battery_poll_sec),
                    "webhook_cooldown_sec": raw_s.get("webhook_cooldown_sec", cur_s.webhook_cooldown_sec),
                    "battery_webhook_url": raw_s.get("battery_webhook_url", cur_s.battery_webhook_url),
                }
                new_safety = SafetyConfig.from_dict(merged_s)
            except (ValueError, TypeError) as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid safety config: {exc}"}

        new_max_conc: int | None = None
        if "max_concurrency" in payload:
            try:
                mc = int(payload["max_concurrency"])
                if not (1 <= mc <= 32):
                    raise ValueError("must be between 1 and 32")
                new_max_conc = mc
            except (ValueError, TypeError) as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid max_concurrency: {exc}"}

        new_net_cfg: NetworkHardeningConfig | None = None
        new_allowed_ips: set[str] | None = None
        if "network" in payload:
            raw_n = payload.get("network")
            if not isinstance(raw_n, dict):
                return HTTPStatus.BAD_REQUEST, {"error": "'network' must be a JSON object"}
            try:
                new_net_cfg = NetworkHardeningConfig.from_dict(raw_n)
            except (ValueError, TypeError) as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid network config: {exc}"}
            if new_net_cfg.enforce_worker_source_ip:
                allowed = {"127.0.0.1", "::1"} | {
                    normalize_host(ip) for ip in new_net_cfg.allowed_master_ips if normalize_host(ip)
                }
                norm_req = normalize_host(requester_ip)
                if norm_req:
                    allowed.add(norm_req)
                new_allowed_ips = allowed
                new_net_cfg.allowed_master_ips = sorted(allowed - {"127.0.0.1", "::1"})
            else:
                new_allowed_ips = set()

        compiled_clients: tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]] | None = None
        if new_allowed_ips is not None:
            # Resolve hostnames OUTSIDE `self.lock` so slow mDNS never stalls worker /health or /exec
            compiled_clients = self._build_allowed_clients(new_allowed_ips)

        persisted = False
        with self.lock:
            if new_safety is not None:
                self.safety = new_safety
                self.thermal_gate.update_limits(new_safety.max_temp_c, new_safety.resume_temp_c)
            if new_max_conc is not None:
                self.max_concurrency = new_max_conc
            if new_allowed_ips is not None and compiled_clients is not None:
                self.allowed_client_ips = new_allowed_ips
                self._allowed_exact_ips, self._allowed_networks = compiled_clients

            if self.config_path is not None and self.config_path.exists():
                try:
                    disk_cfg = load_config(self.config_path)
                    if new_safety is not None:
                        disk_cfg.safety = new_safety
                    if new_max_conc is not None:
                        for n in disk_cfg.nodes:
                            if n.id == self.node_id:
                                n.max_concurrency = new_max_conc
                    if new_net_cfg is not None:
                        disk_cfg.network.enforce_worker_source_ip = new_net_cfg.enforce_worker_source_ip
                        if new_net_cfg.allowed_master_ips:
                            disk_cfg.network.allowed_master_ips = list(new_net_cfg.allowed_master_ips)
                    save_config(disk_cfg, self.config_path)
                    persisted = True
                except Exception as exc:
                    LOG.warning("Live config applied in memory but disk save failed: %s", exc)

        LOG.info(
            "[%s] Applied live Master config push (max_conc=%d, max_temp=%.1fC, ip_lock=%s, persisted=%s)",
            self.node_id,
            self.max_concurrency,
            self.safety.max_temp_c,
            bool(self.allowed_client_ips),
            persisted,
        )
        return HTTPStatus.OK, {
            "updated": True,
            "node_id": self.node_id,
            "max_concurrency": self.max_concurrency,
            "max_temp_c": self.safety.max_temp_c,
            "resume_temp_c": self.safety.resume_temp_c,
            "source_ip_allowlist_active": bool(self.allowed_client_ips),
            "persisted": persisted,
        }

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


def _decode_capped(data: bytes | None, limit: int = MAX_OUTPUT_BYTES, overflow_bytes: int = 0) -> str:
    if not data and overflow_bytes <= 0:
        return ""
    raw = data or b""
    extra = overflow_bytes
    if len(raw) > limit:
        extra += len(raw) - limit
        raw = raw[:limit]
    text = raw.decode("utf-8", errors="replace")
    if extra > 0:
        return f"{text}\n...[truncated {extra} bytes]"
    return text


def _run_process_bounded(
    proc: subprocess.Popen[bytes],
    timeout_sec: float,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> tuple[int, str, str, bool]:
    """Wait for `proc` while draining stdout/stderr with a hard RAM cap (OOM protection for phones)."""
    out_buf = bytearray()
    err_buf = bytearray()
    overflow = [0, 0]
    buf_lock = threading.Lock()
    finished_collecting = threading.Event()

    def _drain(stream: Any, target: bytearray, idx: int) -> None:
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(32768)
                if not chunk:
                    break
                if finished_collecting.is_set():
                    continue
                with buf_lock:
                    rem = max_bytes - len(target)
                    if rem > 0:
                        target.extend(chunk[:rem])
                        if len(chunk) > rem:
                            overflow[idx] += len(chunk) - rem
                    else:
                        overflow[idx] += len(chunk)
        except OSError:
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_buf, 0), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_buf, 1), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_sec)
        returncode = int(proc.returncode if proc.returncode is not None else -1)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(proc)
        returncode = -9

    t_out.join(timeout=2.0)
    t_err.join(timeout=2.0)
    finished_collecting.set()
    with buf_lock:
        out_bytes = bytes(out_buf)
        err_bytes = bytes(err_buf)
        ov_out, ov_err = overflow[0], overflow[1]
    stdout_text = _decode_capped(out_bytes, limit=max_bytes, overflow_bytes=ov_out)
    stderr_text = _decode_capped(err_bytes, limit=max_bytes, overflow_bytes=ov_err)
    if timed_out:
        stderr_text = stderr_text + f"\n[Job timed out after {timeout_sec}s]"
    return returncode, stdout_text, stderr_text, timed_out


def _execute_job_payload(state: WorkerState, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Run a shell command or staged inline script with timeout and cancellation."""
    job_id = str(payload.get("job_id") or uuid.uuid4().hex[:12]).strip() or uuid.uuid4().hex[:12]
    command = payload.get("command")
    script_content = payload.get("script_content")
    if not command and not script_content:
        return HTTPStatus.BAD_REQUEST, {
            "error": "Provide either 'command' or 'script_content'."
        }

    try:
        timeout_sec = float(payload.get("timeout_sec", 600))
    except (TypeError, ValueError):
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a finite number > 0"}
    if not math.isfinite(timeout_sec) or timeout_sec <= 0:
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a finite number > 0"}

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
        code = (
            HTTPStatus.CONFLICT
            if reject_info.get("error") == "duplicate_job_id"
            else HTTPStatus.SERVICE_UNAVAILABLE
        )
        return code, reject_info

    started = time.monotonic()
    temp_script_path: Path | None = None
    timed_out = False
    returncode = -1
    stdout_text = ""
    stderr_text = ""

    try:
        env = os.environ.copy()
        for k, v in extra_env.items():
            clean_k = str(k).replace("\x00", "").strip()
            if clean_k and "=" not in clean_k:
                env[clean_k] = str(v).replace("\x00", "")
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

            safe_job_prefix = re.sub(r"[^A-Za-z0-9._-]+", "_", job_id).strip("._")[:40] or "job"
            fd, tmp_name = tempfile.mkstemp(
                prefix=f"pc_{safe_job_prefix}_", suffix=suffix, dir=str(cwd)
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
        returncode, stdout_text, stderr_text, timed_out = _run_process_bounded(
            proc, timeout_sec=timeout_sec, max_bytes=MAX_OUTPUT_BYTES
        )
    except (OSError, ValueError) as exc:
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
        if self.state.health_provider is not None:
            health = self.state.get_health()
        else:
            health = collect_node_health(
                node_id=self.state.node_id,
                role=self.state.role,
                safety=self.state.safety,
                thermal_gate=self.state.thermal_gate,
                workdir=self.state.workdir,
                safety_only=True,
            )
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
        while not self.stop_event.is_set():
            try:
                self.check_once()
            except Exception as exc:  # pragma: no cover - guard loop resilience
                LOG.exception("Battery guard check failed: %s", exc)
            interval = max(5, int(self.state.safety.battery_poll_sec))
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
        if ":" in str(server_address[0]):
            self.address_family = socket.AF_INET6
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
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _check_auth(self) -> bool:
        client_ip = str(self.client_address[0])
        norm_ip = normalize_host(client_ip)
        if not self.server.state.is_client_ip_allowed(client_ip):
            LOG.warning("Rejected worker HTTP request from non-Master IP %s", client_ip)
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: source IP not in Master allowlist"},
            )
            return False
        blocked, retry_after = self.server.state.rate_limiter.is_blocked(norm_ip)
        if blocked:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "too many failed auth attempts", "retry_after_sec": retry_after},
            )
            return False
        if not verify_token(self.headers, self.server.state.auth_token):
            self.server.state.rate_limiter.record_failure(norm_ip)
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return False
        self.server.state.rate_limiter.record_success(norm_ip)
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
        elif path == "/config":
            status, body = self.server.state.apply_live_config(
                payload, requester_ip=str(self.client_address[0])
            )
            self._send_json(status, body)
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
    enable_discovery: bool = False,
    discovery_port: int = DISCOVERY_PORT,
) -> None:
    """Run the worker HTTP daemon (stealth on UDP by default) until interrupted."""
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
        state.cancel_all_jobs()
        server.server_close()
