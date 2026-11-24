"""PhoneCluster Worker HTTP daemon with thermal gating and 24/7 battery guard."""

from __future__ import annotations

import collections
import http.client
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
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .auth import (
    HMAC_AUTH_SCHEME,
    AuthRateLimiter,
    ReplayCache,
    build_webhook_opener,
    extract_auth_scheme,
    is_allowed_http_host,
    is_webhook_target_unsafe,
    parse_hmac_auth_header,
    parse_strict_content_length,
    safe_json_dumps,
    verify_hmac_request,
    verify_token,
)
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
    require_signed_requests: bool = False
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
        self.replay_cache = ReplayCache(ttl_sec=150.0, max_entries=4096)
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
            health["require_signed_requests"] = bool(self.require_signed_requests)
            if active_count >= self.max_concurrency:
                health["ready_for_jobs"] = False
                raw_reasons = health.get("not_ready_reasons")
                reasons = list(raw_reasons) if isinstance(raw_reasons, list) else []
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
        health["require_signed_requests"] = bool(self.require_signed_requests)
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
            try:
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
                raw_reasons = health.get("not_ready_reasons")
                reasons_list = [str(r) for r in raw_reasons if r is not None] if isinstance(raw_reasons, list) else []
                non_busy_reasons = [r for r in reasons_list if not r.startswith("busy")]
                if not non_busy_reasons:
                    if health.get("overheated"):
                        non_busy_reasons.append("overheated")
                    if health.get("battery_hazard"):
                        non_busy_reasons.append("battery_hazard")
                    if not non_busy_reasons and health.get("ready_for_jobs") is False and not any(
                        r.startswith("busy") for r in reasons_list
                    ):
                        non_busy_reasons.append("node not ready")
            except Exception:
                with self.lock:
                    self.active_jobs.pop(job_id, None)
                raise
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
            except (ValueError, TypeError, OverflowError) as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid safety config: {exc}"}

        new_max_conc: int | None = None
        if "max_concurrency" in payload:
            raw_mc = payload["max_concurrency"]
            try:
                if isinstance(raw_mc, bool):
                    raise ValueError("must be an integer, not boolean")
                if isinstance(raw_mc, float) and (not math.isfinite(raw_mc) or not raw_mc.is_integer()):
                    raise ValueError("must be a finite integer")
                mc = int(raw_mc)
                if not (1 <= mc <= 32):
                    raise ValueError("must be between 1 and 32")
                new_max_conc = mc
            except (ValueError, TypeError, OverflowError) as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid max_concurrency: {exc}"}

        new_net_cfg: NetworkHardeningConfig | None = None
        new_allowed_ips: set[str] | None = None
        if "network" in payload:
            raw_n = payload.get("network")
            if not isinstance(raw_n, dict):
                return HTTPStatus.BAD_REQUEST, {"error": "'network' must be a JSON object"}
            with self.lock:
                cur_enforce = bool(self.allowed_client_ips)
                cur_signed = bool(self.require_signed_requests)
                cur_allowed = sorted(self.allowed_client_ips - {"127.0.0.1", "::1"})
            merged_n = {
                "enforce_worker_source_ip": (
                    cur_enforce
                    if raw_n.get("enforce_worker_source_ip") is None
                    else raw_n.get("enforce_worker_source_ip")
                ),
                "require_signed_requests": (
                    cur_signed
                    if raw_n.get("require_signed_requests") is None
                    else raw_n.get("require_signed_requests")
                ),
                "allowed_master_ips": (
                    cur_allowed
                    if raw_n.get("allowed_master_ips") is None
                    else raw_n.get("allowed_master_ips")
                ),
                "adguard_url": raw_n.get("adguard_url", ""),
                "lan_subnet": raw_n.get("lan_subnet", ""),
            }
            try:
                new_net_cfg = NetworkHardeningConfig.from_dict(merged_n)
            except (ValueError, TypeError, OverflowError) as exc:
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
            if new_net_cfg is not None:
                self.require_signed_requests = bool(new_net_cfg.require_signed_requests)

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
                        disk_cfg.network.require_signed_requests = new_net_cfg.require_signed_requests
                        if new_net_cfg.allowed_master_ips:
                            disk_cfg.network.allowed_master_ips = list(new_net_cfg.allowed_master_ips)
                    save_config(disk_cfg, self.config_path)
                    persisted = True
                except Exception as exc:
                    LOG.warning("Live config applied in memory but disk save failed: %s", exc)

        LOG.info(
            "[%s] Applied live Master config push (max_conc=%d, max_temp=%.1fC, ip_lock=%s, signed_only=%s, persisted=%s)",
            self.node_id,
            self.max_concurrency,
            self.safety.max_temp_c,
            bool(self.allowed_client_ips),
            bool(self.require_signed_requests),
            persisted,
        )
        return HTTPStatus.OK, {
            "updated": True,
            "node_id": self.node_id,
            "max_concurrency": self.max_concurrency,
            "max_temp_c": self.safety.max_temp_c,
            "resume_temp_c": self.safety.resume_temp_c,
            "source_ip_allowlist_active": bool(self.allowed_client_ips),
            "require_signed_requests": bool(self.require_signed_requests),
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
        """Record a battery/thermal safety event respecting monotonic cooldown, and fire webhook."""
        now_mono = time.monotonic()
        now_wall = time.time()
        with self.lock:
            last = self._last_alert_ts.get(event)
            if last is not None and (now_mono - last) < self.safety.webhook_cooldown_sec:
                return False
            self._last_alert_ts[event] = now_mono
            webhook_url = self.safety.battery_webhook_url
            payload = {
                "event": event,
                "node_id": self.node_id,
                "message": message,
                "battery_pct": health.get("battery_pct"),
                "battery_status": health.get("battery_status"),
                "battery_health": health.get("battery_health"),
                "temp_c": health.get("temp_c"),
                "timestamp": int(now_wall),
            }
            self.recent_alerts.appendleft(payload)

        LOG.warning("[%s] %s: %s", self.node_id, event, message)
        if webhook_url:
            _post_webhook(webhook_url, payload)
        return True


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Safely terminate a subprocess and ALL of its children (including SIGTERM-ignoring grandchildren)."""
    pgid: int | None = None
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
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        return

    # Even if the session leader exited promptly on SIGTERM, stubborn grandchildren
    # in `pgid` may ignore SIGTERM and keep stdout/stderr pipes open. Wait briefly,
    # then escalate to SIGKILL on the process group if any members remain alive.
    if pgid is not None:
        deadline = time.monotonic() + 0.35
        still_alive = False
        while True:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                still_alive = False
                break
            except PermissionError:
                still_alive = False
                break
            except OSError:
                still_alive = False
                break
            still_alive = True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if still_alive:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass


_WEBHOOK_OPENER = build_webhook_opener()


def _post_webhook(url: str, payload: dict[str, Any], timeout: float = 5.0) -> None:
    """Send a best-effort JSON webhook (e.g., Home Assistant, ntfy, smart plug bridge)."""
    clean_url = str(url or "").strip()
    try:
        parsed_wb = urllib.parse.urlsplit(clean_url)
        _ = parsed_wb.port
    except ValueError:
        LOG.warning("Skipped invalid safety webhook URL (malformed URL)")
        return
    if (
        not clean_url
        or any(c.isspace() or ord(c) < 32 for c in clean_url)
        or parsed_wb.scheme.lower() not in {"http", "https"}
        or not parsed_wb.hostname
    ):
        LOG.warning("Skipped invalid safety webhook URL (must be http:// or https:// with hostname)")
        return
    if is_webhook_target_unsafe(clean_url):
        LOG.warning("Blocked safety webhook URL %s by SSRF guard (link-local/metadata/unspecified)", clean_url)
        return
    try:
        body = safe_json_dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            clean_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _WEBHOOK_OPENER.open(req, timeout=timeout):
            pass
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        LOG.warning("Safety webhook POST to %s failed: %s", clean_url, exc)


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
    raw_job_id = payload.get("job_id")
    if raw_job_id is not None:
        if not isinstance(raw_job_id, str) or any(c in raw_job_id for c in "\x00\r\n") or len(raw_job_id) > 128:
            return HTTPStatus.BAD_REQUEST, {"error": "'job_id' must be a single-line string (<= 128 chars, no NUL bytes)"}
        job_id = raw_job_id.strip() or uuid.uuid4().hex[:12]
    else:
        job_id = uuid.uuid4().hex[:12]
    command = payload.get("command")
    script_content = payload.get("script_content")
    if command is not None and not isinstance(command, str):
        return HTTPStatus.BAD_REQUEST, {"error": "'command' must be a string"}
    if script_content is not None and not isinstance(script_content, str):
        return HTTPStatus.BAD_REQUEST, {"error": "'script_content' must be a string"}
    if not command and not script_content:
        return HTTPStatus.BAD_REQUEST, {
            "error": "Provide either 'command' or 'script_content'."
        }
    if command and "\x00" in command:
        return HTTPStatus.BAD_REQUEST, {"error": "'command' must not contain NUL bytes"}
    raw_interp = payload.get("interpreter")
    if raw_interp is not None and (not isinstance(raw_interp, str) or "\x00" in raw_interp):
        return HTTPStatus.BAD_REQUEST, {"error": "'interpreter' must be a string without NUL bytes"}
    raw_sname = payload.get("script_name")
    if raw_sname is not None and not isinstance(raw_sname, str):
        return HTTPStatus.BAD_REQUEST, {"error": "'script_name' must be a string"}
    raw_args_chk = payload.get("args")
    if raw_args_chk is not None:
        if isinstance(raw_args_chk, str):
            if "\x00" in raw_args_chk:
                return HTTPStatus.BAD_REQUEST, {"error": "'args' must not contain NUL bytes"}
        elif isinstance(raw_args_chk, list):
            if any("\x00" in str(a) for a in raw_args_chk):
                return HTTPStatus.BAD_REQUEST, {"error": "'args' entries must not contain NUL bytes"}
        else:
            return HTTPStatus.BAD_REQUEST, {"error": "'args' must be a list or string"}

    parsed_interp_parts: list[str] = []
    parsed_script_args: list[str] = []
    if script_content:
        interp_str = (raw_interp or "").strip()
        try:
            parsed_interp_parts = shlex.split(interp_str) if interp_str else []
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": f"invalid 'interpreter' quoting: {exc}"}
        if isinstance(raw_args_chk, str):
            try:
                parsed_script_args = shlex.split(raw_args_chk)
            except ValueError as exc:
                return HTTPStatus.BAD_REQUEST, {"error": f"invalid 'args' quoting: {exc}"}
        elif isinstance(raw_args_chk, list):
            parsed_script_args = [str(a) for a in raw_args_chk]

    raw_timeout = payload.get("timeout_sec", 600)
    if isinstance(raw_timeout, bool):
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a finite number > 0"}
    try:
        timeout_sec = float(raw_timeout)
    except (TypeError, ValueError, OverflowError):
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a finite number > 0"}
    if not math.isfinite(timeout_sec) or timeout_sec <= 0 or timeout_sec > 86400.0:
        return HTTPStatus.BAD_REQUEST, {"error": "timeout_sec must be a finite number between 0 and 86400"}

    force = bool(payload.get("force", False))
    extra_env = payload.get("env") or {}
    if not isinstance(extra_env, dict):
        return HTTPStatus.BAD_REQUEST, {"error": "'env' must be a JSON object"}

    req_workdir = payload.get("workdir")
    if req_workdir is not None and req_workdir != "":
        if not isinstance(req_workdir, str) or "\x00" in req_workdir:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid workdir path"}
        try:
            cwd = Path(req_workdir).expanduser()
            exists_dir = cwd.exists() and cwd.is_dir()
        except (OSError, ValueError, RuntimeError) as exc:
            return HTTPStatus.BAD_REQUEST, {"error": f"invalid workdir path: {exc}"}
    else:
        cwd = state.workdir
        exists_dir = cwd.exists() and cwd.is_dir()
    if not exists_dir:
        return HTTPStatus.BAD_REQUEST, {"error": f"workdir does not exist: {cwd}"}

    preview = (
        f"script:{str(payload.get('script_name') or 'inline')[:100]}"
        if script_content
        else str(command).strip()[:120]
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

        if state.is_cancelled(job_id):
            returncode = -15
        elif script_content:
            script_name = Path(str(payload.get("script_name") or "job.py").replace("\x00", "")).name
            raw_suffix = Path(script_name).suffix
            suffix = raw_suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", raw_suffix) else ".py"
            interp_parts = list(parsed_interp_parts) if parsed_interp_parts else ["python3" if suffix == ".py" else "sh"]
            args = list(parsed_script_args)

            safe_job_prefix = re.sub(r"[^A-Za-z0-9._-]+", "_", job_id).strip("._")[:40] or "job"
            try:
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f"pc_{safe_job_prefix}_", suffix=suffix, dir=str(cwd)
                )
            except OSError:
                # Fall back to system temp dir when `cwd` is read-only (e.g. `/` or `/etc`)
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f"pc_{safe_job_prefix}_", suffix=suffix
                )
            temp_script_path = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(str(script_content))
            os.chmod(temp_script_path, 0o700)

            cmd_list = interp_parts + [str(temp_script_path)] + args
            proc = subprocess.Popen(
                cmd_list,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            state.attach_process(job_id, proc)
            returncode, stdout_text, stderr_text, timed_out = _run_process_bounded(
                proc, timeout_sec=timeout_sec, max_bytes=MAX_OUTPUT_BYTES
            )
        else:
            proc = subprocess.Popen(
                str(command),
                shell=True,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
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
        bat_health = str(health.get("battery_health", "UNKNOWN")).upper()
        temp_c = health.get("temp_c")

        if bat_health in {"OVERHEAT", "OVER_VOLTAGE", "SAFETY_TIMER_EXPIRE"}:
            self.state.record_safety_event(
                "battery_hazard",
                f"Hardware PMIC reported battery health '{bat_health}' (temp={temp_c}C, pct={pct}%); pausing jobs & cut charger power immediately!",
                health,
            )

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
    """ThreadingHTTPServer carrying a WorkerState reference with bounded concurrency."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: WorkerState,
    ) -> None:
        self.state = state
        self._conn_sem = threading.BoundedSemaphore(64)
        if ":" in str(server_address[0]):
            self.address_family = socket.AF_INET6
        super().__init__(server_address, WorkerRequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._conn_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_sem.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_sem.release()


class WorkerRequestHandler(BaseHTTPRequestHandler):
    """HTTP JSON API for PhoneCluster workers."""

    server: WorkerHTTPServer
    timeout = 15.0

    def version_string(self) -> str:
        return "PhoneCluster"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        LOG.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        raw = safe_json_dumps(body).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def _read_raw_body(self) -> bytes | None:
        length, err_status, err_msg = parse_strict_content_length(self.headers, MAX_REQUEST_BYTES)
        if length is None:
            self._send_json(err_status, {"error": err_msg})
            return None
        if length == 0:
            return b""
        try:
            raw = self.rfile.read(length)
        except OSError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"failed reading request body: {exc}"})
            return None
        if len(raw) != length:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "truncated request body"})
            return None
        return raw

    def _authenticate(self, method: str, path: str, read_body: bool) -> tuple[bool, bytes]:
        # Workers are strictly machine-to-machine (Master -> Worker); reject browser CSRF & DNS-rebinding calls.
        if not is_allowed_http_host(self.headers):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: invalid or untrusted Host header (DNS rebinding guard)"},
            )
            return False, b""
        origin_hdr = self.headers.get("Origin", "").strip()
        sec_fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if origin_hdr or sec_fetch_site == "cross-site":
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: browser cross-origin request rejected on worker API"},
            )
            return False, b""
        client_ip = str(self.client_address[0])
        norm_ip = normalize_host(client_ip)
        if not self.server.state.is_client_ip_allowed(client_ip):
            LOG.warning("Rejected worker HTTP request from non-Master IP %s", client_ip)
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: source IP not in Master allowlist"},
            )
            return False, b""
        blocked, retry_after = self.server.state.rate_limiter.is_blocked(norm_ip)
        if blocked:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "too many failed auth attempts", "retry_after_sec": retry_after},
            )
            return False, b""

        scheme = extract_auth_scheme(self.headers)
        if scheme == "bearer":
            if self.server.state.require_signed_requests:
                self.server.state.rate_limiter.record_failure(norm_ip)
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "unauthorized: HMAC-signed request required (legacy Bearer disabled)"},
                )
                return False, b""
            if not verify_token(self.headers, self.server.state.auth_token):
                self.server.state.rate_limiter.record_failure(norm_ip)
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return False, b""
            self.server.state.rate_limiter.record_success(norm_ip)
            if not read_body:
                return True, b""
            raw_body = self._read_raw_body()
            return (raw_body is not None), (raw_body or b"")

        if scheme == HMAC_AUTH_SCHEME.lower():
            parsed_hdr = parse_hmac_auth_header(self.headers)
            if parsed_hdr is None or abs(time.time() - parsed_hdr[0]) > 60.0:
                self.server.state.rate_limiter.record_failure(norm_ip)
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized: invalid or expired HMAC header"})
                return False, b""
            raw_body = self._read_raw_body() if read_body else b""
            if raw_body is None:
                return False, b""
            ok, reason = verify_hmac_request(
                self.headers,
                method,
                path,
                raw_body,
                self.server.state.auth_token,
                replay_cache=self.server.state.replay_cache,
            )
            if not ok:
                self.server.state.rate_limiter.record_failure(norm_ip)
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": f"unauthorized: {reason}"})
                return False, b""
            self.server.state.rate_limiter.record_success(norm_ip)
            return True, raw_body

        self.server.state.rate_limiter.record_failure(norm_ip)
        self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return False, b""

    def _parse_json_body(self, raw: bytes) -> dict[str, Any] | None:
        try:
            parsed = json.loads((raw or b"{}").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
            return None
        if not isinstance(parsed, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"})
            return None
        return parsed

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        ok, _ = self._authenticate("GET", path, read_body=False)
        if not ok:
            return
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
        path = self.path.split("?", 1)[0]
        ok, raw_body = self._authenticate("POST", path, read_body=True)
        if not ok:
            return
        payload = self._parse_json_body(raw_body)
        if payload is None:
            return
        if path == "/exec":
            status, body = _execute_job_payload(self.server.state, payload)
            self._send_json(status, body)
        elif path == "/cancel":
            job_id = str(payload.get("job_id") or "").strip()
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
