"""PhoneCluster Master controller, parallel job scheduler, and workload helpers."""

from __future__ import annotations

import collections
import concurrent.futures
import http.client
import json
import logging
import math
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from typing import Any, Callable

from .auth import (
    MAX_EXEC_RESPONSE_BYTES,
    build_auth_headers,
    build_direct_opener,
    build_signed_auth_headers,
    read_json_object_bounded,
    safe_json_dumps,
)
from .config import (
    ClusterConfig,
    NodeConfig,
    format_host_for_url,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
    validate_host,
)
from .discovery import detect_local_ip
from .gateway import build_worker_proxy_env
from .routing import (
    build_cluster_dns_hosts,
    build_cross_tier_env,
    build_service_registry,
    classify_workload,
    resolve_node_tier_and_pool,
    select_snapshots_for_target,
    summarize_pools,
)
from .usbhub import USB_MESH_DEFAULT_PORTS

LOG = logging.getLogger("phonecluster.master")

# Direct LAN opener: Master <-> Worker traffic ignores host HTTP_PROXY and refuses HTTP redirects (SSRF defense)
_DIRECT_OPENER = build_direct_opener()
_MAX_HEALTH_RESP_BYTES = 256 * 1024
_MAX_JOBS_RESP_BYTES = 512 * 1024
_MAX_CTRL_RESP_BYTES = 64 * 1024
_MAX_JOB_TIMEOUT_SEC = 86400.0


def _read_http_error_body(exc: urllib.error.HTTPError, limit: int) -> str:
    """Read a bounded HTTP error response body safely without letting disconnect/HTTP errors escape."""
    try:
        raw = exc.read(limit)
        return raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw or "")
    except (OSError, http.client.HTTPException):
        return ""
    finally:
        try:
            exc.close()
        except OSError:
            pass


@dataclass
class NodeSnapshot:
    """Live health snapshot of one cluster node."""

    node: NodeConfig
    online: bool
    latency_ms: float = 0.0
    health: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def ready_for_jobs(self) -> bool:
        return self.online and bool(self.health.get("ready_for_jobs", False))

    @property
    def healthy_for_scheduling(self) -> bool:
        """True if online and not thermally/RAM-throttled (ignores stale `busy` flag during live tracking)."""
        if not self.online:
            return False
        if bool(self.health.get("ready_for_jobs", False)):
            return True
        reasons = self.health.get("not_ready_reasons")
        if isinstance(reasons, list) and reasons:
            return all(str(r).startswith("busy") for r in reasons)
        return False

    @property
    def active_jobs(self) -> int:
        return max(0, _safe_int(self.health.get("active_jobs", 0), 0))

    @property
    def max_concurrency(self) -> int:
        return min(32, max(1, _safe_int(self.health.get("max_concurrency", self.node.max_concurrency), self.node.max_concurrency)))

    @property
    def available_slots(self) -> int:
        if not self.ready_for_jobs:
            return 0
        return max(0, self.max_concurrency - self.active_jobs)


@dataclass
class JobSpec:
    """A single unit of work submitted to the cluster."""

    index: int
    job_id: str
    command: str | None = None
    script_content: str | None = None
    script_name: str | None = None
    interpreter: str | None = None
    args: list[str] = field(default_factory=list)
    timeout_sec: float = 600.0
    workdir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    force: bool = False

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "timeout_sec": self.timeout_sec,
            "force": self.force,
        }
        if self.command is not None:
            payload["command"] = self.command
        if self.script_content is not None:
            payload["script_content"] = self.script_content
            if self.script_name:
                payload["script_name"] = self.script_name
            if self.interpreter:
                payload["interpreter"] = self.interpreter
            if self.args:
                payload["args"] = self.args
        if self.workdir:
            payload["workdir"] = self.workdir
        if self.env:
            payload["env"] = self.env
        return payload

    @property
    def label(self) -> str:
        if self.command:
            return self.command
        args_s = " ".join(self.args)
        return f"{self.script_name or 'script'} {args_s}".strip()


@dataclass
class JobOutcome:
    """Result of executing one JobSpec on a cluster node."""

    index: int
    job_id: str
    label: str
    node_id: str
    returncode: int
    duration_sec: float
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    cancelled: bool = False
    attempts: int = 1
    error: str = ""
    routing_reason: str = ""
    node_tier: int = 0
    node_pool: str = ""
    unconfirmed_nodes: list[str] = field(default_factory=list)

    @property
    def outcome_unknown(self) -> bool:
        """At least one attempt may have run, and no attempt confirmed success."""
        return bool(self.unconfirmed_nodes) and not self.ok

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error and not self.timed_out and not self.cancelled

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "job_id": self.job_id,
            "label": self.label,
            "node_id": self.node_id,
            "node_tier": self.node_tier,
            "node_pool": self.node_pool,
            "routing_reason": self.routing_reason,
            "ok": self.ok,
            "outcome_unknown": self.outcome_unknown,
            "unconfirmed_nodes": self.unconfirmed_nodes,
            "returncode": self.returncode,
            "duration_sec": self.duration_sec,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "attempts": self.attempts,
            "error": self.error,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def _safe_int(val: Any, default: int) -> int:
    try:
        if isinstance(val, bool):
            return default
        f = float(val)
        return int(f) if math.isfinite(f) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(val: Any, default: float) -> float:
    try:
        if isinstance(val, bool):
            return default
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError, OverflowError):
        return default


_MAX_WORKER_CPU_CORES = 128
_MAX_WORKER_RAM_MB = 1048576
_SWARM_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{4,256}$")
_PROXY_OVERRIDE_EXACT = frozenset({
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
    "pip_proxy",
    "curl_home",
    "phonecluster_gateway_enabled",
})


def _is_gateway_reserved_env_key(key: str) -> bool:
    kl = str(key or "").replace("\x00", "").strip().lower()
    if not kl:
        return True
    if kl in _PROXY_OVERRIDE_EXACT or kl.endswith("_proxy"):
        return True
    if kl.startswith("git_config_") or kl.startswith("phonecluster_gateway_"):
        return True
    return (kl.startswith("npm_config_") or kl.startswith("yarn_")) and "proxy" in kl


def score_node(
    snapshot: NodeSnapshot, in_flight_local: int | None = None, max_temp_c: float = 40.0
) -> float:
    """Rank healthy nodes so cooler, faster, less-loaded phones get picked first."""
    if not snapshot.online:
        return -1e9
    effective_active = (
        max(0, in_flight_local) if in_flight_local is not None else snapshot.active_jobs
    )
    free_slots = snapshot.max_concurrency - effective_active
    if free_slots <= 0:
        return -1e6

    health = snapshot.health
    cores = max(1, min(_MAX_WORKER_CPU_CORES, _safe_int(health.get("cpu_cores", 1), 1)))
    load_1m = max(0.0, _safe_float(health.get("load_1m", 0.0), 0.0))
    load_ratio = min(load_1m / cores, 2.0)

    temp_raw = health.get("temp_c")
    temp_val = _safe_float(temp_raw, -999.0) if temp_raw is not None else None
    temp_bonus = (
        max(0.0, min(4.0, (max_temp_c - temp_val) / 10.0))
        if temp_val is not None and 0.0 <= temp_val <= 120.0
        else 0.5
    )

    avail_ram_mb = max(0.0, min(float(_MAX_WORKER_RAM_MB), _safe_float(health.get("mem_available_mb", 512), 512.0)))
    avail_ram_gb = avail_ram_mb / 1024.0
    slot_ratio = free_slots / max(1, snapshot.max_concurrency)

    return (
        snapshot.node.weight * 3.0
        + slot_ratio * 2.5
        + temp_bonus * 1.5
        + min(avail_ram_gb, 4.0) * 0.4
        - load_ratio * 1.5
    )


class MetricsHistory:
    """Thread-safe ring buffer of cluster & per-node live metrics for btop sparklines."""

    def __init__(self, maxlen: int = 60) -> None:
        self.maxlen = maxlen
        self._lock = threading.Lock()
        self._cluster: collections.deque[dict[str, Any]] = collections.deque(maxlen=maxlen)
        self._nodes: dict[str, collections.deque[dict[str, Any]]] = {}

    def record(self, summary: dict[str, Any]) -> None:
        ts = int(summary.get("timestamp", time.time()))
        with self._lock:
            self._cluster.append(
                {
                    "ts": ts,
                    "cpu_pct": summary.get("cluster_cpu_pct", 0.0),
                    "ram_pct": summary.get("cluster_ram_pct", 0.0),
                    "max_temp_c": summary.get("max_temp_c"),
                    "active_jobs": summary.get("total_active_jobs", 0),
                    "net_rx_kbps": summary.get("total_net_rx_kbps", 0.0),
                    "net_tx_kbps": summary.get("total_net_tx_kbps", 0.0),
                }
            )
            current_ids: set[str] = set()
            for n in summary.get("nodes", []):
                nid = n["id"]
                current_ids.add(nid)
                if nid not in self._nodes:
                    self._nodes[nid] = collections.deque(maxlen=self.maxlen)
                h = n.get("health") or {}
                if n.get("online"):
                    mem_tot = max(0, _safe_int(h.get("mem_total_mb", 0), 0))
                    mem_avail = max(0, _safe_int(h.get("mem_available_mb", 0), 0))
                    ram_pct = round((max(0, mem_tot - mem_avail) / mem_tot) * 100.0, 1) if mem_tot else 0.0
                    ram_pct = min(100.0, max(0.0, ram_pct))
                    cpu_raw = h.get("cpu_pct")
                    cpu_val = _safe_float(cpu_raw, -1.0) if cpu_raw is not None else -1.0
                    if cpu_val < 0.0:
                        cores = max(1, _safe_int(h.get("cpu_cores", 1), 1))
                        load_val = max(0.0, _safe_float(h.get("load_1m", 0.0), 0.0))
                        cpu_val = min(100.0, round((load_val / cores) * 100.0, 1))
                    temp_raw = h.get("temp_c")
                    temp_clean = _safe_float(temp_raw, -999.0) if temp_raw is not None else None
                    bat_raw = h.get("battery_pct")
                    bat_clean: int | None = None
                    if bat_raw is not None:
                        bi = _safe_int(bat_raw, -1)
                        if 0 <= bi <= 100:
                            bat_clean = bi
                    self._nodes[nid].append(
                        {
                            "ts": ts,
                            "online": True,
                            "cpu_pct": min(100.0, max(0.0, cpu_val)),
                            "ram_pct": ram_pct,
                            "temp_c": temp_clean if temp_clean is not None and temp_clean > -500.0 else None,
                            "battery_pct": bat_clean,
                            "active_jobs": max(0, _safe_int(h.get("active_jobs", 0), 0)),
                        }
                    )
                else:
                    self._nodes[nid].append(
                        {
                            "ts": ts,
                            "online": False,
                            "cpu_pct": 0.0,
                            "ram_pct": 0.0,
                            "temp_c": None,
                            "battery_pct": None,
                            "active_jobs": 0,
                        }
                    )
            for stale_id in [k for k in self._nodes if k not in current_ids]:
                self._nodes.pop(stale_id, None)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "cluster": list(self._cluster),
                "nodes": {nid: list(buf) for nid, buf in self._nodes.items()},
            }


class MasterController:
    """Coordinates health polling, job scheduling, and workload helpers across all nodes."""

    def __init__(self, config: ClusterConfig) -> None:
        self.config = config
        self.config_lock = threading.RLock()
        self.headers = build_auth_headers(config.auth_token)
        self.metrics_history = MetricsHistory(maxlen=60)
        self.gateway_port_override: int | None = None

    def _headers_for(
        self, node: NodeConfig, method: str = "GET", path: str = "/", body: bytes = b""
    ) -> dict[str, str]:
        """Build replay-proof HMAC-SHA256 signed headers for Master -> Worker calls (never sends raw token on wire)."""
        with self.config_lock:
            tok = self.config.token_for_node(node)
        return build_signed_auth_headers(tok, method=method, path=path, body=body)

    def _quarantined_ids(self) -> set[str]:
        with self.config_lock:
            return set(self.config.gateway.quarantined_nodes)

    @staticmethod
    def _is_remote_port_loopback_only(snap: NodeSnapshot, port: int) -> bool:
        if is_loopback_or_unspecified_host(snap.node.host):
            return False
        raw_lp = snap.health.get("listening_ports") if isinstance(snap.health, dict) else None
        for item in (raw_lp if isinstance(raw_lp, list) else []):
            if isinstance(item, dict) and item.get("port") == port:
                return not bool(item.get("exposed", True))
        return False

    def _filter_nodes(self, tags: list[str] | None = None) -> list[NodeConfig]:
        with self.config_lock:
            nodes = list(self.config.nodes)
        if not tags:
            return nodes
        want = set(tags)
        return [n for n in nodes if want.issubset(set(n.tags))]

    def check_node_health(self, node: NodeConfig) -> NodeSnapshot:
        """Query GET /health on a single worker node."""
        url = f"{node.base_url}/health"
        req = urllib.request.Request(
            url, headers=self._headers_for(node, "GET", "/health"), method="GET"
        )
        t0 = time.monotonic()
        try:
            health_to = max(0.5, float(self.config.health_timeout_sec))
            with _DIRECT_OPENER.open(req, timeout=health_to) as resp:
                data = read_json_object_bounded(resp, _MAX_HEALTH_RESP_BYTES, deadline_sec=health_to)
                latency_ms = round((time.monotonic() - t0) * 1000.0, 1)
                return NodeSnapshot(node=node, online=True, latency_ms=latency_ms, health=data)
        except urllib.error.HTTPError as exc:
            err_body = _read_http_error_body(exc, 4096)[:200]
            return NodeSnapshot(
                node=node,
                online=False,
                error=f"HTTP {exc.code}: {err_body}",
            )
        except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError, OverflowError) as exc:
            return NodeSnapshot(node=node, online=False, error=str(exc))

    def poll_health(self, tags: list[str] | None = None) -> list[NodeSnapshot]:
        """Poll all configured nodes in parallel and preserve config ordering."""
        nodes = self._filter_nodes(tags)
        if not nodes:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            futures = {pool.submit(self.check_node_health, n): idx for idx, n in enumerate(nodes)}
            results: list[NodeSnapshot | None] = [None] * len(nodes)
            for fut in concurrent.futures.as_completed(futures):
                results[futures[fut]] = fut.result()
        return [r for r in results if r is not None]

    def exec_on_node(
        self, node: NodeConfig, spec: JobSpec
    ) -> tuple[str, dict[str, Any]]:
        """Send POST /exec to one node.

        Returns tuple `(status_kind, data)` where `status_kind` is one of:
        - `"ok"`: command executed (check `data["returncode"]`)
        - `"retryable"`: worker rejected the job before admission, or connection was refused
        - `"unknown"`: worker may have run the job without delivering a valid result
        - `"error"`: non-retryable rejection
        """
        url = f"{node.base_url}/exec"
        eff_timeout = _safe_float(spec.timeout_sec, float(self.config.default_job_timeout_sec))
        if eff_timeout <= 0:
            eff_timeout = float(self.config.default_job_timeout_sec)
        eff_timeout = min(_MAX_JOB_TIMEOUT_SEC, eff_timeout)
        payload = spec.to_payload()
        payload["timeout_sec"] = eff_timeout
        body = safe_json_dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers=self._headers_for(node, "POST", "/exec", body), method="POST"
        )
        http_timeout = min(_MAX_JOB_TIMEOUT_SEC + 30.0, max(eff_timeout + 15.0, 30.0))

        def unknown_result(reason: str) -> tuple[str, dict[str, Any]]:
            return "unknown", {
                "error": (
                    f"Outcome unknown for {spec.job_id} on {node.id}. "
                    f"The job may have run. Check pc jobs before retrying. ({reason})"
                )
            }

        try:
            with _DIRECT_OPENER.open(req, timeout=http_timeout) as resp:
                data = read_json_object_bounded(resp, MAX_EXEC_RESPONSE_BYTES, deadline_sec=http_timeout)
                expected_id = spec.job_id.strip() if isinstance(spec.job_id, str) else ""
                returned_id = data.get("job_id")
                if not isinstance(returned_id, str) or not returned_id or (expected_id and expected_id != returned_id):
                    return unknown_result("worker returned an unexpected job ID")
                if type(data.get("returncode")) is not int:
                    return unknown_result("worker returned an invalid exit status")
                return "ok", data
        except urllib.error.HTTPError as exc:
            raw_err = _read_http_error_body(exc, 65536)
            try:
                parsed_err = json.loads(raw_err)
                err_data = parsed_err if isinstance(parsed_err, dict) else {"error": raw_err[:300]}
            except (json.JSONDecodeError, RecursionError):
                err_data = {"error": raw_err[:300]}
            reason = err_data.get("error")
            if exc.code == HTTPStatus.SERVICE_UNAVAILABLE and reason in (
                "node_busy", "node_not_ready", "node_shutting_down"
            ):
                return "retryable", err_data
            if exc.code == HTTPStatus.TOO_MANY_REQUESTS and reason == "too many failed auth attempts":
                return "retryable", err_data
            if exc.code >= 500 or exc.code in (HTTPStatus.REQUEST_TIMEOUT, HTTPStatus.TOO_MANY_REQUESTS):
                return unknown_result(f"HTTP {exc.code}")
            return "error", {**err_data, "http_status": exc.code}
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (ConnectionRefusedError, socket.gaierror)):
                return "retryable", {"error": str(exc)}
            return unknown_result(str(exc))
        except (http.client.HTTPException, OSError, ValueError, OverflowError) as exc:
            return unknown_result(str(exc))

    def _resolve_master_lan_host_unlocked(self) -> str:
        """Resolve local LAN IP outside `config_lock` if Master is bound to loopback with remote workers."""
        with self.config_lock:
            nodes = list(self.config.nodes)
        if not nodes:
            return ""
        master_node = next((n for n in nodes if n.role == "master"), nodes[0])
        m_host = normalize_host(master_node.host)
        if is_loopback_or_unspecified_host(m_host) and any(
            not is_loopback_or_unspecified_host(n.host) for n in nodes
        ):
            lan_ip = normalize_host(detect_local_ip())
            if lan_ip and not is_loopback_or_unspecified_host(lan_ip):
                return lan_ip
        return m_host

    def _with_node_env(
        self,
        spec: JobSpec,
        node: NodeConfig,
        cross_env: dict[str, str],
        master_lan_host: str | None = None,
    ) -> JobSpec:
        """Return a copy of `spec` enriched with cross-tier mesh + optional per-worker gateway proxy env."""
        merged = dict(cross_env)
        eff_master = master_lan_host if master_lan_host is not None else self._resolve_master_lan_host_unlocked()
        with self.config_lock:
            proxy_env = build_worker_proxy_env(
                self.config,
                node,
                master_host=eff_master or None,
                port_override=self.gateway_port_override,
            )
        if spec.env:
            for k, v in spec.env.items():
                if not isinstance(k, str):
                    continue
                if proxy_env and _is_gateway_reserved_env_key(k):
                    continue
                merged[k] = str(v)
        if proxy_env:
            # Apply Gateway proxy enforcement LAST so job-supplied env vars can NEVER bypass Master Network Guard
            merged.update(proxy_env)
        return replace(spec, env=merged)

    def run_single(
        self,
        spec: JobSpec,
        target: str = "auto",
        tags: list[str] | None = None,
        workload_hint: str = "",
        retry_unknown: bool = False,
    ) -> list[JobOutcome]:
        """Run a job via smart auto-routing (`auto`), Tier/Pool (`tier:1|2|3`, `pool:<name>`),
        best overall node (`best`), all ready nodes (`all`), or a specific node ID.

        Automatically injects live cross-tier `PHONECLUSTER_*` service-discovery variables
        into every job so Tier 1/2/3 workloads seamlessly communicate as one system.
        """
        # Poll all nodes for complete cross-tier service discovery, then filter eligible targets by `tags`
        all_snapshots = self.poll_health()
        if tags:
            want_tags = set(tags)
            snapshots = [s for s in all_snapshots if want_tags.issubset(set(s.node.tags))]
        else:
            snapshots = all_snapshots
        master_lan = self._resolve_master_lan_host_unlocked()
        with self.config_lock:
            cross_envs = {
                snap.node.id: build_cross_tier_env(
                    all_snapshots, self.config, for_node=snap.node, master_lan_host=master_lan
                )
                for snap in snapshots if snap.online
            }
            quarantined = set(self.config.gateway.quarantined_nodes)
        snap_by_id = {s.node.id: s for s in snapshots}

        if target == "all":
            chosen = [
                s
                for s in snapshots
                if s.online and (s.ready_for_jobs or spec.force) and s.node.id not in quarantined
            ]
            if not chosen:
                return [
                    JobOutcome(
                        index=spec.index,
                        job_id=spec.job_id,
                        label=spec.label,
                        node_id="none",
                        returncode=-1,
                        duration_sec=0.0,
                        error="No online, ready nodes available.",
                        routing_reason="Broadcast requested across all ready phones",
                    )
                ]
            outcomes: list[JobOutcome] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(chosen))) as pool:
                fut_map = {
                    pool.submit(
                        self.exec_on_node,
                        s.node,
                        self._with_node_env(spec, s.node, cross_envs[s.node.id]),
                    ): s
                    for s in chosen
                }
                for fut in concurrent.futures.as_completed(fut_map):
                    snap = fut_map[fut]
                    kind, data = fut.result()
                    tier, pool_name = resolve_node_tier_and_pool(snap.node, snap.health)
                    outcomes.append(
                        self._to_outcome(
                            spec,
                            snap.node.id,
                            kind,
                            data,
                            attempts=1,
                            node_tier=tier,
                            node_pool=pool_name,
                            routing_reason="Broadcast to all ready phones",
                        )
                    )
            outcomes.sort(key=lambda o: o.node_id)
            return outcomes

        if target in {"auto", "best"} or target.startswith(("tier:", "pool:")):
            route = (
                classify_workload(spec.command, spec.script_content, hint=workload_hint)
                if target == "auto"
                else None
            )
            candidates, reason = select_snapshots_for_target(
                snapshots,
                target=target,
                route=route,
                force=spec.force,
                excluded_node_ids=quarantined,
            )
            if not candidates:
                return [
                    JobOutcome(
                        index=spec.index,
                        job_id=spec.job_id,
                        label=spec.label,
                        node_id="none",
                        returncode=-1,
                        duration_sec=0.0,
                        error=reason or "No online, ready nodes available.",
                        routing_reason=reason,
                    )
                ]
            candidates.sort(
                key=lambda s: score_node(s, max_temp_c=self.config.safety.max_temp_c),
                reverse=True,
            )
            # For non-strict auto-routing, append ready spillover nodes behind preferred-pool candidates for 503 failover
            if target == "auto" and route is not None and not route.strict:
                seen_cand_ids = {c.node.id for c in candidates}
                spillover = [
                    s
                    for s in snapshots
                    if s.node.id not in seen_cand_ids
                    and s.online
                    and (s.ready_for_jobs or spec.force)
                    and s.node.id not in quarantined
                ]
                spillover.sort(
                    key=lambda s: score_node(s, max_temp_c=self.config.safety.max_temp_c),
                    reverse=True,
                )
                candidates.extend(spillover)
            # A missing result may follow successful execution. Replay requires explicit opt-in.
            last_snap = candidates[0]
            last_kind = "retryable"
            last_data: dict[str, Any] = {}
            attempts = 0
            unconfirmed_nodes: list[str] = []
            for cand in candidates:
                attempts += 1
                last_snap = cand
                last_kind, last_data = self.exec_on_node(
                    cand.node, self._with_node_env(spec, cand.node, cross_envs[cand.node.id])
                )
                if last_kind == "unknown":
                    unconfirmed_nodes.append(cand.node.id)
                    if not retry_unknown:
                        break
                elif last_kind != "retryable":
                    break
            tier, pool_name = resolve_node_tier_and_pool(last_snap.node, last_snap.health)
            eff_reason = (
                f"{reason} (failover after {attempts - 1} retry)"
                if attempts > 1 and last_kind == "ok"
                else reason
            )
            return [
                self._to_outcome(
                    spec,
                    last_snap.node.id,
                    last_kind,
                    last_data,
                    attempts=attempts,
                    node_tier=tier,
                    node_pool=pool_name,
                    routing_reason=eff_reason,
                    unconfirmed_nodes=unconfirmed_nodes,
                )
            ]

        # Specific node id
        try:
            with self.config_lock:
                node = self.config.get_node(target)
        except KeyError:
            return [
                JobOutcome(
                    index=spec.index,
                    job_id=spec.job_id,
                    label=spec.label,
                    node_id=target,
                    returncode=-1,
                    duration_sec=0.0,
                    error=f"Unknown node id '{target}'. Check cluster.json or `pc status`.",
                    routing_reason=f"Node '{target}' not found in cluster config",
                )
            ]
        if tags and not set(tags).issubset(set(node.tags)):
            return [
                JobOutcome(
                    index=spec.index,
                    job_id=spec.job_id,
                    label=spec.label,
                    node_id=node.id,
                    returncode=-1,
                    duration_sec=0.0,
                    error=f"Node '{node.id}' does not match required tags {tags}.",
                    routing_reason=f"Node '{node.id}' excluded by --tags filter",
                )
            ]
        if node.id in quarantined and not spec.force:
            return [
                JobOutcome(
                    index=spec.index,
                    job_id=spec.job_id,
                    label=spec.label,
                    node_id=node.id,
                    returncode=-1,
                    duration_sec=0.0,
                    error=(
                        f"Node '{node.id}' is quarantined by Master. "
                        "Unblock it in Network & Pi Guard (Tab 5) or pass --force for inspection."
                    ),
                    routing_reason=f"Blocked: node '{node.id}' is quarantined",
                )
            ]
        snap = snap_by_id.get(node.id)
        tier, pool_name = resolve_node_tier_and_pool(
            node, snap.health if snap and snap.online else None
        )
        node_cross_env = cross_envs.get(node.id)
        if node_cross_env is None:
            with self.config_lock:
                node_cross_env = build_cross_tier_env(
                    all_snapshots, self.config, for_node=node, master_lan_host=master_lan
                )
        kind, data = self.exec_on_node(
            node, self._with_node_env(spec, node, node_cross_env, master_lan_host=master_lan)
        )
        return [
            self._to_outcome(
                spec,
                node.id,
                kind,
                data,
                attempts=1,
                node_tier=tier,
                node_pool=pool_name,
                routing_reason=f"Pinned to node '{node.id}'",
            )
        ]

    def map_jobs(
        self,
        jobs: list[JobSpec],
        retries: int = 1,
        tags: list[str] | None = None,
        health_refresh_sec: float = 5.0,
        wait_for_ready_sec: float = 30.0,
        on_result: Callable[[JobOutcome, int, int], None] | None = None,
        target: str = "auto",
        workload_hint: str = "",
        retry_unknown: bool = False,
    ) -> list[JobOutcome]:
        """Dynamically distribute a batch of jobs across compatible healthy cluster nodes.

        With `target="auto"`, every job is classified individually and routed to its ideal
        Tier/Pool (e.g., Docker -> Tier 3, Debian services -> Tier 2, general compute -> Tier 1
        with automatic spillover). Respects per-node `max_concurrency`, avoids overheated phones,
        avoids head-of-line blocking across pools, injects live cross-tier `PHONECLUSTER_*` env
        variables, and retries pre-admission rejections. Lost results require retry_unknown.
        """
        if not jobs:
            return []

        total_jobs = len(jobs)
        outcomes_by_slot: dict[int, JobOutcome] = {}
        last_reason_by_slot: dict[int, str] = {}
        unconfirmed_by_slot: dict[int, list[str]] = collections.defaultdict(list)
        completed_count = 0

        def _record_immediate_fail(slot_idx: int, spec: JobSpec, node_id: str, err: str, why: str) -> None:
            nonlocal completed_count
            outcome = JobOutcome(
                index=spec.index,
                job_id=spec.job_id,
                label=spec.label,
                node_id=node_id,
                returncode=-1,
                duration_sec=0.0,
                attempts=0,
                error=err,
                routing_reason=why,
            )
            outcomes_by_slot[slot_idx] = outcome
            completed_count += 1
            if on_result is not None:
                on_result(outcome, completed_count, total_jobs)

        # Fail fast on syntactically invalid tier, unknown pinned node ID, or quarantined pinned node
        if target.startswith("tier:"):
            raw_t = target.split(":", 1)[1].strip()
            if raw_t not in {"1", "2", "3"}:
                msg = f"Invalid tier target '{target}' (expected tier:1, tier:2, or tier:3)"
                for slot_idx, job in enumerate(jobs):
                    _record_immediate_fail(slot_idx, job, "none", msg, msg)
                return [outcomes_by_slot[i] for i in range(total_jobs)]

        pending: collections.deque[tuple[int, JobSpec, int, set[str]]] = collections.deque()
        if target not in {"auto", "best", "all"} and not target.startswith(("tier:", "pool:")):
            with self.config_lock:
                known_ids = {n.id for n in self.config.nodes}
            eligible_ids = {n.id for n in self._filter_nodes(tags)}
            if target not in known_ids:
                msg = f"Unknown node id '{target}'. Check cluster.json or `pc status`."
                for slot_idx, job in enumerate(jobs):
                    _record_immediate_fail(slot_idx, job, target, msg, f"Node '{target}' not found in cluster config")
                return [outcomes_by_slot[i] for i in range(total_jobs)]
            if target not in eligible_ids:
                msg = f"Node '{target}' does not match required tags {tags}."
                for slot_idx, job in enumerate(jobs):
                    _record_immediate_fail(slot_idx, job, target, msg, f"Node '{target}' excluded by --tags filter")
                return [outcomes_by_slot[i] for i in range(total_jobs)]
            q_now = self._quarantined_ids()
            for slot_idx, job in enumerate(jobs):
                if target in q_now and not job.force:
                    _record_immediate_fail(
                        slot_idx,
                        job,
                        target,
                        (
                            f"Node '{target}' is quarantined by Master. "
                            "Unblock it in Network & Pi Guard (Tab 5) or pass --force for inspection."
                        ),
                        f"Blocked: node '{target}' is quarantined",
                    )
                else:
                    pending.append((slot_idx, job, 0, set()))
            if not pending:
                return [outcomes_by_slot[i] for i in range(total_jobs)]
        else:
            for slot_idx, job in enumerate(jobs):
                pending.append((slot_idx, job, 0, set()))

        in_flight_per_node: dict[str, int] = collections.defaultdict(int)
        external_active: dict[str, int] = collections.defaultdict(int)
        running_futures: dict[
            concurrent.futures.Future[tuple[str, dict[str, Any]]],
            tuple[int, JobSpec, NodeSnapshot, int, set[str], str],
        ] = {}

        snapshots: list[NodeSnapshot] = []
        cross_envs: dict[str, dict[str, str]] = {}
        last_poll = 0.0

        def _refresh_health() -> None:
            nonlocal snapshots, cross_envs, last_poll
            all_snaps = self.poll_health()
            if tags:
                want_tags = set(tags)
                snapshots = [s for s in all_snaps if want_tags.issubset(set(s.node.tags))]
            else:
                snapshots = all_snaps
            m_lan = self._resolve_master_lan_host_unlocked()
            with self.config_lock:
                cross_envs = {
                    snap.node.id: build_cross_tier_env(
                        all_snaps, self.config, for_node=snap.node, master_lan_host=m_lan
                    )
                    for snap in snapshots if snap.online
                }
            last_poll = time.monotonic()
            for s in snapshots:
                # Account for jobs already running on this phone outside this map_jobs() batch
                external_active[s.node.id] = max(0, s.active_jobs - in_flight_per_node[s.node.id])

        _refresh_health()
        no_ready_since: float | None = None

        max_workers = min(
            64,
            total_jobs,
            max(
                1,
                sum(n.max_concurrency for n in self._filter_nodes(tags)),
                sum(s.max_concurrency for s in snapshots if s.online),
            ),
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            while pending or running_futures:
                now = time.monotonic()
                if now - last_poll >= health_refresh_sec:
                    _refresh_health()

                dispatched_any = False
                quarantined = self._quarantined_ids()
                # Dispatch as many pending jobs as there are free compatible healthy slots
                deferred: list[tuple[int, JobSpec, int, set[str]]] = []
                while pending:
                    slot_idx, spec, attempt, failed_nodes = pending.popleft()
                    route = (
                        classify_workload(spec.command, spec.script_content, hint=workload_hint)
                        if target == "auto"
                        else None
                    )
                    busy_ids = {
                        s.node.id
                        for s in snapshots
                        if (external_active[s.node.id] + in_flight_per_node[s.node.id]) >= s.max_concurrency
                    }
                    if failed_nodes:
                        eligible, reason = select_snapshots_for_target(
                            snapshots,
                            target=target,
                            route=route,
                            force=spec.force,
                            busy_node_ids=busy_ids,
                            excluded_node_ids=quarantined | failed_nodes,
                        )
                        if not eligible:
                            eligible, reason = select_snapshots_for_target(
                                snapshots,
                                target=target,
                                route=route,
                                force=spec.force,
                                busy_node_ids=busy_ids,
                                excluded_node_ids=quarantined,
                            )
                    else:
                        eligible, reason = select_snapshots_for_target(
                            snapshots,
                            target=target,
                            route=route,
                            force=spec.force,
                            busy_node_ids=busy_ids,
                            excluded_node_ids=quarantined,
                        )
                    last_reason_by_slot[slot_idx] = reason
                    if not eligible:
                        # Continue inspecting remaining jobs so busy Tier X does not block Tier Y
                        deferred.append((slot_idx, spec, attempt, failed_nodes))
                        continue

                    # Prefer nodes that didn't just reject this job if alternatives exist
                    preferred = [s for s in eligible if s.node.id not in failed_nodes]
                    pool_candidates = preferred if preferred else eligible
                    pool_candidates.sort(
                        key=lambda s: score_node(
                            s,
                            in_flight_local=external_active[s.node.id] + in_flight_per_node[s.node.id],
                            max_temp_c=self.config.safety.max_temp_c,
                        ),
                        reverse=True,
                    )
                    chosen_snap = pool_candidates[0]
                    in_flight_per_node[chosen_snap.node.id] += 1
                    enriched = self._with_node_env(spec, chosen_snap.node, cross_envs[chosen_snap.node.id])
                    fut = pool.submit(self.exec_on_node, chosen_snap.node, enriched)
                    running_futures[fut] = (slot_idx, spec, chosen_snap, attempt + 1, failed_nodes, reason)
                    dispatched_any = True
                    no_ready_since = None

                for item in reversed(deferred):
                    pending.appendleft(item)

                if running_futures:
                    wait_sec = 0.25
                    if health_refresh_sec > 0:
                        until_poll = last_poll + health_refresh_sec - time.monotonic()
                        wait_sec = min(wait_sec, max(0.0, until_poll))
                    done, _ = concurrent.futures.wait(
                        running_futures.keys(),
                        timeout=wait_sec,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    needs_refresh = False
                    for fut in done:
                        slot_idx, spec, snap, attempt, failed_nodes, reason = running_futures.pop(fut)
                        in_flight_per_node[snap.node.id] = max(
                            0, in_flight_per_node[snap.node.id] - 1
                        )
                        kind, data = fut.result()

                        if kind == "unknown" and snap.node.id not in unconfirmed_by_slot[slot_idx]:
                            unconfirmed_by_slot[slot_idx].append(snap.node.id)
                        if attempt <= retries and (kind == "retryable" or (kind == "unknown" and retry_unknown)):
                            failed_nodes.add(snap.node.id)
                            pending.appendleft((slot_idx, spec, attempt, failed_nodes))
                            needs_refresh = True
                            continue

                        tier, pool_name = resolve_node_tier_and_pool(snap.node, snap.health)
                        outcome = self._to_outcome(
                            spec,
                            snap.node.id,
                            kind,
                            data,
                            attempts=attempt,
                            node_tier=tier,
                            node_pool=pool_name,
                            routing_reason=reason,
                            unconfirmed_nodes=unconfirmed_by_slot[slot_idx],
                        )
                        outcomes_by_slot[slot_idx] = outcome
                        completed_count += 1
                        if on_result is not None:
                            on_result(outcome, completed_count, total_jobs)
                    if needs_refresh:
                        # Refresh health once per completed batch since a node throttled or dropped
                        _refresh_health()
                elif pending and not dispatched_any:
                    # No jobs running and no compatible node currently ready (all hot/offline)
                    if no_ready_since is None:
                        no_ready_since = time.monotonic()
                    elapsed_wait = time.monotonic() - no_ready_since
                    if elapsed_wait >= wait_for_ready_sec:
                        # Fail remaining jobs clearly instead of hanging forever
                        while pending:
                            slot_idx, spec, attempt, _ = pending.popleft()
                            why = last_reason_by_slot.get(slot_idx, "")
                            err_text = (
                                f"{why} (waited {wait_for_ready_sec:.0f}s)"
                                if why
                                else (
                                    f"No ready nodes became available within "
                                    f"{wait_for_ready_sec:.0f}s (nodes offline or overheated)."
                                )
                            )
                            outcome = JobOutcome(
                                index=spec.index,
                                job_id=spec.job_id,
                                label=spec.label,
                                node_id="none",
                                returncode=-1,
                                duration_sec=0.0,
                                attempts=attempt,
                                error=err_text,
                                routing_reason=why,
                                unconfirmed_nodes=unconfirmed_by_slot[slot_idx],
                            )
                            outcomes_by_slot[slot_idx] = outcome
                            completed_count += 1
                            if on_result is not None:
                                on_result(outcome, completed_count, total_jobs)
                        break
                    time.sleep(min(1.0, max(0.1, wait_for_ready_sec - elapsed_wait)))
                    _refresh_health()

        return [outcomes_by_slot[i] for i in range(total_jobs)]

    def run_pipeline(
        self,
        steps: list[dict[str, Any]],
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        """Run a multi-step cross-tier workflow chaining outputs & live service env across tiers.

        For example: Step 1 (Tier 1 compute/AI) -> Step 2 (Tier 2 Debian MQTT/services)
        -> Step 3 (Tier 3 Docker/Home Assistant). Each step automatically receives:
        - `PHONECLUSTER_PREV_STDOUT` (previous step stdout, NUL-stripped, capped at 32 KiB)
        - `PHONECLUSTER_STEP_{k}_STDOUT` & `PHONECLUSTER_STEP_{k}_NODE` (all prior steps, capped at 16 KiB each)
        - `PHONECLUSTER_PREV_NODE`, `PHONECLUSTER_PREV_TIER`, `PHONECLUSTER_PREV_POOL`, `PHONECLUSTER_PREV_RC`
        - `PHONECLUSTER_PIPELINE_STEP`, `PHONECLUSTER_PIPELINE_STEP_NAME`
        - Plus all live `PHONECLUSTER_*` cross-tier service discovery variables.
        """
        started = time.monotonic()
        results: list[dict[str, Any]] = []
        prior_step_env: dict[str, str] = {}
        prev_stdout = ""
        prev_node = ""
        prev_tier = 0
        prev_pool = ""
        prev_rc = 0
        all_ok = True
        failed_steps = 0

        for idx, raw_step in enumerate(steps, start=1):
            if not isinstance(raw_step, dict):
                all_ok = False
                failed_steps += 1
                results.append(
                    {
                        "step_index": idx,
                        "name": f"Step {idx}",
                        "target": "auto",
                        "workload": "",
                        "ok": False,
                        "node_id": "none",
                        "node_tier": 0,
                        "node_pool": "",
                        "routing_reason": "Invalid pipeline step object",
                        "returncode": -1,
                        "duration_sec": 0.0,
                        "stdout": "",
                        "stderr": "",
                        "error": "Pipeline step must be a JSON object.",
                    }
                )
                prev_stdout, prev_node, prev_tier, prev_pool, prev_rc = "", "none", 0, "", -1
                if stop_on_error:
                    break
                continue
            bad_str_field: str | None = None
            for fname in ("name", "command", "target", "workload", "workload_hint", "workdir"):
                fv = raw_step.get(fname)
                if fv is not None and not isinstance(fv, str):
                    bad_str_field = fname
                    break
            continue_on_err = bool(raw_step.get("continue_on_error", False))
            if bad_str_field is not None:
                all_ok = False
                failed_steps += 1
                results.append(
                    {
                        "step_index": idx,
                        "name": f"Step {idx}",
                        "target": "auto",
                        "workload": "",
                        "ok": False,
                        "node_id": "none",
                        "node_tier": 0,
                        "node_pool": "",
                        "routing_reason": f"Invalid step field '{bad_str_field}'",
                        "returncode": -1,
                        "duration_sec": 0.0,
                        "stdout": "",
                        "stderr": "",
                        "error": f"Pipeline step '{bad_str_field}' must be a string.",
                    }
                )
                prev_stdout, prev_node, prev_tier, prev_pool, prev_rc = "", "none", 0, "", -1
                if stop_on_error and not continue_on_err:
                    break
                continue
            name = (raw_step.get("name") or f"Step {idx}").strip() or f"Step {idx}"
            command = (raw_step.get("command") or "").strip()
            target = (raw_step.get("target") or "auto").strip() or "auto"
            workload_hint = (raw_step.get("workload") or raw_step.get("workload_hint") or "").strip()

            raw_timeout = raw_step.get("timeout_sec")
            if raw_timeout in (None, ""):
                timeout_sec = float(self.config.default_job_timeout_sec)
            else:
                try:
                    if isinstance(raw_timeout, bool):
                        raise ValueError("must be a number, not boolean")
                    timeout_sec = float(raw_timeout)
                    if not math.isfinite(timeout_sec) or timeout_sec <= 0 or timeout_sec > _MAX_JOB_TIMEOUT_SEC:
                        raise ValueError(f"must be a finite number between 0 and {_MAX_JOB_TIMEOUT_SEC:g}")
                except (TypeError, ValueError, OverflowError):
                    all_ok = False
                    failed_steps += 1
                    results.append(
                        {
                            "step_index": idx,
                            "name": name,
                            "target": target,
                            "workload": workload_hint,
                            "ok": False,
                            "node_id": "none",
                            "node_tier": 0,
                            "node_pool": "",
                            "routing_reason": "Invalid timeout_sec",
                            "returncode": -1,
                            "duration_sec": 0.0,
                            "stdout": "",
                            "stderr": "",
                            "error": f"Invalid timeout_sec '{raw_timeout}' (must be a positive number <= {_MAX_JOB_TIMEOUT_SEC:g}).",
                        }
                    )
                    prev_stdout, prev_node, prev_tier, prev_pool, prev_rc = "", "none", 0, "", -1
                    if stop_on_error and not continue_on_err:
                        break
                    continue

            raw_env = raw_step.get("env")
            if raw_env is not None and not isinstance(raw_env, dict):
                all_ok = False
                failed_steps += 1
                results.append(
                    {
                        "step_index": idx,
                        "name": name,
                        "target": target,
                        "workload": workload_hint,
                        "ok": False,
                        "node_id": "none",
                        "node_tier": 0,
                        "node_pool": "",
                        "routing_reason": "Invalid step env",
                        "returncode": -1,
                        "duration_sec": 0.0,
                        "stdout": "",
                        "stderr": "",
                        "error": "Pipeline step 'env' must be a JSON object.",
                    }
                )
                prev_stdout, prev_node, prev_tier, prev_pool, prev_rc = "", "none", 0, "", -1
                if stop_on_error and not continue_on_err:
                    break
                continue

            step_env: dict[str, str] = dict(prior_step_env)
            if isinstance(raw_env, dict):
                for k, v in raw_env.items():
                    if k is not None:
                        step_env[str(k)] = "" if v is None else str(v)
            step_env["PHONECLUSTER_PIPELINE_STEP"] = str(idx)
            step_env["PHONECLUSTER_PIPELINE_STEP_NAME"] = name
            if idx > 1:
                step_env["PHONECLUSTER_PREV_STDOUT"] = prev_stdout.replace("\x00", "")[:32768]
                step_env["PHONECLUSTER_PREV_NODE"] = prev_node
                step_env["PHONECLUSTER_PREV_TIER"] = str(prev_tier)
                step_env["PHONECLUSTER_PREV_POOL"] = prev_pool
                step_env["PHONECLUSTER_PREV_RC"] = str(prev_rc)

            if not command:
                all_ok = False
                failed_steps += 1
                results.append(
                    {
                        "step_index": idx,
                        "name": name,
                        "target": target,
                        "workload": workload_hint,
                        "ok": False,
                        "node_id": "none",
                        "node_tier": 0,
                        "node_pool": "",
                        "routing_reason": "Empty command in pipeline step",
                        "returncode": -1,
                        "duration_sec": 0.0,
                        "stdout": "",
                        "stderr": "",
                        "error": "Pipeline step requires a non-empty 'command'.",
                    }
                )
                prev_stdout, prev_node, prev_tier, prev_pool, prev_rc = "", "none", 0, "", -1
                if stop_on_error and not continue_on_err:
                    break
                continue

            spec = JobSpec(
                index=idx - 1,
                job_id=f"pipe-{idx}-{uuid.uuid4().hex[:6]}",
                command=command,
                timeout_sec=timeout_sec,
                workdir=raw_step.get("workdir") or None,
                env=step_env,
                force=bool(raw_step.get("force", False)),
            )
            outcomes = self.run_single(spec, target=target, workload_hint=workload_hint)
            primary = outcomes[0]
            step_ok = all(o.ok for o in outcomes)
            rec = primary.to_dict()
            rec.update(
                {
                    "step_index": idx,
                    "name": name,
                    "target": target,
                    "workload": workload_hint,
                    "ok": step_ok,
                }
            )
            if len(outcomes) > 1:
                rec["outcomes"] = [o.to_dict() for o in outcomes]
                rec["stdout"] = "\n".join(f"[{o.node_id}] {o.stdout.rstrip()}" for o in outcomes)
                errs = [f"[{o.node_id}] {o.stderr.rstrip()}" for o in outcomes if o.stderr.strip()]
                if errs:
                    rec["stderr"] = "\n".join(errs)
                err_msgs = [f"[{o.node_id}] {o.error}" for o in outcomes if o.error]
                if err_msgs:
                    rec["error"] = "; ".join(err_msgs)
                if not step_ok:
                    first_fail = next((o for o in outcomes if not o.ok), primary)
                    rec["returncode"] = first_fail.returncode
                    rec["timed_out"] = any(o.timed_out for o in outcomes)
                    rec["cancelled"] = any(o.cancelled for o in outcomes)
                    rec["outcome_unknown"] = any(o.outcome_unknown for o in outcomes)
                    rec["unconfirmed_nodes"] = [node for o in outcomes for node in o.unconfirmed_nodes]
            results.append(rec)

            clean_out = rec["stdout"].replace("\x00", "").strip()
            prev_stdout = clean_out
            prev_node = primary.node_id
            prev_tier = primary.node_tier
            prev_pool = primary.node_pool
            prev_rc = int(rec.get("returncode", primary.returncode))
            prior_step_env[f"PHONECLUSTER_STEP_{idx}_STDOUT"] = clean_out[:16384]
            prior_step_env[f"PHONECLUSTER_STEP_{idx}_NODE"] = primary.node_id
            # Cap cumulative prior_step_env to 64 KiB so multi-step pipelines never hit ARG_MAX (E2BIG) or HTTP 413
            while sum(len(k) + len(v) for k, v in prior_step_env.items()) > 65536:
                oldest_out = next(
                    (k for k in prior_step_env if k.endswith("_STDOUT") and k != f"PHONECLUSTER_STEP_{idx}_STDOUT"),
                    None,
                )
                if oldest_out is None:
                    break
                prior_step_env.pop(oldest_out, None)

            if not step_ok:
                all_ok = False
                failed_steps += 1
                if stop_on_error and not continue_on_err:
                    break

        return {
            "ok": all_ok,
            "steps_total": len(steps),
            "steps_completed": len(results),
            "failed_steps": failed_steps,
            "duration_sec": round(time.monotonic() - started, 3),
            "results": results,
        }

    @staticmethod
    def _to_outcome(
        spec: JobSpec,
        node_id: str,
        kind: str,
        data: dict[str, Any],
        attempts: int,
        node_tier: int = 0,
        node_pool: str = "",
        routing_reason: str = "",
        unconfirmed_nodes: list[str] | None = None,
    ) -> JobOutcome:
        uncertain = list(unconfirmed_nodes or [])
        if kind == "unknown" and node_id not in uncertain:
            uncertain.append(node_id)
        if kind == "ok":
            return JobOutcome(
                index=spec.index,
                job_id=str(data.get("job_id") or spec.job_id),
                label=spec.label,
                node_id=node_id,
                returncode=_safe_int(data.get("returncode", -1), -1),
                duration_sec=max(0.0, _safe_float(data.get("duration_sec", 0.0), 0.0)),
                stdout=str(data.get("stdout") or ""),
                stderr=str(data.get("stderr") or ""),
                timed_out=bool(data.get("timed_out", False)),
                cancelled=bool(data.get("cancelled", False)),
                attempts=attempts,
                routing_reason=routing_reason,
                node_tier=node_tier,
                node_pool=node_pool,
                unconfirmed_nodes=uncertain,
            )
        raw_reasons = data.get("reasons")
        reasons_txt = (
            ", ".join(str(r) for r in raw_reasons if r is not None)
            if isinstance(raw_reasons, list)
            else ""
        )
        err_msg = data.get("error") or reasons_txt or str(data)
        return JobOutcome(
            index=spec.index,
            job_id=spec.job_id,
            label=spec.label,
            node_id=node_id,
            returncode=-1,
            duration_sec=0.0,
            attempts=attempts,
            error=str(err_msg),
            routing_reason=routing_reason,
            node_tier=node_tier,
            node_pool=node_pool,
            unconfirmed_nodes=uncertain,
        )

    # ------------------------------------------------------------------
    # Workload integration helpers (distcc, llama.cpp RPC, OpenMPI)
    # ------------------------------------------------------------------

    def build_distcc_hosts(
        self, include_stopped: bool = False, snapshots: list[NodeSnapshot] | None = None
    ) -> str:
        """Build a `DISTCC_HOSTS` string from currently healthy, non-quarantined cluster nodes."""
        snaps = snapshots if snapshots is not None else self.poll_health()
        quarantined = self._quarantined_ids()
        entries: list[str] = []
        for snap in snaps:
            if not snap.ready_for_jobs or snap.node.id in quarantined:
                continue
            raw_svcs = snap.health.get("services")
            services = raw_svcs if isinstance(raw_svcs, dict) else {}
            raw_tools = snap.health.get("tools")
            tools = raw_tools if isinstance(raw_tools, dict) else {}
            running = bool(services.get("distccd_3632"))
            installed = bool(tools.get("distccd"))
            if not running and not (include_stopped and installed):
                continue
            if running and self._is_remote_port_loopback_only(snap, 3632):
                continue
            cores = max(1, min(_MAX_WORKER_CPU_CORES, _safe_int(snap.health.get("cpu_cores", 4), 4)))
            if snap.node.adb is not None:
                if snap.node.adb.peer_mesh and 3632 in USB_MESH_DEFAULT_PORTS:
                    mesh_port = snap.node.adb.mesh_base_port + USB_MESH_DEFAULT_PORTS.index(3632)
                    entries.append(f"127.0.0.1:{mesh_port}/{cores},lzo")
                continue
            if "usb-mode:adb" in (snap.node.tags or []):
                continue
            if snap.node.role == "master" or is_loopback_or_unspecified_host(snap.node.host):
                slots = max(1, cores - 2)
                entries.append(f"localhost/{slots}")
            else:
                entries.append(f"{format_host_for_url(snap.node.host)}/{cores},lzo")
        return " ".join(entries)

    def start_llama_rpc(self, spec: JobSpec) -> list[JobOutcome]:
        snapshots = self.poll_health()
        quarantined = self._quarantined_ids()
        workers = [
            s for s in snapshots
            if s.ready_for_jobs and s.node.role != "master" and s.node.id not in quarantined
        ]
        if not workers:
            return [JobOutcome(
                index=spec.index, job_id=spec.job_id, label=spec.label, node_id="none",
                returncode=-1, duration_sec=0.0, error="No ready worker phones for llama.cpp RPC. Master skipped.",
            )]
        master_lan = self._resolve_master_lan_host_unlocked()
        with self.config_lock:
            cross_by_id = {
                s.node.id: build_cross_tier_env(snapshots, self.config, for_node=s.node, master_lan_host=master_lan)
                for s in workers
            }
        work = [
            (s, self._with_node_env(spec, s.node, cross_by_id[s.node.id], master_lan_host=master_lan))
            for s in workers
        ]

        def start(item: tuple[NodeSnapshot, JobSpec]) -> JobOutcome:
            snapshot, enriched = item
            kind, data = self.exec_on_node(snapshot.node, enriched)
            tier, pool_name = resolve_node_tier_and_pool(snapshot.node, snapshot.health)
            return self._to_outcome(
                spec, snapshot.node.id, kind, data, attempts=1, node_tier=tier, node_pool=pool_name,
                routing_reason="Start RPC on ready worker phones",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(work))) as pool:
            outcomes = list(pool.map(start, work))
        return sorted(outcomes, key=lambda outcome: outcome.node_id)

    def stop_llama_rpc(self) -> list[dict[str, Any]]:
        """Stop managed RPC servers even if the worker has closed job admission."""
        nodes = self._filter_nodes()
        if not nodes:
            return []

        def stop(node: NodeConfig) -> dict[str, Any]:
            path = "/workloads/llama-rpc-stop"
            body = b"{}"
            request = urllib.request.Request(
                f"{node.base_url}{path}", data=body, method="POST",
                headers=self._headers_for(node, "POST", path, body),
            )
            failed = {"node_id": node.id, "ok": False}
            try:
                with _DIRECT_OPENER.open(request, timeout=14.0) as response:
                    result = read_json_object_bounded(response, _MAX_CTRL_RESP_BYTES, deadline_sec=14.0)
                if result.get("node_id") != node.id or type(result.get("ok")) is not bool:
                    raise ValueError("unexpected worker stop response")
                return result
            except urllib.error.HTTPError as exc:
                _read_http_error_body(exc, 4096)
                if exc.code == HTTPStatus.NOT_FOUND:
                    return {**failed, "error": "RPC stop unavailable. Upgrade this worker."}
                return {**failed, "error": f"RPC stop failed (HTTP {exc.code}).", "outcome_unknown": exc.code >= 500}
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                if isinstance(getattr(exc, "reason", exc), (ConnectionRefusedError, socket.gaierror)):
                    return {**failed, "error": f"Worker unreachable: {exc}"}
                return {**failed, "error": f"RPC stop unconfirmed: {exc}", "outcome_unknown": True}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            return list(pool.map(stop, nodes))

    def build_llama_rpc_arg(
        self,
        port: int = 50052,
        include_master: bool = False,
        snapshots: list[NodeSnapshot] | None = None,
    ) -> str:
        """Build a comma-separated `--rpc` endpoint list for healthy, non-quarantined llama.cpp workers."""
        snaps = snapshots if snapshots is not None else self.poll_health()
        quarantined = self._quarantined_ids()
        endpoints: list[str] = []
        for snap in snaps:
            if not snap.ready_for_jobs or snap.node.id in quarantined:
                continue
            if not include_master and snap.node.role == "master":
                continue
            if snap.node.adb is not None or "usb-mode:adb" in snap.node.tags:
                # An ADB HTTP forward is not the worker's RPC endpoint.
                continue
            tools = snap.health.get("tools")
            if isinstance(tools, dict) and tools.get("llama_rpc") is False:
                continue
            raw_svcs = snap.health.get("services")
            svcs = raw_svcs if isinstance(raw_svcs, dict) else {}
            raw_lp = snap.health.get("listening_ports")
            lp_ports: set[int] = set()
            if isinstance(raw_lp, list):
                for p in raw_lp:
                    if isinstance(p, dict) and "port" in p:
                        pv = _safe_int(p.get("port"), 0)
                        if 1 <= pv <= 65535:
                            lp_ports.add(pv)
            active = (port == 50052 and bool(svcs.get("llama_rpc_50052"))) or (port in lp_ports)
            if active and not self._is_remote_port_loopback_only(snap, port):
                endpoints.append(format_host_port(snap.node.host, port))
        return ",".join(dict.fromkeys(endpoints))

    def build_mpi_hostfile(self, snapshots: list[NodeSnapshot] | None = None) -> str:
        """Generate an OpenMPI hostfile containing healthy, non-quarantined nodes (prefers mpirun-capable)."""
        snaps = snapshots if snapshots is not None else self.poll_health()
        quarantined = self._quarantined_ids()
        ready_snaps = [
            s
            for s in snaps
            if s.ready_for_jobs
            and s.node.id not in quarantined
            and s.node.adb is None
            and "usb-mode:adb" not in (s.node.tags or [])
        ]
        mpi_snaps = [
            s for s in ready_snaps
            if isinstance(s.health.get("tools"), dict) and s.health["tools"].get("mpirun")
        ]
        chosen = mpi_snaps if mpi_snaps else ready_snaps
        lines: list[str] = []
        for snap in chosen:
            cores = max(1, min(_MAX_WORKER_CPU_CORES, _safe_int(snap.health.get("cpu_cores", 4), 4)))
            lines.append(f"{snap.node.host} slots={cores}")
        return "\n".join(lines) + ("\n" if lines else "")

    def cluster_summary(self, record_history: bool = True) -> dict[str, Any]:
        """Return an aggregate 'one PC' resource summary across all nodes."""
        snapshots = self.poll_health()
        quarantined = self._quarantined_ids()
        total_cores = 0
        cpu_weight_total = 0
        total_ram_mb = 0
        avail_ram_mb = 0
        online_count = 0
        ready_count = 0
        total_active_jobs = 0
        total_net_rx = 0.0
        total_net_tx = 0.0
        weighted_cpu_sum = 0.0
        temps: list[float] = []
        latencies: list[float] = []
        node_dicts: list[dict[str, Any]] = []

        for snap in snapshots:
            is_q = snap.node.id in quarantined
            if snap.online:
                online_count += 1
                cores = max(0, min(_MAX_WORKER_CPU_CORES, _safe_int(snap.health.get("cpu_cores", 0), 0)))
                total_cores += cores
                total_ram_mb += max(0, min(_MAX_WORKER_RAM_MB, _safe_int(snap.health.get("mem_total_mb", 0), 0)))
                avail_ram_mb += max(0, min(_MAX_WORKER_RAM_MB, _safe_int(snap.health.get("mem_available_mb", 0), 0)))
                total_active_jobs += max(0, min(256, _safe_int(snap.health.get("active_jobs", 0), 0)))
                latencies.append(max(0.0, _safe_float(snap.latency_ms, 0.0)))
                if snap.ready_for_jobs and not is_q:
                    ready_count += 1
                cpu_raw = snap.health.get("cpu_pct")
                cpu_pct = _safe_float(cpu_raw, -1.0) if cpu_raw is not None else -1.0
                if cpu_pct < 0.0:
                    load_1m = max(0.0, _safe_float(snap.health.get("load_1m", 0.0), 0.0))
                    cpu_pct = min(100.0, (load_1m / max(1, cores)) * 100.0)
                w_cores = max(1, cores)
                weighted_cpu_sum += min(100.0, max(0.0, cpu_pct)) * w_cores
                cpu_weight_total += w_cores
                if snap.health.get("net_rx_kbps") is not None:
                    total_net_rx += max(0.0, _safe_float(snap.health.get("net_rx_kbps"), 0.0))
                if snap.health.get("net_tx_kbps") is not None:
                    total_net_tx += max(0.0, _safe_float(snap.health.get("net_tx_kbps"), 0.0))
                t_raw = snap.health.get("temp_c")
                if t_raw is not None:
                    t_val = _safe_float(t_raw, -999.0)
                    if 0.0 <= t_val <= 120.0:
                        temps.append(t_val)
            eff_tier, eff_pool = resolve_node_tier_and_pool(snap.node, snap.health if snap.online else None)
            node_dicts.append(
                {
                    "id": snap.node.id,
                    "host": snap.node.host,
                    "role": snap.node.role,
                    "tier": eff_tier,
                    "pool": eff_pool,
                    "configured_tier": snap.node.tier,
                    "configured_pool": snap.node.pool,
                    "worker_port": snap.node.worker_port,
                    "ssh_port": snap.node.ssh_port,
                    "ssh_user": snap.node.ssh_user,
                    "max_concurrency": snap.node.max_concurrency,
                    "weight": snap.node.weight,
                    "tags": snap.node.tags,
                    "notes": snap.node.notes,
                    "online": snap.online,
                    "quarantined": is_q,
                    "ready_for_jobs": snap.ready_for_jobs and not is_q,
                    "latency_ms": snap.latency_ms,
                    "error": snap.error,
                    "health": snap.health,
                }
            )

        cluster_cpu_pct = (
            min(100.0, max(0.0, round(weighted_cpu_sum / cpu_weight_total, 1)))
            if cpu_weight_total > 0
            else 0.0
        )
        cluster_ram_pct = (
            min(100.0, max(0.0, round((max(0, total_ram_mb - avail_ram_mb) / total_ram_mb) * 100.0, 1)))
            if total_ram_mb > 0
            else 0.0
        )
        avg_latency_ms = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

        with self.config_lock:
            cluster_name = self.config.cluster_name
            services_reg = build_service_registry(snapshots, self.config)
            s_cfg = self.config.safety
            safety_dict = {
                "max_temp_c": s_cfg.max_temp_c,
                "resume_temp_c": s_cfg.resume_temp_c,
                "min_free_ram_mb": s_cfg.min_free_ram_mb,
                "battery_low_pct": s_cfg.battery_low_pct,
                "battery_high_pct": s_cfg.battery_high_pct,
                "battery_webhook_configured": bool(s_cfg.battery_webhook_url),
            }

        summary = {
            "cluster_name": cluster_name,
            "nodes_total": len(snapshots),
            "nodes_online": online_count,
            "nodes_ready": ready_count,
            "total_cores": total_cores,
            "cluster_cpu_pct": cluster_cpu_pct,
            "cluster_ram_pct": cluster_ram_pct,
            "mem_total_mb": total_ram_mb,
            "mem_available_mb": avail_ram_mb,
            "max_temp_c": max(temps) if temps else None,
            "avg_latency_ms": avg_latency_ms,
            "total_active_jobs": total_active_jobs,
            "total_net_rx_kbps": round(total_net_rx, 1),
            "total_net_tx_kbps": round(total_net_tx, 1),
            "pools": summarize_pools(snapshots, quarantined_nodes=quarantined),
            "services_registry": services_reg,
            "safety": safety_dict,
            "timestamp": int(time.time()),
            "nodes": node_dicts,
        }
        if record_history:
            self.metrics_history.record(summary)
        return summary

    def get_services_info(
        self, snapshots: list[NodeSnapshot] | None = None
    ) -> dict[str, Any]:
        """Return live cross-tier service registry, `.env` vars, and DNS hosts block."""
        snaps = snapshots if snapshots is not None else self.poll_health()
        master_lan = self._resolve_master_lan_host_unlocked()
        with self.config_lock:
            quarantined = set(self.config.gateway.quarantined_nodes)
            services = build_service_registry(snaps, self.config, master_lan_host=master_lan)
            env = build_cross_tier_env(snaps, self.config, master_lan_host=master_lan)
            dns_hosts = build_cluster_dns_hosts(snaps, self.config)
        return {
            "pools": summarize_pools(snaps, quarantined_nodes=quarantined),
            "services": services,
            "env": env,
            "dns_hosts": dns_hosts,
        }

    @staticmethod
    def probe_tcp_endpoint(
        host: str, port: int, timeout_sec: float = 1.5
    ) -> dict[str, Any]:
        """Measure TCP reachability & latency to a registered service mesh endpoint."""
        clean_host = normalize_host(host)
        t0 = time.monotonic()
        if isinstance(port, bool):
            return {"reachable": False, "latency_ms": 0.0, "host": clean_host, "port": 0, "error": "invalid port"}
        try:
            port_i = int(port)
        except (TypeError, ValueError, OverflowError):
            return {"reachable": False, "latency_ms": 0.0, "host": clean_host, "port": 0, "error": "invalid port"}
        if not clean_host or not (1 <= port_i <= 65535):
            return {"reachable": False, "latency_ms": 0.0, "host": clean_host, "port": port_i, "error": "invalid host or port"}
        eff_to = _safe_float(timeout_sec, 1.5)
        if eff_to <= 0 or eff_to > 60.0:
            return {"reachable": False, "latency_ms": 0.0, "host": clean_host, "port": port_i, "error": "invalid timeout_sec"}
        try:
            with socket.create_connection((clean_host, port_i), timeout=eff_to):
                ms = round((time.monotonic() - t0) * 1000.0, 1)
                return {"reachable": True, "latency_ms": ms, "host": clean_host, "port": port_i}
        except (OSError, OverflowError, ValueError) as exc:
            ms = round((time.monotonic() - t0) * 1000.0, 1)
            return {
                "reachable": False,
                "latency_ms": ms,
                "host": clean_host,
                "port": port_i,
                "error": str(exc),
            }

    def docker_cluster_status(self, timeout_sec: float = 12.0) -> dict[str, Any]:
        """Inspect Docker / Snap Docker containers and Swarm state across all online Tier 3 / Docker nodes."""
        snaps = self.poll_health()
        with self.config_lock:
            quarantined = set(self.config.gateway.quarantined_nodes)
        docker_snaps = [
            s
            for s in snaps
            if s.online
            and s.node.id not in quarantined
            and (
                bool((s.health.get("tools") or {}).get("docker"))
                or resolve_node_tier_and_pool(s.node, s.health)[0] == 3
            )
        ]
        inspect_script = (
            "import json, os, shutil, subprocess\n"
            "from pathlib import Path\n"
            "dk = shutil.which('docker') or ('/snap/bin/docker' if os.path.exists('/snap/bin/docker') else '')\n"
            "out = {'docker_bin': dk, 'is_snap': dk.startswith('/snap/') or os.path.exists('/var/snap/docker'), "
            "'ok': False, 'engine_ok': False, 'inventory_ok': False, 'error': '', "
            "'server_version': '', 'swarm_state': 'inactive', 'swarm_manager': False, "
            "'swarm_nodes': 0, 'containers_running': 0, 'containers_total': 0, 'containers': [], "
            "'volume_root': str(Path.home() / 'phonecluster' / 'docker-data')}\n"
            "if not dk:\n"
            "    out['error'] = 'docker binary not found'\n"
            "    print(json.dumps(out)); raise SystemExit(0)\n"
            "try:\n"
            "    p = subprocess.run([dk, 'info', '--format', '{{json .}}'], capture_output=True, text=True, timeout=8)\n"
            "except (OSError, subprocess.TimeoutExpired) as exc:\n"
            "    out['error'] = f'docker info failed: {exc}'[:260]\n"
            "    print(json.dumps(out)); raise SystemExit(0)\n"
            "if p.returncode != 0:\n"
            "    out['error'] = (p.stderr or p.stdout or 'docker info failed').strip()[:260]\n"
            "    print(json.dumps(out)); raise SystemExit(0)\n"
            "try:\n"
            "    info = json.loads(p.stdout)\n"
            "    if not isinstance(info, dict):\n"
            "        raise ValueError('expected a JSON object')\n"
            "except ValueError as exc:\n"
            "    out['error'] = f'invalid docker info JSON: {exc}'\n"
            "    print(json.dumps(out)); raise SystemExit(0)\n"
            "sw = info.get('Swarm') or {}\n"
            "out['engine_ok'] = True\n"
            "out['server_version'] = str(info.get('ServerVersion') or '')\n"
            "out['swarm_state'] = str(sw.get('LocalNodeState') or 'inactive').lower()\n"
            "out['swarm_manager'] = bool(sw.get('ControlAvailable', False))\n"
            "out['swarm_nodes'] = int(sw.get('Nodes') or 0)\n"
            "out['containers_running'] = int(info.get('ContainersRunning') or 0)\n"
            "out['containers_total'] = int(info.get('Containers') or 0)\n"
            "try:\n"
            "    ps = subprocess.run([dk, 'ps', '-a', '--no-trunc', '--format', '{{json .}}'], "
            "capture_output=True, text=True, timeout=8)\n"
            "    if ps.returncode:\n"
            "        raise ValueError((ps.stderr or ps.stdout or 'docker ps failed').strip()[:260])\n"
            "    rows = ps.stdout.splitlines()\n"
            "    items = [json.loads(row) for row in rows[:25]]\n"
            "    out['containers'] = [{'id': row['ID'], 'name': row['Names'], 'image': row['Image'], "
            "'status': row['Status'], 'ports': row.get('Ports', '')} for row in items]\n"
            "    out['containers_truncated'] = len(rows) > 25\n"
            "    out['inventory_ok'] = out['ok'] = True\n"
            "except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:\n"
            "    out['error'] = f'Docker inventory unavailable: {exc}'[:300]\n"
            "print(json.dumps(out))\n"
        )

        def _probe(snap: NodeSnapshot) -> dict[str, Any]:
            spec = JobSpec(
                index=0,
                job_id=f"docker-status-{snap.node.id}-{uuid.uuid4().hex[:6]}",
                script_content=inspect_script,
                script_name="docker_status.py",
                interpreter="python3",
                timeout_sec=max(4.0, min(30.0, float(timeout_sec))),
                force=True,
            )
            kind, data = self.exec_on_node(snap.node, spec)
            base = {
                "node_id": snap.node.id,
                "host": snap.node.host,
                "os_env": str(snap.health.get("os_env", "")),
                "ubuntu_touch": bool(snap.health.get("ubuntu_touch")),
                "docker_snap": bool(snap.health.get("docker_snap")),
                "socket_accessible": bool(snap.health.get("docker_socket_accessible")),
                "engine_ok": False,
                "inventory_ok": False,
            }
            if kind != "ok":
                return {**base, "ok": False, "error": str(data.get("error", kind))}
            stdout = str(data.get("stdout") or "").strip()
            try:
                parsed = json.loads(stdout, parse_constant=lambda _c: None)
                if isinstance(parsed, dict):
                    raw_ct = parsed.get("containers")
                    clean_ct = [
                        {
                            "name": str(c.get("name", ""))[:120],
                            "image": str(c.get("image", ""))[:160],
                            "status": str(c.get("status", ""))[:120],
                            "ports": str(c.get("ports", ""))[:160],
                        }
                        for c in (raw_ct if isinstance(raw_ct, list) else [])[:50]
                        if isinstance(c, dict)
                    ]
                    out_row = {
                        **base,
                        "docker_bin": str(parsed.get("docker_bin") or "")[:160],
                        "is_snap": bool(parsed.get("is_snap", base["docker_snap"])),
                        "ok": bool(parsed.get("ok")),
                        "engine_ok": bool(parsed.get("engine_ok")),
                        "inventory_ok": bool(parsed.get("inventory_ok")),
                        "error": str(parsed.get("error") or "")[:240],
                        "server_version": str(parsed.get("server_version") or "")[:64],
                        "swarm_state": str(parsed.get("swarm_state") or "inactive")[:32],
                        "swarm_manager": bool(parsed.get("swarm_manager")),
                        "swarm_nodes": max(0, min(10000, _safe_int(parsed.get("swarm_nodes", 0), 0))),
                        "containers_running": max(0, min(10000, _safe_int(parsed.get("containers_running", 0), 0))),
                        "containers_total": max(0, min(10000, _safe_int(parsed.get("containers_total", 0), 0))),
                        "containers": clean_ct,
                        "volume_root": str(parsed.get("volume_root") or "")[:200],
                    }
                    if parsed.get("containers_truncated") or parsed.get("inventory_truncated"):
                        out_row["containers_truncated"] = True
                    return out_row
            except (json.JSONDecodeError, RecursionError, ValueError):
                pass
            return {**base, "ok": False, "error": (str(data.get("stderr") or stdout) or "unexpected output")[:240]}

        rows: list[dict[str, Any]] = []
        if docker_snaps:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(docker_snaps))) as pool:
                rows = list(pool.map(_probe, docker_snaps))
        return {
            "nodes": rows,
            "total_nodes": len(rows),
            "ready_nodes": sum(1 for r in rows if r.get("ok")),
            "engine_ready_nodes": sum(1 for r in rows if r.get("engine_ok")),
            "swarm_active": any(r.get("swarm_state") == "active" for r in rows),
            "swarm_managers": [r["node_id"] for r in rows if r.get("swarm_manager")],
            "total_running_containers": sum(
                max(0, _safe_int(r.get("containers_running", 0), 0)) for r in rows if r.get("engine_ok")
            ),
        }

    def docker_swarm_setup(
        self,
        manager_node_id: str | None = None,
        worker_node_ids: list[str] | None = None,
        advertise_addr: str = "",
    ) -> dict[str, Any]:
        """Initialize Docker Swarm on a Tier 3 / Ubuntu Touch manager and join peer Docker phones securely.

        The controller passes the join token to the worker probe through its job environment.
        """
        if advertise_addr:
            advertise_addr = validate_host(advertise_addr)
        snaps = self.poll_health()
        with self.config_lock:
            quarantined = set(self.config.gateway.quarantined_nodes)
        eligible = [
            s
            for s in snaps
            if s.online
            and s.node.id not in quarantined
            and (
                bool((s.health.get("tools") or {}).get("docker"))
                or resolve_node_tier_and_pool(s.node, s.health)[0] == 3
            )
        ]
        if not eligible:
            return {
                "ok": False,
                "error": "No online Docker-capable (Tier 3) nodes found. Ensure Snap Docker is running and accessible.",
                "workers": [],
                "joined_count": 0,
            }

        mgr_snap: NodeSnapshot | None = None
        if manager_node_id:
            mgr_snap = next((s for s in eligible if s.node.id == manager_node_id), None)
            if mgr_snap is None:
                return {
                    "ok": False,
                    "error": f"Manager node '{manager_node_id}' is not online or does not have Docker ready.",
                    "workers": [],
                    "joined_count": 0,
                }
        else:
            mgr_snap = next((s for s in eligible if s.node.role == "master"), eligible[0])

        target_workers = [s for s in eligible if s.node.id != mgr_snap.node.id]
        if worker_node_ids is not None:
            wanted = set(worker_node_ids)
            target_workers = [s for s in target_workers if s.node.id in wanted]
            missing = wanted - {s.node.id for s in target_workers}
            if missing:
                return {
                    "ok": False,
                    "error": "Selected Docker workers unavailable: " + ", ".join(sorted(missing)),
                    "workers": [],
                    "joined_count": 0,
                }

        adv = advertise_addr or normalize_host(mgr_snap.node.host)
        usb = mgr_snap.node.adb is not None or "usb-mode:adb" in mgr_snap.node.tags
        if not advertise_addr and not usb and mgr_snap.node.role == "master" and is_loopback_or_unspecified_host(adv):
            adv = normalize_host(detect_local_ip())
        if not adv or is_loopback_or_unspecified_host(adv):
            return {
                "ok": False,
                "error": "Supply the selected manager's non-loopback address reachable by the Docker workers.",
                "workers": [],
                "joined_count": 0,
            }

        mgr_script = (
            "import json, os, shutil, subprocess\n"
            "dk = shutil.which('docker') or ('/snap/bin/docker' if os.path.exists('/snap/bin/docker') else '')\n"
            "adv = os.environ.get('PHONECLUSTER_SWARM_ADV', '').strip()\n"
            "if not dk:\n"
            "    print(json.dumps({'ok': False, 'error': 'docker binary not found'})); raise SystemExit(0)\n"
            "try:\n"
            "    st = subprocess.run([dk, 'info', '--format', '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}'], "
            "capture_output=True, text=True, timeout=10)\n"
            "except (OSError, subprocess.TimeoutExpired) as exc:\n"
            "    print(json.dumps({'ok': False, 'error': f'docker info failed: {exc}'[:260]})); raise SystemExit(0)\n"
            "if st.returncode != 0:\n"
            "    print(json.dumps({'ok': False, 'error': (st.stderr or st.stdout).strip()[:260]})); raise SystemExit(0)\n"
            "parts = st.stdout.strip().split('|')\n"
            "state = (parts[0] if parts else '').lower()\n"
            "is_mgr = (parts[1].lower() == 'true') if len(parts) > 1 else False\n"
            "initialized = False\n"
            "if state != 'active':\n"
            "    init_cmd = [dk, 'swarm', 'init'] + (['--advertise-addr', adv] if adv else [])\n"
            "    r = subprocess.run(init_cmd, capture_output=True, text=True, timeout=20)\n"
            "    if r.returncode != 0:\n"
            "        print(json.dumps({'ok': False, 'error': (r.stderr or r.stdout).strip()[:280]})); raise SystemExit(0)\n"
            "    initialized = True\n"
            "elif not is_mgr:\n"
            "    print(json.dumps({'ok': False, 'error': 'node is already a Swarm worker, not a manager'})); raise SystemExit(0)\n"
            "tk = subprocess.run([dk, 'swarm', 'join-token', '-q', 'worker'], capture_output=True, text=True, timeout=10)\n"
            "if tk.returncode != 0 or not tk.stdout.strip():\n"
            "    print(json.dumps({'ok': False, 'error': 'failed to fetch worker join token'})); raise SystemExit(0)\n"
            "print(json.dumps({'ok': True, 'initialized': initialized, 'token': tk.stdout.strip()}))\n"
        )
        mgr_spec = JobSpec(
            index=0,
            job_id=f"swarm-mgr-{mgr_snap.node.id}-{uuid.uuid4().hex[:6]}",
            script_content=mgr_script,
            script_name="swarm_init.py",
            interpreter="python3",
            env={"PHONECLUSTER_SWARM_ADV": adv},
            timeout_sec=45.0,
            force=True,
        )
        m_kind, m_data = self.exec_on_node(mgr_snap.node, mgr_spec)
        if m_kind != "ok" or m_data.get("returncode") != 0:
            return {
                "ok": False,
                "manager_node_id": mgr_snap.node.id,
                "manager_addr": format_host_port(adv, 2377),
                "error": str(m_data.get("error") or "Swarm manager probe failed."),
                "workers": [],
                "joined_count": 0,
            }
        try:
            m_parsed = json.loads(str(m_data.get("stdout") or "").strip())
        except json.JSONDecodeError:
            m_parsed = None
        if not isinstance(m_parsed, dict) or not m_parsed.get("ok") or not m_parsed.get("token"):
            return {
                "ok": False,
                "manager_node_id": mgr_snap.node.id,
                "manager_addr": format_host_port(adv, 2377),
                "error": str(m_parsed.get("error", "Swarm init failed")) if isinstance(m_parsed, dict) else "Invalid manager response.",
                "workers": [],
                "joined_count": 0,
                "note": "If your Ubuntu Touch Halium kernel lacks VXLAN/overlay modules, use direct PhoneCluster Tier 3 container jobs (`pc run --target tier:3` / `pc map`) instead of Swarm overlay networks.",
            }

        join_token = str(m_parsed["token"]).strip()
        if join_token.startswith("-") or not _SWARM_TOKEN_RE.fullmatch(join_token):
            return {
                "ok": False,
                "manager_node_id": mgr_snap.node.id,
                "manager_addr": format_host_port(adv, 2377),
                "error": "Swarm manager returned a malformed join token.",
                "workers": [],
                "joined_count": 0,
            }
        manager_addr = format_host_port(adv, 2377)

        join_script = (
            "import json, os, shutil, subprocess\n"
            "dk = shutil.which('docker') or ('/snap/bin/docker' if os.path.exists('/snap/bin/docker') else '')\n"
            "tok = os.environ.get('PHONECLUSTER_SWARM_TOKEN', '').strip()\n"
            "mgr = os.environ.get('PHONECLUSTER_SWARM_MANAGER', '').strip()\n"
            "if not dk:\n"
            "    print(json.dumps({'ok': False, 'error': 'docker binary not found'})); raise SystemExit(0)\n"
            "def swarm_info():\n"
            "    status = subprocess.run([dk, 'info', '--format', '{{.Swarm.LocalNodeState}}|{{.Swarm.NodeID}}'], "
            "capture_output=True, text=True, timeout=8, check=True)\n"
            "    state, _, node_id = status.stdout.strip().partition('|')\n"
            "    return state, node_id\n"
            "try:\n"
            "    state, node_id = swarm_info()\n"
            "    already_active = state.lower() == 'active'\n"
            "    if not already_active:\n"
            "        r = subprocess.run([dk, 'swarm', 'join', '--token', tok, mgr], capture_output=True, text=True, timeout=20)\n"
            "        if r.returncode:\n"
            "            detail = (r.stderr or 'docker swarm join failed').replace(tok, '[redacted]').strip()[:280]\n"
            "            print(json.dumps({'ok': False, 'error': detail})); raise SystemExit(0)\n"
            "        state, node_id = swarm_info()\n"
            "except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:\n"
            "    detail = str(exc).replace(tok, '[redacted]')[:280]\n"
            "    print(json.dumps({'ok': False, 'error': f'docker swarm join failed: {detail}'})); raise SystemExit(0)\n"
            "if state.lower() != 'active' or not node_id:\n"
            "    print(json.dumps({'ok': False, 'error': 'Swarm node ID could not be confirmed'})); raise SystemExit(0)\n"
            "print(json.dumps({'ok': True, 'already_active': already_active, 'swarm_node_id': node_id}))\n"
        )

        worker_results: list[dict[str, Any]] = []
        for ws in target_workers:
            w_spec = JobSpec(
                index=0,
                job_id=f"swarm-join-{ws.node.id}-{uuid.uuid4().hex[:6]}",
                script_content=join_script,
                script_name="swarm_join.py",
                interpreter="python3",
                env={
                    "PHONECLUSTER_SWARM_TOKEN": join_token,
                    "PHONECLUSTER_SWARM_MANAGER": manager_addr,
                },
                timeout_sec=42.0,
                force=True,
            )
            wk, wd = self.exec_on_node(ws.node, w_spec)
            if wk != "ok" or wd.get("returncode") != 0:
                error = str(wd.get("error") or wd.get("stderr") or "Swarm worker probe failed")
                worker_results.append({"node_id": ws.node.id, "ok": False, "error": error.replace(join_token, "[redacted]")[:240]})
                continue
            try:
                wp = json.loads(str(wd.get("stdout") or "").strip())
                if isinstance(wp, dict):
                    worker_results.append({
                        "node_id": ws.node.id, "ok": wp.get("ok") is True,
                        "already_active": wp.get("already_active") is True,
                        "swarm_node_id": str(wp.get("swarm_node_id") or ""),
                        "error": str(wp.get("error") or "").replace(join_token, "[redacted]")[:240],
                    })
                    continue
            except json.JSONDecodeError:
                pass
            worker_results.append(
                {"node_id": ws.node.id, "ok": False, "error": "Invalid Swarm worker response."}
            )

        if any(result["ok"] for result in worker_results):
            membership_script = (
                "import os, shutil, subprocess\n"
                "dk = shutil.which('docker') or ('/snap/bin/docker' if os.path.exists('/snap/bin/docker') else '')\n"
                "if not dk:\n"
                "    raise SystemExit(1)\n"
                "raise SystemExit(subprocess.run([dk, 'node', 'ls', '--no-trunc', '--format', '{{.ID}}'], timeout=10).returncode)\n"
            )
            membership_spec = replace(
                mgr_spec, job_id=f"swarm-members-{mgr_snap.node.id}-{uuid.uuid4().hex[:6]}",
                script_content=membership_script, script_name="swarm_members.py", env={}, timeout_sec=12.0,
            )
            kind, membership = self.exec_on_node(mgr_snap.node, membership_spec)
            verified = kind == "ok" and membership.get("returncode") == 0
            member_ids = set(str(membership.get("stdout") or "").split()) if verified else set()
            for result in worker_results:
                if result["ok"] and result["swarm_node_id"] not in member_ids:
                    error = (
                        "Worker's Swarm node ID is absent from the selected manager."
                        if verified else "Could not verify membership on the selected manager."
                    )
                    result.update(ok=False, error=error)

        joined_ok = sum(1 for r in worker_results if r.get("ok"))
        all_ok = all(r.get("ok") for r in worker_results)
        if not all_ok:
            note = "Some worker joins failed or could not be verified. Check each worker result."
        elif worker_results:
            note = "Selected worker memberships confirmed by the Swarm manager."
        else:
            note = "Swarm manager ready. No worker joins were requested or eligible."
        return {
            "ok": all_ok,
            "manager_node_id": mgr_snap.node.id,
            "manager_addr": manager_addr,
            "manager_initialized": bool(m_parsed.get("initialized")),
            "workers": worker_results,
            "joined_count": joined_ok,
            "note": note,
        }

    def check_workers_wan_isolation(
        self,
        probe_host: str = "1.1.1.1",
        probe_port: int = 443,
        timeout_sec: float = 2.0,
    ) -> list[dict[str, Any]]:
        """Check whether worker phones have direct WAN blocked by your router firewall.

        Runs a raw TCP probe directly from each online worker (bypassing any proxy).
        If the direct connection fails/times out, that worker is air-gapped from WAN.
        """
        clean_probe_host = validate_host(str(probe_host or ""))
        if isinstance(probe_port, bool):
            raise ValueError("probe_port must be an integer, not boolean")
        probe_port_i = int(probe_port)
        if not (1 <= probe_port_i <= 65535):
            raise ValueError(f"probe_port must be between 1 and 65535 (got {probe_port_i})")
        if isinstance(timeout_sec, bool):
            raise ValueError("timeout_sec must be a finite number, not boolean")
        timeout_f = float(timeout_sec)
        if not math.isfinite(timeout_f) or not (0.1 <= timeout_f <= 30.0):
            raise ValueError("timeout_sec must be a finite number between 0.1 and 30.0")
        with self.config_lock:
            quarantined = set(self.config.gateway.quarantined_nodes)
            workers = [n for n in self.config.nodes if n.role != "master"]
        if not workers:
            return []
        check_extra_leaks = (clean_probe_host == "1.1.1.1" and probe_port_i == 443)
        probe_targets: list[tuple[str, str, int]] = [("ipv4_https", clean_probe_host, probe_port_i)]
        if check_extra_leaks:
            probe_targets.append(("ipv6_https", "2606:4700:4700::1111", 443))
            probe_targets.append(("direct_dns_tcp", "1.1.1.1", 53))
        probe_code = (
            "import socket\n"
            f"targets = {probe_targets!r}\n"
            "open_list = []\n"
            "last_err = 'OSError'\n"
            "for label, host, port in targets:\n"
            "    try:\n"
            f"        s = socket.create_connection((host, port), timeout={timeout_f})\n"
            "        s.close()\n"
            "        open_list.append(label)\n"
            "    except OSError as e:\n"
            "        last_err = type(e).__name__\n"
            "if open_list:\n"
            "    print('DIRECT_WAN_OPEN:' + ','.join(open_list))\n"
            "else:\n"
            "    print('WAN_BLOCKED:' + last_err)\n"
        )

        def _probe_one(node: NodeConfig) -> dict[str, Any]:
            if node.id in quarantined:
                return {
                    "node_id": node.id,
                    "host": node.host,
                    "online": False,
                    "wan_blocked": None,
                    "detail": "Skipped — node is quarantined by Master.",
                }
            spec = JobSpec(
                index=0,
                job_id=f"wancheck-{node.id}-{uuid.uuid4().hex[:6]}",
                script_content=probe_code,
                script_name="wan_check.py",
                interpreter="python3",
                timeout_sec=timeout_f * len(probe_targets) + 4.0,
                force=True,
            )
            kind, data = self.exec_on_node(node, spec)
            if kind != "ok":
                return {
                    "node_id": node.id,
                    "host": node.host,
                    "online": False,
                    "wan_blocked": None,
                    "detail": str(data.get("error", "offline")),
                }
            out = str(data.get("stdout", "")).strip()
            if out.startswith("WAN_BLOCKED"):
                return {
                    "node_id": node.id,
                    "host": node.host,
                    "online": True,
                    "wan_blocked": True,
                    "detail": f"Direct WAN blocked ({out.split(':', 1)[-1]}) — isolated on LAN!",
                }
            if "DIRECT_WAN_OPEN" in out:
                leaks = out.split(":", 1)[1] if ":" in out else "ipv4"
                return {
                    "node_id": node.id,
                    "host": node.host,
                    "online": True,
                    "wan_blocked": False,
                    "detail": f"Direct internet reachable ({leaks}) — block this phone's IPv4/IPv6 WAN & external DNS on your router.",
                }
            return {
                "node_id": node.id,
                "host": node.host,
                "online": True,
                "wan_blocked": None,
                "detail": (out or str(data.get("stderr", "")) or "unknown probe output")[:120],
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(workers))) as pool:
            return list(pool.map(_probe_one, workers))

    def exec_terminal_command(
        self,
        command: str,
        target: str = "auto",
        cwd: str | None = None,
        timeout_sec: float | None = None,
        job_id: str | None = None,
        workload_hint: str = "",
    ) -> list[dict[str, Any]]:
        """Execute an interactive Web Terminal command while tracking persistent `cwd`."""
        marker = f"__PC_CWD_{uuid.uuid4().hex[:8]}__"
        norm_cmd = command.replace("\r\n", "\n").replace("\r", "\n")
        # Double newline ensures a dangling trailing `\` line continuation only consumes
        # the extra blank line and never swallows `__pc_rc=$?` or cwd tracking.
        wrapped = (
            f"{norm_cmd}\n\n"
            f"__pc_rc=$?\n"
            f"printf '\\n{marker}%s\\n' \"$PWD\"\n"
            f"exit $__pc_rc"
        )
        eff_term_timeout = _safe_float(timeout_sec, float(self.config.default_job_timeout_sec)) if timeout_sec is not None else float(self.config.default_job_timeout_sec)
        if eff_term_timeout <= 0:
            eff_term_timeout = float(self.config.default_job_timeout_sec)
        eff_term_timeout = min(_MAX_JOB_TIMEOUT_SEC, eff_term_timeout)
        spec = JobSpec(
            index=0,
            job_id=job_id or f"term-{uuid.uuid4().hex[:8]}",
            command=wrapped,
            workdir=cwd or None,
            timeout_sec=eff_term_timeout,
        )
        outcomes = self.run_single(spec, target=target, workload_hint=workload_hint)
        # Self-heal stale tracked `cwd` (e.g. directory removed or worker phone rebooted)
        if cwd and outcomes and all(
            (not o.ok) and not o.outcome_unknown and "workdir does not exist" in (o.error or "").lower()
            for o in outcomes
        ):
            spec_fallback = replace(spec, workdir=None)
            outcomes = self.run_single(spec_fallback, target=target, workload_hint=workload_hint)
            cwd = None
        results: list[dict[str, Any]] = []
        for o in outcomes:
            out_text = o.stdout
            new_cwd = cwd or ""
            idx = out_text.rfind(marker)
            if idx != -1:
                after = out_text[idx + len(marker) :].splitlines()
                if after:
                    new_cwd = after[0].strip()
                out_text = out_text[:idx]
                if out_text.endswith("\n"):
                    out_text = out_text[:-1]
            rec = o.to_dict()
            rec["stdout"] = out_text
            rec["cwd"] = new_cwd
            results.append(rec)
        return results

    def get_node_jobs(self, node: NodeConfig) -> dict[str, Any]:
        """Fetch active and recent jobs from one worker node."""
        url = f"{node.base_url}/jobs"
        req = urllib.request.Request(
            url, headers=self._headers_for(node, "GET", "/jobs"), method="GET"
        )
        try:
            jobs_to = max(0.5, float(self.config.health_timeout_sec))
            with _DIRECT_OPENER.open(req, timeout=jobs_to) as resp:
                data = read_json_object_bounded(resp, _MAX_JOBS_RESP_BYTES, deadline_sec=jobs_to)
                raw_active = data.get("active")
                raw_recent = data.get("recent")
                active = [j for j in raw_active if isinstance(j, dict)][:64] if isinstance(raw_active, list) else []
                recent = [j for j in raw_recent if isinstance(j, dict)][:50] if isinstance(raw_recent, list) else []
                return {"node_id": node.id, "online": True, "active": active, "recent": recent}
        except urllib.error.HTTPError as exc:
            err = _read_http_error_body(exc, 4096)[:200]
            return {"node_id": node.id, "online": False, "error": f"HTTP {exc.code}: {err}", "active": [], "recent": []}
        except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError, OverflowError) as exc:
            return {"node_id": node.id, "online": False, "error": str(exc), "active": [], "recent": []}

    def get_all_jobs(self) -> list[dict[str, Any]]:
        """Query active & recent jobs across all configured nodes in parallel."""
        with self.config_lock:
            nodes = list(self.config.nodes)
        if not nodes:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            futs = {pool.submit(self.get_node_jobs, n): idx for idx, n in enumerate(nodes)}
            out: list[dict[str, Any] | None] = [None] * len(nodes)
            for fut in concurrent.futures.as_completed(futs):
                out[futs[fut]] = fut.result()
        return [item for item in out if item is not None]

    def push_config_to_node(self, node: NodeConfig, timeout_sec: float = 3.0) -> dict[str, Any]:
        """Push Master's live safety, concurrency, and Master-IP allowlist settings to one worker."""
        with self.config_lock:
            s = self.config.safety
            net = self.config.network
            master_node = next(
                (n for n in self.config.nodes if n.role == "master"),
                self.config.nodes[0] if self.config.nodes else None,
            )
            enforce_ip = net.enforce_worker_source_ip
            req_signed = net.require_signed_requests
            allowed_ips = list(net.allowed_master_ips)
            need_lan_ip = False
            if enforce_ip and master_node is not None and master_node.host:
                m_host = normalize_host(master_node.host)
                if m_host and m_host not in {"0.0.0.0", "::"} and m_host not in allowed_ips:
                    allowed_ips.append(m_host)
                if is_loopback_or_unspecified_host(m_host) and not is_loopback_or_unspecified_host(node.host):
                    need_lan_ip = True
            safety_dict = {
                "max_temp_c": s.max_temp_c,
                "resume_temp_c": s.resume_temp_c,
                "min_free_ram_mb": s.min_free_ram_mb,
                "battery_low_pct": s.battery_low_pct,
                "battery_high_pct": s.battery_high_pct,
                "battery_poll_sec": s.battery_poll_sec,
                "webhook_cooldown_sec": s.webhook_cooldown_sec,
                "battery_webhook_url": s.battery_webhook_url,
            }
        if need_lan_ip:
            # Resolve local LAN IP OUTSIDE `config_lock` so slow air-gapped DNS never stalls Master
            lan_ip = normalize_host(detect_local_ip())
            if lan_ip and not is_loopback_or_unspecified_host(lan_ip) and lan_ip not in allowed_ips:
                allowed_ips.append(lan_ip)
        payload = {
            "target_node_id": node.id,
            "max_concurrency": node.max_concurrency,
            "safety": safety_dict,
            "network": {
                "enforce_worker_source_ip": enforce_ip,
                "require_signed_requests": req_signed,
                "allowed_master_ips": allowed_ips,
            },
        }
        url = f"{node.base_url}/config"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers=self._headers_for(node, "POST", "/config", body),
            method="POST",
        )
        try:
            with _DIRECT_OPENER.open(req, timeout=timeout_sec) as resp:
                data = read_json_object_bounded(resp, _MAX_CTRL_RESP_BYTES, deadline_sec=max(1.0, float(timeout_sec)))
                if data.get("node_id") != node.id or data.get("updated") is not True:
                    return {"node_id": node.id, "ok": False, "error": "Worker did not confirm this policy update."}
                return {**data, "persisted": data.get("persisted") is True, "ok": True}
        except urllib.error.HTTPError as exc:
            raw = _read_http_error_body(exc, 4096)[:200]
            return {"node_id": node.id, "ok": False, "error": f"HTTP {exc.code}: {raw}"}
        except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError, OverflowError) as exc:
            return {"node_id": node.id, "ok": False, "error": str(exc)}

    def push_config_to_all(
        self, node_ids: list[str] | None = None, timeout_sec: float = 3.0
    ) -> dict[str, Any]:
        """Push live Master policy (safety, concurrency, source-IP lock) to non-quarantined online workers in parallel."""
        with self.config_lock:
            if node_ids is not None:
                want = set(node_ids)
                nodes = [n for n in self.config.nodes if n.id in want]
            else:
                quarantined = set(self.config.gateway.quarantined_nodes)
                nodes = [n for n in self.config.nodes if n.id not in quarantined]
        if not nodes:
            return {"ok_count": 0, "persisted_count": 0, "total": 0, "results": []}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            futs = {pool.submit(self.push_config_to_node, n, timeout_sec): idx for idx, n in enumerate(nodes)}
            ordered: list[dict[str, Any] | None] = [None] * len(nodes)
            for fut in concurrent.futures.as_completed(futs):
                ordered[futs[fut]] = fut.result()
        results = [r for r in ordered if r is not None]
        ok_count = sum(1 for r in results if r.get("ok"))
        persisted_count = sum(1 for r in results if r.get("ok") and r.get("persisted"))
        return {"ok_count": ok_count, "persisted_count": persisted_count, "total": len(results), "results": results}

    def cancel_node_job(self, node_id: str, job_id: str) -> dict[str, Any]:
        """Cancel a running job on a specific node."""
        with self.config_lock:
            node = self.config.get_node(node_id)
        url = f"{node.base_url}/cancel"
        body = json.dumps({"job_id": job_id}).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers=self._headers_for(node, "POST", "/cancel", body), method="POST"
        )
        try:
            with _DIRECT_OPENER.open(req, timeout=5.0) as resp:
                return read_json_object_bounded(resp, _MAX_CTRL_RESP_BYTES, deadline_sec=5.0)
        except urllib.error.HTTPError as exc:
            raw = _read_http_error_body(exc, 4096)
            try:
                parsed = json.loads(raw)
                data = parsed if isinstance(parsed, dict) else {"error": raw[:200]}
            except (json.JSONDecodeError, RecursionError):
                data = {"error": raw[:200]}
            return {**data, "cancelled": False, "http_status": exc.code}
        except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError, OverflowError) as exc:
            return {"cancelled": False, "error": str(exc)}
