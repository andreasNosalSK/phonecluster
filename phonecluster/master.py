"""PhoneCluster Master controller, parallel job scheduler, and workload helpers."""

from __future__ import annotations

import collections
import concurrent.futures
import json
import logging
import math
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
    build_auth_headers,
    build_direct_opener,
    build_signed_auth_headers,
    read_json_object_bounded,
)
from .config import (
    ClusterConfig,
    NodeConfig,
    format_host_for_url,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
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

LOG = logging.getLogger("phonecluster.master")

# Direct LAN opener: Master <-> Worker traffic ignores host HTTP_PROXY and refuses HTTP redirects (SSRF defense)
_DIRECT_OPENER = build_direct_opener()
_MAX_HEALTH_RESP_BYTES = 256 * 1024
_MAX_JOBS_RESP_BYTES = 512 * 1024
_MAX_CTRL_RESP_BYTES = 64 * 1024
_MAX_EXEC_RESP_BYTES = 4 * 1024 * 1024  # Plenty for 512 KiB stdout + 512 KiB stderr + JSON overhead


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
            return int(val)
        f = float(val)
        return int(f) if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _safe_float(val: Any, default: float) -> float:
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


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
    cores = max(1, _safe_int(health.get("cpu_cores", 1), 1))
    load_1m = max(0.0, _safe_float(health.get("load_1m", 0.0), 0.0))
    load_ratio = min(load_1m / cores, 2.0)

    temp_raw = health.get("temp_c")
    temp_val = _safe_float(temp_raw, -999.0) if temp_raw is not None else None
    temp_bonus = (
        max(0.0, (max_temp_c - temp_val) / 10.0)
        if temp_val is not None and temp_val > -500.0
        else 0.5
    )

    avail_ram_gb = max(0.0, _safe_float(health.get("mem_available_mb", 512), 512.0)) / 1024.0
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
                    ram_pct = round(((mem_tot - mem_avail) / mem_tot) * 100.0, 1) if mem_tot else 0.0
                    cpu_raw = h.get("cpu_pct")
                    cpu_val = _safe_float(cpu_raw, -1.0) if cpu_raw is not None else -1.0
                    if cpu_val < 0.0:
                        cores = max(1, _safe_int(h.get("cpu_cores", 1), 1))
                        load_val = max(0.0, _safe_float(h.get("load_1m", 0.0), 0.0))
                        cpu_val = min(100.0, round((load_val / cores) * 100.0, 1))
                    temp_raw = h.get("temp_c")
                    temp_clean = _safe_float(temp_raw, -999.0) if temp_raw is not None else None
                    self._nodes[nid].append(
                        {
                            "ts": ts,
                            "online": True,
                            "cpu_pct": min(100.0, max(0.0, cpu_val)),
                            "ram_pct": ram_pct,
                            "temp_c": temp_clean if temp_clean is not None and temp_clean > -500.0 else None,
                            "battery_pct": h.get("battery_pct"),
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
            if current_ids:
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
            with _DIRECT_OPENER.open(req, timeout=self.config.health_timeout_sec) as resp:
                data = read_json_object_bounded(resp, _MAX_HEALTH_RESP_BYTES)
                latency_ms = round((time.monotonic() - t0) * 1000.0, 1)
                return NodeSnapshot(node=node, online=True, latency_ms=latency_ms, health=data)
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read(4096).decode("utf-8", errors="replace")[:200]
            finally:
                exc.close()
            return NodeSnapshot(
                node=node,
                online=False,
                error=f"HTTP {exc.code}: {err_body}",
            )
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
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
        - `"retryable"`: HTTP 503 (overheated/busy) or transient network failure
        - `"error"`: non-retryable HTTP 4xx error
        """
        url = f"{node.base_url}/exec"
        body = json.dumps(spec.to_payload()).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers=self._headers_for(node, "POST", "/exec", body), method="POST"
        )
        http_timeout = max(spec.timeout_sec + 15.0, 30.0)
        try:
            with _DIRECT_OPENER.open(req, timeout=http_timeout) as resp:
                return "ok", read_json_object_bounded(resp, _MAX_EXEC_RESP_BYTES)
        except urllib.error.HTTPError as exc:
            try:
                raw_err = exc.read(65536).decode("utf-8", errors="replace")
            finally:
                exc.close()
            try:
                parsed_err = json.loads(raw_err)
                err_data = parsed_err if isinstance(parsed_err, dict) else {"error": raw_err[:300]}
            except json.JSONDecodeError:
                err_data = {"error": raw_err[:300]}
            if exc.code in {HTTPStatus.SERVICE_UNAVAILABLE, HTTPStatus.TOO_MANY_REQUESTS}:
                return "retryable", err_data
            return "error", {"http_status": exc.code, **err_data}
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
            return "retryable", {"error": str(exc)}

    def _with_node_env(
        self, spec: JobSpec, node: NodeConfig, cross_env: dict[str, str]
    ) -> JobSpec:
        """Return a copy of `spec` enriched with cross-tier mesh + optional per-worker gateway proxy env."""
        merged = dict(cross_env)
        with self.config_lock:
            proxy_env = build_worker_proxy_env(
                self.config, node, port_override=self.gateway_port_override
            )
        if proxy_env:
            merged.update(proxy_env)
        if spec.env:
            merged.update(spec.env)
        return replace(spec, env=merged)

    def run_single(
        self,
        spec: JobSpec,
        target: str = "auto",
        tags: list[str] | None = None,
        workload_hint: str = "",
    ) -> list[JobOutcome]:
        """Run a job via smart auto-routing (`auto`), Tier/Pool (`tier:1|2|3`, `pool:<name>`),
        best overall node (`best`), all ready nodes (`all`), or a specific node ID.

        Automatically injects live cross-tier `PHONECLUSTER_*` service-discovery variables
        into every job so Tier 1/2/3 workloads seamlessly communicate as one system.
        """
        snapshots = self.poll_health(tags=tags)
        with self.config_lock:
            cross_env = build_cross_tier_env(snapshots, self.config)
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
                        self._with_node_env(spec, s.node, cross_env),
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
            # Fail over automatically across remaining ranked candidates on transient 503/disconnect
            last_snap = candidates[0]
            last_kind = "retryable"
            last_data: dict[str, Any] = {}
            attempts = 0
            for cand in candidates:
                attempts += 1
                last_snap = cand
                last_kind, last_data = self.exec_on_node(
                    cand.node, self._with_node_env(spec, cand.node, cross_env)
                )
                if last_kind != "retryable":
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
        kind, data = self.exec_on_node(node, self._with_node_env(spec, node, cross_env))
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
    ) -> list[JobOutcome]:
        """Dynamically distribute a batch of jobs across compatible healthy cluster nodes.

        With `target="auto"`, every job is classified individually and routed to its ideal
        Tier/Pool (e.g., Docker -> Tier 3, Debian services -> Tier 2, general compute -> Tier 1
        with automatic spillover). Respects per-node `max_concurrency`, avoids overheated phones,
        avoids head-of-line blocking across pools, injects live cross-tier `PHONECLUSTER_*` env
        variables, and retries/reroutes on worker throttle (HTTP 503) or disconnect.
        """
        if not jobs:
            return []

        total_jobs = len(jobs)
        outcomes_by_slot: dict[int, JobOutcome] = {}
        last_reason_by_slot: dict[int, str] = {}
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
            if target not in known_ids:
                msg = f"Unknown node id '{target}'. Check cluster.json or `pc status`."
                for slot_idx, job in enumerate(jobs):
                    _record_immediate_fail(slot_idx, job, target, msg, f"Node '{target}' not found in cluster config")
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
        cross_env: dict[str, str] = {}
        last_poll = 0.0

        def _refresh_health() -> None:
            nonlocal snapshots, cross_env, last_poll
            snapshots = self.poll_health(tags=tags)
            with self.config_lock:
                cross_env = build_cross_tier_env(snapshots, self.config)
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
                    enriched = self._with_node_env(spec, chosen_snap.node, cross_env)
                    fut = pool.submit(self.exec_on_node, chosen_snap.node, enriched)
                    running_futures[fut] = (slot_idx, spec, chosen_snap, attempt + 1, failed_nodes, reason)
                    dispatched_any = True
                    no_ready_since = None

                for item in reversed(deferred):
                    pending.appendleft(item)

                if running_futures:
                    done, _ = concurrent.futures.wait(
                        running_futures.keys(),
                        timeout=0.25,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    needs_refresh = False
                    for fut in done:
                        slot_idx, spec, snap, attempt, failed_nodes, reason = running_futures.pop(fut)
                        in_flight_per_node[snap.node.id] = max(
                            0, in_flight_per_node[snap.node.id] - 1
                        )
                        kind, data = fut.result()

                        if kind == "retryable" and attempt <= retries:
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
            name = str(raw_step.get("name") or f"Step {idx}").strip()
            command = str(raw_step.get("command") or "").strip()
            target = str(raw_step.get("target") or "auto").strip() or "auto"
            workload_hint = str(raw_step.get("workload") or raw_step.get("workload_hint") or "").strip()
            continue_on_err = bool(raw_step.get("continue_on_error", False))

            raw_timeout = raw_step.get("timeout_sec")
            if raw_timeout in (None, ""):
                timeout_sec = float(self.config.default_job_timeout_sec)
            else:
                try:
                    timeout_sec = float(raw_timeout)
                    if not math.isfinite(timeout_sec) or timeout_sec <= 0:
                        raise ValueError("must be a finite number > 0")
                except (TypeError, ValueError):
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
                            "error": f"Invalid timeout_sec '{raw_timeout}' (must be a positive number).",
                        }
                    )
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
            results.append(rec)

            clean_out = rec["stdout"].replace("\x00", "").strip()
            prev_stdout = clean_out
            prev_node = primary.node_id
            prev_tier = primary.node_tier
            prev_pool = primary.node_pool
            prev_rc = int(rec.get("returncode", primary.returncode))
            prior_step_env[f"PHONECLUSTER_STEP_{idx}_STDOUT"] = clean_out[:16384]
            prior_step_env[f"PHONECLUSTER_STEP_{idx}_NODE"] = primary.node_id

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
    ) -> JobOutcome:
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
            cores = max(1, _safe_int(snap.health.get("cpu_cores", 4), 4))
            if snap.node.role == "master" or snap.node.host in {"127.0.0.1", "localhost"}:
                slots = max(1, cores - 2)
                entries.append(f"localhost/{slots}")
            else:
                entries.append(f"{format_host_for_url(snap.node.host)}/{cores},lzo")
        return " ".join(entries)

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
        return ",".join(endpoints)

    def build_mpi_hostfile(self, snapshots: list[NodeSnapshot] | None = None) -> str:
        """Generate an OpenMPI hostfile containing healthy, non-quarantined nodes (prefers mpirun-capable)."""
        snaps = snapshots if snapshots is not None else self.poll_health()
        quarantined = self._quarantined_ids()
        ready_snaps = [s for s in snaps if s.ready_for_jobs and s.node.id not in quarantined]
        mpi_snaps = [
            s for s in ready_snaps
            if isinstance(s.health.get("tools"), dict) and s.health["tools"].get("mpirun")
        ]
        chosen = mpi_snaps if mpi_snaps else ready_snaps
        lines: list[str] = []
        for snap in chosen:
            cores = max(1, _safe_int(snap.health.get("cpu_cores", 4), 4))
            lines.append(f"{snap.node.host} slots={cores}")
        return "\n".join(lines) + ("\n" if lines else "")

    def cluster_summary(self, record_history: bool = True) -> dict[str, Any]:
        """Return an aggregate 'one PC' resource summary across all nodes."""
        snapshots = self.poll_health()
        quarantined = self._quarantined_ids()
        total_cores = 0
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
                cores = max(0, _safe_int(snap.health.get("cpu_cores", 0), 0))
                total_cores += cores
                total_ram_mb += max(0, _safe_int(snap.health.get("mem_total_mb", 0), 0))
                avail_ram_mb += max(0, _safe_int(snap.health.get("mem_available_mb", 0), 0))
                total_active_jobs += max(0, _safe_int(snap.health.get("active_jobs", 0), 0))
                latencies.append(max(0.0, _safe_float(snap.latency_ms, 0.0)))
                if snap.ready_for_jobs and not is_q:
                    ready_count += 1
                cpu_raw = snap.health.get("cpu_pct")
                cpu_pct = _safe_float(cpu_raw, -1.0) if cpu_raw is not None else -1.0
                if cpu_pct < 0.0:
                    load_1m = max(0.0, _safe_float(snap.health.get("load_1m", 0.0), 0.0))
                    cpu_pct = min(100.0, (load_1m / max(1, cores)) * 100.0)
                weighted_cpu_sum += min(100.0, max(0.0, cpu_pct)) * max(1, cores)
                if snap.health.get("net_rx_kbps") is not None:
                    total_net_rx += max(0.0, _safe_float(snap.health.get("net_rx_kbps"), 0.0))
                if snap.health.get("net_tx_kbps") is not None:
                    total_net_tx += max(0.0, _safe_float(snap.health.get("net_tx_kbps"), 0.0))
                t_raw = snap.health.get("temp_c")
                if t_raw is not None:
                    t_val = _safe_float(t_raw, -999.0)
                    if t_val > -500.0:
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

        cluster_cpu_pct = round(weighted_cpu_sum / total_cores, 1) if total_cores > 0 else 0.0
        cluster_ram_pct = (
            round(((total_ram_mb - avail_ram_mb) / total_ram_mb) * 100.0, 1)
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
        with self.config_lock:
            quarantined = set(self.config.gateway.quarantined_nodes)
            services = build_service_registry(snaps, self.config)
            env = build_cross_tier_env(snaps, self.config)
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
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout_sec):
                ms = round((time.monotonic() - t0) * 1000.0, 1)
                return {"reachable": True, "latency_ms": ms, "host": host, "port": int(port)}
        except OSError as exc:
            ms = round((time.monotonic() - t0) * 1000.0, 1)
            return {
                "reachable": False,
                "latency_ms": ms,
                "host": host,
                "port": int(port),
                "error": str(exc),
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
        with self.config_lock:
            workers = [n for n in self.config.nodes if n.role != "master"]
        if not workers:
            return []
        probe_code = (
            "import socket, sys\n"
            f"try:\n"
            f"    s = socket.create_connection(({probe_host!r}, {int(probe_port)}), timeout={float(timeout_sec)})\n"
            "    s.close()\n"
            "    print('DIRECT_WAN_OPEN')\n"
            "except OSError as e:\n"
            "    print(f'WAN_BLOCKED:{type(e).__name__}')\n"
        )

        def _probe_one(node: NodeConfig) -> dict[str, Any]:
            spec = JobSpec(
                index=0,
                job_id=f"wancheck-{node.id}-{uuid.uuid4().hex[:6]}",
                script_content=probe_code,
                script_name="wan_check.py",
                interpreter="python3",
                timeout_sec=float(timeout_sec) + 4.0,
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
                return {
                    "node_id": node.id,
                    "host": node.host,
                    "online": True,
                    "wan_blocked": False,
                    "detail": "Direct internet reachable — block this phone's MAC/IP on your router for air-gap isolation.",
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
        spec = JobSpec(
            index=0,
            job_id=job_id or f"term-{uuid.uuid4().hex[:8]}",
            command=wrapped,
            workdir=cwd or None,
            timeout_sec=float(timeout_sec or self.config.default_job_timeout_sec),
        )
        outcomes = self.run_single(spec, target=target, workload_hint=workload_hint)
        # Self-heal stale tracked `cwd` (e.g. directory removed or worker phone rebooted)
        if cwd and outcomes and all(
            (not o.ok) and "workdir does not exist" in (o.error or "").lower()
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
            with _DIRECT_OPENER.open(req, timeout=self.config.health_timeout_sec) as resp:
                data = read_json_object_bounded(resp, _MAX_JOBS_RESP_BYTES)
                raw_active = data.get("active")
                raw_recent = data.get("recent")
                active = [j for j in raw_active if isinstance(j, dict)] if isinstance(raw_active, list) else []
                recent = [j for j in raw_recent if isinstance(j, dict)] if isinstance(raw_recent, list) else []
                return {**data, "node_id": node.id, "online": True, "active": active, "recent": recent}
        except urllib.error.HTTPError as exc:
            try:
                err = exc.read(4096).decode("utf-8", errors="replace")[:200]
            finally:
                exc.close()
            return {"node_id": node.id, "online": False, "error": f"HTTP {exc.code}: {err}", "active": [], "recent": []}
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
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
            allowed_ips = list(net.allowed_master_ips)
            if master_node is not None and master_node.host:
                m_host = normalize_host(master_node.host)
                if m_host and m_host not in allowed_ips:
                    allowed_ips.append(m_host)
                if is_loopback_or_unspecified_host(m_host) and not is_loopback_or_unspecified_host(node.host):
                    lan_ip = normalize_host(detect_local_ip())
                    if lan_ip and not is_loopback_or_unspecified_host(lan_ip) and lan_ip not in allowed_ips:
                        allowed_ips.append(lan_ip)
            payload = {
                "target_node_id": node.id,
                "max_concurrency": node.max_concurrency,
                "safety": {
                    "max_temp_c": s.max_temp_c,
                    "resume_temp_c": s.resume_temp_c,
                    "min_free_ram_mb": s.min_free_ram_mb,
                    "battery_low_pct": s.battery_low_pct,
                    "battery_high_pct": s.battery_high_pct,
                    "battery_poll_sec": s.battery_poll_sec,
                    "webhook_cooldown_sec": s.webhook_cooldown_sec,
                    "battery_webhook_url": s.battery_webhook_url,
                },
                "network": {
                    "enforce_worker_source_ip": net.enforce_worker_source_ip,
                    "require_signed_requests": net.require_signed_requests,
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
                data = read_json_object_bounded(resp, _MAX_CTRL_RESP_BYTES)
                return {**data, "node_id": node.id, "ok": True}
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(4096).decode("utf-8", errors="replace")[:200]
            finally:
                exc.close()
            return {"node_id": node.id, "ok": False, "error": f"HTTP {exc.code}: {raw}"}
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
            return {"node_id": node.id, "ok": False, "error": str(exc)}

    def push_config_to_all(
        self, node_ids: list[str] | None = None, timeout_sec: float = 3.0
    ) -> dict[str, Any]:
        """Push live Master policy (safety, concurrency, source-IP lock) to online workers in parallel."""
        with self.config_lock:
            if node_ids is not None:
                want = set(node_ids)
                nodes = [n for n in self.config.nodes if n.id in want]
            else:
                nodes = list(self.config.nodes)
        if not nodes:
            return {"ok_count": 0, "total": 0, "results": []}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            futs = {pool.submit(self.push_config_to_node, n, timeout_sec): idx for idx, n in enumerate(nodes)}
            ordered: list[dict[str, Any] | None] = [None] * len(nodes)
            for fut in concurrent.futures.as_completed(futs):
                ordered[futs[fut]] = fut.result()
        results = [r for r in ordered if r is not None]
        ok_count = sum(1 for r in results if r.get("ok"))
        return {"ok_count": ok_count, "total": len(results), "results": results}

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
                return read_json_object_bounded(resp, _MAX_CTRL_RESP_BYTES)
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(4096).decode("utf-8", errors="replace")
            finally:
                exc.close()
            try:
                parsed = json.loads(raw)
                data = parsed if isinstance(parsed, dict) else {"error": raw[:200]}
            except json.JSONDecodeError:
                data = {"error": raw[:200]}
            return {"cancelled": False, "http_status": exc.code, **data}
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
            return {"cancelled": False, "error": str(exc)}
