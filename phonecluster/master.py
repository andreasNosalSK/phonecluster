"""PhoneCluster Master controller, parallel job scheduler, and workload helpers."""

from __future__ import annotations

import collections
import concurrent.futures
import json
import logging
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Callable

from .auth import build_auth_headers
from .config import ClusterConfig, NodeConfig

LOG = logging.getLogger("phonecluster.master")


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
    def active_jobs(self) -> int:
        return int(self.health.get("active_jobs", 0))

    @property
    def max_concurrency(self) -> int:
        return int(self.health.get("max_concurrency", self.node.max_concurrency))

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

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error and not self.timed_out and not self.cancelled

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "job_id": self.job_id,
            "label": self.label,
            "node_id": self.node_id,
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


def score_node(snapshot: NodeSnapshot, in_flight_local: int = 0, max_temp_c: float = 40.0) -> float:
    """Rank healthy nodes so cooler, faster, less-loaded phones get picked first."""
    if not snapshot.online:
        return -1e9
    effective_active = max(snapshot.active_jobs, in_flight_local)
    free_slots = snapshot.max_concurrency - effective_active
    if free_slots <= 0:
        return -1e6

    health = snapshot.health
    cores = max(1, int(health.get("cpu_cores", 1)))
    load_1m = float(health.get("load_1m", 0.0))
    load_ratio = min(load_1m / cores, 2.0)

    temp_c = health.get("temp_c")
    temp_bonus = max(0.0, (max_temp_c - float(temp_c)) / 10.0) if temp_c is not None else 0.5

    avail_ram_gb = float(health.get("mem_available_mb", 512)) / 1024.0
    slot_ratio = free_slots / max(1, snapshot.max_concurrency)

    return (
        snapshot.node.weight * 3.0
        + slot_ratio * 2.5
        + temp_bonus * 1.5
        + min(avail_ram_gb, 4.0) * 0.4
        - load_ratio * 1.5
    )


class MasterController:
    """Coordinates health polling, job scheduling, and workload helpers across all nodes."""

    def __init__(self, config: ClusterConfig) -> None:
        self.config = config
        self.headers = build_auth_headers(config.auth_token)

    def _filter_nodes(self, tags: list[str] | None = None) -> list[NodeConfig]:
        if not tags:
            return list(self.config.nodes)
        want = set(tags)
        return [n for n in self.config.nodes if want.issubset(set(n.tags))]

    def check_node_health(self, node: NodeConfig) -> NodeSnapshot:
        """Query GET /health on a single worker node."""
        url = f"{node.base_url}/health"
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.config.health_timeout_sec) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                latency_ms = round((time.monotonic() - t0) * 1000.0, 1)
                return NodeSnapshot(node=node, online=True, latency_ms=latency_ms, health=data)
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:200]
            finally:
                exc.close()
            return NodeSnapshot(
                node=node,
                online=False,
                error=f"HTTP {exc.code}: {err_body}",
            )
        except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError) as exc:
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
        req = urllib.request.Request(url, data=body, headers=self.headers, method="POST")
        http_timeout = max(spec.timeout_sec + 15.0, 30.0)
        try:
            with urllib.request.urlopen(req, timeout=http_timeout) as resp:
                raw = resp.read().decode("utf-8")
                return "ok", json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                raw_err = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            try:
                err_data = json.loads(raw_err)
            except json.JSONDecodeError:
                err_data = {"error": raw_err[:300]}
            if exc.code in {HTTPStatus.SERVICE_UNAVAILABLE, HTTPStatus.TOO_MANY_REQUESTS}:
                return "retryable", err_data
            return "error", {"http_status": exc.code, **err_data}
        except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError) as exc:
            return "retryable", {"error": str(exc)}

    def run_single(
        self,
        spec: JobSpec,
        target: str = "best",
        tags: list[str] | None = None,
    ) -> list[JobOutcome]:
        """Run a job on the single best node (`best`), all ready nodes (`all`), or a specific node ID."""
        snapshots = self.poll_health(tags=tags)
        if target == "all":
            chosen = [s for s in snapshots if s.online and (s.ready_for_jobs or spec.force)]
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
                    )
                ]
            outcomes: list[JobOutcome] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(chosen)) as pool:
                fut_map = {
                    pool.submit(self.exec_on_node, s.node, spec): s.node for s in chosen
                }
                for fut in concurrent.futures.as_completed(fut_map):
                    node = fut_map[fut]
                    kind, data = fut.result()
                    outcomes.append(self._to_outcome(spec, node.id, kind, data, attempts=1))
            outcomes.sort(key=lambda o: o.node_id)
            return outcomes

        if target == "best":
            candidates = [s for s in snapshots if s.online and (s.ready_for_jobs or spec.force)]
            if not candidates:
                return [
                    JobOutcome(
                        index=spec.index,
                        job_id=spec.job_id,
                        label=spec.label,
                        node_id="none",
                        returncode=-1,
                        duration_sec=0.0,
                        error="No online, ready nodes available.",
                    )
                ]
            candidates.sort(
                key=lambda s: score_node(s, max_temp_c=self.config.safety.max_temp_c),
                reverse=True,
            )
            best_node = candidates[0].node
            kind, data = self.exec_on_node(best_node, spec)
            return [self._to_outcome(spec, best_node.id, kind, data, attempts=1)]

        # Specific node id
        node = self.config.get_node(target)
        kind, data = self.exec_on_node(node, spec)
        return [self._to_outcome(spec, node.id, kind, data, attempts=1)]

    def map_jobs(
        self,
        jobs: list[JobSpec],
        retries: int = 1,
        tags: list[str] | None = None,
        health_refresh_sec: float = 5.0,
        wait_for_ready_sec: float = 30.0,
        on_result: Callable[[JobOutcome, int, int], None] | None = None,
    ) -> list[JobOutcome]:
        """Dynamically distribute a batch of jobs across all healthy cluster nodes.

        Automatically respects per-node max_concurrency, avoids overheated phones,
        and retries/reroutes jobs if a worker throttles (HTTP 503) or disconnects.
        """
        if not jobs:
            return []

        pending: collections.deque[tuple[JobSpec, int, set[str]]] = collections.deque(
            (job, 0, set()) for job in jobs
        )
        outcomes_by_index: dict[int, JobOutcome] = {}
        in_flight_per_node: dict[str, int] = collections.defaultdict(int)
        running_futures: dict[
            concurrent.futures.Future[tuple[str, dict[str, Any]]],
            tuple[JobSpec, NodeConfig, int, set[str]],
        ] = {}

        snapshots = self.poll_health(tags=tags)
        last_poll = time.monotonic()
        no_ready_since: float | None = None
        completed_count = 0
        total_jobs = len(jobs)

        max_workers = max(
            1,
            sum(n.max_concurrency for n in self._filter_nodes(tags)),
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            while pending or running_futures:
                now = time.monotonic()
                if now - last_poll >= health_refresh_sec:
                    snapshots = self.poll_health(tags=tags)
                    last_poll = time.monotonic()

                dispatched_any = False
                # Dispatch as many pending jobs as there are free healthy slots
                deferred: list[tuple[JobSpec, int, set[str]]] = []
                while pending:
                    spec, attempt, failed_nodes = pending.popleft()
                    eligible = [
                        s
                        for s in snapshots
                        if s.online
                        and (s.ready_for_jobs or spec.force)
                        and in_flight_per_node[s.node.id] < s.max_concurrency
                    ]
                    if not eligible:
                        deferred.append((spec, attempt, failed_nodes))
                        break

                    # Prefer nodes that didn't just reject this job if alternatives exist
                    preferred = [s for s in eligible if s.node.id not in failed_nodes]
                    pool_candidates = preferred if preferred else eligible
                    pool_candidates.sort(
                        key=lambda s: score_node(
                            s,
                            in_flight_local=in_flight_per_node[s.node.id],
                            max_temp_c=self.config.safety.max_temp_c,
                        ),
                        reverse=True,
                    )
                    chosen = pool_candidates[0].node
                    in_flight_per_node[chosen.id] += 1
                    fut = pool.submit(self.exec_on_node, chosen, spec)
                    running_futures[fut] = (spec, chosen, attempt + 1, failed_nodes)
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
                    for fut in done:
                        spec, node, attempt, failed_nodes = running_futures.pop(fut)
                        in_flight_per_node[node.id] = max(0, in_flight_per_node[node.id] - 1)
                        kind, data = fut.result()

                        if kind == "retryable" and attempt <= retries:
                            failed_nodes.add(node.id)
                            pending.appendleft((spec, attempt, failed_nodes))
                            # Refresh health immediately since a node likely throttled or dropped
                            snapshots = self.poll_health(tags=tags)
                            last_poll = time.monotonic()
                            continue

                        outcome = self._to_outcome(spec, node.id, kind, data, attempts=attempt)
                        outcomes_by_index[spec.index] = outcome
                        completed_count += 1
                        if on_result is not None:
                            on_result(outcome, completed_count, total_jobs)
                elif pending and not dispatched_any:
                    # No jobs running and no node currently ready (all hot/offline)
                    if no_ready_since is None:
                        no_ready_since = time.monotonic()
                    elapsed_wait = time.monotonic() - no_ready_since
                    if elapsed_wait >= wait_for_ready_sec:
                        # Fail remaining jobs clearly instead of hanging forever
                        while pending:
                            spec, attempt, _ = pending.popleft()
                            outcome = JobOutcome(
                                index=spec.index,
                                job_id=spec.job_id,
                                label=spec.label,
                                node_id="none",
                                returncode=-1,
                                duration_sec=0.0,
                                attempts=attempt,
                                error=(
                                    f"No ready nodes became available within "
                                    f"{wait_for_ready_sec:.0f}s (nodes offline or overheated)."
                                ),
                            )
                            outcomes_by_index[spec.index] = outcome
                            completed_count += 1
                            if on_result is not None:
                                on_result(outcome, completed_count, total_jobs)
                        break
                    time.sleep(min(1.0, max(0.1, wait_for_ready_sec - elapsed_wait)))
                    snapshots = self.poll_health(tags=tags)
                    last_poll = time.monotonic()

        return [outcomes_by_index[i] for i in sorted(outcomes_by_index.keys())]

    @staticmethod
    def _to_outcome(
        spec: JobSpec,
        node_id: str,
        kind: str,
        data: dict[str, Any],
        attempts: int,
    ) -> JobOutcome:
        if kind == "ok":
            return JobOutcome(
                index=spec.index,
                job_id=str(data.get("job_id", spec.job_id)),
                label=spec.label,
                node_id=node_id,
                returncode=int(data.get("returncode", -1)),
                duration_sec=float(data.get("duration_sec", 0.0)),
                stdout=str(data.get("stdout", "")),
                stderr=str(data.get("stderr", "")),
                timed_out=bool(data.get("timed_out", False)),
                cancelled=bool(data.get("cancelled", False)),
                attempts=attempts,
            )
        err_msg = data.get("error") or ", ".join(data.get("reasons", [])) or str(data)
        return JobOutcome(
            index=spec.index,
            job_id=spec.job_id,
            label=spec.label,
            node_id=node_id,
            returncode=-1,
            duration_sec=0.0,
            attempts=attempts,
            error=str(err_msg),
        )

    # ------------------------------------------------------------------
    # Workload integration helpers (distcc, llama.cpp RPC, OpenMPI)
    # ------------------------------------------------------------------

    def build_distcc_hosts(self, include_stopped: bool = False) -> str:
        """Build a `DISTCC_HOSTS` string from currently healthy cluster nodes."""
        snapshots = self.poll_health()
        entries: list[str] = []
        for snap in snapshots:
            if not snap.ready_for_jobs:
                continue
            services = snap.health.get("services", {})
            tools = snap.health.get("tools", {})
            running = bool(services.get("distccd_3632"))
            installed = bool(tools.get("distccd"))
            if not running and not (include_stopped and installed):
                continue
            cores = max(1, int(snap.health.get("cpu_cores", 4)))
            if snap.node.role == "master" or snap.node.host in {"127.0.0.1", "localhost"}:
                slots = max(1, cores - 2)
                entries.append(f"localhost/{slots}")
            else:
                entries.append(f"{snap.node.host}/{cores},lzo")
        return " ".join(entries)

    def build_llama_rpc_arg(self, port: int = 50052, include_master: bool = False) -> str:
        """Build a comma-separated `--rpc` endpoint list for healthy llama.cpp workers."""
        snapshots = self.poll_health()
        endpoints: list[str] = []
        for snap in snapshots:
            if not snap.ready_for_jobs:
                continue
            if not include_master and snap.node.role == "master":
                continue
            if snap.health.get("services", {}).get("llama_rpc_50052"):
                endpoints.append(f"{snap.node.host}:{port}")
        return ",".join(endpoints)

    def build_mpi_hostfile(self) -> str:
        """Generate an OpenMPI hostfile containing all currently healthy nodes."""
        snapshots = self.poll_health()
        lines: list[str] = []
        for snap in snapshots:
            if not snap.ready_for_jobs:
                continue
            cores = max(1, int(snap.health.get("cpu_cores", 4)))
            lines.append(f"{snap.node.host} slots={cores}")
        return "\n".join(lines) + ("\n" if lines else "")

    def cluster_summary(self) -> dict[str, Any]:
        """Return an aggregate 'one PC' resource summary across all nodes."""
        snapshots = self.poll_health()
        total_cores = 0
        total_ram_mb = 0
        avail_ram_mb = 0
        online_count = 0
        ready_count = 0
        temps: list[float] = []
        node_dicts: list[dict[str, Any]] = []

        for snap in snapshots:
            if snap.online:
                online_count += 1
                total_cores += int(snap.health.get("cpu_cores", 0))
                total_ram_mb += int(snap.health.get("mem_total_mb", 0))
                avail_ram_mb += int(snap.health.get("mem_available_mb", 0))
                if snap.ready_for_jobs:
                    ready_count += 1
                t = snap.health.get("temp_c")
                if t is not None:
                    temps.append(float(t))
            node_dicts.append(
                {
                    "id": snap.node.id,
                    "host": snap.node.host,
                    "role": snap.node.role,
                    "worker_port": snap.node.worker_port,
                    "ssh_port": snap.node.ssh_port,
                    "ssh_user": snap.node.ssh_user,
                    "max_concurrency": snap.node.max_concurrency,
                    "weight": snap.node.weight,
                    "tags": snap.node.tags,
                    "notes": snap.node.notes,
                    "online": snap.online,
                    "ready_for_jobs": snap.ready_for_jobs,
                    "latency_ms": snap.latency_ms,
                    "error": snap.error,
                    "health": snap.health,
                }
            )

        return {
            "cluster_name": self.config.cluster_name,
            "nodes_total": len(snapshots),
            "nodes_online": online_count,
            "nodes_ready": ready_count,
            "total_cores": total_cores,
            "mem_total_mb": total_ram_mb,
            "mem_available_mb": avail_ram_mb,
            "max_temp_c": max(temps) if temps else None,
            "safety": {
                "max_temp_c": self.config.safety.max_temp_c,
                "resume_temp_c": self.config.safety.resume_temp_c,
                "min_free_ram_mb": self.config.safety.min_free_ram_mb,
                "battery_low_pct": self.config.safety.battery_low_pct,
                "battery_high_pct": self.config.safety.battery_high_pct,
                "battery_webhook_configured": bool(self.config.safety.battery_webhook_url),
            },
            "timestamp": int(time.time()),
            "nodes": node_dicts,
        }

    def get_node_jobs(self, node: NodeConfig) -> dict[str, Any]:
        """Fetch active and recent jobs from one worker node."""
        url = f"{node.base_url}/jobs"
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.config.health_timeout_sec) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {"node_id": node.id, "online": True, **data}
        except urllib.error.HTTPError as exc:
            try:
                err = exc.read().decode("utf-8", errors="replace")[:200]
            finally:
                exc.close()
            return {"node_id": node.id, "online": False, "error": f"HTTP {exc.code}: {err}", "active": [], "recent": []}
        except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError) as exc:
            return {"node_id": node.id, "online": False, "error": str(exc), "active": [], "recent": []}

    def get_all_jobs(self) -> list[dict[str, Any]]:
        """Query active & recent jobs across all configured nodes in parallel."""
        nodes = list(self.config.nodes)
        if not nodes:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(nodes))) as pool:
            futs = {pool.submit(self.get_node_jobs, n): idx for idx, n in enumerate(nodes)}
            out: list[dict[str, Any] | None] = [None] * len(nodes)
            for fut in concurrent.futures.as_completed(futs):
                out[futs[fut]] = fut.result()
        return [item for item in out if item is not None]

    def cancel_node_job(self, node_id: str, job_id: str) -> dict[str, Any]:
        """Cancel a running job on a specific node."""
        node = self.config.get_node(node_id)
        url = f"{node.base_url}/cancel"
        body = json.dumps({"job_id": job_id}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            finally:
                exc.close()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"error": raw[:200]}
            return {"cancelled": False, "http_status": exc.code, **data}
        except (urllib.error.URLError, socket.timeout, OSError, json.JSONDecodeError) as exc:
            return {"cancelled": False, "error": str(exc)}
