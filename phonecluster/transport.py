"""Dual-Plane Transport & Failover Manager (USB Control + Wi-Fi Data).

Provides:
- Dual-Plane Split routing: USB RNDIS / ADB for low-latency control & management,
  Wi-Fi / LAN for high-bandwidth data workloads (distcc, llama.cpp RPC, OpenMPI,
  Docker Swarm, Cross-Tier Service Mesh).
- 100% backward compatibility with single-host clusters (`single_wifi` / `single_usb`).
- Hysteresis-based automatic failover (`failover_threshold` consecutive failures)
  and automatic recovery (`recovery_threshold` consecutive healthy probes) back to
  Dual-Plane Split without flapping on transient packet loss.
- Thread-safe live state snapshots, bounded transition event history, manual
  failover/recovery controls, and an optional background probe daemon.
"""

from __future__ import annotations

import collections
import concurrent.futures
import http.client
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .auth import build_direct_opener, read_json_object_bounded
from .config import (
    VALID_TRANSPORT_MODES,
    NodeConfig,
    TransportConfig,
    format_host_port,
    normalize_host,
)

LOG = logging.getLogger("phonecluster.transport")

_DIRECT_OPENER = build_direct_opener()
_MAX_PROBE_RESP_BYTES = 256 * 1024
_MAX_EVENT_HISTORY = 120

ProbeFn = Callable[[NodeConfig, str, str, int, float], tuple[bool, float, str]]


@dataclass
class PlaneHealth:
    """Tracked liveness and hysteresis counters for one transport plane (`usb` or `wifi`)."""

    plane: str
    host: str = ""
    port: int = 0
    configured: bool = False
    status: str = "unconfigured"  # "unconfigured" | "unknown" | "up" | "down"
    healthy: bool = False
    latency_ms: float | None = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_checked_ts: float = 0.0
    last_ok_ts: float = 0.0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plane": self.plane,
            "host": self.host,
            "port": self.port,
            "configured": self.configured,
            "status": self.status,
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "last_checked_ts": int(self.last_checked_ts) if self.last_checked_ts else 0,
            "last_ok_ts": int(self.last_ok_ts) if self.last_ok_ts else 0,
            "last_error": self.last_error,
        }


@dataclass
class NodeTransportState:
    """Live Dual-Plane routing and failover state for a single cluster node."""

    node_id: str
    usb: PlaneHealth
    wifi: PlaneHealth
    control_plane: str  # "usb" | "wifi"
    data_plane: str  # "wifi" | "usb"
    state: str  # "dual_plane" | "failover_usb_only" | "failover_wifi_only" | "forced_usb" | "forced_wifi" | "single_usb" | "single_wifi" | "offline"
    failover_active: bool = False
    manual_override: str = ""  # "" | "usb" | "wifi"
    last_transition_ts: float = 0.0
    last_transition_reason: str = ""
    failover_count: int = 0
    recovery_count: int = 0


def _sanitize_reason(text: str, max_len: int = 180) -> str:
    cleaned = "".join(ch if (ord(ch) >= 32 and ord(ch) != 127) else " " for ch in str(text or ""))
    return " ".join(cleaned.split())[:max_len]


class TransportManager:
    """Thread-safe Dual-Plane Transport, Failover, and Hysteresis Auto-Recovery Manager."""

    def __init__(
        self,
        controller: Any,
        *,
        probe_fn: ProbeFn | None = None,
    ) -> None:
        self.controller = controller
        self._probe_fn = probe_fn
        self._lock = threading.RLock()
        self._states: dict[str, NodeTransportState] = {}
        self._events: collections.deque[dict[str, Any]] = collections.deque(maxlen=_MAX_EVENT_HISTORY)
        self._last_probe_ts: float = 0.0
        self._prober_thread: TransportProbeThread | None = None
        self.sync_nodes()

    def _get_config_snapshot(self) -> tuple[TransportConfig, list[NodeConfig]]:
        lock = getattr(self.controller, "config_lock", None)
        if lock is not None:
            with lock:
                cfg = self.controller.config
                return cfg.transport, list(cfg.nodes)
        cfg = self.controller.config
        return cfg.transport, list(cfg.nodes)

    @staticmethod
    def _build_plane_health(node: NodeConfig, plane: str) -> PlaneHealth:
        host, port = node.plane_endpoint(plane)
        if host and port > 0:
            return PlaneHealth(
                plane=plane,
                host=host,
                port=int(port),
                configured=True,
                status="unknown",
                healthy=True,  # Optimistic until probes reach failover_threshold
            )
        return PlaneHealth(plane=plane, host="", port=0, configured=False, status="unconfigured", healthy=False)

    def _sync_single_node_locked(self, node: NodeConfig, tcfg: TransportConfig) -> NodeTransportState:
        st = self._states.get(node.id)
        uh, up = node.plane_endpoint("usb")
        wh, wp = node.plane_endpoint("wifi")
        if st is None:
            usb_p = self._build_plane_health(node, "usb")
            wifi_p = self._build_plane_health(node, "wifi")
            ctl = "usb" if usb_p.configured else "wifi"
            dat = "wifi" if wifi_p.configured else "usb"
            init_state = "dual_plane" if node.has_dual_plane() else ("single_usb" if usb_p.configured else "single_wifi")
            st = NodeTransportState(
                node_id=node.id,
                usb=usb_p,
                wifi=wifi_p,
                control_plane=ctl,
                data_plane=dat,
                state=init_state,
            )
            self._states[node.id] = st
            self._reconcile_node_locked(st, node, tcfg, reason="initial config", emit_event=False)
            return st

        # Refresh plane endpoints if host/port changed in cluster.json
        changed = False
        if (normalize_host(st.usb.host), st.usb.port, st.usb.configured) != (normalize_host(uh), int(up), bool(uh and up > 0)):
            st.usb = self._build_plane_health(node, "usb")
            changed = True
        if (normalize_host(st.wifi.host), st.wifi.port, st.wifi.configured) != (normalize_host(wh), int(wp), bool(wh and wp > 0)):
            st.wifi = self._build_plane_health(node, "wifi")
            changed = True
        if changed:
            if st.manual_override == "usb" and not st.usb.configured:
                st.manual_override = ""
            elif st.manual_override == "wifi" and not st.wifi.configured:
                st.manual_override = ""
            self._reconcile_node_locked(
                st, node, tcfg, reason="node endpoints updated", emit_event=True, allow_recovery=tcfg.auto_recover
            )
        else:
            self._reconcile_node_locked(
                st, node, tcfg, reason="mode/policy sync", emit_event=False, allow_recovery=tcfg.auto_recover
            )
        return st

    def sync_nodes(self) -> None:
        """Synchronize tracked node plane states with current `controller.config.nodes`."""
        tcfg, nodes = self._get_config_snapshot()
        with self._lock:
            active_ids = {n.id for n in nodes}
            for stale_id in [nid for nid in self._states if nid not in active_ids]:
                self._states.pop(stale_id, None)
            for node in nodes:
                self._sync_single_node_locked(node, tcfg)

    def has_any_dual_plane_node(self) -> bool:
        """Return True if at least one configured node has both distinct USB and Wi-Fi endpoints."""
        _, nodes = self._get_config_snapshot()
        return any(n.has_dual_plane() for n in nodes)

    def _record_event_locked(
        self,
        *,
        node_id: str,
        kind: str,
        from_state: str,
        to_state: str,
        control_plane: str,
        data_plane: str,
        reason: str,
    ) -> None:
        self._events.appendleft(
            {
                "ts": int(time.time()),
                "node_id": node_id,
                "kind": kind,
                "from_state": from_state,
                "to_state": to_state,
                "control_plane": control_plane,
                "data_plane": data_plane,
                "reason": _sanitize_reason(reason),
            }
        )

    def _reconcile_node_locked(
        self,
        st: NodeTransportState,
        node: NodeConfig,
        tcfg: TransportConfig,
        *,
        reason: str,
        emit_event: bool = True,
        allow_recovery: bool = True,
    ) -> None:
        prev_state = st.state
        prev_ctl = st.control_plane
        prev_dat = st.data_plane
        mode = tcfg.mode if tcfg.mode in VALID_TRANSPORT_MODES else "auto"

        usb_avail = st.usb.configured and st.usb.status != "down"
        wifi_avail = st.wifi.configured and st.wifi.status != "down"
        has_dual = node.has_dual_plane()

        new_ctl = st.control_plane
        new_dat = st.data_plane
        new_state = st.state
        new_failover = False

        if not has_dual:
            # Single-plane node (legacy or single-transport)
            only_plane = "usb" if st.usb.configured else "wifi"
            only_health = st.usb if only_plane == "usb" else st.wifi
            new_ctl = only_plane
            new_dat = only_plane
            new_failover = False
            if only_health.status == "down":
                new_state = "offline"
            else:
                new_state = "single_usb" if only_plane == "usb" else "single_wifi"
        elif st.manual_override in {"usb", "wifi"}:
            pinned = st.manual_override
            pinned_h = st.usb if pinned == "usb" else st.wifi
            new_ctl = pinned
            new_dat = pinned
            if pinned_h.status == "down":
                new_state = "offline"
                new_failover = False
            else:
                new_state = "failover_usb_only" if pinned == "usb" else "failover_wifi_only"
                new_failover = True
        elif mode == "usb_only":
            new_ctl = "usb"
            new_dat = "usb"
            new_failover = False
            new_state = "offline" if not usb_avail else "forced_usb"
        elif mode == "wifi_only":
            new_ctl = "wifi"
            new_dat = "wifi"
            new_failover = False
            new_state = "offline" if not wifi_avail else "forced_wifi"
        else:
            # mode in {"dual_plane", "auto"} on a Dual-Plane node
            if not usb_avail and not wifi_avail:
                new_ctl = "usb"
                new_dat = "wifi"
                new_state = "offline"
                new_failover = False
            elif usb_avail and wifi_avail:
                # If previously in failover and auto_recover is disabled, stay pinned until explicit recovery!
                if (not allow_recovery) and prev_state in {"failover_usb_only", "failover_wifi_only"}:
                    new_state = prev_state
                    new_ctl = prev_ctl
                    new_dat = prev_dat
                    new_failover = True
                else:
                    new_ctl = "usb"
                    new_dat = "wifi"
                    new_state = "dual_plane"
                    new_failover = False
            elif usb_avail and not wifi_avail:
                if tcfg.auto_failover:
                    new_ctl = "usb"
                    new_dat = "usb"
                    new_state = "failover_usb_only"
                    new_failover = True
                else:
                    new_ctl = "usb"
                    new_dat = "wifi"
                    new_state = "dual_plane"
                    new_failover = False
            else:  # wifi_avail and not usb_avail
                if tcfg.auto_failover:
                    new_ctl = "wifi"
                    new_dat = "wifi"
                    new_state = "failover_wifi_only"
                    new_failover = True
                else:
                    new_ctl = "usb"
                    new_dat = "wifi"
                    new_state = "dual_plane"
                    new_failover = False

        st.control_plane = new_ctl
        st.data_plane = new_dat
        st.state = new_state
        st.failover_active = new_failover

        if (new_state != prev_state or new_ctl != prev_ctl or new_dat != prev_dat) and emit_event:
            now = time.time()
            st.last_transition_ts = now
            st.last_transition_reason = _sanitize_reason(reason)
            if new_state in {"failover_usb_only", "failover_wifi_only"} and prev_state not in {"failover_usb_only", "failover_wifi_only"}:
                kind = "failover"
                st.failover_count += 1
                LOG.warning(
                    "Transport FAILOVER on %s: %s -> %s (ctl=%s, data=%s, reason=%s)",
                    st.node_id, prev_state, new_state, new_ctl, new_dat, st.last_transition_reason,
                )
            elif new_state == "dual_plane" and prev_state in {"failover_usb_only", "failover_wifi_only", "offline"}:
                kind = "recovery"
                st.recovery_count += 1
                LOG.info(
                    "Transport RECOVERY on %s: %s -> dual_plane (ctl=usb, data=wifi, reason=%s)",
                    st.node_id, prev_state, st.last_transition_reason,
                )
            elif new_state == "offline":
                kind = "offline"
                LOG.warning("Transport OFFLINE on %s: all configured planes unreachable (%s)", st.node_id, st.last_transition_reason)
            elif prev_state == "offline" and new_state != "offline":
                kind = "online"
            else:
                kind = "mode_change"
            self._record_event_locked(
                node_id=st.node_id,
                kind=kind,
                from_state=prev_state,
                to_state=new_state,
                control_plane=new_ctl,
                data_plane=new_dat,
                reason=st.last_transition_reason,
            )

    def record_probe(
        self,
        node_id: str,
        plane: str,
        ok: bool,
        *,
        latency_ms: float | None = None,
        error: str = "",
        force_immediate: bool = False,
    ) -> dict[str, Any] | None:
        """Apply one probe observation with hysteresis thresholds and return updated node transport state."""
        if plane not in {"usb", "wifi"}:
            raise ValueError(f"plane must be 'usb' or 'wifi' (got {plane!r})")
        tcfg, nodes = self._get_config_snapshot()
        node = next((n for n in nodes if n.id == node_id), None)
        if node is None:
            return None

        now = time.time()
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            ph = st.usb if plane == "usb" else st.wifi
            if not ph.configured:
                return self._node_state_dict_locked(st, node)

            ph.last_checked_ts = now
            if latency_ms is not None:
                ph.latency_ms = round(max(0.0, float(latency_ms)), 1)

            fail_th = max(1, int(tcfg.failover_threshold))
            rec_th = max(1, int(tcfg.recovery_threshold))
            reason = ""
            if ok:
                ph.consecutive_successes += 1
                ph.consecutive_failures = 0
                ph.last_ok_ts = now
                ph.last_error = ""
                if ph.status == "unknown":
                    ph.status = "up"
                    ph.healthy = True
                    reason = f"{plane} plane verified healthy"
                elif ph.status == "down":
                    if force_immediate or ph.consecutive_successes >= rec_th:
                        ph.status = "up"
                        ph.healthy = True
                        reason = f"{plane} plane recovered ({ph.consecutive_successes}/{rec_th} healthy probes)"
                else:
                    ph.status = "up"
                    ph.healthy = True
            else:
                ph.consecutive_failures += 1
                ph.consecutive_successes = 0
                ph.last_error = _sanitize_reason(error or "probe failed", 140)
                if ph.status != "down":
                    if force_immediate or ph.consecutive_failures >= fail_th:
                        ph.status = "down"
                        ph.healthy = False
                        reason = f"{plane} plane failed ({ph.consecutive_failures}/{fail_th} consecutive failures: {ph.last_error})"

            allow_rec = bool(force_immediate or tcfg.auto_recover)
            self._reconcile_node_locked(
                st,
                node,
                tcfg,
                reason=reason or f"{plane} probe {'ok' if ok else 'failed'}",
                emit_event=True,
                allow_recovery=allow_rec,
            )
            return self._node_state_dict_locked(st, node)

    def _default_probe_plane(
        self,
        node: NodeConfig,
        plane: str,
        host: str,
        port: int,
        timeout_sec: float,
    ) -> tuple[bool, float, str]:
        """Verify worker reachability & node_id identity via authenticated `GET /health` on `(host, port)`."""
        t0 = time.monotonic()
        url = f"http://{format_host_port(host, port)}/health"
        headers = self.controller._headers_for(node, "GET", "/health")
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with _DIRECT_OPENER.open(req, timeout=max(0.2, float(timeout_sec))) as resp:
                data = read_json_object_bounded(resp, _MAX_PROBE_RESP_BYTES, deadline_sec=max(0.5, float(timeout_sec)))
                ms = round((time.monotonic() - t0) * 1000.0, 1)
                reported_id = data.get("node_id")
                if reported_id and str(reported_id) != node.id:
                    return False, ms, f"identity mismatch (expected {node.id}, got {reported_id})"
                return True, ms, ""
        except urllib.error.HTTPError as exc:
            ms = round((time.monotonic() - t0) * 1000.0, 1)
            try:
                exc.close()
            except Exception:
                pass
            return False, ms, f"HTTP {exc.code}"
        except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError, OverflowError) as exc:
            ms = round((time.monotonic() - t0) * 1000.0, 1)
            return False, ms, _sanitize_reason(str(exc), 120)

    def probe_node(
        self,
        node_id: str,
        *,
        force_immediate: bool = False,
    ) -> dict[str, Any]:
        """Actively probe all configured planes (USB & Wi-Fi) for one node."""
        tcfg, nodes = self._get_config_snapshot()
        node = next((n for n in nodes if n.id == node_id), None)
        if node is None:
            raise KeyError(f"Unknown node id: {node_id}")
        timeout_sec = max(0.2, float(tcfg.probe_timeout_sec))
        probe_fn = self._probe_fn or self._default_probe_plane
        targets: list[tuple[str, str, int]] = []
        for plane in ("usb", "wifi"):
            h, p = node.plane_endpoint(plane)
            if h and p > 0:
                targets.append((plane, h, p))
        if len(targets) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
                futs = {
                    pool.submit(probe_fn, node, plane, host, port, timeout_sec): plane
                    for plane, host, port in targets
                }
                for fut in concurrent.futures.as_completed(futs):
                    plane = futs[fut]
                    try:
                        ok, ms, err = fut.result()
                    except Exception as exc:
                        ok, ms, err = False, 0.0, _sanitize_reason(str(exc), 120)
                    self.record_probe(node.id, plane, ok, latency_ms=ms, error=err, force_immediate=force_immediate)
        elif len(targets) == 1:
            plane, host, port = targets[0]
            try:
                ok, ms, err = probe_fn(node, plane, host, port, timeout_sec)
            except Exception as exc:
                ok, ms, err = False, 0.0, _sanitize_reason(str(exc), 120)
            self.record_probe(node.id, plane, ok, latency_ms=ms, error=err, force_immediate=force_immediate)
        with self._lock:
            self._last_probe_ts = time.time()
            st = self._sync_single_node_locked(node, tcfg)
            return self._node_state_dict_locked(st, node)

    def probe_all(
        self,
        *,
        dual_plane_only: bool = False,
        force_immediate: bool = False,
    ) -> dict[str, Any]:
        """Actively probe configured transport planes across all nodes in parallel."""
        tcfg, nodes = self._get_config_snapshot()
        self.sync_nodes()
        timeout_sec = max(0.2, float(tcfg.probe_timeout_sec))
        probe_fn = self._probe_fn or self._default_probe_plane

        tasks: list[tuple[NodeConfig, str, str, int]] = []
        for node in nodes:
            if dual_plane_only and not node.has_dual_plane():
                continue
            for plane in ("usb", "wifi"):
                h, p = node.plane_endpoint(plane)
                if h and p > 0:
                    tasks.append((node, plane, h, p))

        if tasks:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(tasks))) as pool:
                futs = {
                    pool.submit(probe_fn, node, plane, host, port, timeout_sec): (node.id, plane)
                    for node, plane, host, port in tasks
                }
                for fut in concurrent.futures.as_completed(futs):
                    nid, plane = futs[fut]
                    try:
                        ok, ms, err = fut.result()
                    except Exception as exc:
                        ok, ms, err = False, 0.0, _sanitize_reason(str(exc), 120)
                    self.record_probe(nid, plane, ok, latency_ms=ms, error=err, force_immediate=force_immediate)

        with self._lock:
            self._last_probe_ts = time.time()
        return self.status()

    def apply_mode(self, mode: str) -> dict[str, Any]:
        """Reconcile all nodes immediately after switching cluster transport mode."""
        clean = str(mode or "").strip().lower()
        if clean not in VALID_TRANSPORT_MODES:
            raise ValueError(f"transport mode must be one of {', '.join(VALID_TRANSPORT_MODES)}")
        tcfg, nodes = self._get_config_snapshot()
        with self._lock:
            tcfg.mode = clean
            for node in nodes:
                st = self._sync_single_node_locked(node, tcfg)
                st.manual_override = ""
                self._reconcile_node_locked(
                    st,
                    node,
                    tcfg,
                    reason=f"cluster mode switched to {clean}",
                    emit_event=True,
                    allow_recovery=True,
                )
        return self.status()

    def force_failover(self, node_id: str, plane: str) -> dict[str, Any]:
        """Manually pin a dual-plane node to `'usb'`, `'wifi'`, or `'auto'` (clear override)."""
        clean_p = str(plane or "").strip().lower()
        if clean_p not in {"usb", "wifi", "auto"}:
            raise ValueError("plane must be 'usb', 'wifi', or 'auto'")
        tcfg, nodes = self._get_config_snapshot()
        node = next((n for n in nodes if n.id == node_id), None)
        if node is None:
            raise KeyError(f"Unknown node id: {node_id}")
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            if clean_p == "auto":
                st.manual_override = ""
                reason = "manual failover cleared -> auto/dual_plane"
            else:
                ph = st.usb if clean_p == "usb" else st.wifi
                if not ph.configured:
                    raise ValueError(f"Node '{node_id}' has no configured {clean_p} endpoint")
                st.manual_override = clean_p
                reason = f"manual failover override -> {clean_p}"
            self._reconcile_node_locked(
                st,
                node,
                tcfg,
                reason=reason,
                emit_event=True,
                allow_recovery=True,
            )
            return self._node_state_dict_locked(st, node)

    def trigger_recovery(self, node_id: str | None = None) -> dict[str, Any]:
        """Clear manual overrides and immediately probe/recover healthy planes back to Dual-Plane."""
        tcfg, nodes = self._get_config_snapshot()
        with self._lock:
            targets = [n for n in nodes if (node_id is None or n.id == node_id)]
            if node_id is not None and not targets:
                raise KeyError(f"Unknown node id: {node_id}")
            for node in targets:
                st = self._sync_single_node_locked(node, tcfg)
                st.manual_override = ""
        if node_id is not None:
            self.probe_node(node_id, force_immediate=True)
            return self.status()
        return self.probe_all(force_immediate=True)

    # ------------------------------------------------------------------
    # Active plane resolution (called by MasterController, routing, CLI, TUI)
    # ------------------------------------------------------------------
    def control_endpoint(self, node: NodeConfig) -> tuple[str, int, str]:
        """Return active `(host, worker_port, plane)` for control/management calls to `node`."""
        tcfg, _ = self._get_config_snapshot()
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            plane = st.control_plane
        h, p = node.plane_endpoint(plane)
        if h and p > 0:
            return h, p, plane
        # Fallback to primary host
        return node.host, node.worker_port, ("usb" if node.is_usb_primary() else "wifi")

    def control_base_url(self, node: NodeConfig) -> str:
        host, port, _ = self.control_endpoint(node)
        return f"http://{format_host_port(host, port)}"

    def control_ssh_endpoint(self, node: NodeConfig, plane_override: str = "auto") -> tuple[str, int, str]:
        """Return `(host, ssh_port, plane)` for interactive SSH / SCP management."""
        clean = str(plane_override or "auto").strip().lower()
        if clean in {"usb", "wifi"}:
            h, _ = node.plane_endpoint(clean)
            if not h:
                raise ValueError(f"Node '{node.id}' has no configured {clean} plane")
            sp = node.effective_usb_ssh_port() if clean == "usb" else node.effective_wifi_ssh_port()
            return h, sp, clean
        h, _, plane = self.control_endpoint(node)
        sp = node.effective_usb_ssh_port() if plane == "usb" else node.effective_wifi_ssh_port()
        return h, sp, plane

    def data_endpoint(self, node: NodeConfig) -> tuple[str, int, str]:
        """Return active `(host, worker_port, plane)` for high-speed data workloads & service mesh."""
        tcfg, _ = self._get_config_snapshot()
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            plane = st.data_plane
        h, p = node.plane_endpoint(plane)
        if h and p > 0:
            return h, p, plane
        return node.host, node.worker_port, ("usb" if node.is_usb_primary() else "wifi")

    def data_host(self, node: NodeConfig) -> str:
        """Return the active data-plane IP/hostname for high-bandwidth workloads."""
        host, _, _ = self.data_endpoint(node)
        return host

    def alternate_control_endpoint(self, node: NodeConfig, failed_plane: str) -> tuple[str, int, str] | None:
        """Return standby `(host, port, plane)` if dual-plane failover is allowed and standby is configured."""
        if not node.has_dual_plane():
            return None
        tcfg, _ = self._get_config_snapshot()
        if tcfg.mode not in {"dual_plane", "auto"} or not tcfg.auto_failover:
            return None
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            if st.manual_override:
                return None
        alt_plane = "wifi" if failed_plane == "usb" else "usb"
        h, p = node.plane_endpoint(alt_plane)
        if h and p > 0:
            return h, p, alt_plane
        return None

    def _node_state_dict_locked(self, st: NodeTransportState, node: NodeConfig) -> dict[str, Any]:
        ctl_h, ctl_p = node.plane_endpoint(st.control_plane)
        dat_h, dat_p = node.plane_endpoint(st.data_plane)
        if not ctl_h:
            ctl_h, ctl_p = node.host, node.worker_port
        if not dat_h:
            dat_h, dat_p = node.host, node.worker_port
        return {
            "node_id": st.node_id,
            "has_dual_plane": node.has_dual_plane(),
            "state": st.state,
            "failover_active": st.failover_active,
            "manual_override": st.manual_override,
            "control_plane": st.control_plane,
            "control_host": ctl_h,
            "control_port": ctl_p,
            "data_plane": st.data_plane,
            "data_host": dat_h,
            "data_port": dat_p,
            "usb": st.usb.to_dict(),
            "wifi": st.wifi.to_dict(),
            "failover_count": st.failover_count,
            "recovery_count": st.recovery_count,
            "last_transition_ts": int(st.last_transition_ts) if st.last_transition_ts else 0,
            "last_transition_reason": st.last_transition_reason,
        }

    def compact_node_status(self, node: NodeConfig) -> dict[str, Any]:
        """Return compact per-node transport fields suitable for `/api/status`, `/api/live`, and TUI."""
        tcfg, _ = self._get_config_snapshot()
        with self._lock:
            st = self._sync_single_node_locked(node, tcfg)
            d = self._node_state_dict_locked(st, node)
        return {
            "has_dual_plane": d["has_dual_plane"],
            "state": d["state"],
            "failover_active": d["failover_active"],
            "manual_override": d["manual_override"],
            "control_plane": d["control_plane"],
            "control_host": d["control_host"],
            "control_port": d["control_port"],
            "data_plane": d["data_plane"],
            "data_host": d["data_host"],
            "data_port": d["data_port"],
            "usb_status": d["usb"]["status"],
            "usb_latency_ms": d["usb"]["latency_ms"],
            "wifi_status": d["wifi"]["status"],
            "wifi_latency_ms": d["wifi"]["latency_ms"],
        }

    def status(self, *, event_limit: int = 40) -> dict[str, Any]:
        """Return full cluster transport status, per-node plane health, and recent failover events."""
        tcfg, nodes = self._get_config_snapshot()
        self.sync_nodes()
        with self._lock:
            node_rows: list[dict[str, Any]] = []
            dual_count = 0
            failover_count = 0
            offline_count = 0
            single_count = 0
            for node in nodes:
                st = self._sync_single_node_locked(node, tcfg)
                row = self._node_state_dict_locked(st, node)
                node_rows.append(row)
                if row["has_dual_plane"]:
                    dual_count += 1
                else:
                    single_count += 1
                if row["failover_active"]:
                    failover_count += 1
                if row["state"] == "offline":
                    offline_count += 1
            prober_running = bool(
                self._prober_thread is not None
                and self._prober_thread.is_alive()
                and not self._prober_thread.stopped
            )
            return {
                "mode": tcfg.mode,
                "probe_interval_sec": tcfg.probe_interval_sec,
                "failover_threshold": tcfg.failover_threshold,
                "recovery_threshold": tcfg.recovery_threshold,
                "probe_timeout_sec": tcfg.probe_timeout_sec,
                "auto_failover": tcfg.auto_failover,
                "auto_recover": tcfg.auto_recover,
                "prober_running": prober_running,
                "last_probe_ts": int(self._last_probe_ts) if self._last_probe_ts else 0,
                "dual_plane_nodes": dual_count,
                "single_plane_nodes": single_count,
                "failover_nodes": failover_count,
                "offline_nodes": offline_count,
                "nodes": node_rows,
                "events": list(self._events)[: max(0, int(event_limit))],
            }

    def start_background_prober(self) -> bool:
        """Start the background dual-plane health prober thread if not already running."""
        with self._lock:
            if self._prober_thread is not None and self._prober_thread.is_alive():
                return True
            t = TransportProbeThread(self)
            t.start()
            self._prober_thread = t
            return True

    def stop_background_prober(self) -> None:
        with self._lock:
            t = self._prober_thread
            self._prober_thread = None
        if t is not None:
            t.stop()
            t.join(timeout=2.0)


class TransportProbeThread(threading.Thread):
    """Daemon thread that periodically probes Dual-Plane nodes for hysteresis failover & recovery."""

    def __init__(self, manager: TransportManager) -> None:
        super().__init__(name="transport-prober", daemon=True)
        self.manager = manager
        self._stop_event = threading.Event()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self.manager.has_any_dual_plane_node():
                    self.manager.probe_all(dual_plane_only=True)
            except Exception as exc:
                LOG.warning("Dual-plane transport prober tick error: %s", exc)
            tcfg, _ = self.manager._get_config_snapshot()
            interval = max(1.0, min(300.0, float(tcfg.probe_interval_sec)))
            deadline = time.monotonic() + interval
            while not self._stop_event.is_set():
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                self._stop_event.wait(min(0.25, rem))
