"""Tests for Dual-Plane Communication (USB Control + Wi-Fi Data), Hysteresis Failover, Auto-Recovery & UI/CLI Controls."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from phonecluster.cli import main as cli_main
from phonecluster.config import (
    AdbNodeConfig,
    ClusterConfig,
    NodeConfig,
    TransportConfig,
    load_config,
    save_config,
)
from phonecluster.dashboard import DASHBOARD_HTML, DashboardHTTPServer
from phonecluster.gateway import build_worker_proxy_env
from phonecluster.master import JobSpec, MasterController, NodeSnapshot
from phonecluster.netguard import audit_cluster_network
from phonecluster.routing import build_cross_tier_env, build_service_registry
from phonecluster.transport import TransportManager
from phonecluster.tui import render_top_frame
from phonecluster.usbhub import build_rndis_router_commands, plan_rndis_usb_hub, sync_usb_hub_into_config
from phonecluster.worker import WorkerHTTPServer, WorkerState

REPO_ROOT = Path(__file__).resolve().parent.parent


def _http_json(
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    hdrs: dict[str, str] = {}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    data: bytes | None = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = {"raw": body}
            return exc.code, parsed
        finally:
            exc.close()


class TestDualPlaneConfig(unittest.TestCase):
    def test_legacy_single_host_config_is_100_percent_backward_compatible(self) -> None:
        raw = {
            "cluster_name": "legacy-cluster",
            "auth_token": "legacy-super-secret-token-123456",
            "nodes": [
                {"id": "node0", "host": "192.168.1.10", "role": "master"},
                {"id": "node1", "host": "192.168.1.11", "role": "worker"},
            ],
        }
        cfg = ClusterConfig.from_dict(raw)
        self.assertEqual(cfg.transport.mode, "auto")
        self.assertEqual(cfg.transport.probe_interval_sec, 10)
        self.assertEqual(cfg.transport.failover_threshold, 2)
        self.assertEqual(cfg.transport.recovery_threshold, 2)
        self.assertEqual(cfg.transport.probe_timeout_sec, 2.0)
        self.assertTrue(cfg.transport.auto_failover)
        self.assertTrue(cfg.transport.auto_recover)
        for n in cfg.nodes:
            self.assertFalse(n.has_dual_plane())
            self.assertEqual(n.effective_wifi_host(), n.host)
            self.assertEqual(n.effective_usb_host(), "")

    def test_dual_plane_schema_roundtrip_and_aliases(self) -> None:
        raw = {
            "cluster_name": "dp-cluster",
            "auth_token": "dual-plane-secret-token-12345678",
            "transport": {
                "mode": "dual_plane",
                "probe_interval_sec": 8,
                "failover_threshold": 3,
                "recovery_threshold": 4,
                "probe_timeout_sec": 1.5,
                "auto_failover": True,
                "auto_recover": True,
            },
            "nodes": [
                {
                    "id": "node0",
                    "host": "192.168.1.10",
                    "role": "master",
                },
                {
                    "id": "node1",
                    "host": "10.77.1.2",
                    "usb_host": "10.77.1.2",
                    "wifi_host": "192.168.1.201",
                    "usb_worker_port": 8765,
                    "wifi_worker_port": 8765,
                    "usb_ssh_port": 22,
                    "tags": ["worker", "usb-hub", "usb-mode:rndis"],
                },
                {
                    "id": "node2",
                    "host": "192.168.1.202",
                    "control_host": "10.77.2.2",
                    "data_host": "192.168.1.202",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cluster.json"
            cfg = ClusterConfig.from_dict(raw)
            save_config(cfg, p)
            loaded = load_config(p)
        self.assertEqual(loaded.transport.mode, "dual_plane")
        self.assertEqual(loaded.transport.failover_threshold, 3)
        self.assertEqual(loaded.transport.recovery_threshold, 4)
        self.assertEqual(loaded.transport.probe_timeout_sec, 1.5)
        n1 = loaded.get_node("node1")
        n2 = loaded.get_node("node2")
        self.assertTrue(n1.has_dual_plane())
        self.assertEqual(n1.effective_usb_host(), "10.77.1.2")
        self.assertEqual(n1.effective_wifi_host(), "192.168.1.201")
        self.assertTrue(n2.has_dual_plane())
        self.assertEqual(n2.effective_usb_host(), "10.77.2.2")
        self.assertEqual(n2.effective_wifi_host(), "192.168.1.202")

        # ADB USB forward (127.0.0.1:18761) + Wi-Fi data (192.168.1.205:8765) Dual-Plane endpoint resolution
        adb_dp = NodeConfig(
            id="adb1",
            host="127.0.0.1",
            worker_port=18761,
            ssh_port=18021,
            tags=["worker", "usb-hub", "usb-mode:adb"],
            adb=AdbNodeConfig("SER123", 8765, 8022, 25000, peer_mesh=True),
            wifi_host="192.168.1.205",
        )
        self.assertTrue(adb_dp.has_dual_plane())
        self.assertEqual(adb_dp.plane_endpoint("usb"), ("127.0.0.1", 18761))
        self.assertEqual(adb_dp.plane_endpoint("wifi"), ("192.168.1.205", 8765))
        self.assertEqual(adb_dp.effective_usb_ssh_port(), 18021)
        self.assertEqual(adb_dp.effective_wifi_ssh_port(), 8022)

    def test_transport_config_validation_rejects_invalid_values(self) -> None:
        for bad in (
            {"mode": "bluetooth"},
            {"probe_interval_sec": 0},
            {"probe_interval_sec": True},
            {"failover_threshold": 0},
            {"recovery_threshold": 99},
            {"probe_timeout_sec": 0.05},
            {"probe_timeout_sec": float("nan")},
            {"auto_failover": "yes"},
            {"auto_recover": 1},
        ):
            with self.assertRaises(ValueError, msg=f"Should reject {bad!r}"):
                TransportConfig.from_dict(bad)


class TestTransportStateMachine(unittest.TestCase):
    def _make_dual_plane_controller(
        self,
        *,
        mode: str = "dual_plane",
        failover_threshold: int = 2,
        recovery_threshold: int = 2,
        auto_failover: bool = True,
        auto_recover: bool = True,
    ) -> MasterController:
        cfg = ClusterConfig(
            cluster_name="dp-test",
            auth_token="test-token-1234567890abcdef",
            nodes=[
                NodeConfig(id="node0", host="192.168.1.10", role="master"),
                NodeConfig(
                    id="phone1",
                    host="10.77.1.2",
                    role="worker",
                    worker_port=8765,
                    ssh_port=22,
                    tags=["worker", "usb-hub", "usb-mode:rndis"],
                    auth_token="phone1-secret-token-12345678",
                    usb_host="10.77.1.2",
                    wifi_host="192.168.1.201",
                ),
            ],
            transport=TransportConfig(
                mode=mode,
                probe_interval_sec=5,
                failover_threshold=failover_threshold,
                recovery_threshold=recovery_threshold,
                probe_timeout_sec=1.0,
                auto_failover=auto_failover,
                auto_recover=auto_recover,
            ),
        )
        return MasterController(cfg)

    def test_wifi_failover_and_hysteresis_auto_recovery(self) -> None:
        ctrl = self._make_dual_plane_controller(failover_threshold=2, recovery_threshold=2)
        tm = ctrl.transport
        phone = ctrl.config.get_node("phone1")

        # Initial Dual-Plane Split: USB control, Wi-Fi data
        self.assertEqual(tm.control_endpoint(phone), ("10.77.1.2", 8765, "usb"))
        self.assertEqual(tm.data_endpoint(phone), ("192.168.1.201", 8765, "wifi"))

        # Verify both healthy first
        tm.record_probe("phone1", "usb", True, latency_ms=0.8)
        tm.record_probe("phone1", "wifi", True, latency_ms=4.2)
        st = tm.compact_node_status(phone)
        self.assertEqual(st["state"], "dual_plane")
        self.assertFalse(st["failover_active"])

        # 1st Wi-Fi failure -> hysteresis prevents flapping
        tm.record_probe("phone1", "wifi", False, error="timeout")
        st = tm.compact_node_status(phone)
        self.assertEqual(st["state"], "dual_plane")
        self.assertEqual(tm.data_host(phone), "192.168.1.201")

        # 2nd consecutive Wi-Fi failure -> FAILOVER to USB!
        tm.record_probe("phone1", "wifi", False, error="timeout")
        st = tm.compact_node_status(phone)
        self.assertEqual(st["state"], "failover_usb_only")
        self.assertTrue(st["failover_active"])
        self.assertEqual(tm.control_endpoint(phone)[2], "usb")
        self.assertEqual(tm.data_endpoint(phone), ("10.77.1.2", 8765, "usb"))

        # 1st Wi-Fi success -> hysteresis keeps failover active (no flapping!)
        tm.record_probe("phone1", "wifi", True, latency_ms=5.0)
        st = tm.compact_node_status(phone)
        self.assertEqual(st["state"], "failover_usb_only")
        self.assertEqual(tm.data_host(phone), "10.77.1.2")

        # 2nd consecutive Wi-Fi success -> AUTO-RECOVERY back to Dual-Plane!
        tm.record_probe("phone1", "wifi", True, latency_ms=3.8)
        st = tm.compact_node_status(phone)
        self.assertEqual(st["state"], "dual_plane")
        self.assertFalse(st["failover_active"])
        self.assertEqual((tm.control_endpoint(phone)[0], tm.data_host(phone)), ("10.77.1.2", "192.168.1.201"))
        full = tm.status()
        p_row = next(r for r in full["nodes"] if r["node_id"] == "phone1")
        self.assertEqual(p_row["failover_count"], 1)
        self.assertEqual(p_row["recovery_count"], 1)
        kinds = [e["kind"] for e in full["events"]]
        self.assertIn("failover", kinds)
        self.assertIn("recovery", kinds)

    def test_usb_failover_to_wifi_and_both_down_offline(self) -> None:
        ctrl = self._make_dual_plane_controller(failover_threshold=2, recovery_threshold=2)
        tm = ctrl.transport
        phone = ctrl.config.get_node("phone1")
        tm.record_probe("phone1", "usb", True, latency_ms=0.9)
        tm.record_probe("phone1", "wifi", True, latency_ms=4.1)

        # USB cable unplugged (2 consecutive failures) -> control fails over to Wi-Fi!
        tm.record_probe("phone1", "usb", False, error="network unreachable")
        self.assertEqual(tm.control_endpoint(phone)[2], "usb")
        tm.record_probe("phone1", "usb", False, error="network unreachable")
        self.assertEqual(tm.compact_node_status(phone)["state"], "failover_wifi_only")
        self.assertEqual(tm.control_endpoint(phone), ("192.168.1.201", 8765, "wifi"))
        self.assertEqual(tm.data_endpoint(phone), ("192.168.1.201", 8765, "wifi"))

        # Now Wi-Fi also drops -> offline
        tm.record_probe("phone1", "wifi", False, error="no route")
        tm.record_probe("phone1", "wifi", False, error="no route")
        self.assertEqual(tm.compact_node_status(phone)["state"], "offline")

        # USB comes back (2 consecutive successes) -> failover_usb_only
        tm.record_probe("phone1", "usb", True, latency_ms=1.0)
        self.assertEqual(tm.compact_node_status(phone)["state"], "offline")
        tm.record_probe("phone1", "usb", True, latency_ms=1.0)
        self.assertEqual(tm.compact_node_status(phone)["state"], "failover_usb_only")

    def test_auto_recover_false_holds_failover_until_manual_recovery(self) -> None:
        ctrl = self._make_dual_plane_controller(failover_threshold=1, recovery_threshold=1, auto_recover=False)
        probe_results = {"usb": (True, 1.0, ""), "wifi": (True, 4.0, "")}
        ctrl.transport = TransportManager(
            ctrl,
            probe_fn=lambda _n, plane, _h, _p, _t: probe_results[plane],
        )
        tm = ctrl.transport
        phone = ctrl.config.get_node("phone1")

        # Drop Wi-Fi
        tm.record_probe("phone1", "usb", True, latency_ms=1.0)
        tm.record_probe("phone1", "wifi", False, error="drop")
        self.assertEqual(tm.compact_node_status(phone)["state"], "failover_usb_only")

        # Wi-Fi healthy again, but auto_recover=False holds failover_usb_only
        tm.record_probe("phone1", "wifi", True, latency_ms=3.0)
        self.assertEqual(tm.compact_node_status(phone)["state"], "failover_usb_only")

        # Explicit operator trigger_recovery restores dual_plane immediately!
        tm.trigger_recovery("phone1")
        self.assertEqual(tm.compact_node_status(phone)["state"], "dual_plane")
        self.assertEqual(tm.data_host(phone), "192.168.1.201")

    def test_forced_modes_and_data_plane_workload_helpers(self) -> None:
        ctrl = self._make_dual_plane_controller(mode="dual_plane", failover_threshold=1, recovery_threshold=1)
        phone = ctrl.config.get_node("phone1")
        snap = NodeSnapshot(
            node=phone,
            online=True,
            latency_ms=1.2,
            health={
                "ready_for_jobs": True,
                "cpu_cores": 8,
                "tools": {"distccd": True, "llama_rpc": True, "mpirun": True},
                "services": {"distccd_3632": True, "llama_rpc_50052": True, "mosquitto_1883": True},
            },
        )

        # In dual_plane mode -> data workloads use Wi-Fi IP (192.168.1.201)
        self.assertIn("192.168.1.201/8", ctrl.build_distcc_hosts(snapshots=[snap]))
        self.assertEqual(ctrl.build_llama_rpc_arg(snapshots=[snap]), "192.168.1.201:50052")
        self.assertIn("192.168.1.201 slots=8", ctrl.build_mpi_hostfile(snapshots=[snap]))
        env_dp = build_cross_tier_env([snap], ctrl.config, for_node=phone, transport_manager=ctrl.transport)
        self.assertEqual(env_dp["PHONECLUSTER_CONTROL_PLANE"], "usb")
        self.assertEqual(env_dp["PHONECLUSTER_CONTROL_HOST"], "10.77.1.2")
        self.assertEqual(env_dp["PHONECLUSTER_DATA_PLANE"], "wifi")
        self.assertEqual(env_dp["PHONECLUSTER_DATA_HOST"], "192.168.1.201")
        self.assertEqual(env_dp["PHONECLUSTER_MQTT_HOST"], "192.168.1.201")

        # Switch to usb_only -> data workloads seamlessly shift to USB IP (10.77.1.2)
        ctrl.transport.apply_mode("usb_only")
        self.assertIn("10.77.1.2/8", ctrl.build_distcc_hosts(snapshots=[snap]))
        self.assertEqual(ctrl.build_llama_rpc_arg(snapshots=[snap]), "10.77.1.2:50052")
        self.assertIn("10.77.1.2 slots=8", ctrl.build_mpi_hostfile(snapshots=[snap]))
        regs = build_service_registry([snap], ctrl.config, transport_manager=ctrl.transport)
        mqtt = next(r for r in regs if r["name"] == "mqtt")
        self.assertEqual(mqtt["host"], "10.77.1.2")

        # NO_PROXY includes both USB and Wi-Fi hosts when gateway is enabled
        ctrl.config.gateway.enabled = True
        proxy_env = build_worker_proxy_env(ctrl.config, phone)
        self.assertIn("10.77.1.2", proxy_env["NO_PROXY"])
        self.assertIn("192.168.1.201", proxy_env["NO_PROXY"])


class TestLiveHttpDualPlaneFailover(unittest.TestCase):
    def test_live_worker_control_failover_from_usb_to_wifi(self) -> None:
        tok = "live-dp-worker-token-1234567890"
        cfg_stub = ClusterConfig(
            cluster_name="live-dp",
            auth_token="master-dp-token-1234567890abcd",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master"),
                NodeConfig(id="phone1", host="127.0.0.1", role="worker", auth_token=tok),
            ],
            transport=TransportConfig(
                mode="dual_plane",
                failover_threshold=2,
                recovery_threshold=2,
                probe_timeout_sec=1.0,
            ),
        )
        def _ok_health() -> dict[str, Any]:
            return {
                "temp_c": 31.0,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "cpu_cores": 8,
                "load_1m": 0.2,
                "os_env": "linux",
            }

        usb_state = WorkerState(
            node_id="phone1",
            role="worker",
            auth_token=tok,
            safety=cfg_stub.safety,
            workdir=Path("."),
            health_provider=_ok_health,
        )
        wifi_state = WorkerState(
            node_id="phone1",
            role="worker",
            auth_token=tok,
            safety=cfg_stub.safety,
            workdir=Path("."),
            health_provider=_ok_health,
        )
        usb_srv = WorkerHTTPServer(("127.0.0.1", 0), usb_state)
        wifi_srv = WorkerHTTPServer(("127.0.0.1", 0), wifi_state)
        usb_port = usb_srv.server_address[1]
        wifi_port = wifi_srv.server_address[1]

        usb_thread = threading.Thread(target=usb_srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        wifi_thread = threading.Thread(target=wifi_srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        usb_thread.start()
        wifi_thread.start()
        usb_stopped = False
        try:
            node = cfg_stub.get_node("phone1")
            node.usb_host = "127.0.0.1"
            node.usb_worker_port = usb_port
            node.wifi_host = "127.0.0.1"
            node.wifi_worker_port = wifi_port
            node.worker_port = usb_port

            ctrl = MasterController(cfg_stub)
            self.assertTrue(node.has_dual_plane())

            # Probe both live endpoints -> both UP in dual_plane
            stat = ctrl.transport.probe_all()
            p1 = next(r for r in stat["nodes"] if r["node_id"] == "phone1")
            self.assertEqual(p1["state"], "dual_plane")
            self.assertEqual(p1["usb"]["status"], "up")
            self.assertEqual(p1["wifi"]["status"], "up")

            # Stop USB server to simulate USB cable drop
            usb_srv.shutdown()
            usb_srv.server_close()
            usb_stopped = True

            # 1st check_node_health -> 1st failure (hysteresis holds USB, returns offline)
            snap1 = ctrl.check_node_health(node)
            self.assertFalse(snap1.online)
            self.assertEqual(ctrl.transport.compact_node_status(node)["state"], "dual_plane")

            # 2nd check_node_health -> hits failover_threshold=2 -> immediately fails over & succeeds via Wi-Fi!
            snap2 = ctrl.check_node_health(node)
            self.assertTrue(snap2.online)
            self.assertEqual(ctrl.transport.compact_node_status(node)["state"], "failover_wifi_only")
            self.assertEqual(ctrl.transport.control_endpoint(node), ("127.0.0.1", wifi_port, "wifi"))

            # Executing a real job now runs transparently over the Wi-Fi failover plane!
            kind, data = ctrl.exec_on_node(
                node,
                JobSpec(index=0, job_id="dp-failover-job", command="echo failover-ok", timeout_sec=10.0),
            )
            self.assertEqual(kind, "ok", msg=f"unexpected exec outcome: {data!r}")
            self.assertEqual(data.get("returncode"), 0)
            self.assertIn("failover-ok", data.get("stdout", ""))
        finally:
            if not usb_stopped:
                usb_srv.shutdown()
                usb_srv.server_close()
            wifi_srv.shutdown()
            wifi_srv.server_close()


class TestDashboardAndCliDualPlane(unittest.TestCase):
    def test_dashboard_transport_endpoints_and_security_guards(self) -> None:
        tok = "dash-dp-admin-token-1234567890ab"
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / "cluster.json"
            cfg = ClusterConfig(
                cluster_name="dash-dp",
                auth_token=tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master"),
                    NodeConfig(
                        id="node1",
                        host="10.77.1.2",
                        role="worker",
                        usb_host="10.77.1.2",
                        wifi_host="192.168.1.201",
                        tags=["worker", "usb-hub", "usb-mode:rndis"],
                        auth_token="node1-dp-tok-1234567890",
                    ),
                ],
                transport=TransportConfig(mode="dual_plane", failover_threshold=2, recovery_threshold=2),
            )
            save_config(cfg, cfg_path)
            ctrl = MasterController(load_config(cfg_path))
            srv = DashboardHTTPServer(
                ("127.0.0.1", 0),
                ctrl,
                config_path=cfg_path,
                enable_pairing_beacon=False,
                enable_usb_watchdog=False,
                enable_transport_prober=False,
            )
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                # Auth guard on GET /api/transport
                code, _ = _http_json(f"{base}/api/transport")
                self.assertEqual(code, 401)

                code, data = _http_json(f"{base}/api/transport", token=tok)
                self.assertEqual(code, 200)
                self.assertEqual(data["mode"], "dual_plane")
                self.assertEqual(data["dual_plane_nodes"], 1)

                # CSRF cross-origin rejected on POST /api/transport/config
                code, _ = _http_json(
                    f"{base}/api/transport/config",
                    method="POST",
                    token=tok,
                    payload={"mode": "usb_only"},
                    headers={"Origin": "https://evil.example"},
                )
                self.assertEqual(code, 403)

                # Wrong Content-Type rejected (415)
                req = urllib.request.Request(
                    f"{base}/api/transport/config",
                    data=b'{"mode":"usb_only"}',
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "text/plain"},
                    method="POST",
                )
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    opener.open(req, timeout=5.0)
                try:
                    self.assertEqual(cm.exception.code, 415)
                finally:
                    cm.exception.close()

                # Valid config update persists to disk
                code, data = _http_json(
                    f"{base}/api/transport/config",
                    method="POST",
                    token=tok,
                    payload={
                        "mode": "usb_only",
                        "probe_interval_sec": 15,
                        "failover_threshold": 3,
                        "recovery_threshold": 4,
                        "probe_timeout_sec": 2.5,
                    },
                )
                self.assertEqual(code, 200)
                self.assertEqual(data["transport"]["mode"], "usb_only")
                reloaded = load_config(cfg_path)
                self.assertEqual(reloaded.transport.mode, "usb_only")
                self.assertEqual(reloaded.transport.failover_threshold, 3)
                self.assertEqual(reloaded.transport.recovery_threshold, 4)

                # Switch back to dual_plane & test manual failover pin + clear
                code, _ = _http_json(
                    f"{base}/api/transport/config", method="POST", token=tok, payload={"mode": "dual_plane"}
                )
                self.assertEqual(code, 200)
                code, fo_data = _http_json(
                    f"{base}/api/transport/failover",
                    method="POST",
                    token=tok,
                    payload={"node_id": "node1", "plane": "wifi"},
                )
                self.assertEqual(code, 200)
                self.assertEqual(fo_data["node"]["state"], "failover_wifi_only")
                self.assertEqual(fo_data["node"]["manual_override"], "wifi")

                code, clr_data = _http_json(
                    f"{base}/api/transport/failover",
                    method="POST",
                    token=tok,
                    payload={"node_id": "node1", "plane": "auto"},
                )
                self.assertEqual(code, 200)
                self.assertEqual(clr_data["node"]["state"], "dual_plane")

                # /api/nodes/update supports usb_host & wifi_host and blocks link-local SSRF metadata
                code, _ = _http_json(
                    f"{base}/api/nodes/update",
                    method="POST",
                    token=tok,
                    payload={"id": "node1", "wifi_host": "169.254.169.254"},
                )
                self.assertEqual(code, 400)

                code, upd = _http_json(
                    f"{base}/api/nodes/update",
                    method="POST",
                    token=tok,
                    payload={"id": "node1", "usb_host": "10.77.3.2", "wifi_host": "192.168.1.209"},
                )
                self.assertEqual(code, 200)
                self.assertEqual(upd["node"]["usb_host"], "10.77.3.2")
                self.assertEqual(upd["node"]["wifi_host"], "192.168.1.209")
                reloaded2 = load_config(cfg_path)
                self.assertIn("10.77.3.1", reloaded2.network.allowed_master_ips)

                # Dashboard HTML includes Dual-Plane UI controls
                for marker in (
                    'id="transport-card"',
                    'id="tr-mode"',
                    'id="tr-failover-th"',
                    'id="tr-recovery-th"',
                    'id="overview-transport-pill"',
                    "ed-usb-host",
                    "ed-wifi-host",
                    "saveTransportConfig()",
                    "probeTransportNow()",
                ):
                    self.assertIn(marker, DASHBOARD_HTML)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_cli_transport_subcommands_tui_usbhub_and_router_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / "cluster.json"
            cfg = ClusterConfig(
                cluster_name="cli-dp",
                auth_token="cli-dp-secret-token-1234567890",
                nodes=[
                    NodeConfig(id="node0", host="192.168.1.10", role="master"),
                    NodeConfig(id="node1", host="192.168.1.201", role="worker", auth_token="w1-tok-1234567890"),
                ],
            )
            save_config(cfg, cfg_path)

            # pc transport set-node -> attaches USB + Wi-Fi endpoints and updates allowed_master_ips
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main([
                    "--config", str(cfg_path),
                    "transport", "set-node", "node1",
                    "--usb-host", "10.77.1.2",
                    "--wifi-host", "192.168.1.201",
                    "--json",
                ])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["dual_plane_nodes"], 1)

            # pc transport mode dual_plane + pc transport config
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                rc = cli_main(["--config", str(cfg_path), "transport", "mode", "dual_plane", "--json"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(buf2.getvalue())["mode"], "dual_plane")

            buf3 = io.StringIO()
            with contextlib.redirect_stdout(buf3):
                rc = cli_main([
                    "--config", str(cfg_path),
                    "transport", "config",
                    "--probe-interval", "12",
                    "--failover-threshold", "3",
                    "--recovery-threshold", "4",
                    "--probe-timeout", "1.5",
                    "--json",
                ])
            self.assertEqual(rc, 0)
            out3 = json.loads(buf3.getvalue())
            self.assertEqual(out3["probe_interval_sec"], 12)
            self.assertEqual(out3["failover_threshold"], 3)
            self.assertEqual(out3["recovery_threshold"], 4)

            # Network audit surfaces Dual-Plane Transport check
            ctrl = MasterController(load_config(cfg_path))
            audit = audit_cluster_network(ctrl, snapshots=[])
            self.assertTrue(any(c["name"] == "Dual-Plane Transport & Failover" for c in audit["checks"]))

        # USB Hub sync preserves existing Wi-Fi host for Dual-Plane & builds --dual-plane commands
        cfg_usb = ClusterConfig(
            cluster_name="usb-dp",
            auth_token="usb-dp-token-1234567890123456",
            nodes=[
                NodeConfig(id="node0", host="192.168.1.10", role="master"),
                NodeConfig(id="usb1", host="192.168.1.201", role="worker", auth_token="u1-tok-1234567890"),
            ],
        )
        plan = plan_rndis_usb_hub([{"iface": "usb0", "mac": "aa:bb:cc:dd:ee:01", "driver": "rndis_host"}])
        sync_usb_hub_into_config(cfg_usb, plan, preserve_wifi=True)
        u1 = cfg_usb.get_node("usb1")
        self.assertEqual(u1.usb_host, "10.77.1.2")
        self.assertEqual(u1.wifi_host, "192.168.1.201")
        self.assertTrue(u1.has_dual_plane())
        cmds = build_rndis_router_commands(plan, dual_plane=True)
        self.assertTrue(any("rp_filter=2" in c for c in cmds["host_commands"]))
        self.assertTrue(any("--dual-plane" in c for c in cmds["phone_commands"]["usb1"]))

        # TUI renders XPORT header + USB+WiFi / failover badges cleanly
        summary = {
            "cluster_name": "dp-tui",
            "nodes_total": 1,
            "nodes_online": 1,
            "nodes_ready": 1,
            "total_cores": 8,
            "cluster_cpu_pct": 12.0,
            "cluster_ram_pct": 40.0,
            "mem_total_mb": 4096,
            "mem_available_mb": 2400,
            "safety": {"max_temp_c": 40.0, "battery_high_pct": 60},
            "transport": {
                "mode": "dual_plane",
                "dual_plane_nodes": 1,
                "failover_nodes": 1,
                "failover_threshold": 2,
                "recovery_threshold": 2,
            },
            "nodes": [
                {
                    "id": "phone1",
                    "role": "worker",
                    "host": "10.77.1.2",
                    "tier": 3,
                    "pool": "docker",
                    "online": True,
                    "ready_for_jobs": True,
                    "latency_ms": 1.1,
                    "health": {"cpu_pct": 12.0, "mem_total_mb": 4096, "mem_available_mb": 2400, "os_env": "ubuntu-touch"},
                    "transport": {
                        "has_dual_plane": True,
                        "state": "failover_usb_only",
                        "control_plane": "usb",
                        "control_host": "10.77.1.2",
                        "data_plane": "usb",
                        "data_host": "10.77.1.2",
                        "failover_active": True,
                    },
                }
            ],
        }
        frame = render_top_frame(summary, {"cluster": [], "nodes": {}}, [], width=110, use_color=False)
        self.assertIn("XPORT", frame)
        self.assertIn("DUAL_PLANE", frame)
        self.assertIn("FO→USB", frame)

        # Router script --dual-plane dry-run works cleanly on Ubuntu Touch / Linux
        script = REPO_ROOT / "scripts" / "07_usb_hub_router.sh"
        res = subprocess.run(
            ["bash", str(script), "phone-setup", "1", "--iface", "lo", "--dual-plane", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("rp_filter=2", res.stdout)
        self.assertIn("metric 200", res.stdout)
        self.assertIn("Dual-Plane Split", res.stdout)


if __name__ == "__main__":
    unittest.main()
