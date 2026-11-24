"""End-to-end and unit tests for PhoneCluster (zero external test dependencies)."""

from __future__ import annotations

import base64
import json
import math
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from phonecluster.auth import (
    AuthRateLimiter,
    build_auth_headers,
    extract_bearer_token,
    verify_token,
)
from phonecluster.cli import main as cli_main
from phonecluster.config import (
    ClusterConfig,
    GatewayConfig,
    NodeConfig,
    SafetyConfig,
    create_default_config,
    load_config,
    save_config,
)
from phonecluster.dashboard import DashboardHTTPServer
from phonecluster.discovery import DiscoveryResponder, discover_lan_nodes
from phonecluster.doctor import run_doctor
from phonecluster.gateway import (
    GatewayManager,
    build_worker_proxy_env,
    derive_proxy_password,
    domain_matches,
    evaluate_policy,
    resolve_and_validate_target,
)
from phonecluster.master import (
    JobSpec,
    MasterController,
    NodeSnapshot,
    score_node,
)
from phonecluster.pairing import (
    DH_P,
    PairingManager,
    StandalonePairingServer,
    decrypt_bundle,
    derive_pairing_keys,
    discover_pairing_masters,
    encrypt_bundle,
    join_cluster_via_pairing,
    validate_dh_public,
)
from phonecluster.telemetry import (
    CpuSampler,
    ThermalGate,
    _normalize_sysfs_temp,
    read_battery_via_sysfs,
    read_listening_tcp_ports,
    read_memory_info,
)
from phonecluster.tui import make_sparkline, render_top_frame
from phonecluster.wizard import run_setup_wizard
from phonecluster.worker import BatteryGuardLoop, WorkerState, create_worker_server


class TestConfigAndAuth(unittest.TestCase):
    def test_config_roundtrip_and_validation(self) -> None:
        cfg = create_default_config(
            cluster_name="test-net",
            master_host="127.0.0.1",
            worker_hosts=["127.0.0.2", "127.0.0.3"],
            ssh_user="u0_a1",
        )
        self.assertEqual(len(cfg.nodes), 3)
        self.assertEqual(cfg.nodes[0].role, "master")
        self.assertTrue(len(cfg.auth_token) >= 24)

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "cluster.json"
            save_config(cfg, p)
            loaded = load_config(p)
            self.assertEqual(loaded.cluster_name, "test-net")
            self.assertEqual(loaded.auth_token, cfg.auth_token)
            self.assertEqual(loaded.get_node("node2").host, "127.0.0.3")

    def test_bearer_auth(self) -> None:
        headers = build_auth_headers("super-secret")
        self.assertEqual(extract_bearer_token(headers), "super-secret")
        self.assertTrue(verify_token(headers, "super-secret"))
        self.assertFalse(verify_token(headers, "wrong-secret"))
        self.assertFalse(verify_token({}, "super-secret"))


class TestTelemetry(unittest.TestCase):
    def test_thermal_gate_hysteresis(self) -> None:
        gate = ThermalGate(max_temp_c=40.0, resume_temp_c=37.0)
        self.assertFalse(gate.evaluate(35.0))
        self.assertTrue(gate.evaluate(40.2))
        # Stays overheated in the hysteresis band (37 < temp < 40)
        self.assertTrue(gate.evaluate(38.5))
        # Resumes once cooled to <= 37.0
        self.assertFalse(gate.evaluate(36.9))

    def test_sysfs_battery_and_meminfo_parsing(self) -> None:
        self.assertEqual(_normalize_sysfs_temp("358"), 35.8)
        self.assertEqual(_normalize_sysfs_temp("41250"), 41.25)

        with tempfile.TemporaryDirectory() as tmp:
            ps_dir = Path(tmp) / "power_supply"
            bat = ps_dir / "battery"
            bat.mkdir(parents=True)
            (bat / "type").write_text("Battery\n", encoding="utf-8")
            (bat / "capacity").write_text("57\n", encoding="utf-8")
            (bat / "temp").write_text("364\n", encoding="utf-8")
            (bat / "status").write_text("Charging\n", encoding="utf-8")
            (bat / "health").write_text("Good\n", encoding="utf-8")

            info = read_battery_via_sysfs(ps_dir)
            self.assertIsNotNone(info)
            assert info is not None
            self.assertEqual(info.percentage, 57)
            self.assertEqual(info.temperature_c, 36.4)
            self.assertEqual(info.status, "CHARGING")

            memfile = Path(tmp) / "meminfo"
            memfile.write_text(
                "MemTotal:        4096000 kB\nMemFree:          512000 kB\nMemAvailable:    2048000 kB\n",
                encoding="utf-8",
            )
            mem = read_memory_info(memfile)
            self.assertEqual(mem["total_mb"], 4000)
            self.assertEqual(mem["available_mb"], 2000)
            self.assertEqual(mem["used_mb"], 2000)

    def test_cpu_sampler_delta_and_per_core(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stat_file = Path(tmp) / "stat"
            stat_file.write_text(
                "cpu  100 0 100 800 0 0 0 0\n"
                "cpu0 50 0 50 400 0 0 0 0\n"
                "cpu1 50 0 50 400 0 0 0 0\n",
                encoding="utf-8",
            )
            sampler = CpuSampler(stat_path=stat_file)
            # Second sample: cpu busy increased by 100 out of 200 ticks (50.0%)
            # cpu0: +75 busy / 100 total (75.0%), cpu1: +25 busy / 100 total (25.0%)
            stat_file.write_text(
                "cpu  150 0 150 900 0 0 0 0\n"
                "cpu0 100 0 75 425 0 0 0 0\n"
                "cpu1 50 0 75 475 0 0 0 0\n",
                encoding="utf-8",
            )
            total, cores = sampler.sample(load_1m=0.5, cpu_cores=2)
            self.assertEqual(total, 50.0)
            self.assertEqual(cores, [75.0, 25.0])


class TestLiveClusterEndToEnd(unittest.TestCase):
    """Spins up 3 real local worker HTTP servers (1 master + 2 workers) and tests full workflows."""

    def setUp(self) -> None:
        self.token = "test-cluster-token-123"
        self.safety = SafetyConfig(
            max_temp_c=40.0,
            resume_temp_c=37.0,
            battery_low_pct=45,
            battery_high_pct=60,
            webhook_cooldown_sec=60,
        )
        self.node_temps = {"node0": 34.0, "node1": 33.0, "node2": 43.5}  # node2 starts hot!
        self.servers = []
        self.threads = []
        self.stop_events = []
        self.states: dict[str, WorkerState] = {}
        nodes_cfg: list[NodeConfig] = []

        for idx, (nid, role, weight) in enumerate(
            [("node0", "master", 1.2), ("node1", "worker", 1.0), ("node2", "worker", 0.8)]
        ):
            def _make_health_provider(name: str, r: str):
                def _provider():
                    temp = self.node_temps[name]
                    overheated = temp >= self.safety.max_temp_c
                    reasons = [f"overheated ({temp}C >= 40.0C)"] if overheated else []
                    return {
                        "node_id": name,
                        "role": r,
                        "hostname": f"phone-{name}",
                        "os_env": "debian-13" if name == "node0" else "termux",
                        "arch": "aarch64",
                        "uptime_sec": 7500,
                        "cpu_cores": 8,
                        "cpu_pct": 28.5 if name == "node0" else 14.0,
                        "per_core_pct": [15.0, 42.0, 10.0, 80.0, 22.0, 12.0, 5.0, 35.0],
                        "load_1m": 0.4,
                        "mem_total_mb": 3512,
                        "mem_available_mb": 1900,
                        "disk_free_gb": 42.0,
                        "net_rx_kbps": 14.2,
                        "net_tx_kbps": 3.8,
                        "top_processes": [
                            {"pid": 1001, "cpu_pct": 18.4, "mem_pct": 4.2, "name": "python3"},
                            {"pid": 1002, "cpu_pct": 0.5, "mem_pct": 0.8, "name": "sshd"},
                        ],
                        "battery_pct": 55 if name != "node1" else 65,
                        "temp_c": temp,
                        "battery_status": "CHARGING" if name == "node1" else "DISCHARGING",
                        "battery_health": "GOOD",
                        "overheated": overheated,
                        "ready_for_jobs": not overheated,
                        "not_ready_reasons": reasons,
                        "tools": {"python3": True, "distccd": True, "mpirun": True},
                        "services": {
                            "distccd_3632": True,
                            "llama_rpc_50052": name != "node0",
                            "sshd_8022": True,
                        },
                        "timestamp": int(time.time()),
                    }
                return _provider

            state = WorkerState(
                node_id=nid,
                role=role,
                auth_token=self.token,
                safety=self.safety,
                max_concurrency=2,
                health_provider=_make_health_provider(nid, role),
            )
            srv, _guard, stop_ev = create_worker_server("127.0.0.1", 0, state)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()

            self.states[nid] = state
            self.servers.append(srv)
            self.threads.append(t)
            self.stop_events.append(stop_ev)
            nodes_cfg.append(
                NodeConfig(
                    id=nid,
                    host="127.0.0.1",
                    role=role,
                    worker_port=port,
                    max_concurrency=2,
                    weight=weight,
                    tags=["master"] if role == "master" else ["worker"],
                )
            )

        self.config = ClusterConfig(
            cluster_name="test-redmi-cluster",
            auth_token=self.token,
            nodes=nodes_cfg,
            safety=self.safety,
            health_timeout_sec=2.0,
        )
        self.controller = MasterController(self.config)

    def tearDown(self) -> None:
        for ev in self.stop_events:
            ev.set()
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def test_auth_rejected_without_token(self) -> None:
        node0 = self.config.get_node("node0")
        req = urllib.request.Request(f"{node0.base_url}/health", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2.0)
        try:
            self.assertEqual(ctx.exception.code, 401)
        finally:
            ctx.exception.close()

    def test_status_and_thermal_exclusion(self) -> None:
        summary = self.controller.cluster_summary()
        self.assertEqual(summary["nodes_total"], 3)
        self.assertEqual(summary["nodes_online"], 3)
        # node2 is at 43.5C -> paused, so only 2 nodes ready
        self.assertEqual(summary["nodes_ready"], 2)
        self.assertEqual(summary["total_cores"], 24)

        # Workload helper outputs should exclude hot node2!
        distcc = self.controller.build_distcc_hosts()
        self.assertIn("localhost/6", distcc)
        self.assertEqual(len(distcc.split()), 2)

        llama_rpc = self.controller.build_llama_rpc_arg()
        self.assertEqual(llama_rpc, "127.0.0.1:50052")  # only node1 (node0 is master, node2 is hot)

        mpi = self.controller.build_mpi_hostfile()
        self.assertEqual(len(mpi.strip().splitlines()), 2)

    def test_parallel_map_inline_script_and_reroute_on_overheat(self) -> None:
        script_src = (
            "import os, sys\n"
            "print(f'ok:{sys.argv[1]}:{os.environ.get(\"PHONECLUSTER_NODE_ID\")}')\n"
        )
        jobs = [
            JobSpec(
                index=i,
                job_id=f"job-{i}",
                script_content=script_src,
                script_name="worker_test.py",
                interpreter=sys.executable,
                args=[str(i)],
                timeout_sec=15.0,
            )
            for i in range(10)
        ]

        outcomes = self.controller.map_jobs(jobs, retries=1)
        self.assertEqual(len(outcomes), 10)
        self.assertTrue(all(o.ok for o in outcomes), [o.to_dict() for o in outcomes if not o.ok])

        # Verify hot node2 received zero jobs while node0 & node1 shared the load
        used_nodes = {o.node_id for o in outcomes}
        self.assertNotIn("node2", used_nodes)
        self.assertTrue(used_nodes.issubset({"node0", "node1"}))

        # Now cool node2 down and overheat node1 mid-flight -> verify failover!
        self.node_temps["node2"] = 32.0
        self.node_temps["node1"] = 45.0
        retry_spec = JobSpec(index=0, job_id="failover-1", command="echo survived", timeout_sec=10.0)
        # Direct call to overheated node1 must return retryable HTTP 503
        kind, _ = self.controller.exec_on_node(self.config.get_node("node1"), retry_spec)
        self.assertEqual(kind, "retryable")

        # Map routes cleanly onto node0/node2 instead
        outcomes2 = self.controller.map_jobs([retry_spec], retries=1)
        self.assertEqual(len(outcomes2), 1)
        self.assertTrue(outcomes2[0].ok)
        self.assertIn(outcomes2[0].node_id, {"node0", "node2"})
        self.assertIn("survived", outcomes2[0].stdout)

    def test_battery_guard_records_charge_off_alert(self) -> None:
        # node1 is at 65% CHARGING (above battery_high_pct=60)
        stop = threading.Event()
        guard = BatteryGuardLoop(self.states["node1"], stop)
        guard.check_once()
        alerts = list(self.states["node1"].recent_alerts)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event"], "charge_off")
        # Second immediate check should be suppressed by cooldown
        guard.check_once()
        self.assertEqual(len(self.states["node1"].recent_alerts), 1)

    def test_master_dashboard_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(self.config, cfg_path)

            dash = DashboardHTTPServer(("127.0.0.1", 0), self.controller, config_path=cfg_path)
            port = dash.server_address[1]
            t = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            try:
                # 1. Accessible HTML UI check
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3.0) as resp:
                    html = resp.read().decode("utf-8")
                    self.assertIn('role="tablist"', html)
                    self.assertIn("skip-link", html)
                    self.assertIn("High Contrast", html)

                # 2. Status, Doctor, and Workloads endpoints
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=3.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(data["cluster_name"], "test-redmi-cluster")
                    self.assertEqual(data["nodes_ready"], 2)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/doctor", timeout=3.0) as resp:
                    doc = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("checks", doc)
                    names = {c["name"] for c in doc["checks"]}
                    self.assertIn("24/7 Battery Safety", names)
                    self.assertIn("Thermal Safety", names)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/workloads", timeout=3.0) as resp:
                    wl = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("localhost/6", wl["distcc_hosts"])
                    self.assertEqual(wl["llama_rpc"], "127.0.0.1:50052")

                # 3. Authenticated POST /api/exec
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/exec",
                    data=json.dumps({"command": "echo dash-ok", "target": "best"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(len(res["results"]), 1)
                    self.assertIn("dash-ok", res["results"][0]["stdout"])

                # 4. Authenticated POST /api/map (parallel batch via Web UI)
                req_map = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/map",
                    data=json.dumps(
                        {
                            "mode": "script",
                            "interpreter": sys.executable,
                            "script_content": "import sys; print(int(sys.argv[1]) * 2)",
                            "args_lines": ["5", "10", "15", "20"],
                        }
                    ).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_map, timeout=10.0) as resp:
                    mres = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(mres["ok_count"], 4)
                    self.assertEqual(mres["fail_count"], 0)

                # 5. Authenticated GET /api/auth/verify (rejects bad token, accepts good token)
                bad_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/auth/verify",
                    headers=build_auth_headers("wrong-token"),
                    method="GET",
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_ctx:
                    urllib.request.urlopen(bad_req, timeout=3.0)
                try:
                    self.assertEqual(bad_ctx.exception.code, 401)
                finally:
                    bad_ctx.exception.close()

                ok_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/auth/verify",
                    headers=build_auth_headers(self.token),
                    method="GET",
                )
                with urllib.request.urlopen(ok_req, timeout=3.0) as resp:
                    self.assertTrue(json.loads(resp.read().decode("utf-8"))["valid"])

                # 6. Authenticated POST /api/nodes/add & /api/nodes/remove
                req_add = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/nodes/add",
                    data=json.dumps({"host": "192.168.1.210", "ssh_user": "u0_a999"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_add, timeout=3.0) as resp:
                    ares = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(ares["node"]["id"], "node3")
                reloaded = load_config(cfg_path)
                self.assertEqual(len(reloaded.nodes), 4)
                self.assertEqual(reloaded.get_node("node3").host, "192.168.1.210")

                # Removing master node must fail with 400
                req_rm_master = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/nodes/remove",
                    data=json.dumps({"id": "node0"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as rm_ctx:
                    urllib.request.urlopen(req_rm_master, timeout=3.0)
                try:
                    self.assertEqual(rm_ctx.exception.code, 400)
                finally:
                    rm_ctx.exception.close()

                # Removing worker node3 succeeds and persists
                req_rm = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/nodes/remove",
                    data=json.dumps({"id": "node3"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_rm, timeout=3.0) as resp:
                    self.assertEqual(json.loads(resp.read().decode("utf-8"))["removed"], "node3")
                self.assertEqual(len(load_config(cfg_path).nodes), 3)

                # 7. Authenticated safety settings update & non-leakage on /api/status
                req_set = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/settings",
                    data=json.dumps(
                        {
                            "max_temp_c": 39.0,
                            "resume_temp_c": 36.0,
                            "battery_low_pct": 40,
                            "battery_high_pct": 55,
                            "battery_webhook_url": "http://127.0.0.1:9999/secret-hook",
                        }
                    ).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_set, timeout=3.0) as resp:
                    self.assertTrue(json.loads(resp.read().decode("utf-8"))["saved"])
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=3.0) as resp:
                    st = json.loads(resp.read().decode("utf-8"))
                    self.assertNotIn("battery_webhook_url", st["safety"])
                    self.assertTrue(st["safety"]["battery_webhook_configured"])
                    self.assertEqual(st["safety"]["max_temp_c"], 39.0)

                # 8. Live job inspection (/api/jobs) and cancellation (/api/jobs/cancel)
                slow_result: list[dict] = []

                def _run_slow() -> None:
                    spec = JobSpec(index=0, job_id="slow-cancel-1", command="sleep 10", timeout_sec=15.0)
                    _kind, res_data = self.controller.exec_on_node(self.config.get_node("node0"), spec)
                    slow_result.append(res_data)

                bg = threading.Thread(target=_run_slow, daemon=True)
                bg.start()
                # Wait briefly until slow-cancel-1 shows up as active
                found_active = False
                for _ in range(30):
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/jobs", timeout=3.0) as resp:
                        jdata = json.loads(resp.read().decode("utf-8"))
                    n0 = next(n for n in jdata["nodes"] if n["node_id"] == "node0")
                    if any(j["job_id"] == "slow-cancel-1" for j in n0["active"]):
                        found_active = True
                        break
                    time.sleep(0.05)
                self.assertTrue(found_active)

                req_cancel = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/jobs/cancel",
                    data=json.dumps({"node_id": "node0", "job_id": "slow-cancel-1"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_cancel, timeout=3.0) as resp:
                    self.assertTrue(json.loads(resp.read().decode("utf-8"))["cancelled"])
                bg.join(timeout=5.0)
                self.assertTrue(slow_result and slow_result[0].get("cancelled"))
                # 9. Unified /api/live & /api/metrics sparkline history
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live", timeout=3.0) as resp:
                    live = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("summary", live)
                    self.assertIn("jobs", live)
                    self.assertIn("history", live)
                    self.assertGreaterEqual(len(live["history"]["cluster"]), 1)
                    self.assertGreater(live["summary"]["cluster_cpu_pct"], 0)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/metrics", timeout=3.0) as resp:
                    hist = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("node0", hist["nodes"])

                # 10. Interactive Web Terminal (/api/terminal/exec) with persistent cd
                req_cd = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/terminal/exec",
                    data=json.dumps({"command": "cd /tmp && echo in-tmp", "target": "node0"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_cd, timeout=5.0) as resp:
                    t1 = json.loads(resp.read().decode("utf-8"))["results"][0]
                    self.assertTrue(t1["ok"])
                    self.assertEqual(t1["stdout"].strip(), "in-tmp")
                    self.assertEqual(t1["cwd"], "/tmp")

                req_pwd = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/terminal/exec",
                    data=json.dumps({"command": "pwd", "target": "node0", "cwd": t1["cwd"]}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_pwd, timeout=5.0) as resp:
                    t2 = json.loads(resp.read().decode("utf-8"))["results"][0]
                    self.assertEqual(t2["stdout"].strip(), "/tmp")
            finally:
                dash.shutdown()
                dash.server_close()

    def test_btop_tui_renderer_and_cli_top_once(self) -> None:
        from phonecluster import cli

        summary = self.controller.cluster_summary()
        all_jobs = self.controller.get_all_jobs()
        hist = self.controller.metrics_history.snapshot()

        frame_tasks = render_top_frame(
            summary=summary,
            history=hist,
            all_jobs=all_jobs,
            view_mode="tasks",
            width=100,
            use_color=False,
        )
        self.assertIn("UNIFIED MULTI-DEVICE BTOP", frame_tasks)
        self.assertIn("node0", frame_tasks)
        self.assertIn("node2", frame_tasks)
        self.assertIn("RUNNING & RECENT CLUSTER TASKS", frame_tasks)

        frame_procs = render_top_frame(
            summary=summary,
            history=hist,
            all_jobs=all_jobs,
            view_mode="procs",
            width=100,
            use_color=False,
        )
        self.assertIn("SHARED TOP PROCESSES", frame_procs)
        self.assertIn("python3", frame_procs)
        self.assertEqual(len(make_sparkline([10, 50, 90], width=8)), 8)

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(self.config, cfg_path)
            self.assertEqual(cli.main(["--config", str(cfg_path), "top", "--once"]), 0)

    def test_udp_lan_discovery(self) -> None:
        responder = DiscoveryResponder(
            node_id="node9",
            role="worker",
            worker_port=8765,
            ssh_port=8022,
            ssh_user="u0_test",
            listen_host="127.0.0.1",
            discovery_port=0,
        )
        self.assertTrue(responder.bind())
        responder.start()
        try:
            found = discover_lan_nodes(
                timeout_sec=0.5,
                discovery_port=responder.bound_port,
                targets=["127.0.0.1"],
            )
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["node_id"], "node9")
            self.assertEqual(found[0]["ssh_user"], "u0_test")
        finally:
            responder.stop()

    def test_doctor_flags_hot_and_high_battery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(self.config, cfg_path)
            report = run_doctor(cfg_path, check_remote=True)
            by_name = {c["name"]: c for c in report["checks"]}
            self.assertEqual(by_name["Thermal Safety"]["status"], "warn")
            self.assertIn("node2", by_name["Thermal Safety"]["detail"])
            self.assertEqual(by_name["24/7 Battery Safety"]["status"], "warn")
            self.assertIn("node1", by_name["24/7 Battery Safety"]["detail"])

    def test_setup_wizard_non_interactive_mock(self) -> None:
        answers = iter(
            [
                "my-home-cluster",  # cluster name
                "192.168.1.201",    # master ip
                "u0_a123",          # ssh user
                "8022",             # ssh port
                "n",                # skip wifi scan in unit test
                "192.168.1.202, 192.168.1.203",  # workers
                "39.5",             # max temp
                "",                 # webhook
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            rc = run_setup_wizard(cfg_path, input_fn=lambda _prompt: next(answers))
            self.assertEqual(rc, 0)
            cfg = load_config(cfg_path)
            self.assertEqual(cfg.cluster_name, "my-home-cluster")
            self.assertEqual(len(cfg.nodes), 3)
            self.assertEqual(cfg.safety.max_temp_c, 39.5)
            self.assertEqual(cfg.safety.resume_temp_c, 36.5)

    def test_score_node_prefers_higher_weight_and_cooler(self) -> None:
        snaps = self.controller.poll_health()
        s0 = next(s for s in snaps if s.node.id == "node0")
        s1 = next(s for s in snaps if s.node.id == "node1")
        self.assertGreater(score_node(s0), score_node(s1))

    def test_cli_status_run_and_map_example_script(self) -> None:
        from phonecluster import cli

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            out_jsonl = Path(tmp) / "results.jsonl"
            save_config(self.config, cfg_path)

            self.assertEqual(cli.main(["--config", str(cfg_path), "status"]), 0)
            self.assertEqual(cli.main(["--config", str(cfg_path), "jobs"]), 0)
            self.assertEqual(cli.main(["--config", str(cfg_path), "token"]), 0)
            self.assertEqual(
                cli.main(["--config", str(cfg_path), "run", "--target", "best", "echo hello"]),
                0,
            )
            rc = cli.main(
                [
                    "--config",
                    str(cfg_path),
                    "map",
                    "--script",
                    "examples/sample_job.py",
                    "--args-file",
                    "examples/sample_args.txt",
                    "--interpreter",
                    sys.executable,
                    "--output-jsonl",
                    str(out_jsonl),
                    "--quiet",
                ]
            )
            self.assertEqual(rc, 0)
            lines = out_jsonl.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 8)
            for line in lines:
                rec = json.loads(line)
                self.assertTrue(rec["ok"], rec)
                self.assertIn("primes=", rec["stdout"])
                self.assertNotEqual(rec["node_id"], "node2")  # hot node excluded

            # Token rotation updates cluster.json atomically
            old_tok = load_config(cfg_path).auth_token
            self.assertEqual(cli.main(["--config", str(cfg_path), "token", "--rotate"]), 0)
            new_tok = load_config(cfg_path).auth_token
            self.assertNotEqual(old_tok, new_tok)
            self.assertGreaterEqual(len(new_tok), 24)


class TestSecurePairingAndSecurity(unittest.TestCase):
    def test_dh_subgroup_validation_and_encrypt_then_mac_tamper_detection(self) -> None:
        self.assertFalse(validate_dh_public(0))
        self.assertFalse(validate_dh_public(1))
        self.assertFalse(validate_dh_public(DH_P - 1))
        self.assertFalse(validate_dh_public(DH_P))

        _ka, ke, km = derive_pairing_keys("482-917", b"\x42" * 256, "00" * 16, "sid1", iterations=1000)
        env = encrypt_bundle(ke, km, {"node_token": "secret-123"}, aad="sid1|node3")
        dec = decrypt_bundle(ke, km, env, aad="sid1|node3")
        self.assertEqual(dec["node_token"], "secret-123")

        # Tampering with ciphertext, tag, or AAD must fail MAC check before decrypting
        bad_ct = dict(env, ciphertext="AAAA" + env["ciphertext"][4:])
        with self.assertRaises(ValueError):
            decrypt_bundle(ke, km, bad_ct, aad="sid1|node3")
        with self.assertRaises(ValueError):
            decrypt_bundle(ke, km, env, aad="sid1|wrong-node")

    def test_e2e_secure_pairing_beacon_isolation_and_auto_close(self) -> None:
        master_cfg = create_default_config(
            cluster_name="sec-cluster",
            master_host="127.0.0.1",
            worker_hosts=[],
        )
        with tempfile.TemporaryDirectory() as tmp:
            master_cfg_path = Path(tmp) / "master_cluster.json"
            worker_cfg_path = Path(tmp) / "worker_cluster.json"
            save_config(master_cfg, master_cfg_path)

            ctrl = MasterController(master_cfg)
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0),
                ctrl,
                config_path=master_cfg_path,
                enable_pairing_beacon=True,
                pairing_fail_delay_sec=0.0,
            )
            dash.pairing_manager.discovery_port = 0  # Ephemeral UDP port for isolated test
            port = dash.server_address[1]
            t = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            worker_srv = None
            try:
                # 1. Closed by default: /api/pair/hello MUST fail with 403
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/pair/hello", timeout=3.0)
                try:
                    self.assertEqual(ctx.exception.code, 403)
                finally:
                    ctx.exception.close()

                # 2. Authenticated Master opens a 1-slot pairing window
                req_open = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/pair/open",
                    data=json.dumps({"ttl_sec": 60, "max_devices": 1}).encode("utf-8"),
                    headers=build_auth_headers(master_cfg.auth_token),
                    method="POST",
                )
                with urllib.request.urlopen(req_open, timeout=3.0) as resp:
                    pinfo = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(pinfo["active"])
                pin = pinfo["pin"]

                # 3. New phone auto-searches Wi-Fi for Master's temporary UDP beacon
                found = discover_pairing_masters(
                    timeout_sec=0.6,
                    discovery_port=dash.pairing_manager.beacon_port,
                    targets=["127.0.0.1"],
                )
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["cluster_name"], "sec-cluster")
                self.assertEqual(found[0]["fingerprint"], pinfo["fingerprint"])

                # 4. Join securely via 2048-bit DH + PIN mutual proof
                # Start a real worker HTTP server first on an ephemeral port so Master can talk to it!
                res = join_cluster_via_pairing(
                    master_host=found[0]["host"],
                    pair_port=found[0]["pair_port"],
                    pin=pin,
                    config_out=worker_cfg_path,
                    worker_port=0,
                    trust_ssh_key=False,
                )
                self.assertEqual(res["node_id"], "node1")

                # 5. Pairing window MUST auto-close after single-use join!
                with self.assertRaises(urllib.error.HTTPError) as ctx2:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/pair/hello", timeout=3.0)
                try:
                    self.assertEqual(ctx2.exception.code, 403)
                finally:
                    ctx2.exception.close()

                # 6. Least-privilege check: worker got its OWN unique token != master admin token
                worker_cfg = load_config(worker_cfg_path)
                self.assertNotEqual(worker_cfg.auth_token, master_cfg.auth_token)
                self.assertEqual(
                    master_cfg.get_node("node1").auth_token, worker_cfg.auth_token
                )

                # Worker token MUST NOT unlock Master's admin API!
                req_bad_admin = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/auth/verify",
                    headers=build_auth_headers(worker_cfg.auth_token),
                    method="GET",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx3:
                    urllib.request.urlopen(req_bad_admin, timeout=3.0)
                try:
                    self.assertEqual(ctx3.exception.code, 401)
                finally:
                    ctx3.exception.close()

                # 7. MasterController CAN communicate with the paired worker using its per-node token!
                w_state = WorkerState(
                    node_id="node1",
                    role="worker",
                    auth_token=worker_cfg.auth_token,
                    safety=worker_cfg.safety,
                )
                worker_srv, _g, stop_ev = create_worker_server("127.0.0.1", 0, w_state)
                w_port = worker_srv.server_address[1]
                master_cfg.get_node("node1").worker_port = w_port
                wt = threading.Thread(
                    target=worker_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
                )
                wt.start()
                snap = ctrl.check_node_health(master_cfg.get_node("node1"))
                self.assertTrue(snap.online, snap.error)
                self.assertEqual(snap.health["node_id"], "node1")
                stop_ev.set()
            finally:
                if worker_srv is not None:
                    worker_srv.shutdown()
                    worker_srv.server_close()
                dash.shutdown()
                dash.server_close()

    def test_wrong_pin_5_attempt_lockout(self) -> None:
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        mgr = PairingManager(
            config=cfg,
            config_path=None,
            pair_port=0,
            fail_delay_sec=0.0,
            enable_beacon=False,
        )
        srv = StandalonePairingServer(("127.0.0.1", 0), mgr)
        port = srv.server_address[1]
        info = mgr.open_session(ttl_sec=60, max_devices=1, pair_port=port)
        real_pin = info["pin"]
        wrong_pin = "000000" if real_pin.replace("-", "") != "000000" else "999999"

        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "w.json"
                # 5 failed PIN attempts must destroy the session
                for _ in range(5):
                    with self.assertRaises(RuntimeError):
                        join_cluster_via_pairing("127.0.0.1", port, wrong_pin, out)
                self.assertFalse(mgr.admin_status()["active"])
                # Even the real PIN must fail now because the window self-destructed!
                with self.assertRaises(RuntimeError):
                    join_cluster_via_pairing("127.0.0.1", port, real_pin, out)
        finally:
            mgr.close_session()
            srv.shutdown()
            srv.server_close()

    def test_dashboard_require_auth_and_rate_limit_429(self) -> None:
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        cfg.dashboard_require_auth = True
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0),
            ctrl,
            enable_pairing_beacon=False,
        )
        dash.rate_limiter = AuthRateLimiter(max_failures=3, window_sec=60.0, block_sec=30.0)
        port = dash.server_address[1]
        t = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            # Read endpoint /api/live blocked without token when dashboard_require_auth=True
            for _ in range(3):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live", timeout=3.0)
                try:
                    self.assertEqual(ctx.exception.code, 401)
                finally:
                    ctx.exception.close()

            # 4th attempt from same IP must hit 429 Too Many Requests!
            with self.assertRaises(urllib.error.HTTPError) as ctx429:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live", timeout=3.0)
            try:
                self.assertEqual(ctx429.exception.code, 429)
            finally:
                ctx429.exception.close()
        finally:
            dash.shutdown()
            dash.server_close()


class TestHeterogeneousMultiTierCluster(unittest.TestCase):
    """Tests mixed Tier 1 (Termux) + Tier 2 (Debian 13) + Tier 3 (Docker) cluster as ONE system."""

    def setUp(self) -> None:
        self.token = "mixed-tier-secret-token"
        self.safety = SafetyConfig(max_temp_c=40.0, resume_temp_c=37.0)
        self.temps = {"t1_compute": 33.0, "t2_services": 34.0, "t3_docker": 35.0}
        self.servers = []
        self.threads = []
        self.stop_events = []
        nodes_cfg: list[NodeConfig] = []

        profiles = [
            (
                "t1_compute",
                "master",
                "termux",
                1,
                "compute",
                {"python3": True, "distccd": True, "llama_cli": True},
                {"sshd_8022": True, "llama_api_8081": True, "distccd_3632": True},
            ),
            (
                "t2_services",
                "worker",
                "debian-13",
                2,
                "services",
                {"python3": True, "apt": True, "mosquitto": True, "adguard": True},
                {"sshd_22": True, "mosquitto_1883": True, "adguard_3000": True, "dns_53": True},
            ),
            (
                "t3_docker",
                "worker",
                "debian-13",
                3,
                "docker",
                {"python3": True, "docker": True, "apt": True},
                {"sshd_22": True, "homeassistant_8123": True},
            ),
        ]

        for nid, role, os_env, tier, pool_name, tools, svcs in profiles:
            def _make_provider(
                n_id: str,
                r_name: str,
                o_env: str,
                t_num: int,
                p_name: str,
                tl: dict[str, bool],
                sv: dict[str, bool],
            ):
                def _prov():
                    temp = self.temps[n_id]
                    hot = temp >= self.safety.max_temp_c
                    return {
                        "node_id": n_id,
                        "role": r_name,
                        "hostname": f"phone-{n_id}",
                        "os_env": o_env,
                        "tier": t_num,
                        "pool": p_name,
                        "arch": "aarch64",
                        "uptime_sec": 3600,
                        "cpu_cores": 8,
                        "cpu_pct": 12.0,
                        "per_core_pct": [10.0] * 8,
                        "load_1m": 0.25,
                        "mem_total_mb": 4096,
                        "mem_available_mb": 2200,
                        "battery_pct": 52,
                        "temp_c": temp,
                        "battery_status": "DISCHARGING",
                        "overheated": hot,
                        "ready_for_jobs": not hot,
                        "not_ready_reasons": [f"overheated ({temp}C)"] if hot else [],
                        "tools": dict(tl),
                        "services": dict(sv),
                    }

                return _prov

            state = WorkerState(
                node_id=nid,
                role=role,
                auth_token=self.token,
                safety=self.safety,
                max_concurrency=2,
                health_provider=_make_provider(nid, role, os_env, tier, pool_name, tools, svcs),
            )
            srv, _guard, stop_ev = create_worker_server("127.0.0.1", 0, state)
            port = srv.server_address[1]
            th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            th.start()
            self.servers.append(srv)
            self.threads.append(th)
            self.stop_events.append(stop_ev)
            nodes_cfg.append(
                NodeConfig(
                    id=nid,
                    host="127.0.0.1",
                    role=role,
                    worker_port=port,
                    max_concurrency=2,
                    tier=0,  # verify automatic detection from telemetry works seamlessly!
                    pool="auto",
                )
            )

        self.config = ClusterConfig(
            cluster_name="mixed-tier-home",
            auth_token=self.token,
            safety=self.safety,
            nodes=nodes_cfg,
            custom_services={"custom_api": "http://192.168.1.209:9000"},
        )
        self.controller = MasterController(self.config)

    def tearDown(self) -> None:
        for ev in self.stop_events:
            ev.set()
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def test_smart_auto_routing_spillover_and_strict_docker_isolation(self) -> None:
        # 1. Docker command routes strictly to Tier 3
        out_docker = self.controller.run_single(
            JobSpec(index=0, job_id="j-doc", command="true && echo docker-ok # docker ps"),
            target="auto",
            workload_hint="docker",
        )[0]
        self.assertTrue(out_docker.ok, out_docker.error)
        self.assertEqual(out_docker.node_id, "t3_docker")
        self.assertEqual(out_docker.node_tier, 3)
        self.assertEqual(out_docker.node_pool, "docker")

        # 2. Keyword auto-detection without explicit hint: mosquitto_pub -> Tier 2
        out_svc = self.controller.run_single(
            JobSpec(index=0, job_id="j-svc", command="echo mqtt-ok; false && mosquitto_pub -h localhost || true"),
            target="auto",
        )[0]
        self.assertTrue(out_svc.ok, out_svc.error)
        self.assertEqual(out_svc.node_id, "t2_services")
        self.assertEqual(out_svc.node_tier, 2)
        self.assertEqual(out_svc.node_pool, "services")
        self.assertIn("mosquitto_pub", out_svc.routing_reason)

        # 3. General compute prefers Tier 1
        out_comp = self.controller.run_single(
            JobSpec(index=0, job_id="j-comp", command="python3 -c 'print(2+2)'"),
            target="auto",
        )[0]
        self.assertTrue(out_comp.ok, out_comp.error)
        self.assertEqual(out_comp.node_id, "t1_compute")
        self.assertEqual(out_comp.node_tier, 1)

        # 4. Compute gracefully spills over to Tier 2/3 when Tier 1 overheats!
        self.temps["t1_compute"] = 44.0
        out_spill = self.controller.run_single(
            JobSpec(index=0, job_id="j-spill", command="echo spillover-ok"),
            target="auto",
        )[0]
        self.assertTrue(out_spill.ok, out_spill.error)
        self.assertIn(out_spill.node_id, {"t2_services", "t3_docker"})
        self.temps["t1_compute"] = 33.0

        # 5. Strict isolation: when Tier 3 overheats, docker jobs NEVER run on Termux Tier 1!
        self.temps["t3_docker"] = 44.5
        out_no_doc = self.controller.run_single(
            JobSpec(index=0, job_id="j-nodoc", command="docker ps"),
            target="auto",
        )[0]
        self.assertFalse(out_no_doc.ok)
        self.assertEqual(out_no_doc.node_id, "none")
        self.assertIn("Tier 3", out_no_doc.error)

    def test_cross_tier_service_mesh_env_injection_and_dns_hosts(self) -> None:
        # Run a Tier 1 job and verify it automatically receives Tier 2 MQTT/AdGuard + Tier 3 HA URLs!
        py_cmd = (
            "python3 -c \"import json, os; "
            "print(json.dumps({k: v for k, v in os.environ.items() if k.startswith('PHONECLUSTER_')}))\""
        )
        outcome = self.controller.run_single(
            JobSpec(index=0, job_id="j-env", command=py_cmd),
            target="tier:1",
        )[0]
        self.assertTrue(outcome.ok, outcome.error)
        self.assertEqual(outcome.node_id, "t1_compute")
        env_seen = json.loads(outcome.stdout)
        self.assertEqual(env_seen["PHONECLUSTER_MQTT_HOST"], "127.0.0.1")
        self.assertEqual(env_seen["PHONECLUSTER_MQTT_PORT"], "1883")
        self.assertEqual(env_seen["PHONECLUSTER_MQTT_URL"], "mqtt://127.0.0.1:1883")
        self.assertEqual(env_seen["PHONECLUSTER_HOMEASSISTANT_URL"], "http://127.0.0.1:8123")
        self.assertEqual(env_seen["PHONECLUSTER_ADGUARD_URL"], "http://127.0.0.1:3000")
        self.assertEqual(env_seen["PHONECLUSTER_LLAMA_API_URL"], "http://127.0.0.1:8081")
        self.assertEqual(env_seen["PHONECLUSTER_POOL_COMPUTE_HOSTS"], "127.0.0.1")
        self.assertEqual(env_seen["PHONECLUSTER_POOL_SERVICES_HOSTS"], "127.0.0.1")
        self.assertEqual(env_seen["PHONECLUSTER_POOL_DOCKER_HOSTS"], "127.0.0.1")
        self.assertEqual(env_seen["PHONECLUSTER_SVC_CUSTOM_API"], "http://192.168.1.209:9000")

        svc_info = self.controller.get_services_info()
        hosts_txt = svc_info["dns_hosts"]
        for expected_alias in (
            "mqtt.cluster",
            "ha.cluster",
            "adguard.cluster",
            "ai.cluster",
            "t1_compute.cluster",
            "custom_api.cluster",
        ):
            self.assertIn(expected_alias, hosts_txt)

        # Verify custom service URL host & port are parsed properly
        custom_entry = next(s for s in svc_info["services"] if s["name"] == "custom_api")
        self.assertEqual(custom_entry["host"], "192.168.1.209")
        self.assertEqual(custom_entry["port"], 9000)

    def test_mixed_parallel_map_and_cross_tier_pipeline(self) -> None:
        # Mixed parallel map auto-routes each job to its exact Tier in one batch
        jobs = [
            JobSpec(index=0, job_id="m0", command="echo compute-job"),
            JobSpec(index=1, job_id="m1", command="echo svc-job; false && apt-cache -v || true"),
            JobSpec(index=2, job_id="m2", command="echo docker-job; false && docker --version || true"),
        ]
        outcomes = self.controller.map_jobs(jobs, target="auto", wait_for_ready_sec=3.0)
        self.assertEqual(len(outcomes), 3)
        self.assertTrue(all(o.ok for o in outcomes))
        self.assertEqual(outcomes[0].node_id, "t1_compute")
        self.assertEqual(outcomes[1].node_id, "t2_services")
        self.assertEqual(outcomes[2].node_id, "t3_docker")

        # 3-step Cross-Tier Pipeline: Tier 1 -> Tier 2 -> Tier 3
        pipe = self.controller.run_pipeline(
            [
                {
                    "name": "Step 1 Compute",
                    "target": "tier:1",
                    "command": "echo 'inference=sunny'",
                },
                {
                    "name": "Step 2 MQTT Service",
                    "target": "tier:2",
                    "command": 'echo "relay:$PHONECLUSTER_PREV_STDOUT:from=$PHONECLUSTER_PREV_NODE:mqtt=$PHONECLUSTER_MQTT_PORT"',
                },
                {
                    "name": "Step 3 Docker HA",
                    "target": "tier:3",
                    "command": 'echo "final:$PHONECLUSTER_PREV_STDOUT|step1=$PHONECLUSTER_STEP_1_STDOUT|ha=$PHONECLUSTER_HOMEASSISTANT_URL"',
                },
            ]
        )
        self.assertTrue(pipe["ok"], pipe)
        self.assertEqual(pipe["steps_completed"], 3)
        self.assertEqual(pipe["failed_steps"], 0)
        self.assertEqual(pipe["results"][0]["node_id"], "t1_compute")
        self.assertEqual(pipe["results"][1]["node_id"], "t2_services")
        self.assertEqual(pipe["results"][2]["node_id"], "t3_docker")
        self.assertIn("relay:inference=sunny:from=t1_compute:mqtt=1883", pipe["results"][1]["stdout"])
        self.assertIn("step1=inference=sunny", pipe["results"][2]["stdout"])
        self.assertIn("ha=http://127.0.0.1:8123", pipe["results"][2]["stdout"])

    def test_pipeline_resilience_edge_cases_and_custom_service_api(self) -> None:
        # 1. Unknown node target, bad timeout, bad env, NUL bytes in stdout, continue_on_error
        res = self.controller.run_pipeline(
            [
                {
                    "name": "Missing Node",
                    "target": "ghost_phone_99",
                    "command": "echo hi",
                    "continue_on_error": True,
                },
                {
                    "name": "Bad Timeout",
                    "target": "tier:1",
                    "timeout_sec": -10,
                    "command": "echo hi",
                    "continue_on_error": True,
                },
                {
                    "name": "Bad Env Type",
                    "target": "tier:1",
                    "env": ["not-a-dict"],
                    "command": "echo hi",
                    "continue_on_error": True,
                },
                {
                    "name": "NUL Byte Producer",
                    "target": "tier:1",
                    "command": "python3 -c \"import sys; sys.stdout.write('safe\\x00value')\"",
                },
                {
                    "name": "NUL Consumer",
                    "target": "tier:2",
                    "command": 'echo "clean:$PHONECLUSTER_PREV_STDOUT"',
                },
            ]
        )
        self.assertFalse(res["ok"])
        self.assertEqual(res["steps_completed"], 5)
        self.assertEqual(res["failed_steps"], 3)
        self.assertIn("Unknown node id", res["results"][0]["error"])
        self.assertIn("Invalid timeout_sec", res["results"][1]["error"])
        self.assertIn("JSON object", res["results"][2]["error"])
        self.assertTrue(res["results"][3]["ok"])
        self.assertTrue(res["results"][4]["ok"])
        self.assertIn("clean:safevalue", res["results"][4]["stdout"])

        # 2. Dashboard /api/services/custom, /api/services/custom/remove, /api/services/probe (incl. SSRF guard)
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(self.config, cfg_path)
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0),
                self.controller,
                config_path=cfg_path,
                enable_pairing_beacon=False,
            )
            port = dash.server_address[1]
            t = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            try:
                # Register a custom service pointing to a live local worker port so probe succeeds!
                live_w_port = self.config.get_node("t1_compute").worker_port
                req_add = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/services/custom",
                    data=json.dumps({"name": "portainer", "url": f"http://127.0.0.1:{live_w_port}"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_add, timeout=5.0) as resp:
                    add_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(add_res["name"], "portainer")
                self.assertEqual(load_config(cfg_path).custom_services["portainer"], f"http://127.0.0.1:{live_w_port}")

                # Valid probe against registered service endpoint succeeds
                req_probe = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/services/probe",
                    data=json.dumps({"host": "127.0.0.1", "port": live_w_port}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_probe, timeout=5.0) as resp:
                    p_ok = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(p_ok["reachable"])

                # Unregistered arbitrary host/port probe MUST be rejected with 403 (SSRF protection)
                req_ssrf = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/services/probe",
                    data=json.dumps({"host": "127.0.0.1", "port": 22222}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req_ssrf, timeout=5.0)
                try:
                    self.assertEqual(ctx.exception.code, 403)
                finally:
                    ctx.exception.close()

                # Remove custom service
                req_rm = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/services/custom/remove",
                    data=json.dumps({"name": "portainer"}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_rm, timeout=5.0) as resp:
                    rm_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(rm_res["removed"], "portainer")
                self.assertNotIn("portainer", load_config(cfg_path).custom_services)
            finally:
                dash.shutdown()
                dash.server_close()

    def test_dashboard_api_services_pipeline_node_update_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(self.config, cfg_path)
            pipe_path = Path(tmp) / "pipe.json"
            pipe_path.write_text(
                json.dumps(
                    [
                        {"name": "S1", "target": "tier:1", "command": "echo hello-t1"},
                        {"name": "S2", "target": "tier:3", "command": 'echo "got:$PHONECLUSTER_PREV_STDOUT"'},
                    ]
                ),
                encoding="utf-8",
            )

            # CLI subcommands: pools, services (--env / --hosts), pipeline
            self.assertEqual(cli_main(["--config", str(cfg_path), "pools"]), 0)
            self.assertEqual(cli_main(["--config", str(cfg_path), "services", "--env"]), 0)
            self.assertEqual(cli_main(["--config", str(cfg_path), "services", "--hosts"]), 0)
            self.assertEqual(cli_main(["--config", str(cfg_path), "pipeline", str(pipe_path)]), 0)

            # Verify shipped mixed-tier example config & pipeline JSON stay valid
            repo_root = Path(__file__).resolve().parent.parent
            mixed_cfg = ClusterConfig.from_dict(
                json.loads((repo_root / "examples" / "mixed_cluster.example.json").read_text(encoding="utf-8"))
            )
            self.assertEqual(len(mixed_cfg.nodes), 9)
            self.assertEqual(sum(1 for n in mixed_cfg.nodes if n.tier == 1), 3)
            self.assertEqual(sum(1 for n in mixed_cfg.nodes if n.tier == 2), 2)
            self.assertEqual(sum(1 for n in mixed_cfg.nodes if n.tier == 3), 4)
            pipe_ex = json.loads((repo_root / "examples" / "cross_tier_pipeline.json").read_text(encoding="utf-8"))
            self.assertEqual(len(pipe_ex["steps"]), 3)

            # TUI frame with Tier badges, POOLS/SVCS header, and pool_filter
            summary = self.controller.cluster_summary()
            frame_all = render_top_frame(summary, self.controller.metrics_history.snapshot(), [], use_color=False)
            self.assertIn("T1:compute", frame_all)
            self.assertIn("T2:services", frame_all)
            self.assertIn("T3:docker", frame_all)
            self.assertIn("POOLS", frame_all)
            self.assertIn("SVCS", frame_all)
            frame_doc = render_top_frame(
                summary,
                self.controller.metrics_history.snapshot(),
                [],
                use_color=False,
                pool_filter="docker",
            )
            dev_section = frame_doc.split("DEVICES · POOL FILTER: DOCKER", 1)[1]
            self.assertIn("t3_docker", dev_section)
            self.assertNotIn("t1_compute", dev_section)
            self.assertNotIn("t2_services", dev_section)

            # Dashboard endpoints: /api/services, /api/pipeline, /api/nodes/update
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0),
                self.controller,
                config_path=cfg_path,
                enable_pairing_beacon=False,
            )
            port = dash.server_address[1]
            t = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/services", timeout=5.0) as resp:
                    svcs_api = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(svcs_api["pools"]), 3)
                self.assertEqual(svcs_api["env"]["PHONECLUSTER_MQTT_PORT"], "1883")

                req_pipe = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/pipeline",
                    data=json.dumps(
                        {
                            "steps": [
                                {"name": "Compute", "target": "tier:1", "command": "echo web-t1"},
                                {"name": "Docker", "target": "tier:3", "command": 'echo "ok:$PHONECLUSTER_PREV_STDOUT"'},
                            ]
                        }
                    ).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_pipe, timeout=5.0) as resp:
                    p_res = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(p_res["ok"])
                self.assertEqual(p_res["results"][1]["node_id"], "t3_docker")
                self.assertIn("ok:web-t1", p_res["results"][1]["stdout"])

                req_upd = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/nodes/update",
                    data=json.dumps({"id": "t2_services", "tier": 2, "pool": "iot", "max_concurrency": 3}).encode("utf-8"),
                    headers=build_auth_headers(self.token),
                    method="POST",
                )
                with urllib.request.urlopen(req_upd, timeout=5.0) as resp:
                    u_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(u_res["node"]["pool"], "iot")
                reloaded = load_config(cfg_path)
                self.assertEqual(reloaded.get_node("t2_services").pool, "iot")
                self.assertEqual(reloaded.get_node("t2_services").max_concurrency, 3)
            finally:
                dash.shutdown()
                dash.server_close()


class TestMasterNetworkGuard(unittest.TestCase):
    """Tests optional Master Network Guard (allowlist HTTP/HTTPS proxy, SSRF guard, audit log, toggle)."""

    def test_off_by_default_policy_matching_and_ssrf_guard(self) -> None:
        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=["127.0.0.2"])
        self.assertFalse(cfg.gateway.enabled)
        self.assertEqual(build_worker_proxy_env(cfg, cfg.get_node("node1")), {})

        # Derived proxy secret must be distinct from both worker and master tokens
        p_secret = derive_proxy_password(cfg.token_for_node(cfg.get_node("node1")), "node1")
        self.assertNotEqual(p_secret, cfg.auth_token)
        self.assertEqual(len(p_secret), 32)

        # Strict domain matching (exact + wildcard + trailing dot, no substring tricks!)
        self.assertTrue(domain_matches("github.com", "github.com"))
        self.assertTrue(domain_matches("GITHUB.COM.", "github.com"))
        self.assertTrue(domain_matches("api.github.com", "*.github.com"))
        self.assertFalse(domain_matches("evilgithub.com", "*.github.com"))
        self.assertFalse(domain_matches("github.com", "*.github.com"))

        # Policy modes: allowlist, monitor, block_all, blocked_domains, port filter
        gw = GatewayConfig(
            enabled=True,
            mode="allowlist",
            allowed_domains=["github.com", "*.debian.org"],
            blocked_domains=["bad.debian.org"],
            allowed_ports=[80, 443],
        )
        self.assertTrue(evaluate_policy("github.com", 443, gw)[0])
        self.assertTrue(evaluate_policy("deb.debian.org", 80, gw)[0])
        self.assertFalse(evaluate_policy("bad.debian.org", 443, gw)[0])
        self.assertFalse(evaluate_policy("evil.example", 443, gw)[0])
        self.assertFalse(evaluate_policy("github.com", 22, gw)[0])

        gw.mode = "monitor"
        self.assertTrue(evaluate_policy("any-site.example", 443, gw)[0])
        self.assertFalse(evaluate_policy("bad.debian.org", 443, gw)[0])

        gw.mode = "block_all"
        self.assertFalse(evaluate_policy("github.com", 443, gw)[0])

        # SSRF private/loopback IP blocking
        for priv in ("127.0.0.1", "192.168.1.1", "10.0.0.1", "::1", "::ffff:127.0.0.1"):
            res, why = resolve_and_validate_target(priv, 80, block_private_ips=True)
            self.assertIsNone(res)
            self.assertIn("SSRF", why)

    def test_live_proxy_auth_ssrf_http_connect_and_audit_log(self) -> None:
        seen_headers: list[dict[str, str]] = []

        class _DummyUpstream(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                seen_headers.append({k.lower(): v for k, v in self.headers.items()})
                body = b"hello-from-upstream"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _DummyUpstream)
        up_port = upstream.server_address[1]
        up_thread = threading.Thread(target=upstream.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        up_thread.start()

        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=["127.0.0.1"])
        cfg.get_node("node1").auth_token = "unique-worker-token-node1"
        cfg.gateway = GatewayConfig(
            enabled=True,
            bind_host="127.0.0.1",
            port=0,
            mode="allowlist",
            allowed_domains=["localhost"],
            allowed_ports=[80, 443, up_port],
            block_private_ips=True,
        )
        mgr = GatewayManager(cfg)
        ok, msg = mgr.start()
        self.assertTrue(ok, msg)
        gw_port = mgr.bound_port

        def _raw_proxy_req(req_bytes: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(req_bytes)
                s.settimeout(3.0)
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = s.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)

        pw = derive_proxy_password("unique-worker-token-node1", "node1")
        auth_b64 = base64.b64encode(f"node1:{pw}".encode("utf-8")).decode("ascii")

        try:
            # 1. Stranger without Proxy-Authorization -> 407
            r_noauth = _raw_proxy_req(f"GET http://localhost:{up_port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            self.assertTrue(r_noauth.startswith(b"HTTP/1.1 407"))

            # 2. Authenticated worker blocked by SSRF guard (localhost -> 127.0.0.1) -> 403
            r_ssrf = _raw_proxy_req(
                f"GET http://localhost:{up_port}/ HTTP/1.1\r\n"
                f"Host: localhost:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
            )
            self.assertTrue(r_ssrf.startswith(b"HTTP/1.1 403"))
            self.assertIn(b"SSRF", r_ssrf)

            # 3. Disable SSRF guard ONLY for local loopback upstream test; non-allowlisted domain -> 403
            cfg.gateway.block_private_ips = False
            r_denied = _raw_proxy_req(
                f"GET http://evil.example:{up_port}/ HTTP/1.1\r\n"
                f"Host: evil.example\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
            )
            self.assertTrue(r_denied.startswith(b"HTTP/1.1 403"))

            # 4. Allowlisted plain HTTP succeeds AND strips Proxy-Authorization before forwarding upstream!
            r_ok = _raw_proxy_req(
                f"GET http://localhost:{up_port}/test HTTP/1.1\r\n"
                f"Host: localhost:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
            )
            self.assertIn(b"200 OK", r_ok[:32], r_ok[:120])
            self.assertIn(b"hello-from-upstream", r_ok)
            self.assertTrue(seen_headers)
            self.assertNotIn("proxy-authorization", seen_headers[-1])

            # 5. HTTPS CONNECT tunnel works cleanly end-to-end
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"CONNECT localhost:{up_port} HTTP/1.1\r\n"
                    f"Host: localhost:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
                )
                est = s.recv(1024)
                self.assertIn(b"200 Connection Established", est)
                s.sendall(f"GET /tun HTTP/1.1\r\nHost: localhost:{up_port}\r\nConnection: close\r\n\r\n".encode())
                tun_resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    tun_resp += chunk
                self.assertIn(b"hello-from-upstream", tun_resp)

            # 6. Air-gap mode blocks everything
            cfg.gateway.mode = "block_all"
            r_airgap = _raw_proxy_req(
                f"CONNECT localhost:{up_port} HTTP/1.1\r\n"
                f"Host: localhost:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
            )
            self.assertTrue(r_airgap.startswith(b"HTTP/1.1 403"))

            st = mgr.status()
            self.assertEqual(st["stats"]["total_allowed"], 2)
            self.assertEqual(st["stats"]["auth_failures"], 1)
            self.assertGreaterEqual(st["stats"]["total_blocked"], 4)
        finally:
            mgr.stop()
            upstream.shutdown()
            upstream.server_close()

    def test_dashboard_live_gateway_toggle_env_injection_and_cli(self) -> None:
        token = "gw-master-secret"
        w_token = "gw-worker1-secret"
        safety = SafetyConfig()
        servers = []
        stop_evs = []
        nodes: list[NodeConfig] = []

        for nid, role, tok in [("node0", "master", token), ("node1", "worker", w_token)]:
            def _make_cool_health(n_id: str, r_name: str):
                return lambda: {
                    "node_id": n_id,
                    "role": r_name,
                    "os_env": "debian-13" if r_name == "master" else "termux",
                    "cpu_cores": 4,
                    "load_1m": 0.2,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 33.0,
                    "battery_pct": 55,
                    "battery_status": "DISCHARGING",
                    "overheated": False,
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "tools": {"python3": True},
                    "services": {},
                }

            st = WorkerState(
                node_id=nid,
                role=role,
                auth_token=tok,
                safety=safety,
                health_provider=_make_cool_health(nid, role),
            )
            srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            servers.append(srv)
            stop_evs.append(ev)
            nodes.append(
                NodeConfig(
                    id=nid,
                    host="127.0.0.1",
                    role=role,
                    worker_port=port,
                    auth_token="" if role == "master" else tok,
                )
            )

        cfg = ClusterConfig(cluster_name="gw-test", auth_token=token, nodes=nodes, safety=safety)
        ctrl = MasterController(cfg)

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "cluster.json"
            save_config(cfg, cfg_path)
            dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=cfg_path, enable_pairing_beacon=False)
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            try:
                # 1. OFF by default -> proxy not running!
                self.assertFalse(dash.gateway_manager.is_running)

                # 2. Toggle ON live via Dashboard API
                req_on = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/gateway/settings",
                    data=json.dumps({"enabled": True, "port": 0, "mode": "allowlist"}).encode("utf-8"),
                    headers=build_auth_headers(token),
                    method="POST",
                )
                with urllib.request.urlopen(req_on, timeout=5.0) as resp:
                    gw_st = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(gw_st["enabled"])
                self.assertTrue(gw_st["running"])
                self.assertTrue(dash.gateway_manager.is_running)

                # 3. Worker job gets derived proxy env + NO_PROXY excluding LAN/.cluster, Master job does NOT!
                env_cmd = (
                    "python3 -c \"import json, os; "
                    "print(json.dumps({k: os.environ.get(k, '') for k in ('HTTP_PROXY', 'NO_PROXY', 'PHONECLUSTER_GATEWAY_ENABLED')}))\""
                )
                w_out = ctrl.run_single(JobSpec(index=0, job_id="gw-w", command=env_cmd), target="node1")[0]
                self.assertTrue(w_out.ok, w_out.error)
                w_env = json.loads(w_out.stdout)
                self.assertEqual(w_env["PHONECLUSTER_GATEWAY_ENABLED"], "1")
                self.assertIn("node1:", w_env["HTTP_PROXY"])
                self.assertNotIn(w_token, w_env["HTTP_PROXY"])  # Never leaks worker API token!
                self.assertNotIn(token, w_env["HTTP_PROXY"])    # Never leaks master admin token!
                self.assertIn(".cluster", w_env["NO_PROXY"])
                self.assertIn("127.0.0.1", w_env["NO_PROXY"])

                m_out = ctrl.run_single(JobSpec(index=0, job_id="gw-m", command=env_cmd), target="node0")[0]
                self.assertTrue(m_out.ok, m_out.error)
                self.assertEqual(json.loads(m_out.stdout)["PHONECLUSTER_GATEWAY_ENABLED"], "")

                # 4. One-click allow-domain + clear logs + check-isolation
                req_allow = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/gateway/allow-domain",
                    data=json.dumps({"domain": "api.open-meteo.com"}).encode("utf-8"),
                    headers=build_auth_headers(token),
                    method="POST",
                )
                with urllib.request.urlopen(req_allow, timeout=5.0) as resp:
                    self.assertIn("api.open-meteo.com", json.loads(resp.read().decode("utf-8"))["allowed_domains"])

                req_iso = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/gateway/check-isolation",
                    data=b"{}",
                    headers=build_auth_headers(token),
                    method="POST",
                )
                with urllib.request.urlopen(req_iso, timeout=10.0) as resp:
                    iso = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(len(iso["workers"]), 1)
                self.assertEqual(iso["workers"][0]["node_id"], "node1")

                # 5. Toggle OFF live -> stops proxy cleanly and removes injected proxy env!
                req_off = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/gateway/settings",
                    data=json.dumps({"enabled": False}).encode("utf-8"),
                    headers=build_auth_headers(token),
                    method="POST",
                )
                with urllib.request.urlopen(req_off, timeout=5.0) as resp:
                    gw_off = json.loads(resp.read().decode("utf-8"))
                self.assertFalse(gw_off["enabled"])
                self.assertFalse(gw_off["running"])
                self.assertFalse(dash.gateway_manager.is_running)

                # 6. CLI `pc gateway` toggle & status
                self.assertEqual(cli_main(["--config", str(cfg_path), "gateway", "--status"]), 0)
                self.assertEqual(cli_main(["--config", str(cfg_path), "gateway", "--enable", "--mode", "monitor"]), 0)
                self.assertTrue(load_config(cfg_path).gateway.enabled)
                self.assertEqual(load_config(cfg_path).gateway.mode, "monitor")
                self.assertEqual(cli_main(["--config", str(cfg_path), "gateway", "--disable"]), 0)
                self.assertFalse(load_config(cfg_path).gateway.enabled)
            finally:
                dash.shutdown()
                dash.server_close()
                for ev in stop_evs:
                    ev.set()
                for srv in servers:
                    srv.shutdown()
                    srv.server_close()

    def test_worker_source_ip_allowlist_quarantine_rate_limit_csrf_and_net_audit(self) -> None:
        # 1. `/proc/net/tcp` listening port parser (distinguishes loopback vs exposed!)
        with tempfile.TemporaryDirectory() as tmp:
            fake_tcp = Path(tmp) / "tcp"
            fake_tcp.write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
                "   0: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000\n"  # 0.0.0.0:5555 LISTEN
                "   1: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000\n"  # 127.0.0.1:8765 LISTEN
                "   2: 00000000:0050 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000\n",  # ESTABLISHED (ignored)
                encoding="utf-8",
            )
            parsed = read_listening_tcp_ports(tcp_path=fake_tcp, tcp6_path=Path(tmp) / "missing")
            self.assertEqual(parsed, [{"port": 5555, "exposed": True}, {"port": 8765, "exposed": False}])

        # 2. Worker Source-IP Allowlist rejects non-Master IP (403) even with valid Bearer token!
        w_tok = "strict-worker-token"
        st_blocked = WorkerState(
            node_id="w_strict",
            role="worker",
            auth_token=w_tok,
            safety=SafetyConfig(),
            allowed_client_ips={"10.99.0.1"},
        )
        srv_blk, _g1, ev1 = create_worker_server("127.0.0.1", 0, st_blocked)
        p_blk = srv_blk.server_address[1]
        threading.Thread(target=srv_blk.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        st_ok = WorkerState(
            node_id="node1",
            role="worker",
            auth_token=w_tok,
            safety=SafetyConfig(),
            allowed_client_ips={"127.0.0.1"},
            health_provider=lambda: {
                "node_id": "node1",
                "role": "worker",
                "os_env": "termux",
                "cpu_cores": 8,
                "load_1m": 0.1,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "temp_c": 33.0,
                "battery_pct": 55,
                "battery_status": "DISCHARGING",
                "overheated": False,
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "listening_ports": [{"port": 8765, "exposed": True}, {"port": 5555, "exposed": True}],
                "tools": {"python3": True},
                "services": {},
            },
        )
        srv_ok, _g2, ev2 = create_worker_server("127.0.0.1", 0, st_ok)
        p_ok = srv_ok.server_address[1]
        threading.Thread(target=srv_ok.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        try:
            req_403 = urllib.request.Request(
                f"http://127.0.0.1:{p_blk}/health",
                headers=build_auth_headers(w_tok),
                method="GET",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req_403, timeout=3.0)
            try:
                self.assertEqual(ctx.exception.code, 403)
            finally:
                ctx.exception.close()

            req_200 = urllib.request.Request(
                f"http://127.0.0.1:{p_ok}/health",
                headers=build_auth_headers(w_tok),
                method="GET",
            )
            with urllib.request.urlopen(req_200, timeout=3.0) as resp:
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                self.assertEqual(resp.headers.get("Cache-Control"), "no-store")
                h_ok = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(h_ok["source_ip_allowlist_active"])

            # 3. Per-worker Quarantine + Rate Limit + Dashboard CSRF + 1-click Profiles + `pc net-audit`
            m_tok = "hardened-master-tok"
            cfg = ClusterConfig(
                cluster_name="hardened-cluster",
                auth_token=m_tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=p_ok),
                    NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=p_ok, auth_token=w_tok),
                ],
                gateway=GatewayConfig(
                    enabled=True,
                    bind_host="127.0.0.1",
                    port=0,
                    mode="allowlist",
                    allowed_domains=["example.com"],
                    max_requests_per_min_per_node=2,
                ),
            )
            ctrl = MasterController(cfg)

            with tempfile.TemporaryDirectory() as tmp:
                cfg_path = Path(tmp) / "cluster.json"
                save_config(cfg, cfg_path)
                dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=cfg_path, enable_pairing_beacon=False)
                d_port = dash.server_address[1]
                gw_port = dash.gateway_manager.bound_port
                threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
                try:
                    # 3a. Cross-origin browser POST must be blocked by CSRF Origin check (403)!
                    csrf_headers = build_auth_headers(m_tok)
                    csrf_headers["Origin"] = "http://evil.attacker.com"
                    req_csrf = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}/api/network/hardening",
                        data=json.dumps({"enforce_worker_source_ip": True}).encode("utf-8"),
                        headers=csrf_headers,
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as csrf_ctx:
                        urllib.request.urlopen(req_csrf, timeout=3.0)
                    try:
                        self.assertEqual(csrf_ctx.exception.code, 403)
                    finally:
                        csrf_ctx.exception.close()

                    # 3b. Quarantine node1 via API -> proxy immediately returns 403 quarantined!
                    req_q = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}/api/gateway/quarantine",
                        data=json.dumps({"node_id": "node1", "quarantine": True}).encode("utf-8"),
                        headers=build_auth_headers(m_tok),
                        method="POST",
                    )
                    with urllib.request.urlopen(req_q, timeout=3.0) as resp:
                        self.assertTrue(json.loads(resp.read().decode("utf-8"))["quarantined"])

                    pw = derive_proxy_password(w_tok, "node1")
                    auth_b64 = base64.b64encode(f"node1:{pw}".encode("utf-8")).decode("ascii")

                    def _proxy_try() -> bytes:
                        with socket.create_connection(("127.0.0.1", gw_port), timeout=3.0) as s:
                            s.sendall(
                                f"GET http://blocked.invalid/ HTTP/1.1\r\n"
                                f"Host: blocked.invalid\r\n"
                                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
                            )
                            return s.recv(1024)

                    q_resp = _proxy_try()
                    self.assertIn(b"403 Forbidden", q_resp)
                    self.assertIn(b"quarantined", q_resp)

                    # Unblock node1 -> first 2 hit allowlist (403), 3rd hits per-worker rate limit (429)!
                    req_unq = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}/api/gateway/quarantine",
                        data=json.dumps({"node_id": "node1", "quarantine": False}).encode("utf-8"),
                        headers=build_auth_headers(m_tok),
                        method="POST",
                    )
                    with urllib.request.urlopen(req_unq, timeout=3.0) as resp:
                        self.assertFalse(json.loads(resp.read().decode("utf-8"))["quarantined"])
                    self.assertIn(b"403 Forbidden", _proxy_try())
                    self.assertIn(b"403 Forbidden", _proxy_try())
                    self.assertIn(b"429 Too Many Requests", _proxy_try())

                    # 3c. GET /api/network/audit flags unexpected port 5555 & includes AdGuard/nftables guides
                    with urllib.request.urlopen(f"http://127.0.0.1:{d_port}/api/network/audit", timeout=5.0) as resp:
                        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")
                        audit = json.loads(resp.read().decode("utf-8"))
                    self.assertGreater(audit["score"], 0)
                    self.assertFalse(audit["host_info"]["docker_required_for_adguard"])
                    self.assertIn("rewrites:", audit["adguard_snippets"]["rewrites_yaml"])
                    self.assertIn("nft", audit["firewall_guides"]["nftables"])
                    w_surf = next(n for n in audit["nodes"] if n["id"] == "node1")
                    self.assertIn(5555, w_surf["unexpected_ports"])

                    # 3d. 1-Click Security Profile `lockdown` + `standard`
                    req_prof = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}/api/network/profile",
                        data=json.dumps({"profile": "lockdown"}).encode("utf-8"),
                        headers=build_auth_headers(m_tok),
                        method="POST",
                    )
                    with urllib.request.urlopen(req_prof, timeout=5.0) as resp:
                        pres = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(pres["profile"], "lockdown")
                    reloaded = load_config(cfg_path)
                    self.assertTrue(reloaded.dashboard_require_auth)
                    self.assertTrue(reloaded.network.enforce_worker_source_ip)
                    self.assertEqual(reloaded.gateway.mode, "block_all")

                    # 3e. CLI `pc net-audit` flags
                    self.assertEqual(cli_main(["--config", str(cfg_path), "net-audit", "--firewall"]), 0)
                    self.assertEqual(cli_main(["--config", str(cfg_path), "net-audit", "--adguard"]), 0)
                    self.assertEqual(cli_main(["--config", str(cfg_path), "net-audit", "--router"]), 0)
                    self.assertEqual(cli_main(["--config", str(cfg_path), "net-audit", "--profile", "standard"]), 0)
                    self.assertFalse(load_config(cfg_path).gateway.enabled)
                finally:
                    dash.shutdown()
                    dash.server_close()
        finally:
            ev1.set()
            ev2.set()
            srv_blk.shutdown()
            srv_blk.server_close()
            srv_ok.shutdown()
            srv_ok.server_close()


class TestConnectivityAndResourceSharingFixes(unittest.TestCase):
    """Regression tests for connectivity, IPv6, proxy, Service Mesh, scheduler, and firewall fixes."""

    def test_proc_net_tcp_dot127_and_ipv6_loopback_detection(self) -> None:
        import struct
        from phonecluster.telemetry import detect_capabilities

        # Build host-endian hex strings matching real Linux /proc/net/tcp & /proc/net/tcp6
        ip_192_127_hex = f"{struct.unpack('=I', socket.inet_aton('192.168.1.127'))[0]:08X}"
        ip_127_0_0_1_hex = f"{struct.unpack('=I', socket.inet_aton('127.0.0.1'))[0]:08X}"
        v6_loop_words = struct.unpack("=4I", socket.inet_pton(socket.AF_INET6, "::1"))
        v6_loop_hex = "".join(f"{w:08X}" for w in v6_loop_words)
        v6_ula_words = struct.unpack("=4I", socket.inet_pton(socket.AF_INET6, "fd00::1"))
        v6_ula_hex = "".join(f"{w:08X}" for w in v6_ula_words)

        with tempfile.TemporaryDirectory() as tmp:
            t4 = Path(tmp) / "tcp"
            t6 = Path(tmp) / "tcp6"
            t4.write_text(
                "  sl  local_address rem_address st\n"
                f"   0: {ip_192_127_hex}:075B 00000000:0000 0A\n"  # 192.168.1.127:1883 (LAN -> exposed=True!)
                f"   1: {ip_127_0_0_1_hex}:18EB 00000000:0000 0A\n",  # 127.0.0.1:6379 (loopback -> exposed=False)
                encoding="utf-8",
            )
            t6.write_text(
                "  sl  local_address rem_address st\n"
                f"   0: {v6_loop_hex}:1F90 00000000000000000000000000000000:0000 0A\n"  # [::1]:8080 -> False
                f"   1: {v6_ula_hex}:1FBB 00000000000000000000000000000000:0000 0A\n",  # [fd00::1]:8123 -> True
                encoding="utf-8",
            )
            parsed = {p["port"]: p["exposed"] for p in read_listening_tcp_ports(tcp_path=t4, tcp6_path=t6)}
            self.assertTrue(parsed[1883], "192.168.1.127 must NOT be misclassified as loopback!")
            self.assertFalse(parsed[6379])
            self.assertFalse(parsed[8080])
            self.assertTrue(parsed[8123])

        # detect_capabilities uses listening_map directly without dummy TCP connects
        caps = detect_capabilities(listening_map={1883: True, 3632: True, 50052: True})
        self.assertTrue(caps["services"]["mosquitto_1883"])
        self.assertTrue(caps["services"]["distccd_3632"])
        self.assertTrue(caps["services"]["llama_rpc_50052"])
        self.assertFalse(caps["services"]["redis_6379"])

    def test_ipv6_urls_adguard80_distcc_env_and_loopback_service_preference(self) -> None:
        from phonecluster.config import NetworkHardeningConfig
        from phonecluster.netguard import build_firewall_guides
        from phonecluster.routing import build_cluster_dns_hosts, build_cross_tier_env, build_service_registry

        n_v6 = NodeConfig(id="node0", host="fd7a:115c:a1e0::1", role="master", worker_port=8765, ssh_port=8022, tier=2)
        n_lan_loop = NodeConfig(id="node1", host="192.168.1.202", role="worker", worker_port=8765, tier=2)
        n_lan_pub = NodeConfig(id="node2", host="192.168.1.203", role="worker", worker_port=8765, tier=2)
        self.assertEqual(n_v6.base_url, "http://[fd7a:115c:a1e0::1]:8765")

        cfg = ClusterConfig(
            cluster_name="v6-mesh",
            auth_token="tok-v6-mesh-1234567890",
            nodes=[n_v6, n_lan_loop, n_lan_pub],
            network=NetworkHardeningConfig(adguard_url="http://192.168.1.200:3000"),
            custom_services={"ollama": "http://192.168.1.50:11434"},
        )
        snaps = [
            NodeSnapshot(
                node=n_v6,
                online=True,
                health={
                    "ready_for_jobs": True,
                    "cpu_cores": 8,
                    "services": {"adguard_80": True, "distccd_3632": True, "llama_rpc_50052": True},
                    "listening_ports": [
                        {"port": 80, "exposed": True},
                        {"port": 3632, "exposed": True},
                        {"port": 50052, "exposed": True},
                        {"port": 50055, "exposed": True},
                    ],
                },
            ),
            NodeSnapshot(
                node=n_lan_loop,
                online=True,
                health={
                    "ready_for_jobs": True,
                    "cpu_cores": 4,
                    "services": {"mosquitto_1883": True, "distccd_3632": True},
                    "listening_ports": [
                        {"port": 1883, "exposed": False},  # Localhost-only MQTT!
                        {"port": 3632, "exposed": True},
                    ],
                },
            ),
            NodeSnapshot(
                node=n_lan_pub,
                online=True,
                health={
                    "ready_for_jobs": True,
                    "cpu_cores": 4,
                    "services": {"mosquitto_1883": True, "llama_rpc_50052": True},
                    "listening_ports": [
                        {"port": 1883, "exposed": True},  # Externally reachable MQTT!
                        {"port": 50052, "exposed": True},
                        {"port": 50055, "exposed": True},
                    ],
                },
            ),
        ]

        reg = build_service_registry(snaps, cfg)
        ag_entries = [e for e in reg if e["name"] == "adguard"]
        self.assertEqual(len(ag_entries), 1)
        self.assertEqual(ag_entries[0]["url"], "http://[fd7a:115c:a1e0::1]:80")

        env = build_cross_tier_env(snaps, cfg)
        # Must prefer externally reachable node2 over loopback-only node1 for MQTT!
        self.assertEqual(env["PHONECLUSTER_MQTT_HOST"], "192.168.1.203")
        self.assertEqual(env["PHONECLUSTER_ADGUARD_URL"], "http://[fd7a:115c:a1e0::1]:80")
        self.assertIn("[fd7a:115c:a1e0::1]:50052", env["PHONECLUSTER_LLAMA_RPC"])
        self.assertIn("192.168.1.202/4,lzo", env["PHONECLUSTER_DISTCC_HOSTS"])

        hosts = build_cluster_dns_hosts(snaps, cfg)
        self.assertIn("adguard.cluster", hosts)
        self.assertIn("192.168.1.203    mqtt.cluster", hosts)

        ctrl = MasterController(cfg)
        self.assertIn("192.168.1.203:50055", ctrl.build_llama_rpc_arg(port=50055, snapshots=snaps))
        self.assertIn("[fd7a:115c:a1e0::1]:50055", ctrl.build_llama_rpc_arg(port=50055, include_master=True, snapshots=snaps))

        # Firewall rules on non-Termux host MUST always keep port 22 open & handle IPv6 CIDR!
        fw_v4 = build_firewall_guides(cfg, {"lan_subnet": "192.168.1.0/24", "is_termux": False})
        self.assertIn("22,", fw_v4["nftables"])
        self.assertIn("8767", fw_v4["nftables"])
        self.assertIn("port 22", fw_v4["ufw"])
        fw_v6 = build_firewall_guides(cfg, {"lan_subnet": "fd00::/64", "is_termux": False})
        self.assertIn("ip6 saddr fd00::/64", fw_v6["nftables"])

    def test_direct_lan_opener_ignores_broken_host_http_proxy_env(self) -> None:
        import os

        tok = "direct-lan-tok-123456"
        state = WorkerState(
            node_id="node0",
            role="master",
            auth_token=tok,
            safety=SafetyConfig(),
            health_provider=lambda: {
                "node_id": "node0",
                "role": "master",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        srv, _g, ev = create_worker_server("127.0.0.1", 0, state)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="proxy-bypass",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=port)],
        )
        ctrl = MasterController(cfg)

        old_http = os.environ.get("HTTP_PROXY")
        old_http_l = os.environ.get("http_proxy")
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"
        os.environ["http_proxy"] = "http://127.0.0.1:1"
        try:
            snap = ctrl.check_node_health(cfg.get_node("node0"))
            self.assertTrue(snap.online, f"LAN health check was hijacked by HTTP_PROXY: {snap.error}")
            out = ctrl.run_single(JobSpec(index=0, job_id="direct-1", command="echo direct-ok"), target="node0")[0]
            self.assertTrue(out.ok, out.error)
            self.assertIn("direct-ok", out.stdout)
        finally:
            if old_http is None:
                os.environ.pop("HTTP_PROXY", None)
            else:
                os.environ["HTTP_PROXY"] = old_http
            if old_http_l is None:
                os.environ.pop("http_proxy", None)
            else:
                os.environ["http_proxy"] = old_http_l
            ev.set()
            srv.shutdown()
            srv.server_close()

    def test_gateway_chunked_post_half_close_rebind_rollback_and_no_proxy_custom_services(self) -> None:
        from phonecluster.config import NetworkHardeningConfig

        # 1. NO_PROXY includes custom LAN services + AdGuard + brackets IPv6 Master
        cfg_np = ClusterConfig(
            cluster_name="np-test",
            auth_token="tok-np-1234567890",
            nodes=[
                NodeConfig(id="node0", host="fd00::1", role="master"),
                NodeConfig(id="node1", host="192.168.1.202", role="worker", auth_token="w1-tok"),
            ],
            gateway=GatewayConfig(enabled=True, port=8888, inject_proxy_env=True),
            network=NetworkHardeningConfig(adguard_url="http://192.168.1.250:3000"),
            custom_services={"ollama": "http://192.168.1.50:11434"},
        )
        penv = build_worker_proxy_env(cfg_np, cfg_np.get_node("node1"))
        self.assertIn("@[fd00::1]:8888", penv["HTTP_PROXY"])
        self.assertIn("192.168.1.50", penv["NO_PROXY"])
        self.assertIn("192.168.1.250", penv["NO_PROXY"])
        self.assertIn("fd00::1", penv["NO_PROXY"])

        # 2. Live HTTP POST with Transfer-Encoding: chunked + Expect: 100-continue + CONNECT half-close
        class _ChunkedEchoHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                chunks: list[bytes] = []
                if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                    while True:
                        line = self.rfile.readline()
                        sz = int(line.split(b";", 1)[0].strip(), 16)
                        if sz == 0:
                            self.rfile.readline()
                            break
                        chunks.append(self.rfile.read(sz))
                        self.rfile.readline()
                else:
                    n = int(self.headers.get("Content-Length", "0"))
                    chunks.append(self.rfile.read(n))
                body = b"ECHO:" + b"".join(chunks)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                time.sleep(0.08)  # Reply arrives AFTER client half-closes write side!
                body = b"HALFCLOSE_OK"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _ChunkedEchoHandler)
        up_port = upstream.server_address[1]
        threading.Thread(target=upstream.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = create_default_config(master_host="127.0.0.1", worker_hosts=["127.0.0.1"])
        cfg.get_node("node1").auth_token = "chunk-worker-tok"
        cfg.gateway = GatewayConfig(
            enabled=True,
            bind_host="127.0.0.1",
            port=0,
            mode="allowlist",
            allowed_domains=["localhost"],
            allowed_ports=[80, 443, up_port],
            block_private_ips=False,
            max_connections=8,
        )
        mgr = GatewayManager(cfg)
        ok, msg = mgr.start()
        self.assertTrue(ok, msg)
        gw_port = mgr.bound_port
        pw = derive_proxy_password("chunk-worker-tok", "node1")
        auth_b64 = base64.b64encode(f"node1:{pw}".encode("utf-8")).decode("ascii")

        try:
            # 2a. Chunked POST + Expect: 100-continue
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://localhost:{up_port}/upload HTTP/1.1\r\n"
                    f"Host: localhost:{up_port}\r\n"
                    f"Expect: 100-continue\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
                )
                cont = s.recv(1024)
                self.assertIn(b"100 Continue", cont)
                s.sendall(b"5\r\nhello\r\n6\r\n-world\r\n0\r\n\r\n")
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                self.assertIn(b"ECHO:hello-world", resp)

            # 2b. CONNECT tunnel half-close: client sends GET then SHUT_WR before upstream responds
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"CONNECT localhost:{up_port} HTTP/1.1\r\n"
                    f"Host: localhost:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode()
                )
                est = s.recv(1024)
                self.assertIn(b"200 Connection Established", est)
                s.sendall(f"GET /slow HTTP/1.1\r\nHost: localhost:{up_port}\r\nConnection: close\r\n\r\n".encode())
                s.shutdown(socket.SHUT_WR)
                tun_resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    tun_resp += chunk
                self.assertIn(b"HALFCLOSE_OK", tun_resp)

            # 2c. sync_with_config rebinds when max_connections changes
            old_srv = mgr._server
            cfg.gateway.max_connections = 16
            ok2, _ = mgr.sync_with_config()
            self.assertTrue(ok2)
            self.assertIsNot(mgr._server, old_srv)
        finally:
            mgr.stop()
            upstream.shutdown()
            upstream.server_close()

        # 3. Dashboard /api/gateway/settings rolls back cleanly when new port fails to bind
        busy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy_sock.bind(("127.0.0.1", 0))
        busy_sock.listen(1)
        busy_port = busy_sock.getsockname()[1]
        cfg_rb = create_default_config(master_host="127.0.0.1", worker_hosts=[])
        cfg_rb.gateway = GatewayConfig(enabled=True, bind_host="127.0.0.1", port=0, mode="allowlist")
        ctrl_rb = MasterController(cfg_rb)
        dash_rb = DashboardHTTPServer(("127.0.0.1", 0), ctrl_rb, enable_pairing_beacon=False)
        d_port = dash_rb.server_address[1]
        threading.Thread(target=dash_rb.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            self.assertTrue(dash_rb.gateway_manager.is_running)
            req_bad = urllib.request.Request(
                f"http://127.0.0.1:{d_port}/api/gateway/settings",
                data=json.dumps({"enabled": True, "bind_host": "127.0.0.1", "port": busy_port}).encode("utf-8"),
                headers=build_auth_headers(cfg_rb.auth_token),
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req_bad, timeout=5.0)
            try:
                self.assertEqual(ctx.exception.code, 400)
            finally:
                ctx.exception.close()
            # Previous working gateway MUST still be enabled and running after rollback!
            self.assertTrue(ctrl_rb.config.gateway.enabled)
            self.assertTrue(dash_rb.gateway_manager.is_running)
        finally:
            dash_rb.shutdown()
            dash_rb.server_close()
            busy_sock.close()

    def test_scheduler_preexisting_jobs_failover_stale_cwd_cidr_and_pairing_local_ip(self) -> None:
        tok = "sched-fix-tok-1234"
        overheat_w1 = {"hot": False}

        def _make_prov(nid: str):
            def _p():
                hot = overheat_w1["hot"] if nid == "w1" else False
                return {
                    "node_id": nid,
                    "role": "worker",
                    "os_env": "termux",
                    "cpu_cores": 4,
                    "load_1m": 0.1,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 45.0 if hot else 32.0,
                    "overheated": hot,
                    "ready_for_jobs": not hot,
                    "not_ready_reasons": ["overheated"] if hot else [],
                    "tools": {"python3": True},
                    "services": {},
                }
            return _p

        # 1. Worker CIDR / hostname / ::ffff: allowlist check
        st1 = WorkerState(
            node_id="w1",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=1,
            allowed_client_ips={"127.0.0.0/8", "localhost"},
            health_provider=_make_prov("w1"),
        )
        self.assertTrue(st1.is_client_ip_allowed("127.0.0.1"))
        self.assertTrue(st1.is_client_ip_allowed("::ffff:127.0.0.1"))
        self.assertFalse(st1.is_client_ip_allowed("10.0.0.9"))

        st2 = WorkerState(
            node_id="w2",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=1,
            health_provider=_make_prov("w2"),
        )
        srv1, _g1, ev1 = create_worker_server("127.0.0.1", 0, st1)
        srv2, _g2, ev2 = create_worker_server("127.0.0.1", 0, st2)
        p1, p2 = srv1.server_address[1], srv2.server_address[1]
        threading.Thread(target=srv1.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        threading.Thread(target=srv2.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="sched-fix",
            auth_token=tok,
            nodes=[
                NodeConfig(id="w1", host="127.0.0.1", role="worker", worker_port=p1, max_concurrency=1, weight=2.0),
                NodeConfig(id="w2", host="127.0.0.1", role="worker", worker_port=p2, max_concurrency=1, weight=1.0),
            ],
        )
        ctrl = MasterController(cfg)

        try:
            # 2. Pre-existing job occupies w1's 1 slot -> map_jobs with retries=0 MUST route to w2 without 503!
            bg_done = threading.Event()
            def _occupy_w1() -> None:
                ctrl.exec_on_node(
                    cfg.get_node("w1"),
                    JobSpec(index=0, job_id="ext-busy", command="sleep 1.2", timeout_sec=5.0),
                )
                bg_done.set()

            t_bg = threading.Thread(target=_occupy_w1, daemon=True)
            t_bg.start()
            for _ in range(30):
                if len(st1.active_jobs) == 1:
                    break
                time.sleep(0.03)
            self.assertEqual(len(st1.active_jobs), 1)

            batch_outcomes = ctrl.map_jobs(
                [
                    JobSpec(index=0, job_id="b0", command="echo ok0", timeout_sec=5.0),
                    JobSpec(index=1, job_id="b1", command="echo ok1", timeout_sec=5.0),
                ],
                retries=0,
            )
            self.assertTrue(all(o.ok for o in batch_outcomes), [o.to_dict() for o in batch_outcomes])
            self.assertTrue(all(o.node_id == "w2" for o in batch_outcomes))
            t_bg.join(timeout=5.0)

            # 3. run_single(target="best") auto-failover when top-ranked w1 rejects with 503 after /health!
            orig_poll = ctrl.poll_health
            def _poll_then_overheat(tags=None):
                snaps = orig_poll(tags=tags)
                overheat_w1["hot"] = True  # Simulates thermal spike between /health and /exec!
                return snaps

            ctrl.poll_health = _poll_then_overheat  # type: ignore[method-assign]
            try:
                res_fo = ctrl.run_single(JobSpec(index=0, job_id="fo-1", command="echo survived-fo"), target="best")[0]
            finally:
                ctrl.poll_health = orig_poll  # type: ignore[method-assign]
                overheat_w1["hot"] = False
            self.assertTrue(res_fo.ok, res_fo.error)
            self.assertEqual(res_fo.node_id, "w2")
            self.assertEqual(res_fo.attempts, 2)

            # 4. Web Terminal self-heals when tracked cwd no longer exists
            term_res = ctrl.exec_terminal_command(
                command="echo recovered-cwd",
                target="w2",
                cwd="/nonexistent_dir_phonecluster_test_99999",
            )[0]
            self.assertTrue(term_res["ok"], term_res)
            self.assertIn("recovered-cwd", term_res["stdout"])
            self.assertNotEqual(term_res["cwd"], "/nonexistent_dir_phonecluster_test_99999")

            # 5. Pairing with ::ffff: client IP and loopback master_host resolves real local_ip in bundle!
            p_cfg = create_default_config(master_host="127.0.0.1", worker_hosts=[])
            p_cfg.network.enforce_worker_source_ip = True
            pm = PairingManager(p_cfg, config_path=None, pair_port=8080, fail_delay_sec=0.0, enable_beacon=False)
            p_info = pm.open_session(ttl_sec=60, max_devices=1)
            _, hello = pm.public_hello()
            from phonecluster.pairing import compute_proof, compute_shared_secret, generate_dh_keypair
            priv_b, pub_b = generate_dh_keypair()
            pub_b_hex = format(pub_b, "x")
            shared = compute_shared_secret(priv_b, int(hello["dh_pub"], 16))
            ka, ke, km = derive_pairing_keys(p_info["pin"], shared, hello["salt"], hello["session_id"])
            meta = {"worker_port": 8765, "ssh_port": 8022, "os_env": "termux", "cpu_cores": 8, "mem_total_mb": 4096}
            meta_c = json.dumps(meta, sort_keys=True, separators=(",", ":"))
            c_proof = compute_proof(ka, "client", hello["session_id"], hello["dh_pub"], pub_b_hex, meta_c)
            st_code, reply = pm.complete_pairing(
                "::ffff:192.168.1.205",
                {"session_id": hello["session_id"], "dh_pub": pub_b_hex, "client_proof": c_proof, "metadata": meta},
                local_ip="::ffff:192.168.1.200",
            )
            self.assertEqual(st_code, 200, reply)
            aad = f"{hello['session_id']}|{reply['node_id']}|{hello['dh_pub'][:16]}|{pub_b_hex[:16]}"
            bundle = decrypt_bundle(ke, km, reply["encrypted_bundle"], aad=aad)
            self.assertEqual(bundle["node_host"], "192.168.1.205")
            self.assertEqual(bundle["master_host"], "192.168.1.200")
            self.assertIn("192.168.1.200", bundle["network"]["allowed_master_ips"])
            self.assertEqual(p_cfg.get_node(reply["node_id"]).host, "192.168.1.205")
        finally:
            ev1.set()
            ev2.set()
            srv1.shutdown()
            srv1.server_close()
            srv2.shutdown()
            srv2.server_close()

    def test_live_master_to_slave_config_push_and_audit_enforcement(self) -> None:
        from phonecluster.netguard import audit_cluster_network

        m_tok = "master-push-tok-1234"
        w_tok = "worker-push-tok-5678"
        with tempfile.TemporaryDirectory() as tmp:
            master_cfg_path = Path(tmp) / "master.json"
            worker_cfg_path = Path(tmp) / "worker.json"

            # Save scoped worker config on disk first
            w_disk_cfg = ClusterConfig(
                cluster_name="push-test",
                auth_token=w_tok,
                nodes=[NodeConfig(id="node1", host="127.0.0.1", role="worker", max_concurrency=2, auth_token=w_tok)],
                safety=SafetyConfig(max_temp_c=40.0, resume_temp_c=37.0),
            )
            save_config(w_disk_cfg, worker_cfg_path)

            w_state = WorkerState(
                node_id="node1",
                role="worker",
                auth_token=w_tok,
                safety=w_disk_cfg.safety,
                max_concurrency=2,
                config_path=worker_cfg_path,
                health_provider=lambda: {
                    "node_id": "node1",
                    "role": "worker",
                    "os_env": "termux",
                    "cpu_cores": 8,
                    "load_1m": 0.1,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 32.0,
                    "overheated": False,
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "tools": {"python3": True},
                    "services": {},
                },
            )
            w_srv, _g, ev = create_worker_server("127.0.0.1", 0, w_state)
            w_port = w_srv.server_address[1]
            threading.Thread(target=w_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

            m_cfg = ClusterConfig(
                cluster_name="push-test",
                auth_token=m_tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=59996),
                    NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=w_port, max_concurrency=2, auth_token=w_tok),
                ],
            )
            save_config(m_cfg, master_cfg_path)
            ctrl = MasterController(m_cfg)
            dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=master_cfg_path, enable_pairing_beacon=False)
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

            try:
                # 1. If Master enables source-IP lock in config ONLY (before push), audit warns worker isn't enforcing yet!
                m_cfg.network.enforce_worker_source_ip = True
                audit_before = audit_cluster_network(ctrl, gateway_manager=dash.gateway_manager)
                ip_chk_before = next(c for c in audit_before["checks"] if c["name"] == "Worker Master-IP Firewall Allowlist")
                self.assertEqual(ip_chk_before["status"], "warn")
                self.assertIn("node1", ip_chk_before["detail"])

                # 2. Save hardening via Dashboard -> automatically pushes live to worker over HTTP (no SSH)!
                req_h = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/network/hardening",
                    data=json.dumps({"enforce_worker_source_ip": True}).encode("utf-8"),
                    headers=build_auth_headers(m_tok),
                    method="POST",
                )
                with urllib.request.urlopen(req_h, timeout=5.0) as resp:
                    h_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(h_res["pushed"]["ok_count"], 1)
                self.assertTrue(w_state.allowed_client_ips)
                self.assertTrue(w_state.is_client_ip_allowed("127.0.0.1"))
                self.assertFalse(w_state.is_client_ip_allowed("10.99.99.99"))

                # Audit now reports OK because live worker is ACTUALLY enforcing!
                audit_after = audit_cluster_network(ctrl, gateway_manager=dash.gateway_manager)
                ip_chk_after = next(c for c in audit_after["checks"] if c["name"] == "Worker Master-IP Firewall Allowlist")
                self.assertEqual(ip_chk_after["status"], "ok")

                # 3. Updating max_concurrency & safety pushes live AND persists to worker's cluster.json without changing token!
                req_u = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/nodes/update",
                    data=json.dumps({"id": "node1", "max_concurrency": 4}).encode("utf-8"),
                    headers=build_auth_headers(m_tok),
                    method="POST",
                )
                with urllib.request.urlopen(req_u, timeout=5.0) as resp:
                    u_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(u_res["pushed"]["ok_count"], 1)
                self.assertEqual(w_state.max_concurrency, 4)

                req_s = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/settings",
                    data=json.dumps({"max_temp_c": 38.0, "resume_temp_c": 35.0}).encode("utf-8"),
                    headers=build_auth_headers(m_tok),
                    method="POST",
                )
                with urllib.request.urlopen(req_s, timeout=5.0) as resp:
                    s_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(s_res["pushed"]["ok_count"], 1)
                self.assertEqual(w_state.safety.max_temp_c, 38.0)
                self.assertEqual(w_state.thermal_gate.max_temp_c, 38.0)

                # Verify disk persistence on worker & immutable unique token
                w_reloaded = load_config(worker_cfg_path)
                self.assertEqual(w_reloaded.auth_token, w_tok)
                self.assertEqual(w_reloaded.get_node("node1").max_concurrency, 4)
                self.assertEqual(w_reloaded.safety.max_temp_c, 38.0)
                self.assertTrue(w_reloaded.network.enforce_worker_source_ip)

                # 4. Target node_id mismatch protection (guards against DHCP IP swap!)
                bad_push = ctrl.push_config_to_node(
                    NodeConfig(id="wrong_node", host="127.0.0.1", role="worker", worker_port=w_port, auth_token=w_tok)
                )
                self.assertFalse(bad_push["ok"])
                self.assertIn("409", bad_push["error"])

                # CLI `pc push-config --node-id node1` succeeds cleanly
                self.assertEqual(cli_main(["--config", str(master_cfg_path), "push-config", "--node-id", "node1"]), 0)
            finally:
                dash.shutdown()
                dash.server_close()
                ev.set()
                w_srv.shutdown()
                w_srv.server_close()

    def test_cluster_wide_quarantine_isolates_jobs_workloads_and_service_mesh(self) -> None:
        tok = "quar-iso-tok-1234"
        servers = []
        evs = []
        nodes: list[NodeConfig] = []
        for nid, role, has_mpi in [("node0", "master", True), ("node1", "worker", False)]:
            def _make_h(n_id: str, r_name: str, mpi_ok: bool):
                return lambda: {
                    "node_id": n_id,
                    "role": r_name,
                    "os_env": "termux",
                    "cpu_cores": 8,
                    "load_1m": 0.1,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 32.0,
                    "overheated": False,
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "tools": {"python3": True, "distccd": True, "mpirun": mpi_ok},
                    "services": {
                        "distccd_3632": True,
                        "llama_rpc_50052": n_id == "node1",
                        "mosquitto_1883": n_id == "node1",
                    },
                }

            st = WorkerState(node_id=nid, role=role, auth_token=tok, safety=SafetyConfig(), health_provider=_make_h(nid, role, has_mpi))
            srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            servers.append(srv)
            evs.append(ev)
            nodes.append(NodeConfig(id=nid, host="127.0.0.1", role=role, worker_port=srv.server_address[1]))

        cfg = ClusterConfig(
            cluster_name="quar-cluster",
            auth_token=tok,
            nodes=nodes,
            gateway=GatewayConfig(quarantined_nodes=["node1"]),
        )
        ctrl = MasterController(cfg)
        try:
            # 1. Broadcast & pinned run exclude quarantined node1 (unless forced)
            all_outs = ctrl.run_single(JobSpec(index=0, job_id="q-all", command="echo hi"), target="all")
            self.assertEqual([o.node_id for o in all_outs], ["node0"])

            pin_out = ctrl.run_single(JobSpec(index=0, job_id="q-pin", command="echo hi"), target="node1")[0]
            self.assertFalse(pin_out.ok)
            self.assertIn("quarantined", pin_out.error.lower())

            # 2. Shared resources & Service Mesh exclude quarantined node1 completely!
            self.assertEqual(ctrl.build_llama_rpc_arg(), "")
            svc_info = ctrl.get_services_info()
            self.assertFalse(any(e["node_id"] == "node1" for e in svc_info["services"]))
            self.assertNotIn("node1.cluster", svc_info["dns_hosts"])
            self.assertNotIn("PHONECLUSTER_MQTT_HOST", svc_info["env"])

            # 3. OpenMPI hostfile excludes nodes without mpirun even when unquarantined!
            cfg.gateway.quarantined_nodes = []
            mpi_lines = [ln for ln in ctrl.build_mpi_hostfile().splitlines() if ln.strip()]
            self.assertEqual(len(mpi_lines), 1)  # Only node0 has mpirun=True

            # 4. Summary & btop TUI clearly show QUARANTINED badge
            cfg.gateway.quarantined_nodes = ["node1"]
            summary = ctrl.cluster_summary()
            self.assertEqual(summary["nodes_ready"], 1)
            n1 = next(n for n in summary["nodes"] if n["id"] == "node1")
            self.assertTrue(n1["quarantined"])
            self.assertFalse(n1["ready_for_jobs"])
            frame = render_top_frame(summary, ctrl.metrics_history.snapshot(), [], width=100, use_color=False)
            self.assertIn("QUARANTINED", frame)
        finally:
            for ev in evs:
                ev.set()
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_heterogeneous_parallel_map_immediate_spillover_across_tiers(self) -> None:
        tok = "spill-tok-1234"
        servers = []
        evs = []
        nodes: list[NodeConfig] = []
        for nid, tier, pool, max_c in [("t1", 1, "compute", 1), ("t2", 2, "services", 2)]:
            def _mh(n_id: str, t_num: int, p_name: str):
                return lambda: {
                    "node_id": n_id,
                    "role": "worker",
                    "os_env": "termux" if t_num == 1 else "debian-13",
                    "tier": t_num,
                    "pool": p_name,
                    "cpu_cores": 4,
                    "load_1m": 0.1,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "temp_c": 32.0,
                    "overheated": False,
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "tools": {"python3": True},
                    "services": {},
                }

            st = WorkerState(
                node_id=nid,
                role="worker",
                auth_token=tok,
                safety=SafetyConfig(),
                max_concurrency=max_c,
                health_provider=_mh(nid, tier, pool),
            )
            srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            servers.append(srv)
            evs.append(ev)
            nodes.append(NodeConfig(id=nid, host="127.0.0.1", role="worker", worker_port=srv.server_address[1], max_concurrency=max_c, tier=tier, pool=pool))

        ctrl = MasterController(ClusterConfig(cluster_name="spill", auth_token=tok, nodes=nodes))
        try:
            jobs = [
                JobSpec(index=i, job_id=f"sp-{i}", command="sleep 0.3 && echo ok", timeout_sec=5.0)
                for i in range(3)
            ]
            t0 = time.monotonic()
            outs = ctrl.map_jobs(jobs, target="auto", retries=0)
            elapsed = time.monotonic() - t0
            self.assertTrue(all(o.ok for o in outs), [o.to_dict() for o in outs])
            # Job 0 lands on Tier 1 (max_conc=1), Jobs 1 & 2 IMMEDIATELY spill over to Tier 2 in parallel!
            used = {o.node_id for o in outs}
            self.assertEqual(used, {"t1", "t2"})
            self.assertLess(elapsed, 0.85, f"Expected parallel spillover (<0.85s), took {elapsed:.2f}s")
        finally:
            for ev in evs:
                ev.set()
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_worker_oom_bounded_output_duplicate_job_id_cgnat_ssrf_and_doctor_gateway_check(self) -> None:
        # 1. CGNAT / Tailscale (100.64.0.0/10) MUST be blocked by SSRF guard!
        for cgnat in ("100.64.0.1", "100.100.100.100", "::ffff:100.64.0.1", "169.254.169.254"):
            res, why = resolve_and_validate_target(cgnat, 443, block_private_ips=True)
            self.assertIsNone(res, f"SSRF guard failed to block {cgnat}")
            self.assertIn("SSRF", why)

        # 2. Bounded streaming output cap (OOM protection) & duplicate active job_id rejection (409)
        tok = "oom-dup-tok-1234"
        st = WorkerState(
            node_id="w_cap",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "node_id": "w_cap",
                "role": "worker",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        cfg = ClusterConfig(
            cluster_name="cap-test",
            auth_token=tok,
            nodes=[NodeConfig(id="w_cap", host="127.0.0.1", role="worker", worker_port=port, max_concurrency=2)],
            gateway=GatewayConfig(enabled=True, port=59997),  # Unused port -> doctor should warn!
        )
        ctrl = MasterController(cfg)
        try:
            # 2a. 1.2 MB stdout is cleanly capped & annotated with truncation count
            big_cmd = f"{sys.executable} -c \"import sys; sys.stdout.write('A' * 1200000)\""
            big_out = ctrl.run_single(JobSpec(index=0, job_id="big-1", command=big_cmd, timeout_sec=10.0), target="w_cap")[0]
            self.assertTrue(big_out.ok, big_out.error)
            self.assertIn("...[truncated ", big_out.stdout)
            self.assertLess(len(big_out.stdout.encode("utf-8")), 540 * 1024)

            # 2b. Duplicate active job_id returns HTTP 409 instead of overwriting active_jobs!
            slow_t = threading.Thread(
                target=ctrl.exec_on_node,
                args=(cfg.get_node("w_cap"), JobSpec(index=0, job_id="dup-id-1", command="sleep 0.8", timeout_sec=5.0)),
                daemon=True,
            )
            slow_t.start()
            for _ in range(30):
                if "dup-id-1" in st.active_jobs:
                    break
                time.sleep(0.02)
            self.assertIn("dup-id-1", st.active_jobs)
            kind, err_data = ctrl.exec_on_node(
                cfg.get_node("w_cap"),
                JobSpec(index=0, job_id="dup-id-1", command="echo collide", timeout_sec=5.0),
            )
            self.assertEqual(kind, "error")
            self.assertEqual(err_data.get("http_status"), 409)
            self.assertEqual(err_data.get("error"), "duplicate_job_id")
            slow_t.join(timeout=5.0)

            # 3. Doctor warns when gateway.enabled=True but nothing is listening on gateway.port
            with tempfile.TemporaryDirectory() as tmp:
                cp = Path(tmp) / "c.json"
                save_config(cfg, cp)
                doc = run_doctor(cp, check_remote=False)
                gw_chk = next(c for c in doc["checks"] if c["name"] == "Master Network Guard")
                self.assertEqual(gw_chk["status"], "warn")
        finally:
            ev.set()
            srv.shutdown()
            srv.server_close()

    def test_map_jobs_no_starvation_after_busy_poll_and_concurrent_batch_job_ids(self) -> None:
        """Verify map_jobs does not starve a worker caught busy by health poll, and concurrent /api/map batches do not collide."""
        tok = "starve-tok-1234567890"
        st_fast = WorkerState(
            node_id="fast1",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=1,
            health_provider=lambda: {
                "node_id": "fast1",
                "role": "worker",
                "os_env": "termux",
                "tier": 1,
                "pool": "compute",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 8,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        st_slow = WorkerState(
            node_id="slow2",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=1,
            health_provider=lambda: {
                "node_id": "slow2",
                "role": "worker",
                "os_env": "termux",
                "tier": 1,
                "pool": "compute",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        srv1, _g1, ev1 = create_worker_server("127.0.0.1", 0, st_fast)
        srv2, _g2, ev2 = create_worker_server("127.0.0.1", 0, st_slow)
        p1, p2 = srv1.server_address[1], srv2.server_address[1]
        threading.Thread(target=srv1.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        threading.Thread(target=srv2.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="nostarve",
            auth_token=tok,
            nodes=[
                NodeConfig(id="fast1", host="127.0.0.1", role="worker", worker_port=p1, max_concurrency=1, tier=1, pool="compute", weight=2.0),
                NodeConfig(id="slow2", host="127.0.0.1", role="worker", worker_port=p2, max_concurrency=1, tier=1, pool="compute", weight=1.0),
            ],
        )
        ctrl = MasterController(cfg)
        try:
            # Verify healthy_for_scheduling differentiates busy-only from thermal/RAM throttle
            snap_busy = NodeSnapshot(
                node=cfg.nodes[0],
                online=True,
                health={"ready_for_jobs": False, "not_ready_reasons": ["busy (1/1)"], "active_jobs": 1, "max_concurrency": 1},
            )
            snap_hot = NodeSnapshot(
                node=cfg.nodes[0],
                online=True,
                health={"ready_for_jobs": False, "not_ready_reasons": ["overheated (41C >= 40C)", "busy (1/1)"], "active_jobs": 1, "max_concurrency": 1},
            )
            self.assertTrue(snap_busy.healthy_for_scheduling)
            self.assertFalse(snap_hot.healthy_for_scheduling)
            from phonecluster.routing import classify_workload, select_snapshots_for_target

            picked_busy, _ = select_snapshots_for_target(
                [snap_busy, snap_hot],
                target="auto",
                route=classify_workload("echo ok"),
                busy_node_ids=set(),
            )
            self.assertEqual([s.node.id for s in picked_busy], ["fast1"])
            self.assertEqual(score_node(snap_busy, in_flight_local=0), score_node(
                NodeSnapshot(node=cfg.nodes[0], online=True, health={"ready_for_jobs": True, "active_jobs": 0, "max_concurrency": 1}),
                in_flight_local=0,
            ))

            # Poll #1 sees both idle -> dispatches j0 (0.25s) to fast1 and j1 (1.2s) to slow2.
            # At t=0.10s, poll #2 catches fast1 busy (`ready_for_jobs=False, not_ready_reasons=["busy (1/1)"]`).
            # Even with a long 10s interval after poll #2, fast1 MUST immediately take j2 and j3 once j0 finishes!
            jobs = [
                JobSpec(index=0, job_id="ns-0", command="sleep 0.25 && echo j0", timeout_sec=5.0),
                JobSpec(index=1, job_id="ns-1", command="sleep 1.2 && echo j1", timeout_sec=5.0),
                JobSpec(index=2, job_id="ns-2", command="sleep 0.20 && echo j2", timeout_sec=5.0),
                JobSpec(index=3, job_id="ns-3", command="sleep 0.20 && echo j3", timeout_sec=5.0),
            ]
            saw_busy_poll = [False]
            orig_poll = ctrl.poll_health

            def _poll_track_busy(tags: list[str] | None = None) -> list[NodeSnapshot]:
                snaps = orig_poll(tags=tags)
                for s in snaps:
                    if s.node.id == "fast1" and not s.ready_for_jobs and any(
                        str(r).startswith("busy") for r in s.health.get("not_ready_reasons", [])
                    ):
                        saw_busy_poll[0] = True
                return snaps

            ctrl.poll_health = _poll_track_busy  # type: ignore[method-assign]
            t0 = time.monotonic()
            outs = ctrl.map_jobs(jobs, health_refresh_sec=0.12, wait_for_ready_sec=5.0)
            elapsed = time.monotonic() - t0
            self.assertTrue(all(o.ok for o in outs), [o.to_dict() for o in outs])
            self.assertTrue(saw_busy_poll[0], "Expected mid-batch poll to observe fast1 busy")
            self.assertLess(elapsed, 3.0)
            ctrl.poll_health = orig_poll  # type: ignore[method-assign]

            # Also verify two concurrent Web UI /api/map requests NEVER collide on job_id!
            st_fast.max_concurrency = 4
            cfg.nodes[0].max_concurrency = 4
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
            )
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            try:
                results_pair: list[dict[str, Any]] = []

                def _run_web_map() -> None:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}/api/map",
                        data=json.dumps({"mode": "commands", "commands": ["sleep 0.15 && echo a", "sleep 0.15 && echo b"]}).encode("utf-8"),
                        headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=8.0) as resp:
                        results_pair.append(json.loads(resp.read().decode("utf-8")))

                ta = threading.Thread(target=_run_web_map)
                tb = threading.Thread(target=_run_web_map)
                ta.start()
                tb.start()
                ta.join(timeout=8.0)
                tb.join(timeout=8.0)
                self.assertEqual(len(results_pair), 2)
                for res in results_pair:
                    self.assertEqual(res["ok_count"], 2, res)
                    self.assertEqual(res["fail_count"], 0, res)
            finally:
                dash.shutdown()
                dash.server_close()
        finally:
            ev1.set()
            ev2.set()
            srv1.shutdown()
            srv2.shutdown()
            srv1.server_close()
            srv2.server_close()

    def test_gateway_quarantine_disconnects_active_tunnel_and_rejects_smuggling(self) -> None:
        """Verify quarantining severs open CONNECT tunnels immediately, and smuggling/truncated-chunked requests are rejected."""
        import base64
        import socketserver

        received_bodies: list[bytes] = []

        class _EchoTunnelHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(5.0)
                try:
                    while True:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        received_bodies.append(chunk)
                        self.request.sendall(b"ECHO:" + chunk)
                except OSError:
                    pass

        class _ReuseTCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        upstream_srv = _ReuseTCPServer(("127.0.0.1", 0), _EchoTunnelHandler)
        up_port = upstream_srv.server_address[1]
        threading.Thread(target=upstream_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        tok = "gw-smug-tok-1234567890"
        w_tok = "gw-smug-worker-token-987654"
        cfg = ClusterConfig(
            cluster_name="gw-hardening",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1"],
                allowed_ports=[up_port],
                block_private_ips=False,
                idle_timeout_sec=15.0,
            ),
        )
        gw_mgr = GatewayManager(cfg)
        ok, msg = gw_mgr.start()
        self.assertTrue(ok, msg)
        gw_port = gw_mgr.bound_port
        secret = derive_proxy_password(w_tok, "node1")
        auth_b64 = base64.b64encode(f"node1:{secret}".encode("utf-8")).decode("ascii")

        try:
            # 1. Open active CONNECT tunnel, verify echo works, then Quarantine -> tunnel MUST close immediately!
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
                )
                resp_head = s.recv(1024)
                self.assertIn(b"200 Connection Established", resp_head)
                s.sendall(b"ping1")
                self.assertEqual(s.recv(1024), b"ECHO:ping1")

                # Quarantine node1 and sever active sockets!
                cfg.gateway.quarantined_nodes = ["node1"]
                closed_n = gw_mgr.disconnect_node("node1")
                self.assertGreaterEqual(closed_n, 1)

                t0 = time.monotonic()
                s.settimeout(2.0)
                try:
                    tail = s.recv(1024)
                    self.assertEqual(tail, b"")
                except OSError:
                    pass
                self.assertLess(time.monotonic() - t0, 1.5)

            # Unblock node1 for smuggling tests
            cfg.gateway.quarantined_nodes = []

            # 2a. CL + TE simultaneous headers -> 400 Bad Request (request smuggling defense)
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/smug HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Length: 5\r\n\r\n0\r\n\r\n".encode("ascii")
                )
                r1 = s.recv(1024)
                self.assertIn(b"400 Bad Request", r1)

            # 2b. Conflicting duplicate Content-Length -> 400 Bad Request
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/smug2 HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Content-Length: 3\r\n"
                    f"Content-Length: 9\r\n\r\nabc".encode("ascii")
                )
                r2 = s.recv(1024)
                self.assertIn(b"400 Bad Request", r2)

            # 2c. Negative Content-Length -> 400 Bad Request
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/neg HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Content-Length: -5\r\n\r\n".encode("ascii")
                )
                r3 = s.recv(1024)
                self.assertIn(b"400 Bad Request", r3)

            # 2d. Truncated chunked request body fails fast with 502 (does not hang until idle_timeout)
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/trunc HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Transfer-Encoding: chunked\r\n\r\n5\r\nhel".encode("ascii")
                )
                s.shutdown(socket.SHUT_WR)
                t0 = time.monotonic()
                r4 = s.recv(1024)
                self.assertLess(time.monotonic() - t0, 2.0)
                self.assertIn(b"502 Bad Gateway", r4)
        finally:
            gw_mgr.stop()
            upstream_srv.shutdown()
            upstream_srv.server_close()

    def test_worker_input_safety_pipeline_all_failure_node_removal_and_audit_accuracy(self) -> None:
        """Verify job_id path sanitization, NaN timeout rejection, IPv4-mapped allowlist, pipeline all-failure, node removal quarantine cleanup, llama-rpc guard, audit warning, and dashboard XSS fix."""
        tok = "safety-audit-tok-123456"
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "work"
            workdir.mkdir()
            st1 = WorkerState(
                node_id="node0",
                role="master",
                auth_token=tok,
                safety=SafetyConfig(),
                max_concurrency=2,
                workdir=workdir,
                allowed_client_ips={"127.0.0.1", "192.168.1.50"},
                health_provider=lambda: {
                    "node_id": "node0",
                    "role": "master",
                    "os_env": "debian-13",
                    "tier": 1,
                    "pool": "compute",
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "cpu_cores": 4,
                    "mem_total_mb": 512,
                    "mem_available_mb": 256,
                    "tools": {},
                    "services": {},
                },
            )
            st2 = WorkerState(
                node_id="node1",
                role="worker",
                auth_token="worker-tok-unique-123456",
                safety=SafetyConfig(),
                max_concurrency=2,
                workdir=workdir,
                health_provider=lambda: {
                    "node_id": "node1",
                    "role": "worker",
                    "os_env": "termux",
                    "tier": 1,
                    "pool": "compute",
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "cpu_cores": 8,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "tools": {},
                    "services": {},
                },
            )
            # 1. IPv4-mapped IPv6 address matches exact IPv4 allowlist safely
            self.assertTrue(st1.is_client_ip_allowed("::ffff:192.168.1.50"))
            self.assertFalse(st1.is_client_ip_allowed("::ffff:192.168.1.99"))

            srv1, _g1, ev1 = create_worker_server("127.0.0.1", 0, st1)
            srv2, _g2, ev2 = create_worker_server("127.0.0.1", 0, st2)
            p1, p2 = srv1.server_address[1], srv2.server_address[1]
            threading.Thread(target=srv1.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            threading.Thread(target=srv2.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

            cfg_path = Path(tmp) / "cluster.json"
            cfg = ClusterConfig(
                cluster_name="audit-fix",
                auth_token=tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=p1, max_concurrency=2),
                    NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=p2, max_concurrency=2, auth_token="worker-tok-unique-123456"),
                ],
                gateway=GatewayConfig(enabled=False),
            )
            save_config(cfg, cfg_path)
            ctrl = MasterController(cfg)
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0), ctrl, config_path=cfg_path, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
            )
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            try:
                # 2. Path-traversal job_id executes safely inside cwd & NaN timeout returns 400
                trav_spec = JobSpec(
                    index=0,
                    job_id="../../outside/escape",
                    script_content="import os; print(os.getcwd())\n",
                    script_name="ok.py",
                    interpreter=sys.executable,
                    timeout_sec=5.0,
                )
                kind, res_t = ctrl.exec_on_node(cfg.nodes[0], trav_spec)
                self.assertEqual(kind, "ok", res_t)
                self.assertEqual(res_t["returncode"], 0)
                self.assertEqual(Path(res_t["stdout"].strip()).resolve(), workdir.resolve())

                req_nan = urllib.request.Request(
                    f"http://127.0.0.1:{p1}/exec",
                    data=json.dumps({"command": "echo hi", "timeout_sec": "nan"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as exc_ctx:
                    urllib.request.urlopen(req_nan, timeout=3.0)
                try:
                    self.assertEqual(exc_ctx.exception.code, 400)
                finally:
                    exc_ctx.exception.close()

                # 3. run_pipeline with target='all' where node0 succeeds & node1 fails preserves failure returncode & stderr
                pipe = ctrl.run_pipeline(
                    [
                        {
                            "name": "partial-fail",
                            "target": "all",
                            "command": 'if [ "$PHONECLUSTER_NODE_ID" = "node1" ]; then echo boom >&2; exit 7; fi; echo ok',
                        }
                    ]
                )
                self.assertFalse(pipe["ok"])
                step0 = pipe["results"][0]
                self.assertFalse(step0["ok"])
                self.assertEqual(step0["returncode"], 7)
                self.assertIn("boom", step0["stderr"])

                # 4. Quarantine node1 -> llama-rpc-start must NOT fall back to Master!
                def _post_dash(ep: str, payload: dict[str, Any]) -> dict[str, Any]:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{d_port}{ep}",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5.0) as resp:
                        return json.loads(resp.read().decode("utf-8"))

                _post_dash("/api/gateway/quarantine", {"node_id": "node1", "quarantine": True})
                wl_res = _post_dash("/api/workloads/action", {"action": "llama-rpc-start"})
                self.assertEqual(wl_res["results"][0]["node_id"], "none")
                self.assertFalse(wl_res["results"][0]["ok"])

                # 5. Removing a quarantined node clears it from quarantined_nodes so reused ID isn't stuck!
                _post_dash("/api/nodes/remove", {"id": "node1"})
                self.assertNotIn("node1", cfg.gateway.quarantined_nodes)

                # 6. audit_cluster_network warns (not 20/20 ok) if gateway.enabled=True while gateway_manager is stopped
                from phonecluster.dashboard import DASHBOARD_HTML
                from phonecluster.netguard import audit_cluster_network

                cfg.gateway.enabled = True
                rep = audit_cluster_network(ctrl, gateway_manager=dash.gateway_manager)
                gw_chk = next(c for c in rep["checks"] if c["name"] == "Master Network Guard (WAN Filter)")
                self.assertEqual(gw_chk["status"], "warn")

                # 7. Dashboard HTML uses jsArg() and never passes raw esc(...) inside single-quoted onclick attributes
                self.assertIn("function jsArg(", DASHBOARD_HTML)
                self.assertNotRegex(DASHBOARD_HTML, r"onclick=\"[^\"]*\\'\s*\+\s*esc\(")
            finally:
                dash.shutdown()
                dash.server_close()
                ev1.set()
                ev2.set()
                srv1.shutdown()
                srv2.shutdown()
                srv1.server_close()
                srv2.server_close()

    def test_master_defends_against_compromised_worker_redirect_ssrf_oom_and_malformed_json(self) -> None:
        """Verify Master refuses HTTP redirects from workers, caps oversized responses, and survives non-dict JSON."""
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        canary_hits: list[str] = []

        class _CanaryHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_GET(self) -> None:  # noqa: N802
                canary_hits.append(self.path)
                body = b'{"leaked": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        canary = ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
        canary_port = canary.server_address[1]
        threading.Thread(target=canary.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        mode = ["redirect"]

        class _RogueWorkerHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_GET(self) -> None:  # noqa: N802
                if mode[0] == "redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{canary_port}/secret-ssrf")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif mode[0] == "oom":
                    payload = b'{"blob":"' + (b"X" * (400 * 1024)) + b'"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    payload = b'["not", "an", "object"]'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        rogue = ThreadingHTTPServer(("127.0.0.1", 0), _RogueWorkerHandler)
        rogue_port = rogue.server_address[1]
        threading.Thread(target=rogue.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="rogue-defense",
            auth_token="master-tok-1234567890",
            nodes=[
                NodeConfig(id="rogue1", host="127.0.0.1", role="worker", worker_port=rogue_port, auth_token="rogue-tok-1234567890")
            ],
        )
        ctrl = MasterController(cfg)
        try:
            # 1. HTTP 302 redirect from compromised worker MUST NOT be followed to Master localhost!
            mode[0] = "redirect"
            snap_r = ctrl.check_node_health(cfg.nodes[0])
            self.assertFalse(snap_r.online)
            self.assertIn("302", snap_r.error)
            self.assertEqual(canary_hits, [], "Master MUST NOT follow redirects from worker nodes!")

            # 2. Oversized 400 KiB /health response MUST be rejected cleanly by bounded reader!
            mode[0] = "oom"
            snap_o = ctrl.check_node_health(cfg.nodes[0])
            self.assertFalse(snap_o.online)
            self.assertIn("exceeds", snap_o.error)

            # 3. Non-dict JSON (`[...]`) MUST NOT crash cluster_summary() or get_all_jobs()!
            mode[0] = "list"
            summary = ctrl.cluster_summary(record_history=False)
            self.assertEqual(summary["nodes_online"], 0)
            jobs = ctrl.get_all_jobs()
            self.assertEqual(len(jobs), 1)
            self.assertFalse(jobs[0]["online"])
        finally:
            rogue.shutdown()
            rogue.server_close()
            canary.shutdown()
            canary.server_close()

    def test_pairing_parallel_pin_bruteforce_locked_strictly_at_5_attempts_and_csrf_blocked(self) -> None:
        """Verify 15 concurrent wrong-PIN threads can NEVER exceed 5 guesses, oversized DH pub is blocked, and cross-origin CSRF is rejected."""
        tok = "pair-race-tok-12345678"
        cfg = ClusterConfig(
            cluster_name="pair-race",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765)],
        )
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.02
        )
        d_port = dash.server_address[1]
        threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            st = dash.pairing_manager.open_session(ttl_sec=120, max_devices=1)
            self.assertTrue(st["active"])
            _, hello = dash.pairing_manager.public_hello()
            sid = hello["session_id"]

            # 1. Cross-origin browser POST to /api/pair/complete is rejected with 403 CSRF!
            req_csrf = urllib.request.Request(
                f"http://127.0.0.1:{d_port}/api/pair/complete",
                data=json.dumps({"session_id": sid, "dh_pub": "2", "client_proof": "00", "metadata": {}}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Origin": "http://evil.example"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as csrf_exc:
                urllib.request.urlopen(req_csrf, timeout=3.0)
            try:
                self.assertEqual(csrf_exc.exception.code, 403)
            finally:
                csrf_exc.exception.close()

            # 2. Oversized dh_pub (> 600 hex chars) rejected fast with 400!
            code_big, body_big = dash.pairing_manager.complete_pairing(
                "127.0.0.1",
                {"session_id": sid, "dh_pub": "a" * 1000, "client_proof": "00", "metadata": {}},
            )
            self.assertEqual(code_big, 400)
            self.assertIn("Oversized", body_big["error"])

            # 3. 15 concurrent attacker threads with valid DH pubkey & wrong PINs -> STRICTLY 5 evaluations!
            from phonecluster.pairing import generate_dh_keypair

            _priv, pub = generate_dh_keypair()
            pub_hex = format(pub, "x")
            barrier = threading.Barrier(15)
            responses: list[tuple[int, dict[str, Any]]] = []
            resp_lock = threading.Lock()

            def _attack(i: int) -> None:
                barrier.wait()
                res = dash.pairing_manager.complete_pairing(
                    "127.0.0.1",
                    {
                        "session_id": sid,
                        "dh_pub": pub_hex,
                        "client_proof": f"{i:064x}",
                        "metadata": {"worker_port": 8765, "ssh_port": 8022},
                    },
                )
                with resp_lock:
                    responses.append(res)

            threads = [threading.Thread(target=_attack, args=(i,)) for i in range(15)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15.0)

            self.assertEqual(len(responses), 15)
            # Exactly 5 attempts evaluated ("attempts_left" present -> 4, 3, 2, 1, 0), remaining 10 hit closed window!
            evaluated = [r[1] for r in responses if "attempts_left" in r[1]]
            closed_rejects = [r[1] for r in responses if "closed" in str(r[1].get("error", "")).lower() and "attempts_left" not in r[1]]
            self.assertEqual(len(evaluated), 5, f"Expected strictly 5 PIN evaluations, got {len(evaluated)}: {responses}")
            self.assertEqual(sorted(e["attempts_left"] for e in evaluated), [0, 1, 2, 3, 4])
            self.assertEqual(len(closed_rejects), 10)
            self.assertFalse(dash.pairing_manager.admin_status()["active"])
        finally:
            dash.shutdown()
            dash.server_close()

    def test_proxy_domain_fronting_header_injection_truncated_body_and_security_headers(self) -> None:
        """Verify proxy blocks Host domain-fronting, whitespace-before-colon smuggling, truncated POST body, and dashboard enforces CSP + strict CIDR/webhook validation."""
        import base64
        import socketserver

        class _SilentUpstream(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(3.0)
                try:
                    while self.request.recv(4096):
                        pass
                except OSError:
                    pass

        class _ReuseServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up_srv = _ReuseServer(("127.0.0.1", 0), _SilentUpstream)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        tok = "edge-sec-tok-1234567890"
        w_tok = "edge-worker-tok-987654321"
        cfg = ClusterConfig(
            cluster_name="edge-sec",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1"],
                allowed_ports=[up_port],
                block_private_ips=False,
                idle_timeout_sec=10.0,
            ),
        )
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
        )
        d_port = dash.server_address[1]
        gw_port = dash.gateway_manager.bound_port
        threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        secret = derive_proxy_password(w_tok, "node1")
        auth_b64 = base64.b64encode(f"node1:{secret}".encode("utf-8")).decode("ascii")
        try:
            # 1. Domain fronting: Host header != target URL host -> 400 Bad Request
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"GET http://127.0.0.1:{up_port}/front HTTP/1.1\r\n"
                    f"Host: attacker-c2.example.com\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
                )
                r_front = s.recv(1024)
                self.assertIn(b"400 Bad Request", r_front)
                self.assertIn(b"Host header", r_front)

            # 2. RFC 9112 space before colon in header name -> 400 Bad Request
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/ws HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n".encode("ascii")
                )
                r_ws = s.recv(1024)
                self.assertIn(b"400 Bad Request", r_ws)

            # 3. Truncated fixed-length Content-Length body fails fast with 502 (does not hang 10s!)
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/short HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Content-Length: 500\r\n\r\nhello".encode("ascii")
                )
                s.shutdown(socket.SHUT_WR)
                t0 = time.monotonic()
                r_short = s.recv(1024)
                self.assertLess(time.monotonic() - t0, 2.0)
                self.assertIn(b"502 Bad Gateway", r_short)

            # 4. Dashboard HTML sends Content-Security-Policy & security headers
            with urllib.request.urlopen(f"http://127.0.0.1:{d_port}/", timeout=3.0) as resp:
                self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

            # 5. Invalid CIDR in hardening & distcc-start rejected with 400; non-http webhook rejected!
            for ep, payload in (
                ("/api/network/hardening", {"lan_subnet": "192.168.1.0/99; rm -rf /"}),
                ("/api/workloads/action", {"action": "distcc-start", "cidr": "not-a-cidr; id"}),
            ):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}{ep}",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_ctx:
                    urllib.request.urlopen(req, timeout=3.0)
                try:
                    self.assertEqual(bad_ctx.exception.code, 400)
                finally:
                    bad_ctx.exception.close()

            with self.assertRaises(ValueError):
                SafetyConfig.from_dict({"battery_webhook_url": "file:///etc/passwd"})
        finally:
            dash.shutdown()
            dash.server_close()
            up_srv.shutdown()
            up_srv.server_close()

    def test_hmac_signed_master_worker_auth_replay_tamper_expiry_and_strict_mode(self) -> None:
        """Verify Master signs requests with HMAC-SHA256 (zero raw token on wire), workers reject replay/tamper/expired, lockdown disables Bearer, and server banners hide Python version."""
        from phonecluster.auth import build_signed_auth_headers

        m_tok = "master-hmac-secret-123456"
        w_tok = "worker-hmac-secret-654321"
        with tempfile.TemporaryDirectory() as tmp:
            w_cfg_path = Path(tmp) / "worker.json"
            m_cfg_path = Path(tmp) / "master.json"
            st = WorkerState(
                node_id="node1",
                role="worker",
                auth_token=w_tok,
                safety=SafetyConfig(),
                max_concurrency=2,
                config_path=w_cfg_path,
                health_provider=lambda: {
                    "node_id": "node1",
                    "role": "worker",
                    "os_env": "termux",
                    "tier": 1,
                    "pool": "compute",
                    "ready_for_jobs": True,
                    "not_ready_reasons": [],
                    "cpu_cores": 8,
                    "mem_total_mb": 4096,
                    "mem_available_mb": 2048,
                    "tools": {},
                    "services": {},
                },
            )
            srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
            w_port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

            save_config(
                ClusterConfig(
                    cluster_name="hmac-test",
                    auth_token=w_tok,
                    nodes=[NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=w_port, auth_token=w_tok)],
                ),
                w_cfg_path,
            )
            m_cfg = ClusterConfig(
                cluster_name="hmac-test",
                auth_token=m_tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=59994),
                    NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=w_port, auth_token=w_tok),
                ],
            )
            save_config(m_cfg, m_cfg_path)
            ctrl = MasterController(m_cfg)
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0), ctrl, config_path=m_cfg_path, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
            )
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            try:
                # 1. Master headers use PC-HMAC-SHA256 and NEVER contain the raw worker token!
                hdrs = ctrl._headers_for(m_cfg.get_node("node1"), "POST", "/exec", b'{"command":"echo ok"}')
                self.assertTrue(hdrs["Authorization"].startswith("PC-HMAC-SHA256 "))
                self.assertNotIn(w_tok, hdrs["Authorization"])

                # 2. Signed POST /exec succeeds once, then EXACT REPLAY is rejected with 401!
                exec_body = json.dumps({"job_id": "hmac-j1", "command": "echo signed-ok"}).encode("utf-8")
                signed_hdrs = build_signed_auth_headers(w_tok, "POST", "/exec", exec_body)
                req1 = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/exec", data=exec_body, headers=signed_hdrs, method="POST"
                )
                with urllib.request.urlopen(req1, timeout=5.0) as resp:
                    self.assertEqual(resp.headers.get("Server"), "PhoneCluster")
                    d1 = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(d1["stdout"].strip(), "signed-ok")

                # Exact replay of captured signed request -> 401!
                req_replay = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/exec", data=exec_body, headers=signed_hdrs, method="POST"
                )
                with self.assertRaises(urllib.error.HTTPError) as rep_exc:
                    urllib.request.urlopen(req_replay, timeout=5.0)
                try:
                    self.assertEqual(rep_exc.exception.code, 401)
                    self.assertIn("replayed", rep_exc.exception.read().decode("utf-8").lower())
                finally:
                    rep_exc.exception.close()

                # 3. Body tampering (different command with valid header) -> 401!
                tampered_body = json.dumps({"job_id": "hmac-j2", "command": "echo pwned"}).encode("utf-8")
                fresh_for_orig = build_signed_auth_headers(w_tok, "POST", "/exec", exec_body)
                req_tamp = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/exec", data=tampered_body, headers=fresh_for_orig, method="POST"
                )
                with self.assertRaises(urllib.error.HTTPError) as tamp_exc:
                    urllib.request.urlopen(req_tamp, timeout=5.0)
                try:
                    self.assertEqual(tamp_exc.exception.code, 401)
                finally:
                    tamp_exc.exception.close()

                # 4. Expired timestamp (> 60s old) -> 401!
                expired_hdrs = build_signed_auth_headers(
                    w_tok, "GET", "/health", b"", ts=int(time.time()) - 180
                )
                req_exp = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/health", headers=expired_hdrs, method="GET"
                )
                with self.assertRaises(urllib.error.HTTPError) as exp_exc:
                    urllib.request.urlopen(req_exp, timeout=5.0)
                try:
                    self.assertEqual(exp_exc.exception.code, 401)
                finally:
                    exp_exc.exception.close()

                # 5. Lockdown / strict HMAC-only pushed live -> legacy raw Bearer is REJECTED while Master still works!
                req_hard = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/network/hardening",
                    data=json.dumps({"require_signed_requests": True}).encode("utf-8"),
                    headers=build_auth_headers(m_tok),
                    method="POST",
                )
                with urllib.request.urlopen(req_hard, timeout=5.0) as r_h:
                    self.assertEqual(r_h.headers.get("Server"), "PhoneCluster")
                    h_res = json.loads(r_h.read().decode("utf-8"))
                    self.assertTrue(h_res["require_signed_requests"])
                self.assertTrue(st.require_signed_requests)
                self.assertTrue(load_config(w_cfg_path).network.require_signed_requests)

                # Legacy Bearer rejected with 401 now!
                req_bearer = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/health", headers=build_auth_headers(w_tok), method="GET"
                )
                with self.assertRaises(urllib.error.HTTPError) as b_exc:
                    urllib.request.urlopen(req_bearer, timeout=5.0)
                try:
                    self.assertEqual(b_exc.exception.code, 401)
                finally:
                    b_exc.exception.close()

                # MasterController (signed HMAC) still runs jobs seamlessly!
                out = ctrl.run_single(JobSpec(index=0, job_id="strict-ok", command="echo strict-hmac"), target="node1")[0]
                self.assertTrue(out.ok, out.error)
                self.assertEqual(out.stdout.strip(), "strict-hmac")
            finally:
                dash.shutdown()
                dash.server_close()
                ev.set()
                srv.shutdown()
                srv.server_close()

    def test_nat64_6to4_teredo_scoped_ipv6_ssrf_and_ssh_node_injection_blocked(self) -> None:
        """Verify NAT64/6to4/Teredo/zone-ID SSRF bypasses are blocked and SSH/node/host injection is rejected everywhere."""
        from phonecluster.gateway import _is_disallowed_ip
        from phonecluster.pairing import compute_proof, compute_shared_secret, derive_pairing_keys, generate_dh_keypair

        # 1. NAT64 (64:ff9b::/96), 6to4, Teredo, scoped IPv6 %zone SSRF vectors
        for bad_ip in (
            "64:ff9b::127.0.0.1",
            "64:ff9b::192.168.1.1",
            "64:ff9b::100.64.0.1",
            "64:ff9b::169.254.169.254",
            "2002:7f00:0001::1",
            "2002:c0a8:0101::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "fe80::1%eth0",
        ):
            self.assertTrue(_is_disallowed_ip(bad_ip), f"Expected SSRF guard to block {bad_ip}")
        self.assertFalse(_is_disallowed_ip("64:ff9b::1.1.1.1"))
        self.assertFalse(_is_disallowed_ip("2606:4700:4700::1111"))

        # 2. NodeConfig.from_dict rejects SSH option injection, colon/path node IDs, and host injection
        for bad_node in (
            {"id": "node1", "host": "192.168.1.20", "ssh_user": "-oProxyCommand=id"},
            {"id": "node1", "host": "-oProxyCommand=id"},
            {"id": "node1", "host": "192.168.1.20\n127.0.0.1 evil.com"},
            {"id": "node:1", "host": "192.168.1.20"},
            {"id": "../evil", "host": "192.168.1.20"},
            {"id": "node1", "host": "192.168.1.20", "pool": "bad pool!"},
        ):
            with self.assertRaises(ValueError, msg=f"Should reject {bad_node}"):
                NodeConfig.from_dict(bad_node)

        # 3. Dashboard /api/nodes/add & Pairing complete_pairing reject SSH option injection with 400
        tok = "inj-test-tok-1234567890"
        cfg = ClusterConfig(
            cluster_name="inj-test",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765)],
        )
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
        )
        d_port = dash.server_address[1]
        threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            for payload in (
                {"host": "192.168.1.50", "ssh_user": "-oProxyCommand=id"},
                {"id": "bad:id", "host": "192.168.1.50"},
                {"host": "evil@127.0.0.1"},
            ):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/nodes/add",
                    data=json.dumps(payload).encode("utf-8"),
                    headers=build_auth_headers(tok),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as exc_ctx:
                    urllib.request.urlopen(req, timeout=3.0)
                try:
                    self.assertEqual(exc_ctx.exception.code, 400)
                finally:
                    exc_ctx.exception.close()

            # Pairing with valid PIN but malicious ssh_user="-oProxyCommand=id" -> 400 Bad Request!
            p_info = dash.pairing_manager.open_session(ttl_sec=120, max_devices=1)
            _, hello = dash.pairing_manager.public_hello()
            priv_b, pub_b = generate_dh_keypair()
            pub_b_hex = format(pub_b, "x")
            shared = compute_shared_secret(priv_b, int(hello["dh_pub"], 16))
            k_auth, _ke, _km = derive_pairing_keys(p_info["pin"], shared, hello["salt"], hello["session_id"])
            bad_meta = {"worker_port": 8765, "ssh_port": 8022, "ssh_user": "-oProxyCommand=id"}
            meta_can = json.dumps(bad_meta, sort_keys=True, separators=(",", ":"))
            proof = compute_proof(k_auth, "client", hello["session_id"], hello["dh_pub"], pub_b_hex, meta_can)
            status, reply = dash.pairing_manager.complete_pairing(
                "192.168.1.99",
                {"session_id": hello["session_id"], "dh_pub": pub_b_hex, "client_proof": proof, "metadata": bad_meta},
            )
            self.assertEqual(status, 400)
            self.assertIn("ssh_user", reply["error"])
        finally:
            dash.shutdown()
            dash.server_close()

    def test_strict_http_smuggling_defense_chunk_framing_connect_ipv6_and_audit_sanitization(self) -> None:
        """Verify RFC-strict Content-Length/chunk-size parsing, Host/TE/CONNECT checks, truncated-body rejection, and ANSI log sanitization."""
        import base64
        import socketserver
        from phonecluster.pairing import PairingManager, StandalonePairingServer

        class _OkHttpHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(0.4)
                try:
                    buf = b""
                    while len(buf) < 8192:
                        try:
                            chunk = self.request.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        buf += chunk
                        if b"0\r\n\r\n" in buf:
                            break
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                except OSError:
                    pass

        class _ReuseTCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up_srv = _ReuseTCP(("127.0.0.1", 0), _OkHttpHandler)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        tok = "pass5-smug-tok-12345678"
        w_tok = "pass5-worker-tok-87654321"
        st = WorkerState(
            node_id="node1",
            role="worker",
            auth_token=w_tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "node_id": "node1",
                "role": "worker",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        w_srv, _g, w_ev = create_worker_server("127.0.0.1", 0, st)
        w_port = w_srv.server_address[1]
        threading.Thread(target=w_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="smug-strict",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=w_port, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1"],
                allowed_ports=[up_port],
                block_private_ips=False,
                idle_timeout_sec=10.0,
            ),
        )
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
        )
        d_port = dash.server_address[1]
        threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        gw_port = dash.gateway_manager.bound_port

        pm = PairingManager(config=cfg, pair_port=0, enable_beacon=False, fail_delay_sec=0.0)
        p_srv = StandalonePairingServer(("127.0.0.1", 0), pm)
        p_port = p_srv.server_address[1]
        threading.Thread(target=p_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        secret = derive_proxy_password(w_tok, "node1")
        auth_b64 = base64.b64encode(f"node1:{secret}".encode("utf-8")).decode("ascii")

        def _raw_exchange(port: int, payload: bytes, half_close: bool = False) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=4.0) as s:
                s.sendall(payload)
                if half_close:
                    s.shutdown(socket.SHUT_WR)
                s.settimeout(3.0)
                return s.recv(4096)

        try:
            # 1. Proxy rejects Python int() smuggling (1_0, +5), duplicate CL, bad TE, duplicate Host, unbracketed IPv6 CONNECT
            bad_proxy_cases: list[tuple[bytes, bytes, str]] = [
                (
                    f"POST http://127.0.0.1:{up_port}/a HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nContent-Length: 1_0\r\n\r\n0123456789".encode("ascii"),
                    b"400 Bad Request",
                    "underscore CL",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/b HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nContent-Length: +2\r\n\r\nhi".encode("ascii"),
                    b"400 Bad Request",
                    "plus CL",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/c HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi".encode("ascii"),
                    b"400 Bad Request",
                    "duplicate identical CL",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/d HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n".encode("ascii"),
                    b"501 Not Implemented",
                    "xchunked TE",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/e HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n".encode("ascii"),
                    b"501 Not Implemented",
                    "compound TE",
                ),
                (
                    f"GET http://127.0.0.1:{up_port}/f HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Host: evil.example\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "duplicate Host",
                ),
                (
                    f"CONNECT 2001:db8::1 HTTP/1.1\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "unbracketed IPv6 CONNECT",
                ),
                (
                    f"CONNECT 127.0.0.1:4_43 HTTP/1.1\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "underscore CONNECT port",
                ),
                (
                    f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: evil.example:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "CONNECT Host mismatch",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/hex HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "0x hex chunk size",
                ),
                (
                    f"POST http://127.0.0.1:{up_port}/crlf HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n".encode("ascii"),
                    b"400 Bad Request",
                    "missing chunk CRLF",
                ),
            ]
            for raw_req, expected, desc in bad_proxy_cases:
                resp = _raw_exchange(gw_port, raw_req)
                self.assertIn(expected, resp, f"Proxy failed case '{desc}': {resp!r}")

            # 2. Proxy audit log strips ANSI escape / control chars from untrusted request targets
            _raw_exchange(gw_port, b"GET http://\x1b[31mevil\x07.test/ HTTP/1.1\r\nHost: test\r\n\r\n")
            evs = dash.gateway_manager.status()["events"]
            self.assertTrue(evs)
            self.assertNotIn("\x1b", evs[0]["host"])
            self.assertNotIn("\x07", evs[0]["host"])

            # 3. Worker, Dashboard, and Standalone Pairing reject 1_0 / +5 / duplicate CL / TE / truncated bodies
            for port, path, auth_hdr in (
                (w_port, "/exec", f"Authorization: Bearer {w_tok}\r\n"),
                (d_port, "/api/exec", f"Authorization: Bearer {tok}\r\n"),
                (p_port, "/api/pair/complete", ""),
            ):
                r_under = _raw_exchange(
                    port,
                    f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Content-Length: 1_0\r\n\r\n0123456789".encode("ascii"),
                )
                self.assertIn(b"400", r_under, f"{path} accepted underscore CL: {r_under!r}")

                r_plus = _raw_exchange(
                    port,
                    f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Content-Length: +2\r\n\r\n{{}}".encode("ascii"),
                )
                self.assertIn(b"400", r_plus, f"{path} accepted +CL: {r_plus!r}")

                r_dup = _raw_exchange(
                    port,
                    f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Content-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}".encode("ascii"),
                )
                self.assertIn(b"400", r_dup, f"{path} accepted duplicate CL: {r_dup!r}")

                r_te = _raw_exchange(
                    port,
                    f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode("ascii"),
                )
                self.assertIn(b"501", r_te, f"{path} accepted TE: {r_te!r}")

                r_trunc = _raw_exchange(
                    port,
                    f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_hdr}Content-Length: 40\r\n\r\n{{}}".encode("ascii"),
                    half_close=True,
                )
                self.assertIn(b"400", r_trunc, f"{path} accepted truncated body: {r_trunc!r}")
        finally:
            p_srv.shutdown()
            p_srv.server_close()
            dash.shutdown()
            dash.server_close()
            w_ev.set()
            w_srv.shutdown()
            w_srv.server_close()
            up_srv.shutdown()
            up_srv.server_close()

    def test_csrf_dns_rebinding_udp_poisoning_and_config_domain_validation(self) -> None:
        """Verify Worker/Dashboard/Pairing CSRF & CORP headers, strict domain/config validation, and UDP poison resilience."""
        from phonecluster.config import NetworkHardeningConfig, validate_domain_pattern
        from phonecluster.discovery import REPLY_TYPE, discover_lan_nodes
        from phonecluster.pairing import PAIR_BEACON_TYPE, PairingManager, StandalonePairingServer, discover_pairing_masters

        # 1. Domain & config validation rejects wildcards '*', inf/NaN idle timeout, bad CIDR, file:// adguard_url
        for bad_dom in ("*", "*.", "*.bad_domain/x", "http://evil.com", "evil.com\x00", "-bad.com"):
            with self.assertRaises(ValueError, msg=f"Should reject domain {bad_dom!r}"):
                validate_domain_pattern(bad_dom)
        self.assertEqual(validate_domain_pattern("*.GitHub.com."), "*.github.com")
        self.assertEqual(validate_domain_pattern("127.0.0.1"), "127.0.0.1")

        with self.assertRaises(ValueError):
            GatewayConfig.from_dict({"idle_timeout_sec": float("inf")})
        with self.assertRaises(ValueError):
            GatewayConfig.from_dict({"idle_timeout_sec": float("nan")})
        with self.assertRaises(ValueError):
            GatewayConfig.from_dict({"allowed_domains": ["*"]})
        with self.assertRaises(ValueError):
            NetworkHardeningConfig.from_dict({"lan_subnet": "not-a-cidr"})
        with self.assertRaises(ValueError):
            NetworkHardeningConfig.from_dict({"adguard_url": "file:///etc/passwd"})

        # 2. Worker rejects browser Origin / Sec-Fetch-Site: cross-site (DNS-rebinding/CSRF), sets CORP header
        tok = "csrf-pass5-tok-12345678"
        st = WorkerState(
            node_id="w_csrf",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "node_id": "w_csrf",
                "role": "worker",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        w_srv, _g, w_ev = create_worker_server("127.0.0.1", 0, st)
        w_port = w_srv.server_address[1]
        threading.Thread(target=w_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="csrf-test",
            auth_token=tok,
            nodes=[NodeConfig(id="w_csrf", host="127.0.0.1", role="master", worker_port=w_port)],
        )
        ctrl = MasterController(cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
        )
        d_port = dash.server_address[1]
        threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        pm = PairingManager(config=cfg, pair_port=0, enable_beacon=False, fail_delay_sec=0.0)
        p_srv = StandalonePairingServer(("127.0.0.1", 0), pm)
        p_port = p_srv.server_address[1]
        threading.Thread(target=p_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        try:
            # Worker normal GET returns CORP header
            req_ok = urllib.request.Request(f"http://127.0.0.1:{w_port}/health", headers=build_auth_headers(tok))
            with urllib.request.urlopen(req_ok, timeout=3.0) as resp_ok:
                self.assertEqual(resp_ok.headers.get("Cross-Origin-Resource-Policy"), "same-origin")

            # Worker rejects Origin or Sec-Fetch-Site: cross-site with 403
            for bad_hdrs in (
                {**build_auth_headers(tok), "Origin": "http://evil.example"},
                {**build_auth_headers(tok), "Sec-Fetch-Site": "cross-site"},
            ):
                req_bad = urllib.request.Request(f"http://127.0.0.1:{w_port}/health", headers=bad_hdrs)
                with self.assertRaises(urllib.error.HTTPError) as exc_ctx:
                    urllib.request.urlopen(req_bad, timeout=3.0)
                try:
                    self.assertEqual(exc_ctx.exception.code, 403)
                finally:
                    exc_ctx.exception.close()

            # Dashboard /api/status returns CORP header
            with urllib.request.urlopen(f"http://127.0.0.1:{d_port}/api/status", timeout=3.0) as d_resp:
                self.assertEqual(d_resp.headers.get("Cross-Origin-Resource-Policy"), "same-origin")

            # Dashboard rejects Sec-Fetch-Site: cross-site, Origin: null, cross-origin Referer
            for bad_hdrs in (
                {**build_auth_headers(tok), "Sec-Fetch-Site": "cross-site"},
                {**build_auth_headers(tok), "Origin": "null"},
                {**build_auth_headers(tok), "Referer": "http://evil.example/attack.html"},
            ):
                req_d = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}/api/exec",
                    data=b'{"command":"echo nope"}',
                    headers=bad_hdrs,
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as exc_ctx:
                    urllib.request.urlopen(req_d, timeout=3.0)
                try:
                    self.assertEqual(exc_ctx.exception.code, 403)
                finally:
                    exc_ctx.exception.close()

            # Dashboard /api/gateway/allow-domain rejects wildcard "*"
            req_dom = urllib.request.Request(
                f"http://127.0.0.1:{d_port}/api/gateway/allow-domain",
                data=b'{"domain":"*"}',
                headers=build_auth_headers(tok),
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as dom_exc:
                urllib.request.urlopen(req_dom, timeout=3.0)
            try:
                self.assertEqual(dom_exc.exception.code, 400)
            finally:
                dom_exc.exception.close()

            # Standalone pairing rejects Referer & Sec-Fetch-Site: cross-site
            for bad_hdrs in (
                {"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
                {"Content-Type": "application/json", "Referer": "http://evil.example/"},
            ):
                req_p = urllib.request.Request(
                    f"http://127.0.0.1:{p_port}/api/pair/complete",
                    data=b"{}",
                    headers=bad_hdrs,
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as p_exc:
                    urllib.request.urlopen(req_p, timeout=3.0)
                try:
                    self.assertEqual(p_exc.exception.code, 403)
                finally:
                    p_exc.exception.close()

            # 3. Malformed UDP poison packets NEVER crash discover_lan_nodes() or discover_pairing_masters()
            udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_srv.bind(("127.0.0.1", 0))
            udp_port = udp_srv.getsockname()[1]
            udp_srv.settimeout(0.2)
            stop_udp = threading.Event()

            def _poison_responder() -> None:
                while not stop_udp.is_set():
                    try:
                        raw, addr = udp_srv.recvfrom(2048)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    msg = json.loads(raw.decode("utf-8"))
                    if msg.get("type") == "phonecluster_discover_v1":
                        for pkt in (
                            {"type": REPLY_TYPE, "worker_port": "crash_me"},
                            {"type": REPLY_TYPE, "worker_port": 99999},
                            {"type": REPLY_TYPE, "worker_port": 8765, "ssh_port": "bad"},
                            {"type": REPLY_TYPE, "node_id": "ok\x1bnode", "worker_port": 8765, "ssh_port": 8022, "cpu_cores": 8, "mem_total_mb": 4096},
                        ):
                            udp_srv.sendto(json.dumps(pkt).encode("utf-8"), addr)
                    else:
                        for pkt in (
                            {"type": PAIR_BEACON_TYPE, "pair_port": None},
                            {"type": PAIR_BEACON_TYPE, "pair_port": -1},
                            {"type": PAIR_BEACON_TYPE, "pair_port": 8767, "expires_in_sec": "bad"},
                            {"type": PAIR_BEACON_TYPE, "pair_port": 8767, "cluster_name": "good\x07c", "session_id": "s1", "fingerprint": "fp", "expires_in_sec": 60},
                        ):
                            udp_srv.sendto(json.dumps(pkt).encode("utf-8"), addr)

            t_udp = threading.Thread(target=_poison_responder, daemon=True)
            t_udp.start()
            try:
                nodes_found = discover_lan_nodes(timeout_sec=0.4, discovery_port=udp_port, targets=["127.0.0.1"])
                self.assertEqual(len(nodes_found), 1)
                self.assertEqual(nodes_found[0]["node_id"], "oknode")

                masters_found = discover_pairing_masters(timeout_sec=0.4, discovery_port=udp_port, targets=["127.0.0.1"])
                self.assertEqual(len(masters_found), 1)
                self.assertEqual(masters_found[0]["cluster_name"], "goodc")
            finally:
                stop_udp.set()
                udp_srv.close()
                t_udp.join(timeout=2.0)
        finally:
            p_srv.shutdown()
            p_srv.server_close()
            dash.shutdown()
            dash.server_close()
            w_ev.set()
            w_srv.shutdown()
            w_srv.server_close()

    def test_thermal_hottest_cpu_zone_grandchild_sigkill_empty_script_scheduler_and_terminal_backslash(self) -> None:
        """Verify hottest CPU thermal zone selection, SIGTERM-ignoring grandchild SIGKILL, empty script_content fallback, terminal backslash/CRLF safety, and map_jobs duplicate-index/fast-fail."""
        from phonecluster.telemetry import read_thermal_zone_temp

        # 1. read_thermal_zone_temp returns HOTTEST CPU zone (47.0C), not first cool zone (28.0C)
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            z0 = tdir / "thermal_zone0"
            z1 = tdir / "thermal_zone1"
            z2 = tdir / "thermal_zone2"
            for z in (z0, z1, z2):
                z.mkdir()
            (z0 / "type").write_text("cpu-0-0\n", encoding="utf-8")
            (z0 / "temp").write_text("28000\n", encoding="utf-8")
            (z1 / "type").write_text("cpu-1-0\n", encoding="utf-8")
            (z1 / "temp").write_text("47000\n", encoding="utf-8")
            (z2 / "type").write_text("battery-skin\n", encoding="utf-8")
            (z2 / "temp").write_text("55000\n", encoding="utf-8")
            self.assertEqual(read_thermal_zone_temp(tdir), 47.0)

        # 2. Live worker tests: empty script_content, stubborn grandchild SIGKILL, terminal backslash/CRLF, map_jobs & pipeline
        tok = "pass5-exec-tok-12345678"
        st = WorkerState(
            node_id="w_exec",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "node_id": "w_exec",
                "role": "worker",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        srv, _g, ev = create_worker_server("127.0.0.1", 0, st)
        w_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="exec-pass5",
            auth_token=tok,
            nodes=[NodeConfig(id="w_exec", host="127.0.0.1", role="worker", worker_port=w_port, max_concurrency=2)],
        )
        ctrl = MasterController(cfg)
        try:
            # 2a. Empty script_content="" must fall through to `command`
            req_empty = urllib.request.Request(
                f"http://127.0.0.1:{w_port}/exec",
                data=json.dumps({"command": "echo cmd_ran", "script_content": ""}).encode("utf-8"),
                headers=build_auth_headers(tok),
                method="POST",
            )
            with urllib.request.urlopen(req_empty, timeout=5.0) as resp_empty:
                res_empty = json.loads(resp_empty.read().decode("utf-8"))
                self.assertEqual(res_empty["returncode"], 0)
                self.assertEqual(res_empty["stdout"].strip(), "cmd_ran")

            # 2b. Stubborn grandchild ignoring SIGTERM gets SIGKILLed when parent exits on SIGTERM!
            with tempfile.TemporaryDirectory() as tmp:
                pid_file = Path(tmp) / "grandchild.pid"
                spawn_cmd = (
                    f"{sys.executable} -c \""
                    "import os, signal, subprocess, sys, time\n"
                    f"p = subprocess.Popen([sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
                    f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
                    "time.sleep(30)\""
                )
                t_gc = time.monotonic()
                out_to = ctrl.run_single(
                    JobSpec(index=0, job_id="sigterm-gc", command=spawn_cmd, timeout_sec=0.6),
                    target="w_exec",
                )[0]
                gc_elapsed = time.monotonic() - t_gc
                self.assertTrue(out_to.timed_out)
                self.assertLess(gc_elapsed, 3.0, f"Stubborn grandchild held pipes open ({gc_elapsed:.2f}s)")
                self.assertTrue(pid_file.exists(), "Grandchild PID file should have been written")
                gc_pid = int(pid_file.read_text(encoding="utf-8").strip())
                # Verify grandchild is dead (gone or zombie 'Z' if sandbox PID 1 hasn't reaped yet)
                alive = True
                for _ in range(20):
                    try:
                        os.kill(gc_pid, 0)
                    except ProcessLookupError:
                        alive = False
                        break
                    stat_path = Path(f"/proc/{gc_pid}/stat")
                    if stat_path.exists():
                        st_txt = stat_path.read_text(encoding="utf-8", errors="ignore")
                        rp = st_txt.rfind(")")
                        if rp != -1 and st_txt[rp + 2 : rp + 3] in {"Z", "X"}:
                            alive = False
                            break
                    time.sleep(0.05)
                self.assertFalse(alive, f"SIGTERM-ignoring grandchild PID {gc_pid} survived timeout!")

            # 2c. Terminal exec with trailing backslash and CRLF preserves stdout, rc=0, and cwd tracking
            with tempfile.TemporaryDirectory() as tmp:
                r_bs = ctrl.exec_terminal_command(f"cd {tmp} && echo bs_ok \\", target="w_exec")
                self.assertEqual(len(r_bs), 1)
                self.assertTrue(r_bs[0]["ok"], r_bs[0])
                self.assertEqual(r_bs[0]["stdout"].strip(), "bs_ok")
                self.assertEqual(Path(r_bs[0]["cwd"]).resolve(), Path(tmp).resolve())

                r_crlf = ctrl.exec_terminal_command("echo crlf_ok\r\n", target="w_exec")
                self.assertTrue(r_crlf[0]["ok"], r_crlf[0])
                self.assertEqual(r_crlf[0]["stdout"].strip(), "crlf_ok")

            # 2d. map_jobs preserves duplicate spec.index outcomes & fails fast on unknown/tier:9/quarantined pinned targets
            dup_jobs = [
                JobSpec(index=0, job_id="dupidx-a", command="echo first_job", timeout_sec=5.0),
                JobSpec(index=0, job_id="dupidx-b", command="echo second_job", timeout_sec=5.0),
            ]
            dup_outs = ctrl.map_jobs(dup_jobs, target="w_exec")
            self.assertEqual(len(dup_outs), 2)
            self.assertEqual([o.stdout.strip() for o in dup_outs], ["first_job", "second_job"])

            t0 = time.monotonic()
            unk_outs = ctrl.map_jobs([JobSpec(index=0, job_id="u1", command="echo x")], target="no_such_node", wait_for_ready_sec=15.0)
            self.assertLess(time.monotonic() - t0, 1.0)
            self.assertFalse(unk_outs[0].ok)
            self.assertIn("Unknown node", unk_outs[0].error)

            t0 = time.monotonic()
            bad_t_outs = ctrl.map_jobs([JobSpec(index=0, job_id="t9", command="echo x")], target="tier:9", wait_for_ready_sec=15.0)
            self.assertLess(time.monotonic() - t0, 1.0)
            self.assertFalse(bad_t_outs[0].ok)

            cfg.gateway.quarantined_nodes = ["w_exec"]
            t0 = time.monotonic()
            q_outs = ctrl.map_jobs([JobSpec(index=0, job_id="q1", command="echo x")], target="w_exec", wait_for_ready_sec=15.0)
            self.assertLess(time.monotonic() - t0, 1.0)
            self.assertFalse(q_outs[0].ok)
            self.assertIn("quarantined", q_outs[0].error.lower())
            cfg.gateway.quarantined_nodes = []

            # 2e. run_pipeline rejects NaN/Inf timeouts and score_node survives malformed NaN health fields
            pipe_res = ctrl.run_pipeline([{"name": "nan-step", "command": "echo hi", "timeout_sec": "NaN"}])
            self.assertFalse(pipe_res["ok"])
            self.assertIn("Invalid timeout_sec", pipe_res["results"][0]["error"])

            weird_snap = NodeSnapshot(
                node=cfg.nodes[0],
                online=True,
                health={"cpu_cores": "bad", "load_1m": "NaN", "temp_c": "inf", "mem_available_mb": "bad"},
            )
            self.assertTrue(math.isfinite(score_node(weird_snap, in_flight_local=0)))
        finally:
            ev.set()
            srv.shutdown()
            srv.server_close()

    def test_proxy_hop_by_hop_abuse_request_line_strictness_post_dns_ip_block_and_upload_quarantine(self) -> None:
        """Verify Connection: header cannot strip Host/Content-Length, strict HTTP version/tabs/NUL checks, post-DNS IP blocklist, and mid-upload quarantine."""
        import socketserver

        captured_reqs: list[bytes] = []

        class _CaptureHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(1.5)
                try:
                    buf = bytearray()
                    while b"\r\n\r\n" not in buf:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    sep = buf.find(b"\r\n\r\n")
                    if sep != -1:
                        head = buf[:sep].decode("iso-8859-1", errors="replace")
                        want = 0
                        for ln in head.split("\r\n")[1:]:
                            if ln.lower().startswith("content-length:"):
                                try:
                                    want = int(ln.split(":", 1)[1].strip())
                                except ValueError:
                                    want = 0
                        while len(buf) < sep + 4 + want:
                            chunk = self.request.recv(4096)
                            if not chunk:
                                break
                            buf.extend(chunk)
                    captured_reqs.append(bytes(buf))
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                except OSError:
                    pass

        class _ReuseTCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up_srv = _ReuseTCP(("127.0.0.1", 0), _CaptureHandler)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        tok = "pass6-gw-tok-12345678"
        w_tok = "pass6-w-tok-87654321"
        cfg = ClusterConfig(
            cluster_name="pass6-gw",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="monitor",
                allowed_ports=[up_port],
                block_private_ips=False,
                idle_timeout_sec=10.0,
            ),
        )
        gw_mgr = GatewayManager(cfg)
        ok, msg = gw_mgr.start()
        self.assertTrue(ok, msg)
        gw_port = gw_mgr.bound_port
        secret = derive_proxy_password(w_tok, "node1")
        auth_b64 = base64.b64encode(f"node1:{secret}".encode("utf-8")).decode("ascii")

        def _raw_send(payload: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", gw_port), timeout=4.0) as s:
                s.sendall(payload)
                s.settimeout(3.0)
                return s.recv(4096)

        try:
            # 1. Malicious Connection: Content-Length, Host MUST NOT strip Host or Content-Length!
            captured_reqs.clear()
            r_hop = _raw_send(
                f"POST http://127.0.0.1:{up_port}/hop HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n"
                f"Connection: Content-Length, Host, X-Custom-Hop\r\n"
                f"X-Custom-Hop: should-strip\r\n"
                f"Content-Length: 5\r\n\r\nhello".encode("ascii")
            )
            self.assertIn(b"200 OK", r_hop)
            self.assertTrue(captured_reqs)
            fwd = captured_reqs[-1]
            self.assertIn(b"Content-Length: 5", fwd)
            self.assertIn(f"Host: 127.0.0.1:{up_port}".encode("ascii"), fwd)
            self.assertIn(b"hello", fwd)
            self.assertNotIn(b"X-Custom-Hop", fwd)
            self.assertNotIn(b"Proxy-Authorization", fwd)

            # 2. Strict request-line & header-value checks: HTTP/1.9, tab separators, NUL/BEL in header value
            for raw_bad, label in (
                (
                    f"GET http://127.0.0.1:{up_port}/v HTTP/1.9\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    "HTTP/1.9",
                ),
                (
                    f"GET\thttp://127.0.0.1:{up_port}/t\tHTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    "tab request-line",
                ),
                (
                    f"GET http://127.0.0.1:{up_port}/nul HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\nX-Evil: a\x00b\r\n\r\n".encode("latin-1"),
                    "NUL header value",
                ),
            ):
                r_bad = _raw_send(raw_bad)
                self.assertIn(b"400 Bad Request", r_bad, f"Proxy accepted {label}: {r_bad!r}")

            # 3. Post-DNS blocked_domains enforcement defeats hex/decimal/IPv4-mapped IPv6 bypasses
            cfg.gateway.blocked_domains = ["127.0.0.1"]
            for bypass_req, label in (
                (
                    f"GET http://0x7f000001:{up_port}/hex HTTP/1.1\r\nHost: 0x7f000001:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    "hex IP",
                ),
                (
                    f"GET http://2130706433:{up_port}/dec HTTP/1.1\r\nHost: 2130706433:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    "decimal IP",
                ),
                (
                    f"CONNECT [::ffff:127.0.0.1]:{up_port} HTTP/1.1\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii"),
                    "IPv4-mapped IPv6",
                ),
            ):
                r_blk = _raw_send(bypass_req)
                self.assertIn(b"403 Forbidden", r_blk, f"Post-DNS blocklist missed {label}: {r_blk!r}")
            cfg.gateway.blocked_domains = []

            # 4. Mid-upload quarantine aborts active fixed-length POST body immediately
            with socket.create_connection(("127.0.0.1", gw_port), timeout=4.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/upload HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Content-Length: 50000\r\n\r\npart1".encode("ascii")
                )
                time.sleep(0.1)
                cfg.gateway.quarantined_nodes = ["node1"]
                gw_mgr.disconnect_node("node1")
                s.settimeout(2.0)
                t0 = time.monotonic()
                try:
                    s.sendall(b"more-data")
                    tail = s.recv(1024)
                    self.assertTrue(tail == b"" or b"502" in tail or b"403" in tail)
                except OSError:
                    pass
                self.assertLess(time.monotonic() - t0, 1.5)
        finally:
            gw_mgr.stop()
            up_srv.shutdown()
            up_srv.server_close()

    def test_webhook_redirect_ssrf_canonical_ip_normalization_and_rogue_pairing_master(self) -> None:
        """Verify webhook redirect SSRF guard, canonical IPv6/IPv4-mapped normalization, rogue pairing hello defense, and CLI validation."""
        from phonecluster.auth import _is_webhook_redirect_target_unsafe, build_webhook_opener
        from phonecluster.config import normalize_host
        from phonecluster.pairing import join_cluster_via_pairing

        # 1. Canonical IP normalization across IPv4-mapped IPv6 and expanded/uppercase IPv6
        self.assertEqual(normalize_host("0:0:0:0:0:ffff:7f00:1"), "127.0.0.1")
        self.assertEqual(normalize_host("::FFFF:192.168.1.20"), "192.168.1.20")
        self.assertEqual(normalize_host("[2001:DB8:0:0::1]"), "2001:db8::1")

        # 2. Webhook redirect SSRF classifier blocks file://, cloud metadata, link-local, and remote->loopback
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/x", "file:///etc/passwd"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/x", "http://169.254.169.254/latest/meta-data"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/x", "http://[fe80::1]/"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/x", "http://127.0.0.1:8765/exec"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/x", "http://[::1]:8765/health"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("http://192.168.1.50:8123/hook", "http://localhost:8080/api/exec"))
        # Same-loopback test redirect and public->public HTTPS remain allowed
        self.assertFalse(_is_webhook_redirect_target_unsafe("http://127.0.0.1:9000/a", "http://127.0.0.1:9000/b"))
        self.assertFalse(_is_webhook_redirect_target_unsafe("https://ntfy.sh/a", "https://1.1.1.1/b"))

        # Empty-hostname webhook URL rejected in SafetyConfig
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"battery_webhook_url": "http://"})

        # Live test: webhook opener refuses 302 redirect to cloud metadata 169.254.169.254
        class _RedirectAndRogueMasterHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/api/pair/hello":
                    # Oversized dh_pub DoS payload from rogue Master
                    raw = json.dumps({"session_id": "rogue1", "dh_pub": "a" * 5000, "salt": "00" * 16}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_response(404)
                    self.end_headers()

        class _ReuseHTTP(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        evil_srv = _ReuseHTTP(("127.0.0.1", 0), _RedirectAndRogueMasterHandler)
        evil_port = evil_srv.server_address[1]
        threading.Thread(target=evil_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            wb_opener = build_webhook_opener()
            req = urllib.request.Request(f"http://127.0.0.1:{evil_port}/hook", data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as redir_exc:
                wb_opener.open(req, timeout=3.0)
            try:
                self.assertEqual(redir_exc.exception.code, 302)
            finally:
                redir_exc.exception.close()

            # 3. Rogue Master oversized dh_pub on /api/pair/hello rejected cleanly before big-int math
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(RuntimeError) as pair_exc:
                    join_cluster_via_pairing("127.0.0.1", evil_port, "123456", Path(tmp) / "w.json")
                self.assertIn("Malformed pairing hello", str(pair_exc.exception))

                # 4. CLI rejects invalid gateway --port, invalid net-audit --lan-subnet, and bad --master port without bricking cluster.json
                cfg_p = Path(tmp) / "cluster.json"
                save_config(create_default_config(master_host="127.0.0.1", worker_hosts=[]), cfg_p)
                self.assertEqual(cli_main(["--config", str(cfg_p), "gateway", "--port", "99999"]), 2)
                self.assertEqual(cli_main(["--config", str(cfg_p), "net-audit", "--lan-subnet", "not-a-cidr"]), 2)
                self.assertEqual(cli_main(["--config", str(cfg_p), "join", "--master", "http://127.0.0.1:99999", "--pin", "123456"]), 2)
                # Config file remained valid and uncorrupted!
                loaded = load_config(cfg_p)
                self.assertEqual(loaded.network.lan_subnet, "")
        finally:
            evil_srv.shutdown()
            evil_srv.server_close()

    def test_poisoned_worker_telemetry_resilience_and_shared_udp_discovery_coexistence(self) -> None:
        """Verify Master survives poisoned worker /health JSON everywhere, and UDP discovery + pairing beacon coexist on the same port."""
        from phonecluster.netguard import audit_cluster_network
        from phonecluster.pairing import PairingBeaconResponder, discover_pairing_masters

        tok = "poison-tel-tok-12345678"

        class _PoisonHealthHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                raw = json.dumps(
                    {
                        "node_id": "poison1",
                        "role": "worker",
                        "ready_for_jobs": True,
                        "tier": True,  # bool! Must NOT coerce to Tier 1 via `True in {1,2,3}`
                        "pool": "evil pool;rm -rf /",
                        "active_jobs": "not-an-int",
                        "max_concurrency": "NaN",
                        "cpu_cores": "bad",
                        "mem_total_mb": None,
                        "mem_available_mb": "NaN",
                        "load_1m": "inf",
                        "cpu_pct": "bad",
                        "temp_c": "NaN",
                        "net_rx_kbps": "bad",
                        "net_tx_kbps": "inf",
                        "services": ["not", "a", "dict"],
                        "tools": "not-a-dict",
                        "listening_ports": [{"port": "abc", "exposed": True}, "junk", {"port": 99999, "exposed": True}],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        class _ReuseHTTP(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        p_srv = _ReuseHTTP(("127.0.0.1", 0), _PoisonHealthHandler)
        p_port = p_srv.server_address[1]
        threading.Thread(target=p_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        cfg = ClusterConfig(
            cluster_name="poison-resilience",
            auth_token=tok,
            nodes=[NodeConfig(id="poison1", host="127.0.0.1", role="worker", worker_port=p_port)],
        )
        ctrl = MasterController(cfg)
        try:
            snaps = ctrl.poll_health()
            self.assertEqual(len(snaps), 1)
            self.assertTrue(snaps[0].online)
            self.assertEqual(snaps[0].active_jobs, 0)
            self.assertGreaterEqual(snaps[0].max_concurrency, 1)

            summary = ctrl.cluster_summary(record_history=True)
            self.assertEqual(summary["nodes_online"], 1)
            self.assertTrue(math.isfinite(summary["cluster_cpu_pct"]))
            self.assertEqual(summary["nodes"][0]["pool"], "compute")  # Unsafe pool sanitized to default!

            svcs_info = ctrl.get_services_info(snapshots=snaps)
            self.assertIn("services", svcs_info)
            self.assertEqual(ctrl.build_distcc_hosts(snapshots=snaps), "")
            self.assertEqual(ctrl.build_llama_rpc_arg(snapshots=snaps), "")
            self.assertIn("slots=4", ctrl.build_mpi_hostfile(snapshots=snaps))

            audit = audit_cluster_network(ctrl, snapshots=snaps)
            self.assertIn("score", audit)
            self.assertEqual(audit["nodes"][0]["exposed_ports"], [])
        finally:
            p_srv.shutdown()
            p_srv.server_close()

        # 2. UDP DiscoveryResponder and PairingBeaconResponder coexisting on the SAME port (SO_REUSEPORT retry test)
        disc = DiscoveryResponder(
            node_id="node0",
            role="master",
            worker_port=8765,
            listen_host="127.0.0.1",
            discovery_port=0,
        )
        self.assertTrue(disc.bind())
        shared_port = disc.bound_port
        beacon = PairingBeaconResponder(
            cluster_name="coexist-net",
            pair_port=8767,
            session_id="sess1234",
            fingerprint="ABCD-1234",
            expires_at=time.time() + 60.0,
            listen_host="127.0.0.1",
            discovery_port=shared_port,
        )
        disc.start()
        bound_both = beacon.bind()
        if bound_both:
            beacon.start()
        try:
            # Verify fresh-socket retry reliably discovers even when both sockets share the same UDP port!
            got_disc = False
            for _ in range(4):
                if discover_lan_nodes(timeout_sec=0.85, discovery_port=shared_port, targets=["127.0.0.1"]):
                    got_disc = True
                    break
            self.assertTrue(got_disc, "discover_lan_nodes failed with shared UDP port")
            if bound_both:
                got_pair = False
                for _ in range(4):
                    if discover_pairing_masters(timeout_sec=0.85, discovery_port=shared_port, targets=["127.0.0.1"]):
                        got_pair = True
                        break
                self.assertTrue(got_pair, "discover_pairing_masters failed with shared UDP port")
        finally:
            disc.stop()
            beacon.stop()

    def test_battery_pmic_hazard_gating_worker_workdir_safety_and_config_wizard_validation(self) -> None:
        """Verify PMIC battery_health hazard pauses jobs & fires alert, worker workdir NUL/type safety, wizard/CLI validation, and UDP ssh_user sanitization."""
        from unittest import mock
        from phonecluster.discovery import REPLY_TYPE
        from phonecluster.telemetry import BatteryInfo, ThermalGate, collect_node_health
        from phonecluster.wizard import run_setup_wizard
        from phonecluster.worker import BatteryGuardLoop

        # 1. PMIC battery_health OVERHEAT / OVER_VOLTAGE pauses jobs even when temperature reading is cool
        for hazard in ("OVERHEAT", "OVER_VOLTAGE"):
            fake_bat = BatteryInfo(percentage=52, temperature_c=32.0, status="CHARGING", health=hazard, plugged="PLUGGED", source="sysfs:battery")
            with mock.patch("phonecluster.telemetry.read_battery_info", return_value=fake_bat):
                h_full = collect_node_health("n0", "worker", SafetyConfig(), ThermalGate(), safety_only=True)
                self.assertFalse(h_full["ready_for_jobs"], f"Should pause jobs on battery_health={hazard}")
                self.assertTrue(any("battery_health" in r for r in h_full["not_ready_reasons"]))
                self.assertEqual(h_full["battery_health"], hazard)

        # 2. BatteryGuardLoop emits 'battery_hazard' alert on OVER_VOLTAGE
        st_haz = WorkerState(
            node_id="bat_node",
            role="worker",
            auth_token="bat-tok-12345678",
            safety=SafetyConfig(webhook_cooldown_sec=0),
            health_provider=lambda: {
                "node_id": "bat_node",
                "role": "worker",
                "battery_pct": 50,
                "battery_status": "CHARGING",
                "battery_health": "OVER_VOLTAGE",
                "temp_c": 34.0,
                "overheated": False,
                "ready_for_jobs": False,
                "not_ready_reasons": ["battery_health (OVER_VOLTAGE)"],
            },
        )
        guard = BatteryGuardLoop(st_haz, threading.Event())
        guard.check_once()
        self.assertTrue(any(a["event"] == "battery_hazard" for a in st_haz.recent_alerts))

        # 3. Live worker cleanly returns 400 (never 500) on NUL-byte or non-string workdir
        tok = "workdir-safe-tok-123456"
        st_w = WorkerState(
            node_id="w_dir",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "node_id": "w_dir",
                "role": "worker",
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "cpu_cores": 4,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
                "tools": {},
                "services": {},
            },
        )
        srv, _g, ev = create_worker_server("127.0.0.1", 0, st_w)
        w_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            for bad_wd in ("/tmp\x00evil", 12345):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/exec",
                    data=json.dumps({"command": "echo hi", "workdir": bad_wd}).encode("utf-8"),
                    headers=build_auth_headers(tok),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as exc_ctx:
                    urllib.request.urlopen(req, timeout=3.0)
                try:
                    self.assertEqual(exc_ctx.exception.code, 400)
                finally:
                    exc_ctx.exception.close()
        finally:
            ev.set()
            srv.shutdown()
            srv.server_close()

        # 4. create_default_config & wizard reject/sanitize invalid host, ssh_user, ssh_port, NaN temp, file:// webhook
        with self.assertRaises(ValueError):
            create_default_config(master_host="-oProxyCommand=id")
        with self.assertRaises(ValueError):
            create_default_config(master_host="127.0.0.1", ssh_user="-oProxyCommand=id")
        with self.assertRaises(ValueError):
            create_default_config(master_host="127.0.0.1", ssh_port=99999)

        with tempfile.TemporaryDirectory() as tmp:
            wiz_cfg = Path(tmp) / "wiz.json"
            answers = iter([
                "safe-cluster",          # cluster_name
                "127.0.0.1",             # master_host
                "-oEvilUser",            # invalid ssh_user -> sanitized to ""
                "8022",                  # ssh_port
                "n",                     # skip LAN scan
                "bad host!, 192.168.1.9",  # one bad, one valid worker IP
                "NaN",                   # NaN temp -> falls back to 40.0
                "file:///etc/passwd",    # bad webhook -> ignored cleanly
            ])
            rc = run_setup_wizard(wiz_cfg, input_fn=lambda _p: next(answers))
            self.assertEqual(rc, 0)
            loaded = load_config(wiz_cfg)
            self.assertEqual(loaded.nodes[0].ssh_user, "")
            self.assertEqual([n.host for n in loaded.nodes], ["127.0.0.1", "192.168.1.9"])
            self.assertEqual(loaded.safety.max_temp_c, 40.0)
            self.assertEqual(loaded.safety.battery_webhook_url, "")

            # CLI worker validation rejects bad port, concurrency, and missing workdir
            self.assertEqual(cli_main(["--config", str(wiz_cfg), "worker", "--node-id", "node0", "--port", "99999"]), 2)
            self.assertEqual(cli_main(["--config", str(wiz_cfg), "worker", "--node-id", "node0", "--max-concurrency", "99"]), 2)
            self.assertEqual(cli_main(["--config", str(wiz_cfg), "worker", "--node-id", "node0", "--workdir", str(Path(tmp) / "missing")]), 2)

        # 5. UDP discovery strips malicious '-oProxyCommand=id' ssh_user
        udp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_s.bind(("127.0.0.1", 0))
        u_port = udp_s.getsockname()[1]
        udp_s.settimeout(0.2)
        stop_u = threading.Event()

        def _bad_ssh_udp() -> None:
            while not stop_u.is_set():
                try:
                    _raw, addr = udp_s.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                pkt = {"type": REPLY_TYPE, "node_id": "n1", "worker_port": 8765, "ssh_port": 8022, "ssh_user": "-oProxyCommand=id"}
                udp_s.sendto(json.dumps(pkt).encode("utf-8"), addr)

        tu = threading.Thread(target=_bad_ssh_udp, daemon=True)
        tu.start()
        try:
            res = discover_lan_nodes(timeout_sec=0.35, discovery_port=u_port, targets=["127.0.0.1"])
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["ssh_user"], "")
        finally:
            stop_u.set()
            udp_s.close()
            tu.join(timeout=2.0)

    def test_tui_status_ansi_escape_sanitization_poisoned_health_and_script_safety_guards(self) -> None:
        """Verify pc top & pc status strip worker ANSI/OSC escapes, survive poisoned fields, and shell scripts reject dangerous flags."""
        import subprocess
        from phonecluster.tui import render_top_frame

        poison_summary = {
            "cluster_name": "test-safe",
            "nodes_total": 1,
            "nodes_online": 1,
            "nodes_ready": 0,
            "total_cores": 4,
            "cluster_cpu_pct": 12.0,
            "cluster_ram_pct": 40.0,
            "mem_total_mb": 4096,
            "mem_available_mb": 2048,
            "max_temp_c": 35.0,
            "avg_latency_ms": 2.0,
            "total_active_jobs": 1,
            "total_net_rx_kbps": 1.0,
            "total_net_tx_kbps": 2.0,
            "safety": {"max_temp_c": 40.0, "battery_high_pct": 60},
            "nodes": [
                {
                    "id": "node1",
                    "host": "127.0.0.1",
                    "role": "worker",
                    "tier": 1,
                    "pool": "compute",
                    "online": True,
                    "quarantined": False,
                    "ready_for_jobs": False,
                    "latency_ms": "bad",
                    "health": {
                        "os_env": "\x1b]52;c;ZXZpbA==\x07termux",
                        "not_ready_reasons": ["\x1b[2Joverheated"],
                        "cpu_pct": "bad",
                        "per_core_pct": ["bad", 50.0],
                        "mem_total_mb": "bad",
                        "mem_available_mb": None,
                        "temp_c": "NaN",
                        "battery_pct": "bad",
                        "battery_status": "\x1b[31mCHAR",
                        "net_rx_kbps": "bad",
                        "net_tx_kbps": "bad",
                        "services": ["not-a-dict"],
                        "active_job_list": [{"job_id": "\x1b[2Jj1", "running_sec": "nan", "command": "\x1b]0;pwn\x07echo"}],
                        "top_processes": [{"pid": "bad", "cpu_pct": "nan", "mem_pct": "bad", "name": "\x1b]52;c;x\x07proc"}],
                    },
                }
            ],
        }
        poison_jobs = [
            {
                "node_id": "node1",
                "active": [{"job_id": "\x1b[2Ja1", "running_sec": "bad", "command": "\x1b[31mcmd"}],
                "recent": [{"job_id": "r1", "returncode": "bad", "duration_sec": "nan", "command": "\x1b]0;hi\x07ok"}],
            }
        ]
        for mode in ("tasks", "procs"):
            frame = render_top_frame(
                summary=poison_summary,
                history={"cluster": [], "nodes": {}},
                all_jobs=poison_jobs,
                view_mode=mode,
                use_color=False,
            )
            self.assertNotIn("\x1b", frame, f"Unstripped ESC sequence leaked in TUI ({mode} mode)!")

        # Shell script safety guards reject dangerous node-ids, root chroot dir, and non-HTTP rootfs URLs
        repo = Path(__file__).resolve().parent.parent
        for cmd in (
            ["bash", str(repo / "scripts" / "02_termux_node_setup.sh"), "--node-id", "bad;id"],
            ["bash", str(repo / "scripts" / "04_debian13_chroot_setup.sh"), "--dir", "/"],
            ["bash", str(repo / "scripts" / "04_debian13_chroot_setup.sh"), "--rootfs-url", "file:///etc/passwd"],
            ["bash", str(repo / "install.sh"), "--node-id", "../evil"],
        ):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 2, f"Expected exit 2 for {cmd}, got {proc.returncode}: {proc.stderr}")

    def test_worker_stdin_devnull_whitespace_interpreter_and_readonly_workdir_script(self) -> None:
        """Verify worker detaches stdin (no interactive hang), handles whitespace interpreter, and falls back to system tmp on read-only workdir."""
        tok = "pass8-worker-tok-123456"
        with tempfile.TemporaryDirectory() as tmp:
            ro_dir = Path(tmp) / "ro_work"
            ro_dir.mkdir()
            st = WorkerState(
                node_id="node0",
                role="master",
                auth_token=tok,
                safety=SafetyConfig(max_temp_c=95.0, resume_temp_c=90.0, min_free_ram_mb=0),
                max_concurrency=2,
                workdir=Path(tmp),
            )
            srv, _guard, stop_ev = create_worker_server("127.0.0.1", 0, st)
            w_port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            t.start()
            cfg = ClusterConfig(
                cluster_name="pass8-worker",
                auth_token=tok,
                nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=w_port)],
            )
            ctrl = MasterController(cfg)
            try:
                # 1. Interactive stdin command returns EOF immediately instead of hanging until timeout
                t0 = time.monotonic()
                out_stdin = ctrl.run_single(
                    JobSpec(index=0, job_id="p8-stdin", command="read line || true; echo done_eof", timeout_sec=5.0),
                    target="node0",
                )[0]
                self.assertTrue(out_stdin.ok, out_stdin.to_dict())
                self.assertIn("done_eof", out_stdin.stdout)
                self.assertLess(time.monotonic() - t0, 3.0)

                # 2. Whitespace-only interpreter falls back cleanly to python3 for .py script
                out_ws = ctrl.run_single(
                    JobSpec(
                        index=0,
                        job_id="p8-ws-interp",
                        script_content="print('ws_interp_ok')\n",
                        script_name="test.py",
                        interpreter="   ",
                        timeout_sec=5.0,
                    ),
                    target="node0",
                )[0]
                self.assertTrue(out_ws.ok, out_ws.to_dict())
                self.assertIn("ws_interp_ok", out_ws.stdout)

                # 3. Script executed inside a read-only workdir falls back to system tmp dir and succeeds
                os.chmod(ro_dir, 0o555)
                try:
                    out_ro = ctrl.run_single(
                        JobSpec(
                            index=0,
                            job_id="p8-ro-dir",
                            script_content="import os; print('cwd=' + os.getcwd())\n",
                            script_name="ro.py",
                            workdir=str(ro_dir),
                            timeout_sec=5.0,
                        ),
                        target="node0",
                    )[0]
                    self.assertTrue(out_ro.ok, out_ro.to_dict())
                    self.assertIn(f"cwd={ro_dir.resolve()}", out_ro.stdout)
                finally:
                    os.chmod(ro_dir, 0o755)
            finally:
                stop_ev.set()
                srv.shutdown()
                srv.server_close()
                t.join(timeout=2.0)

    def test_pass8_json_null_safety_concurrency_clamp_failed_gateway_proxy_and_cli_flags(self) -> None:
        """Verify JSON null never becomes 'None', max_concurrency is clamped, failed gateway suppresses dead proxy env, and bad CLI flags exit 2."""
        from phonecluster.cli import main as cli_main
        from phonecluster.gateway import build_worker_proxy_env

        # 1. Config JSON null safety
        with self.assertRaises(ValueError):
            ClusterConfig.from_dict({"auth_token": None, "nodes": [{"id": "n0", "host": "127.0.0.1"}]})
        safe_cfg = ClusterConfig.from_dict(
            {
                "cluster_name": None,
                "auth_token": "tok-pass8-abcdef",
                "nodes": [{"id": "n0", "host": "127.0.0.1", "ssh_user": None, "pool": None, "tags": None, "notes": None, "auth_token": None}],
                "safety": None,
                "gateway": {"bind_host": None, "allowed_domains": [None, "pypi.org"], "blocked_domains": [None], "quarantined_nodes": [None]},
                "network": {"adguard_url": None, "lan_subnet": None},
            }
        )
        self.assertEqual(safe_cfg.cluster_name, "phonecluster")
        self.assertEqual(safe_cfg.nodes[0].ssh_user, "")
        self.assertEqual(safe_cfg.nodes[0].pool, "auto")
        self.assertEqual(safe_cfg.nodes[0].notes, "")
        self.assertEqual(safe_cfg.safety.battery_webhook_url, "")
        self.assertEqual(safe_cfg.gateway.bind_host, "0.0.0.0")
        self.assertEqual(safe_cfg.gateway.allowed_domains, ["pypi.org"])
        self.assertEqual(safe_cfg.gateway.blocked_domains, [])
        self.assertEqual(safe_cfg.gateway.quarantined_nodes, [])
        self.assertEqual(safe_cfg.network.adguard_url, "")
        self.assertEqual(safe_cfg.network.lan_subnet, "")
        self.assertEqual(SafetyConfig.from_dict({"battery_webhook_url": None}).battery_webhook_url, "")

        # 2. Poisoned worker max_concurrency clamped to 32
        snap_huge = NodeSnapshot(
            node=NodeConfig(id="w1", host="127.0.0.1", role="worker", max_concurrency=2),
            online=True,
            health={"max_concurrency": 1_000_000},
        )
        self.assertEqual(snap_huge.max_concurrency, 32)

        # 3. Failed gateway port_override=-1 suppresses dead proxy injection
        gw_cfg = ClusterConfig(
            cluster_name="gw-fail",
            auth_token="tok-gw-fail-123456",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766),
            ],
            gateway=GatewayConfig(enabled=True, bind_host="127.0.0.1", port=8888, inject_proxy_env=True),
        )
        self.assertEqual(build_worker_proxy_env(gw_cfg, gw_cfg.nodes[1], port_override=-1), {})
        self.assertIn("HTTP_PROXY", build_worker_proxy_env(gw_cfg, gw_cfg.nodes[1], port_override=None))

        # 4. Dashboard backend JSON null handling + failed gateway boot override=-1
        tok = "pass8-dash-tok-123456"
        st = WorkerState(
            node_id="node0",
            role="master",
            auth_token=tok,
            safety=SafetyConfig(max_temp_c=95.0, resume_temp_c=90.0, min_free_ram_mb=0),
            max_concurrency=2,
        )
        wsrv, _wg, w_ev = create_worker_server("127.0.0.1", 0, st)
        w_port = wsrv.server_address[1]
        wt = threading.Thread(target=wsrv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        wt.start()

        # Occupy a TCP port to force Dashboard's gateway_manager.start() to fail on boot
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy_port = blocker.getsockname()[1]

        d_cfg = ClusterConfig(
            cluster_name="pass8-dash",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=w_port),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=w_port),
            ],
            gateway=GatewayConfig(enabled=True, bind_host="127.0.0.1", port=busy_port, inject_proxy_env=True),
        )
        d_ctrl = MasterController(d_cfg)
        dash = DashboardHTTPServer(
            ("127.0.0.1", 0), d_ctrl, enable_pairing_beacon=False, pairing_fail_delay_sec=0.0
        )
        d_port = dash.server_address[1]
        dt = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        dt.start()

        def _post_dash(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
            req = urllib.request.Request(
                f"http://127.0.0.1:{d_port}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8")
                exc.close()
                return exc.code, json.loads(raw)

        try:
            # Failed gateway on boot sets gateway_port_override=-1 so workers don't get broken proxy env
            self.assertEqual(d_ctrl.gateway_port_override, -1)
            self.assertEqual(build_worker_proxy_env(d_cfg, d_cfg.nodes[1], port_override=d_ctrl.gateway_port_override), {})

            # POST /api/exec with command=None returns 400 (does NOT run shell command "None")
            code, data = _post_dash("/api/exec", {"command": None, "target": None})
            self.assertEqual(code, 400, data)

            # POST /api/terminal/exec with cwd=None, job_id=None, target=None works cleanly
            code, data = _post_dash(
                "/api/terminal/exec",
                {"command": "echo ok_null_safe", "cwd": None, "job_id": None, "target": None},
            )
            self.assertEqual(code, 200, data)
            self.assertIn("ok_null_safe", data["results"][0]["stdout"])

            # POST /api/map with commands=[None, ""] returns 400
            code, data = _post_dash("/api/map", {"mode": "commands", "commands": [None, "   "]})
            self.assertEqual(code, 400, data)

            # POST /api/services/custom with name=None, url=None returns 400
            code, data = _post_dash("/api/services/custom", {"name": None, "url": None})
            self.assertEqual(code, 400, data)

            # POST /api/network/hardening with adguard_url=None, lan_subnet=None clears to "" (NOT "None")
            code, data = _post_dash("/api/network/hardening", {"adguard_url": None, "lan_subnet": None})
            self.assertEqual(code, 200, data)
            self.assertEqual(d_cfg.network.adguard_url, "")
            self.assertEqual(d_cfg.network.lan_subnet, "")
        finally:
            dash.shutdown()
            dash.server_close()
            blocker.close()
            w_ev.set()
            wsrv.shutdown()
            wsrv.server_close()
            dt.join(timeout=2.0)
            wt.join(timeout=2.0)

        # 5. CLI flag validation returns exit code 2 cleanly on negative/NaN/out-of-range/bad-quote inputs
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "c.json"
            save_config(safe_cfg, cfg_p)
            script_p = Path(tmp) / "ok.py"
            script_p.write_text("print(1)\n", encoding="utf-8")
            bad_args_p = Path(tmp) / "bad_args.txt"
            bad_args_p.write_text('valid arg\n"unclosed quote\n', encoding="utf-8")
            for argv in (
                ["--config", str(cfg_p), "run", "--timeout", "-1", "echo", "x"],
                ["--config", str(cfg_p), "run", "--timeout", "nan", "echo", "x"],
                ["--config", str(cfg_p), "map", "--timeout", "-5", "--repeat", "1", "echo", "x"],
                ["--config", str(cfg_p), "map", "--retries", "-1", "--repeat", "1", "echo", "x"],
                ["--config", str(cfg_p), "map", "--wait-ready", "nan", "--repeat", "1", "echo", "x"],
                ["--config", str(cfg_p), "map", "--script", str(script_p), "--args-file", str(bad_args_p)],
                ["--config", str(cfg_p), "status", "--watch", "nan"],
                ["--config", str(cfg_p), "top", "--interval", "nan", "--once"],
                ["--config", str(cfg_p), "discover", "--timeout", "nan"],
                ["--config", str(cfg_p), "dashboard", "--port", "99999"],
                ["--config", str(cfg_p), "pair", "--port", "99999"],
                ["--config", str(cfg_p), "join", "--timeout", "nan"],
                ["--config", str(cfg_p), "join", "--worker-port", "99999"],
                ["--config", str(cfg_p), "llama-rpc", "--port", "99999"],
            ):
                self.assertEqual(cli_main(argv), 2, f"Expected exit 2 for CLI args: {argv}")

    def test_pass9_proxy_host_port_chunk_ext_trailer_url_hardening_and_ip_canonicalization(self) -> None:
        """Verify proxy Host-port check, malformed URL/userinfo/backslash blocking, chunk-ext & trailer sanitization, IP pattern canonicalization, and rate-limiter memory cap."""
        import base64
        import socketserver
        from phonecluster.auth import AuthRateLimiter, _is_webhook_redirect_target_unsafe
        from phonecluster.config import validate_domain_pattern

        captured_raw: list[bytes] = []

        class _CaptureHTTPHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(3.0)
                buf = bytearray()
                try:
                    while True:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        buf.extend(chunk)
                        if b"\r\n0\r\n" in buf and buf.endswith(b"\r\n\r\n"):
                            break
                        if b"Transfer-Encoding:" not in buf and b"\r\n\r\n" in buf:
                            break
                except OSError:
                    pass
                captured_raw.append(bytes(buf))
                try:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                except OSError:
                    pass

        class _ReuseTCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up_srv = _ReuseTCP(("127.0.0.1", 0), _CaptureHTTPHandler)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        tok = "pass9-gw-tok-1234567890"
        w_tok = "pass9-gw-worker-987654321"
        cfg = ClusterConfig(
            cluster_name="pass9-gw",
            auth_token=tok,
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1"],
                allowed_ports=[up_port],
                block_private_ips=False,
                idle_timeout_sec=10.0,
            ),
        )
        gw_mgr = GatewayManager(cfg)
        ok, msg = gw_mgr.start()
        self.assertTrue(ok, msg)
        gw_port = gw_mgr.bound_port
        secret = derive_proxy_password(w_tok, "node1")
        auth_b64 = base64.b64encode(f"node1:{secret}".encode("utf-8")).decode("ascii")

        def _raw_req(payload: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", gw_port), timeout=5.0) as s:
                s.sendall(payload)
                s.settimeout(3.0)
                out = bytearray()
                while True:
                    try:
                        c = s.recv(4096)
                    except OSError:
                        break
                    if not c:
                        break
                    out.extend(c)
                return bytes(out)

        try:
            # 1. Host header port mismatch -> 400
            r_port = _raw_req(
                f"GET http://127.0.0.1:{up_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:9999\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", r_port)

            # 2. Malformed IPv6 bracket target URL -> 400 (no uncaught ValueError)
            r_badv6 = _raw_req(
                f"GET http://[bad/ HTTP/1.1\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", r_badv6)

            # 3. Backslash & userinfo URL differentials -> 400
            r_bslash = _raw_req(
                f"GET http://127.0.0.1\\@evil.com/ HTTP/1.1\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", r_bslash)

            r_uinfo = _raw_req(
                f"GET http://user:pass@127.0.0.1:{up_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", r_uinfo)

            # 4. Chunk extension stripped & forbidden Proxy-Authorization trailer dropped while valid trailer passes
            captured_raw.clear()
            r_chunk = _raw_req(
                f"POST http://127.0.0.1:{up_port}/chunk HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n"
                f"5;ext=sneaky\r\nhello\r\n"
                f"0;last=ext\r\n"
                f"Proxy-Authorization: Basic leaked\r\n"
                f"X-Safe-Trailer: yes\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"200 OK", r_chunk)
            self.assertEqual(len(captured_raw), 1)
            sent_up = captured_raw[0]
            self.assertIn(b"\r\n5\r\nhello\r\n0\r\n", sent_up)
            self.assertNotIn(b"ext=sneaky", sent_up)
            self.assertNotIn(b"Proxy-Authorization", sent_up)
            self.assertIn(b"X-Safe-Trailer: yes\r\n", sent_up)

            # 5. Malformed chunk trailer (missing colon) -> 400
            r_badtr = _raw_req(
                f"POST http://127.0.0.1:{up_port}/badtr HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n"
                f"Proxy-Authorization: Basic {auth_b64}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n"
                f"0\r\nBadTrailerNoColon\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", r_badtr)
        finally:
            gw_mgr.stop()
            up_srv.shutdown()
            up_srv.server_close()

        # 6. IP pattern canonicalization, malformed webhook redirect port, and rate-limiter memory cap
        self.assertEqual(validate_domain_pattern("::ffff:127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_domain_pattern("0:0:0:0:0:0:0:1"), "::1")
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://example.com/hook", "http://evil.com:99999/"))
        rl = AuthRateLimiter(max_failures=5, window_sec=60.0, block_sec=60.0)
        for i in range(2500):
            rl.record_failure(f"10.0.{i // 256}.{i % 256}")
        self.assertLessEqual(len(rl._failures), 2048)

    def test_pass9_ssh_pubkey_injection_json_nan_poison_sync_empty_ssh_user_and_self_resilience(self) -> None:
        """Verify SSH pubkey newline injection block, RFC 8259 JSON NaN sanitization, malformed Origin/URL guards, doctor/netguard/TUI/wizard resilience, and 03_sync_cluster empty ssh_user."""
        import base64
        import subprocess
        from unittest import mock
        from phonecluster.auth import safe_json_dumps
        from phonecluster.doctor import run_doctor
        from phonecluster.gateway import build_worker_proxy_env
        from phonecluster.netguard import build_firewall_guides
        from phonecluster.pairing import _validate_ssh_pubkey
        from phonecluster.routing import build_service_registry
        from phonecluster.telemetry import BatteryInfo, ThermalGate, collect_node_health
        from phonecluster.tui import render_top_frame
        from phonecluster.wizard import run_interactive_menu

        # 1. SSH authorized_keys multi-line / command injection rejected; valid key accepted
        valid_blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + b"A" * 32).decode("ascii")
        good_key = f"ssh-ed25519 {valid_blob} master@node0"
        self.assertEqual(_validate_ssh_pubkey(good_key), good_key)
        self.assertIsNone(_validate_ssh_pubkey(good_key + '\ncommand="/bin/evil" ' + good_key))
        self.assertIsNone(_validate_ssh_pubkey("ssh-ed25519 !!!notbase64!!! user"))
        self.assertIsNone(_validate_ssh_pubkey("ssh-ed25519 " + valid_blob + "\x1b[31muser"))

        # 2. Strict RFC 8259 JSON serialization eliminates bare NaN / Infinity
        strict_s = safe_json_dumps({"temp": float("nan"), "vals": [float("inf"), float("-inf"), 36.5]})
        self.assertNotIn("NaN", strict_s)
        self.assertNotIn("Infinity", strict_s)
        def _forbid_const(c: str) -> None:
            raise AssertionError(f"Non-RFC JSON constant emitted: {c}")
        parsed = json.loads(strict_s, parse_constant=_forbid_const)
        self.assertIsNone(parsed["temp"])
        self.assertEqual(parsed["vals"], [None, None, 36.5])

        # 3. collect_node_health(safety_only=True) does NOT conflate OVER_VOLTAGE with overheated
        with mock.patch(
            "phonecluster.telemetry.read_battery_info",
            return_value=BatteryInfo(percentage=50, temperature_c=33.0, status="CHARGING", health="OVER_VOLTAGE", source="test"),
        ), mock.patch(
            "phonecluster.telemetry.read_memory_info",
            return_value={"total_mb": 4096, "available_mb": 2048, "used_mb": 2048},
        ):
            h_safe = collect_node_health("n1", "worker", SafetyConfig(), ThermalGate(), safety_only=True)
            self.assertFalse(h_safe["overheated"])
            self.assertTrue(h_safe["battery_hazard"])
            self.assertFalse(h_safe["ready_for_jobs"])

        # 4. MasterController._to_outcome & service/proxy builders survive poisoned payloads and malformed URLs
        spec = JobSpec(index=0, job_id="j1", command="echo x")
        out_null = MasterController._to_outcome(spec, "n1", "ok", {"stdout": None, "stderr": None, "returncode": 0}, 1)
        self.assertEqual(out_null.stdout, "")
        self.assertEqual(out_null.stderr, "")
        out_bad_r = MasterController._to_outcome(spec, "n1", "retryable", {"reasons": "not-a-list"}, 1)
        self.assertFalse(out_bad_r.ok)

        bad_url_cfg = ClusterConfig(
            cluster_name="badurl",
            auth_token="tok-badurl-1234567890",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=0),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766),
            ],
            dashboard_port=0,
            gateway=GatewayConfig(enabled=True, port=8888, inject_proxy_env=True),
            custom_services={"broken": "http://[bad/"},
        )
        self.assertTrue(isinstance(build_service_registry([], bad_url_cfg), list))
        self.assertIn("HTTP_PROXY", build_worker_proxy_env(bad_url_cfg, bad_url_cfg.nodes[1]))

        # 5. Firewall guides never emit port 0
        fw = build_firewall_guides(bad_url_cfg, {"lan_subnet": "192.168.1.0/24", "is_termux": False})
        self.assertNotIn("port 0 ", fw["ufw"])
        self.assertNotIn("{ 0,", fw["nftables"])

        # 6. Dashboard rejects malformed Origin (403) and malformed webhook/adguard URLs (400), never 500
        tok = "pass9-dash-tok-123456"
        d_cfg = ClusterConfig(
            cluster_name="p9-dash",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765)],
        )
        dash = DashboardHTTPServer(("127.0.0.1", 0), MasterController(d_cfg), enable_pairing_beacon=False, pairing_fail_delay_sec=0.0)
        d_port = dash.server_address[1]
        dt = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        dt.start()
        try:
            def _post(path: str, body: dict[str, Any], extra_hdrs: dict[str, str] | None = None) -> int:
                hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {tok}"}
                if extra_hdrs:
                    hdrs.update(extra_hdrs)
                req = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}{path}",
                    data=json.dumps(body).encode("utf-8"),
                    headers=hdrs,
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        return resp.status
                except urllib.error.HTTPError as exc:
                    exc.close()
                    return exc.code

            self.assertEqual(_post("/api/exec", {"command": "echo hi"}, {"Origin": "http://[bad"}), 403)
            self.assertEqual(_post("/api/settings/test-webhook", {"battery_webhook_url": "http://[bad/"}), 400)
            self.assertEqual(_post("/api/network/hardening", {"adguard_url": "http://[bad/"}), 400)
        finally:
            dash.shutdown()
            dash.server_close()
            dt.join(timeout=2.0)

        # 7. Doctor survives poisoned string battery_pct and flags PMIC OVER_VOLTAGE as fail
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "doc.json"
            save_config(d_cfg, cfg_p)
            poison_snap = NodeSnapshot(
                node=d_cfg.nodes[0],
                online=True,
                health={"battery_pct": "bad", "battery_status": "CHARGING", "battery_health": "OVER_VOLTAGE", "overheated": False, "ready_for_jobs": False},
            )
            with mock.patch.object(MasterController, "poll_health", return_value=[poison_snap]):
                rep = run_doctor(cfg_p, check_remote=True)
            self.assertEqual(rep["overall"], "fail")
            self.assertTrue(any(c["name"] == "Battery Hardware Health (PMIC)" and c["status"] == "fail" for c in rep["checks"]))

        # 8. TUI strips ANSI/OSC escapes from last_command_banner & interactive menu exits cleanly on EOF
        frame = render_top_frame(
            summary={"cluster_name": "c", "nodes": [], "safety": {}},
            history={"cluster": [], "nodes": {}},
            all_jobs=[],
            last_command_banner="\x1b]52;c;ZXZpbA==\x07\x1b[2Jclean_out",
            use_color=False,
        )
        self.assertNotIn("\x1b", frame)
        self.assertIn("clean_out", frame)
        def _eof_input(_p: str) -> str:
            raise EOFError()
        self.assertEqual(run_interactive_menu(input_fn=_eof_input), 0)

        # 9. Shell script hardening: 03_sync_cluster empty ssh_user IFS preservation + setup_pi_master & 05_workload_helpers guards
        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            sync_cfg = Path(tmp) / "sync.json"
            save_config(
                ClusterConfig(
                    cluster_name="sync-empty-user",
                    auth_token="tok-sync-empty-1234567890",
                    nodes=[
                        NodeConfig(id="node0", host="192.168.1.201", role="master", ssh_user=""),
                        NodeConfig(id="node1", host="192.168.1.202", role="worker", ssh_user=""),
                    ],
                ),
                sync_cfg,
            )
            # Verify pipe-delimited parsing keeps SSH_USER empty and preserves ROLE="worker"
            p_ifs = subprocess.run(
                [
                    "bash",
                    "-c",
                    'NODES_PSV="$(python3 - "$1" <<\'PY\'\n'
                    'import json, sys\n'
                    'cfg = json.load(open(sys.argv[1]))\n'
                    'for n in cfg["nodes"]:\n'
                    '    print("|".join([str(n["id"]), str(n["host"]), str(n.get("ssh_port", 8022)), str(n.get("ssh_user") or ""), str(n.get("role") or "worker")]))\n'
                    'PY\n'
                    ')"\n'
                    'while IFS="|" read -r ID H P U R; do echo "$ID:$U:$R"; done <<< "$NODES_PSV"',
                    "_",
                    str(sync_cfg),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(p_ifs.stdout.strip().splitlines(), ["node0::master", "node1::worker"])
            self.assertIn("IFS='|' read -r NODE_ID HOST SSH_PORT SSH_USER ROLE", (repo / "scripts" / "03_sync_cluster.sh").read_text(encoding="utf-8"))

        for bad_cmd in (
            ["bash", str(repo / "scripts" / "setup_pi_master.sh"), "--user", "bad;id"],
            ["bash", str(repo / "scripts" / "setup_pi_master.sh"), "--lan-subnet", "not-a-cidr"],
            ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "distcc-start", "-evil"],
            ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "distcc-start", "192.168.1.0/24", "0"],
            ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "llama-rpc-start", "/tmp", "99999"],
        ):
            proc = subprocess.run(bad_cmd, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 2, f"Expected exit 2 for {bad_cmd}, got {proc.returncode}: {proc.stderr}")

    def test_pass10_dns_rebinding_host_guard_webhook_ssrf_and_worker_type_validation(self) -> None:
        """Verify DNS-rebinding & duplicate-Host 403 guards across Dashboard/Worker/Pairing, webhook metadata SSRF block, batch caps, and strict worker /exec types."""
        from unittest import mock
        from phonecluster.auth import is_allowed_http_host, is_webhook_target_unsafe
        from phonecluster.pairing import PairingManager, StandalonePairingServer

        # 1. Unit checks for is_allowed_http_host
        for good_h in (
            "127.0.0.1:8080",
            "192.168.1.201:8080",
            "[::1]:8080",
            "localhost:8080",
            "raspberrypi",
            "raspberrypi.local:8080",
            "master.cluster",
            "pi-node.tail1234.ts.net:8080",
        ):
            self.assertTrue(is_allowed_http_host({"Host": good_h}), f"Should allow Host: {good_h}")
        self.assertTrue(is_allowed_http_host({"Host": "mycluster.example.org:8080"}, extra_allowed_hosts={"mycluster.example.org"}))
        with mock.patch.dict(os.environ, {"PHONECLUSTER_ALLOWED_HOSTS": "custom.domain.org"}):
            self.assertTrue(is_allowed_http_host({"Host": "custom.domain.org:8080"}))
        for bad_h in (
            "evil.com:8080",
            "192.168.1.201.nip.io:8080",
            "rebind.attacker.net",
            "localhost:99999",
            "localhost:abc",
            "::1",
            "[::1",
        ):
            self.assertFalse(is_allowed_http_host({"Host": bad_h}), f"Should reject Host: {bad_h}")

        # 2. Direct webhook SSRF target checks
        for unsafe_u in (
            "http://169.254.169.254/latest/meta-data/",
            "http://[fe80::1]/hook",
            "http://[::ffff:169.254.169.254]/hook",
            "http://0.0.0.0:8080/api/exec",
            "http://224.0.0.1/mcast",
            "file:///etc/passwd",
        ):
            self.assertTrue(is_webhook_target_unsafe(unsafe_u), f"Should block webhook target: {unsafe_u}")
        for safe_u in (
            "http://192.168.1.202:8123/api/webhook/battery",
            "http://127.0.0.1:1880/hook",
        ):
            self.assertFalse(is_webhook_target_unsafe(safe_u), f"Should allow local webhook target: {safe_u}")

        # 3. Live servers: Dashboard, Worker, and StandalonePairing all reject DNS-rebinding Host headers with 403
        tok = "pass10-hardening-tok-123456"
        st = WorkerState(
            node_id="node0",
            role="master",
            auth_token=tok,
            safety=SafetyConfig(max_temp_c=95.0, resume_temp_c=90.0, min_free_ram_mb=0),
            max_concurrency=2,
        )
        wsrv, _wg, w_ev = create_worker_server("127.0.0.1", 0, st)
        w_port = wsrv.server_address[1]
        wt = threading.Thread(target=wsrv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        wt.start()

        cfg = ClusterConfig(
            cluster_name="p10-sec",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=w_port)],
        )
        dash = DashboardHTTPServer(("127.0.0.1", 0), MasterController(cfg), enable_pairing_beacon=False, pairing_fail_delay_sec=0.0)
        d_port = dash.server_address[1]
        dt = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        dt.start()

        pm = PairingManager(config=cfg, enable_beacon=False, fail_delay_sec=0.0)
        pm.open_session(ttl_sec=60, max_devices=1)
        psrv = StandalonePairingServer(("127.0.0.1", 0), pm)
        p_port = psrv.server_address[1]
        pt = threading.Thread(target=psrv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        pt.start()

        def _raw_http(port: int, raw: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=4.0) as s:
                s.sendall(raw)
                s.settimeout(3.0)
                return s.recv(4096)

        try:
            # DNS-rebinding Host rejected (403) on Dashboard GET, duplicate Host, Worker GET, and Pairing GET
            self.assertIn(b"403 ", _raw_http(d_port, b"GET /api/live HTTP/1.1\r\nHost: evil.com:8080\r\nConnection: close\r\n\r\n"))
            self.assertIn(b"403 ", _raw_http(d_port, f"GET /api/live HTTP/1.1\r\nHost: 127.0.0.1:{d_port}\r\nHost: evil.com\r\nConnection: close\r\n\r\n".encode("ascii")))
            self.assertIn(b"200 ", _raw_http(d_port, f"HEAD / HTTP/1.1\r\nHost: 127.0.0.1:{d_port}\r\nConnection: close\r\n\r\n".encode("ascii")))
            self.assertIn(b"403 ", _raw_http(w_port, f"GET /health HTTP/1.1\r\nHost: evil.com:{w_port}\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n".encode("ascii")))
            self.assertIn(b"403 ", _raw_http(p_port, f"GET /api/pair/hello HTTP/1.1\r\nHost: evil.com:{p_port}\r\nConnection: close\r\n\r\n".encode("ascii")))

            # Dashboard blocks cloud metadata SSRF on /api/settings/test-webhook & enforces batch/pipeline caps
            def _post_code(port: int, path: str, body: dict[str, Any]) -> int:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}{path}",
                    data=json.dumps(body).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        return resp.status
                except urllib.error.HTTPError as exc:
                    exc.close()
                    return exc.code

            self.assertEqual(_post_code(d_port, "/api/settings/test-webhook", {"battery_webhook_url": "http://169.254.169.254/latest/meta-data/"}), 400)
            self.assertEqual(_post_code(d_port, "/api/settings/test-webhook", {"battery_webhook_url": "http://0.0.0.0:8080/"}), 400)
            self.assertEqual(_post_code(d_port, "/api/pipeline", {"steps": [{"command": "echo x"}] * 101}), 400)
            self.assertEqual(_post_code(d_port, "/api/map", {"mode": "commands", "commands": ["echo x"] * 2001}), 400)

            # Worker /exec strictly rejects non-string command/script_content and NUL bytes with 400
            for bad_exec in (
                {"command": ["ls"]},
                {"script_content": 12345},
                {"command": "echo\x00hi"},
                {"script_content": "print(1)", "interpreter": "python3\x00"},
                {"script_content": "print(1)", "args": ["ok", "bad\x00arg"]},
            ):
                self.assertEqual(_post_code(w_port, "/exec", bad_exec), 400, f"Expected 400 for {bad_exec}")
        finally:
            pm.close_session()
            psrv.shutdown()
            psrv.server_close()
            dash.shutdown()
            dash.server_close()
            w_ev.set()
            wsrv.shutdown()
            wsrv.server_close()
            pt.join(timeout=2.0)
            dt.join(timeout=2.0)
            wt.join(timeout=2.0)

    def test_pass10_unicode_isdigit_pid_reuse_guard_authorized_keys_mode_and_http10_expect(self) -> None:
        """Verify Unicode superscript isdigit safety, stale PID-file reuse guard, 0600 authorized_keys creation, and HTTP/1.0 Expect: 100-continue compliance."""
        import base64
        import socketserver
        import stat
        import subprocess
        from unittest import mock
        from phonecluster.config import DEFAULT_SSH_PORT
        from phonecluster.pairing import _install_ssh_pubkey
        from phonecluster.routing import select_snapshots_for_target
        from phonecluster.wizard import run_setup_wizard

        # 1. Unicode superscript '²' does not crash tier routing or setup wizard
        matched, reason = select_snapshots_for_target([], target="tier:\u00b2")
        self.assertEqual(matched, [])
        self.assertIn("Invalid tier target", reason)

        with tempfile.TemporaryDirectory() as tmp:
            from phonecluster.telemetry import detect_os_environment
            wiz_cfg = Path(tmp) / "wiz_u.json"
            answers = iter(["u-cluster", "127.0.0.1", "", "\u00b2", "n", "", "40", ""])
            self.assertEqual(run_setup_wizard(wiz_cfg, input_fn=lambda _p: next(answers)), 0)
            expected_ssh_port = DEFAULT_SSH_PORT if detect_os_environment() == "termux" else 22
            self.assertEqual(load_config(wiz_cfg).nodes[0].ssh_port, expected_ssh_port)

            # 2. _install_ssh_pubkey creates authorized_keys with atomic 0600 mode
            fake_home = Path(tmp) / "home"
            fake_home.mkdir()
            valid_blob = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + b"B" * 32).decode("ascii")
            with mock.patch.object(Path, "home", return_value=fake_home):
                self.assertTrue(_install_ssh_pubkey(f"ssh-ed25519 {valid_blob} test@master"))
            ak_path = fake_home / ".ssh" / "authorized_keys"
            self.assertTrue(ak_path.exists())
            self.assertEqual(stat.S_IMODE(os.stat(ak_path).st_mode) & 0o077, 0)

            # 3. 05_workload_helpers.sh llama-rpc-stop NEVER kills an unrelated process whose PID was reused in a stale .pid file
            repo = Path(__file__).resolve().parent.parent
            innocent = subprocess.Popen(["sleep", "30"])
            try:
                fake_tmp = Path(tmp) / "tmp_pid"
                fake_tmp.mkdir()
                stale_pid_file = fake_tmp / "llama-rpc-50052.pid"
                stale_pid_file.write_text(f"{innocent.pid}\n", encoding="utf-8")
                env_run = os.environ.copy()
                env_run["HOME"] = str(fake_home)
                env_run["TMPDIR"] = str(fake_tmp)
                subprocess.run(
                    ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "llama-rpc-stop"],
                    env=env_run,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertIsNone(innocent.poll(), "Stale PID-file cleanup MUST NOT kill an unrelated process!")
                self.assertFalse(stale_pid_file.exists())
            finally:
                innocent.terminate()
                innocent.wait(timeout=3.0)

        # 4. Proxy does NOT send HTTP/1.1 100 Continue to an HTTP/1.0 client
        class _OkUp(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(2.0)
                try:
                    self.request.recv(4096)
                    self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except OSError:
                    pass

        class _ReuseUp(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up = _ReuseUp(("127.0.0.1", 0), _OkUp)
        up_port = up.server_address[1]
        threading.Thread(target=up.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        w_tok = "p10-http10-worker-tok-123"
        gw_cfg = ClusterConfig(
            cluster_name="p10-http10",
            auth_token="p10-http10-master-tok-123",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1"],
                allowed_ports=[up_port],
                block_private_ips=False,
            ),
        )
        gw = GatewayManager(gw_cfg)
        ok, msg = gw.start()
        self.assertTrue(ok, msg)
        auth_b64 = base64.b64encode(f"node1:{derive_proxy_password(w_tok, 'node1')}".encode("utf-8")).decode("ascii")
        try:
            with socket.create_connection(("127.0.0.1", gw.bound_port), timeout=4.0) as s:
                s.sendall(
                    f"POST http://127.0.0.1:{up_port}/h10 HTTP/1.0\r\n"
                    f"Host: 127.0.0.1:{up_port}\r\n"
                    f"Proxy-Authorization: Basic {auth_b64}\r\n"
                    f"Expect: 100-continue\r\n"
                    f"Content-Length: 2\r\n\r\nhi".encode("ascii")
                )
                s.settimeout(3.0)
                resp_b = s.recv(4096)
                self.assertNotIn(b"100 Continue", resp_b)
                self.assertIn(b"200 OK", resp_b)
        finally:
            gw.stop()
            up.shutdown()
            up.server_close()


class TestPass11HardeningAndBugHunt(unittest.TestCase):
    """Regression suite for Pass 11 security, stability, networking, UI, CLI, and script fixes."""

    def test_config_auth_ipv6_zone_null_bool_and_webhook_hardening(self) -> None:
        from phonecluster.auth import is_allowed_http_host, is_webhook_target_unsafe
        from phonecluster.config import (
            GatewayConfig,
            NetworkHardeningConfig,
            SafetyConfig,
            is_loopback_or_unspecified_host,
            validate_domain_pattern,
            validate_host,
        )

        # 1. IPv6 % zone IDs, DEL, and malformed multi-dot hostnames rejected
        for bad_host in ("fe80::1%$(id)", "fe80::1%eth0", "foo..bar", "foo...", "bad\x7fhost"):
            with self.assertRaises(ValueError, msg=f"validate_host should reject {bad_host!r}"):
                validate_host(bad_host)
        for bad_dom in ("*.evil\x7f.com", "fe80::1%eth0", "a..b.com"):
            with self.assertRaises(ValueError, msg=f"validate_domain_pattern should reject {bad_dom!r}"):
                validate_domain_pattern(bad_dom)

        # 2. Trailing-dot localhost detected as loopback
        self.assertTrue(is_loopback_or_unspecified_host("localhost."))
        self.assertTrue(is_loopback_or_unspecified_host("LOCALHOST."))

        # 3. Host header guard rejects IPv6 scope IDs and malformed suffix-only / XSS hosts
        for bad_hdr in (
            "[::1%evil.com]:8080",
            ".local",
            ".local:8080",
            "..localhost",
            "foo<script>.ts.net",
            "bad..host.lan",
        ):
            self.assertFalse(is_allowed_http_host({"Host": bad_hdr}), f"Host header {bad_hdr!r} must be rejected")
        self.assertTrue(is_allowed_http_host({"Host": "my-phone.local:8080"}))
        self.assertTrue(is_allowed_http_host({"Host": "[::1]:8080"}))

        # 4. Webhook SSRF guard rejects explicit :0, NAT64 embedded metadata, and remote->localhost. / NAT64 loopback redirects
        from phonecluster.auth import _is_webhook_redirect_target_unsafe
        self.assertTrue(is_webhook_target_unsafe("http://example.com:0/hook"))
        self.assertTrue(is_webhook_target_unsafe("http://[64:ff9b::169.254.169.254]/hook"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/topic", "http://localhost./hook"))
        self.assertTrue(_is_webhook_redirect_target_unsafe("https://ntfy.sh/topic", "http://[64:ff9b::127.0.0.1]/hook"))

        # 5. Strict config deserialization: no None->'None', no bool->int, no NaN, null preserves secure defaults
        with self.assertRaises(ValueError):
            NodeConfig.from_dict({"id": None, "host": "127.0.0.1"})
        with self.assertRaises(ValueError):
            NodeConfig.from_dict({"id": "n1", "host": None})
        with self.assertRaises(ValueError):
            NodeConfig.from_dict({"id": "n1", "host": "127.0.0.1", "worker_port": True})
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"max_temp_c": True})
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"max_temp_c": float("nan")})
        with self.assertRaises(ValueError):
            NetworkHardeningConfig.from_dict({"adguard_url": "http://10.0.0.2:0"})

        gw_null = GatewayConfig.from_dict({"block_private_ips": None, "inject_proxy_env": None})
        self.assertTrue(gw_null.block_private_ips)
        self.assertTrue(gw_null.inject_proxy_env)

    def test_core_master_worker_telemetry_and_routing_fixes(self) -> None:
        import socketserver
        from unittest import mock

        from phonecluster.master import _safe_float, _safe_int
        from phonecluster.routing import resolve_node_tier_and_pool
        from phonecluster.telemetry import NetSampler
        from phonecluster.worker import WorkerState, create_worker_server

        # 1. _safe_int / _safe_float reject bool
        self.assertEqual(_safe_int(False, -1), -1)
        self.assertEqual(_safe_int(True, -1), -1)
        self.assertEqual(_safe_float(True, 9.5), 9.5)

        # 2. routing ignores non-str os_env=None / pool=True
        n_plain = NodeConfig(id="n1", host="127.0.0.1", role="worker")
        tier, pool = resolve_node_tier_and_pool(n_plain, {"os_env": None, "pool": True})
        self.assertEqual(tier, 1)
        self.assertEqual(pool, "compute")

        # 3. NetSampler preserves baseline across rapid (<0.2s) polls instead of starving to (0.0, 0.0)
        with mock.patch("phonecluster.telemetry._read_net_bytes", side_effect=[(0, 0), (10240, 20480), (10240, 20480)]):
            with mock.patch("phonecluster.telemetry.time.monotonic", side_effect=[100.0, 101.0, 101.05]):
                sampler = NetSampler()
                r1 = sampler.sample()
                self.assertAlmostEqual(r1[0], 10.0, places=1)
                self.assertAlmostEqual(r1[1], 20.0, places=1)
                # Rapid poll within 0.05s returns cached rate without wiping baseline
                r2 = sampler.sample()
                self.assertEqual(r2, r1)

        # 4. cluster_summary CPU % never exceeds 100% when cpu_cores==0, and RAM % clamped [0, 100]
        tok = "p11-core-tok-123456"
        cfg = ClusterConfig(
            cluster_name="p11-core",
            auth_token=tok,
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765)],
        )
        ctrl = MasterController(cfg)
        fake_status = NodeSnapshot(
            node=cfg.nodes[0],
            online=True,
            latency_ms=1.0,
            health={
                "cpu_cores": 0,
                "cpu_pct": 50.0,
                "mem_total_mb": 100,
                "mem_available_mb": 200,
                "ready_for_jobs": True,
            },
        )
        with mock.patch.object(ctrl, "poll_health", return_value=[fake_status]):
            summary = ctrl.cluster_summary()
        self.assertLessEqual(summary["cluster_cpu_pct"], 100.0)
        self.assertGreaterEqual(summary["cluster_ram_pct"], 0.0)
        self.assertLessEqual(summary["cluster_ram_pct"], 100.0)

        # 5. MasterController handles http.client.BadStatusLine AND boolean returncode safely
        class _BadHttpHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    self.request.settimeout(1.0)
                    raw = self.request.recv(4096)
                    if b"/exec" in raw:
                        body = json.dumps({"ok": True, "returncode": False, "stdout": "spoof"}).encode("utf-8")
                        self.request.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                            + body
                        )
                    else:
                        self.request.sendall(b"GARBAGE_NOT_HTTP\r\n\r\n")
                except OSError:
                    pass

        class _ReuseSrv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        bad_srv = _ReuseSrv(("127.0.0.1", 0), _BadHttpHandler)
        bad_port = bad_srv.server_address[1]
        threading.Thread(target=bad_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            bad_node = NodeConfig(id="bad1", host="127.0.0.1", role="worker", worker_port=bad_port)
            bad_ctrl = MasterController(ClusterConfig(cluster_name="bad", auth_token=tok, nodes=[bad_node]))
            st = bad_ctrl.check_node_health(bad_node)
            self.assertFalse(st.online)
            self.assertTrue(bool(st.error))
            spec_bad = JobSpec(index=0, job_id="j-bad-bool", command="echo hi", timeout_sec=5.0)
            kind, data = bad_ctrl.exec_on_node(bad_node, spec_bad)
            out = bad_ctrl._to_outcome(spec_bad, bad_node.id, kind, data, attempts=1)
            self.assertEqual(out.returncode, -1)
            self.assertFalse(out.ok)
        finally:
            bad_srv.shutdown()
            bad_srv.server_close()

        # 6. WorkerState slot leak guard, non-list not_ready_reasons, partial live config merge, and /exec input validation
        w_state = WorkerState(
            node_id="w11",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            allowed_client_ips={"10.0.0.5"},
        )
        # Bool max_concurrency is rejected with 400 without mutating state
        st_mc, _ = w_state.apply_live_config({"max_concurrency": True})
        self.assertEqual(st_mc, 400)
        self.assertEqual(w_state.max_concurrency, 2)
        # Partial network push must NOT wipe allowed_client_ips
        st_net, _ = w_state.apply_live_config({"network": {"require_signed_requests": True}})
        self.assertEqual(st_net, 200)
        self.assertIn("10.0.0.5", w_state.allowed_client_ips)
        self.assertTrue(w_state.require_signed_requests)

        # ready_for_jobs=False with non-list or empty not_ready_reasons still blocks jobs without crashing
        w_state.health_provider = lambda: {"ready_for_jobs": False, "not_ready_reasons": "overheated"}
        ok_r, info_r = w_state.try_reserve_slot("j-block", "echo hi")
        self.assertFalse(ok_r)
        self.assertTrue(info_r.get("reasons"))
        w_state.health_provider = lambda: {"ready_for_jobs": False, "not_ready_reasons": []}
        ok_r2, _ = w_state.try_reserve_slot("j-block2", "echo hi")
        self.assertFalse(ok_r2)

        # Exception during try_reserve_slot (both fast path and custom health_provider) must NOT leak active_jobs slot
        w_state.health_provider = None
        with mock.patch("phonecluster.worker.collect_node_health", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                w_state.try_reserve_slot("j-leak", "echo hi")
        self.assertNotIn("j-leak", w_state.active_jobs)

        # Live worker HTTP /exec validation checks
        w_http_state = WorkerState(
            node_id="w11-http",
            role="worker",
            auth_token=tok,
            safety=SafetyConfig(),
            max_concurrency=2,
            health_provider=lambda: {
                "ready_for_jobs": True,
                "not_ready_reasons": [],
                "temp_c": 30.0,
                "mem_total_mb": 4096,
                "mem_available_mb": 3000,
                "cpu_cores": 4,
                "load_1m": 0.1,
            },
        )
        w_srv, _w_g, w_ev = create_worker_server("127.0.0.1", 0, w_http_state)
        w_port = w_srv.server_address[1]
        threading.Thread(target=w_srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        try:
            for bad_payload in (
                {"command": "echo hi", "job_id": "bad\x00id"},
                {"command": "echo hi", "timeout_sec": True},
                {"command": "echo hi", "workdir": "~nonexistent_pc_user_xyz_999"},
                {"script_content": "echo hi", "interpreter": "sh", "args": "'unclosed"},
            ):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{w_port}/exec",
                    data=json.dumps(bad_payload).encode("utf-8"),
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as exc:
                    urllib.request.urlopen(req, timeout=3.0)
                try:
                    self.assertEqual(exc.exception.code, 400, f"Expected 400 for {bad_payload!r}")
                finally:
                    exc.exception.close()

            # 7. run_pipeline resets prev_* env on validation error when continue_on_error=True
            p_cfg = ClusterConfig(
                cluster_name="p11-pipe",
                auth_token=tok,
                nodes=[NodeConfig(id="w11-http", host="127.0.0.1", role="worker", worker_port=w_port)],
            )
            p_ctrl = MasterController(p_cfg)
            pipe_res = p_ctrl.run_pipeline(
                steps=[
                    {"name": "s1", "target": "w11-http", "command": "echo SECRET_PREV_OUT"},
                    {"name": "s2-bad", "target": "w11-http", "command": "echo x", "timeout_sec": True},
                    {"name": "s3", "target": "w11-http", "command": 'printf "PREV=[%s]" "$PHONECLUSTER_PREV_STDOUT"'},
                ],
                stop_on_error=False,
            )
            self.assertEqual(len(pipe_res["results"]), 3)
            self.assertTrue(pipe_res["results"][0]["ok"])
            self.assertEqual(pipe_res["results"][0]["stdout"].strip(), "SECRET_PREV_OUT")
            self.assertFalse(pipe_res["results"][1]["ok"])
            self.assertTrue(pipe_res["results"][2]["ok"])
            self.assertEqual(pipe_res["results"][2]["stdout"], "PREV=[]")
        finally:
            w_ev.set()
            w_srv.shutdown()
            w_srv.server_close()

    def test_gateway_http_response_relay_smuggling_head_204_and_14k_headers(self) -> None:
        import socketserver
        from phonecluster.gateway import derive_proxy_password

        class _KeepAliveUpstream(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(5.0)
                try:
                    buf = bytearray()
                    while b"\r\n\r\n" not in buf and len(buf) < 65536:
                        c = self.request.recv(4096)
                        if not c:
                            return
                        buf.extend(c)
                    head_end = buf.find(b"\r\n\r\n")
                    req_line = buf[: buf.find(b"\r\n")].decode("iso-8859-1", errors="replace")
                    if req_line.startswith("HEAD /head-test"):
                        self.request.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n"
                            b"Connection: keep-alive, X-Custom-Hop\r\n"
                            b"Keep-Alive: timeout=30\r\n"
                            b"Proxy-Secret: leak\r\n"
                            b"X-Custom-Hop: dropme\r\n\r\n"
                        )
                        # Deliberately hold socket open to ensure proxy does NOT stall for idle_timeout!
                        time.sleep(3.0)
                    elif req_line.startswith("GET /no-content"):
                        self.request.sendall(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
                        time.sleep(3.0)
                    elif req_line.startswith("GET /chunked"):
                        self.request.sendall(
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                            b"Content-Length: 999\r\nConnection: keep-alive\r\n\r\n"
                            b"5\r\nhello\r\n0\r\n\r\n"
                        )
                        time.sleep(3.0)
                    elif req_line.startswith("POST /big-head"):
                        # Drain 4096-byte body
                        body_have = len(buf) - (head_end + 4)
                        while body_have < 4096:
                            c = self.request.recv(4096)
                            if not c:
                                break
                            body_have += len(c)
                        resp_b = f"got={body_have}".encode("ascii")
                        self.request.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: "
                            + str(len(resp_b)).encode("ascii")
                            + b"\r\nConnection: close\r\n\r\n"
                            + resp_b
                        )
                except OSError:
                    pass

        class _ReuseUp(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        up = _ReuseUp(("127.0.0.1", 0), _KeepAliveUpstream)
        up_port = up.server_address[1]
        threading.Thread(target=up.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

        w_tok = "p11-gw-worker-token-999"
        gw_cfg = ClusterConfig(
            cluster_name="p11-gw",
            auth_token="p11-gw-master-token-999",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, auth_token=w_tok),
            ],
            gateway=GatewayConfig(
                enabled=True,
                bind_host="127.0.0.1",
                port=0,
                mode="allowlist",
                allowed_domains=["127.0.0.1", "::1"],
                allowed_ports=[up_port],
                block_private_ips=False,
            ),
        )
        gw = GatewayManager(gw_cfg)
        ok, msg = gw.start()
        self.assertTrue(ok, msg)
        auth_b64 = base64.b64encode(f"node1:{derive_proxy_password(w_tok, 'node1')}".encode("utf-8")).decode("ascii")

        def _raw_proxy_call(payload: bytes) -> tuple[bytes, float]:
            t0 = time.monotonic()
            with socket.create_connection(("127.0.0.1", gw.bound_port), timeout=4.0) as s:
                s.settimeout(4.0)
                s.sendall(payload)
                out = bytearray()
                while True:
                    c = s.recv(4096)
                    if not c:
                        break
                    out.extend(c)
            return bytes(out), time.monotonic() - t0

        try:
            # 1. HEAD finishes immediately without 30s hang, strips hop-by-hop/Proxy-*, sets Connection: close
            resp_h, dt_h = _raw_proxy_call(
                f"HEAD http://127.0.0.1:{up_port}/head-test HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertLess(dt_h, 1.5, f"HEAD hung for {dt_h:.2f}s")
            self.assertIn(b"200 OK", resp_h)
            self.assertIn(b"Connection: close", resp_h)
            self.assertNotIn(b"Proxy-Secret", resp_h)
            self.assertNotIn(b"X-Custom-Hop", resp_h)
            self.assertNotIn(b"Keep-Alive", resp_h)

            # 2. 204 No Content finishes immediately
            resp_204, dt_204 = _raw_proxy_call(
                f"GET http://127.0.0.1:{up_port}/no-content HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertLess(dt_204, 1.5)
            self.assertIn(b"204 No Content", resp_204)

            # 3. Chunked + conflicting Content-Length strips Content-Length and finishes immediately
            resp_ch, dt_ch = _raw_proxy_call(
                f"GET http://127.0.0.1:{up_port}/chunked HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertLess(dt_ch, 1.5)
            self.assertNotIn(b"Content-Length: 999", resp_ch)
            self.assertIn(b"5\r\nhello\r\n0\r\n\r\n", resp_ch)

            # 4. 14 KiB headers + 4 KiB body succeeds (headers alone < 16 KiB)
            big_hdr = "".join(f"X-Pad-{i:03d}: " + ("a" * 120) + "\r\n" for i in range(100))
            body_4k = b"B" * 4096
            resp_big, _ = _raw_proxy_call(
                f"POST http://127.0.0.1:{up_port}/big-head HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\nProxy-Authorization: Basic {auth_b64}\r\n"
                f"{big_hdr}Content-Length: 4096\r\n\r\n".encode("ascii")
                + body_4k
            )
            self.assertIn(b"200 OK", resp_big)
            self.assertIn(b"got=4096", resp_big)

            # 5. Port :0 and HTTP/1.0 Transfer-Encoding: chunked rejected with 400
            resp_p0, _ = _raw_proxy_call(
                f"GET http://127.0.0.1:0/bad HTTP/1.1\r\n"
                f"Host: 127.0.0.1:0\r\nProxy-Authorization: Basic {auth_b64}\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", resp_p0)

            resp_te10, _ = _raw_proxy_call(
                f"POST http://127.0.0.1:{up_port}/te10 HTTP/1.0\r\n"
                f"Host: 127.0.0.1:{up_port}\r\nProxy-Authorization: Basic {auth_b64}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode("ascii")
            )
            self.assertIn(b"400 Bad Request", resp_te10)

            # 6. IPv6 canonicalization in evaluate_policy
            allowed_v6, _ = evaluate_policy("0:0:0:0:0:0:0:1", up_port, gw_cfg.gateway)
            self.assertTrue(allowed_v6)
        finally:
            gw.stop()
            up.shutdown()
            up.server_close()

    def test_pairing_replay_rollback_udp_inf_netguard_and_doctor(self) -> None:
        from unittest import mock

        from phonecluster.discovery import REPLY_TYPE, discover_lan_nodes
        from phonecluster.doctor import run_doctor
        from phonecluster.netguard import apply_security_profile, infer_lan_subnet
        from phonecluster.pairing import (
            PAIR_BEACON_TYPE,
            PairingManager,
            compute_proof,
            compute_shared_secret,
            derive_pairing_keys,
            discover_pairing_masters,
            generate_dh_keypair,
        )

        # 1. Multi-device pairing rejects passive replay of client_proof / peer_pub
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "cluster.json"
            cfg = ClusterConfig(
                cluster_name="p11-pair",
                auth_token="p11-pair-master-tok",
                nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765)],
            )
            save_config(cfg, cfg_p)
            pm = PairingManager(cfg, config_path=cfg_p, pair_port=8767, enable_beacon=False, fail_delay_sec=0.0)
            opened = pm.open_session(ttl_sec=120, max_devices=2)
            pin = opened["pin"]
            h_code, hello = pm.public_hello()
            self.assertEqual(h_code, 200)
            sid = hello["session_id"]
            salt_hex = hello["salt"]
            srv_pub_hex = hello["dh_pub"]
            srv_pub = int(srv_pub_hex, 16)

            c_priv, c_pub = generate_dh_keypair()
            c_pub_hex = format(c_pub, "x")
            secret = compute_shared_secret(c_priv, srv_pub)
            k_auth, _enc, _mac = derive_pairing_keys(pin, secret, salt_hex, sid)
            meta = {"hostname": "phone-a", "worker_port": 8765, "ssh_port": 8022, "cpu_cores": 8, "mem_total_mb": 4096}
            meta_canonical = json.dumps(meta, sort_keys=True, separators=(",", ":"))
            proof = compute_proof(k_auth, "client", sid, srv_pub_hex, c_pub_hex, meta_canonical)

            code1, res1 = pm.complete_pairing(
                "10.0.0.21",
                {"session_id": sid, "dh_pub": c_pub_hex, "client_proof": proof, "metadata": meta},
            )
            self.assertEqual(code1, 200, res1)
            self.assertEqual(pm.admin_status()["remaining_slots"], 1)

            # Passive attacker replays exact proof from another IP: MUST be rejected (403) and slot preserved!
            code_rep, res_rep = pm.complete_pairing(
                "10.0.0.99",
                {"session_id": sid, "dh_pub": c_pub_hex, "client_proof": proof, "metadata": meta},
            )
            self.assertEqual(code_rep, 403, res_rep)
            self.assertEqual(pm.admin_status()["remaining_slots"], 1)
            self.assertNotIn("node2", [n.id for n in cfg.nodes])

            # 2. Rollback in-memory config if save_config fails
            c2_priv, c2_pub = generate_dh_keypair()
            c2_pub_hex = format(c2_pub, "x")
            sec2 = compute_shared_secret(c2_priv, srv_pub)
            ka2, _, _ = derive_pairing_keys(pin, sec2, salt_hex, sid)
            proof2 = compute_proof(ka2, "client", sid, srv_pub_hex, c2_pub_hex, meta_canonical)
            with mock.patch("phonecluster.pairing.save_config", side_effect=OSError("disk full")):
                code_fail, _ = pm.complete_pairing(
                    "10.0.0.22",
                    {"session_id": sid, "dh_pub": c2_pub_hex, "client_proof": proof2, "metadata": meta},
                )
            self.assertEqual(code_fail, 500)
            self.assertEqual(len(cfg.nodes), 2)
            self.assertEqual(pm.admin_status()["remaining_slots"], 1)
            pm.close_session()

        # 3. UDP discovery / pairing survive 1e400 (Infinity) and bool poison packets
        udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_srv.bind(("127.0.0.1", 0))
        udp_port = udp_srv.getsockname()[1]
        udp_srv.settimeout(0.15)
        stop_ev = threading.Event()

        def _inf_responder() -> None:
            while not stop_ev.is_set():
                try:
                    raw, addr = udp_srv.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                msg = json.loads(raw.decode("utf-8"))
                if msg.get("type") == "phonecluster_discover_v1":
                    for p in (
                        b'{"type":"' + REPLY_TYPE.encode() + b'","worker_port":1e400}',
                        b'{"type":"' + REPLY_TYPE.encode() + b'","worker_port":true}',
                        json.dumps({"type": REPLY_TYPE, "node_id": "clean1", "worker_port": 8765, "ssh_port": 8022}).encode(),
                    ):
                        udp_srv.sendto(p, addr)
                else:
                    for p in (
                        b'{"type":"' + PAIR_BEACON_TYPE.encode() + b'","pair_port":1e400}',
                        b'{"type":"' + PAIR_BEACON_TYPE.encode() + b'","pair_port":true}',
                        json.dumps({"type": PAIR_BEACON_TYPE, "pair_port": 8767, "cluster_name": "cleanm", "expires_in_sec": 30}).encode(),
                    ):
                        udp_srv.sendto(p, addr)

        t_u = threading.Thread(target=_inf_responder, daemon=True)
        t_u.start()
        try:
            n_found = discover_lan_nodes(timeout_sec=0.35, discovery_port=udp_port, targets=["127.0.0.1"])
            self.assertEqual(len(n_found), 1)
            self.assertEqual(n_found[0]["node_id"], "clean1")
            m_found = discover_pairing_masters(timeout_sec=0.35, discovery_port=udp_port, targets=["127.0.0.1"])
            self.assertEqual(len(m_found), 1)
            self.assertEqual(m_found[0]["cluster_name"], "cleanm")
        finally:
            stop_ev.set()
            udp_srv.close()
            t_u.join(timeout=2.0)

        # 4. netguard infer_lan_subnet rejects 0.0.0.0 and apply_security_profile doesn't mutate on invalid profile
        self.assertNotEqual(infer_lan_subnet("0.0.0.0"), "0.0.0.0/24")
        self.assertEqual(infer_lan_subnet("192.168.42.9"), "192.168.42.0/24")
        ng_cfg = ClusterConfig(
            cluster_name="p11-ng",
            auth_token="p11-ng-tok",
            nodes=[NodeConfig(id="node0", host="192.168.42.9", role="master")],
        )
        orig_ips = list(ng_cfg.network.allowed_master_ips)
        with self.assertRaises(ValueError):
            apply_security_profile(ng_cfg, "totally-invalid-profile")
        self.assertEqual(ng_cfg.network.allowed_master_ips, orig_ips)

        # 5. doctor warns when gateway.enabled=True and gateway.port==0
        with tempfile.TemporaryDirectory() as tmp:
            doc_p = Path(tmp) / "doc.json"
            doc_cfg = ClusterConfig(
                cluster_name="p11-doc",
                auth_token="p11-doc-tok",
                nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master")],
                gateway=GatewayConfig(enabled=True, bind_host="127.0.0.1", port=0),
            )
            save_config(doc_cfg, doc_p)
            rep = run_doctor(config_path=doc_p, check_remote=False)
        gw_checks = [c for c in rep["checks"] if "Network Guard" in c.get("name", "")]
        self.assertTrue(gw_checks)
        self.assertEqual(gw_checks[0]["status"], "warn")

    def test_dashboard_atomic_api_xss_tui_cli_and_scripts(self) -> None:
        import subprocess
        from typing import Any
        from unittest import mock

        from phonecluster.cli import main as cli_main
        from phonecluster.dashboard import DASHBOARD_HTML, DashboardHTTPServer
        from phonecluster.tui import _format_uptime, _read_key

        # 1. Dashboard API atomic validation, null preservation, case-insensitive service remove, last-node guard
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "cluster.json"
            tok = "p11-dash-token-123456"
            cfg = ClusterConfig(
                cluster_name="p11-dash",
                auth_token=tok,
                nodes=[
                    NodeConfig(id="node0", host="127.0.0.1", role="master", worker_port=8765, ssh_port=8022),
                    NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=8766, ssh_port=8022),
                ],
                gateway=GatewayConfig(
                    enabled=False,
                    block_private_ips=True,
                    quarantined_nodes=["node1"],
                ),
            )
            save_config(cfg, cfg_p)
            ctrl = MasterController(cfg)
            dash = DashboardHTTPServer(
                ("127.0.0.1", 0),
                ctrl,
                config_path=cfg_p,
                enable_pairing_beacon=False,
                pairing_fail_delay_sec=0.0,
            )
            d_port = dash.server_address[1]
            threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

            def _dash_post(path: str, raw_body: bytes) -> tuple[int, dict[str, Any]]:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}{path}",
                    data=raw_body,
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    try:
                        return exc.code, json.loads(exc.read().decode("utf-8"))
                    finally:
                        exc.close()

            try:
                # Partial mutation guard on /api/nodes/update
                st1, _ = _dash_post(
                    "/api/nodes/update",
                    json.dumps({"id": "node1", "tier": 2, "max_concurrency": 999}).encode("utf-8"),
                )
                self.assertEqual(st1, 400)
                self.assertEqual(cfg.get_node("node1").tier, 0)  # type: ignore[union-attr]

                # Partial mutation guard on /api/network/hardening
                st2, _ = _dash_post(
                    "/api/network/hardening",
                    json.dumps({"dashboard_require_auth": True, "enforce_worker_source_ip": True, "adguard_url": "ftp://invalid"}).encode("utf-8"),
                )
                self.assertEqual(st2, 400)
                self.assertFalse(cfg.dashboard_require_auth)
                self.assertFalse(cfg.network.enforce_worker_source_ip)

                # JSON null in /api/gateway/settings must NOT disable block_private_ips or clear quarantine
                st3, _ = _dash_post(
                    "/api/gateway/settings",
                    json.dumps({"block_private_ips": None, "quarantined_nodes": None}).encode("utf-8"),
                )
                self.assertEqual(st3, 200)
                self.assertTrue(cfg.gateway.block_private_ips)
                self.assertEqual(cfg.gateway.quarantined_nodes, ["node1"])

                # Case-insensitive custom service removal (works even for pre-existing mixed-case keys in cluster.json)
                st_add, _ = _dash_post(
                    "/api/services/custom",
                    json.dumps({"name": "myapp", "url": "http://127.0.0.1:9000"}).encode("utf-8"),
                )
                self.assertEqual(st_add, 200)
                self.assertEqual(len(cfg.custom_services), 1)
                cfg.custom_services["MixedApp"] = "http://127.0.0.1:9001"
                st_rm1_s, _ = _dash_post("/api/services/custom/remove", json.dumps({"name": "MYAPP"}).encode("utf-8"))
                self.assertEqual(st_rm1_s, 200)
                st_rm2_s, _ = _dash_post("/api/services/custom/remove", json.dumps({"name": "mixedapp"}).encode("utf-8"))
                self.assertEqual(st_rm2_s, 200)
                self.assertEqual(len(cfg.custom_services), 0)

                # NaN JSON rejected with 400
                st_nan, _ = _dash_post("/api/exec", b'{"command":"echo hi","timeout_sec":NaN}')
                self.assertEqual(st_nan, 400)

                # Removing node1 succeeds, then removing last remaining node (node0) is blocked with 400
                st_rm1, _ = _dash_post("/api/nodes/remove", json.dumps({"id": "node1"}).encode("utf-8"))
                self.assertEqual(st_rm1, 200)
                st_rm0, _ = _dash_post("/api/nodes/remove", json.dumps({"id": "node0"}).encode("utf-8"))
                self.assertEqual(st_rm0, 400)
                self.assertEqual(len(cfg.nodes), 1)
            finally:
                dash.shutdown()
                dash.server_close()

        # 2. Dashboard HTML escapes worker active_jobs / max_concurrency / cpu_cores and guards top_processes
        self.assertIn("esc(actNum)", DASHBOARD_HTML)
        self.assertIn("esc(maxNum)", DASHBOARD_HTML)
        self.assertIn("esc(cores)", DASHBOARD_HTML)
        self.assertIn("Array.isArray(h.top_processes)", DASHBOARD_HTML)

        # 3. TUI negative uptime & stdin EOF handling
        self.assertEqual(_format_uptime(-5), "0m")
        with mock.patch("phonecluster.tui.select.select", return_value=([0], [], [])):
            with mock.patch("phonecluster.tui.os.read", return_value=b""):
                self.assertEqual(_read_key(0.01), "EOF")

        # 4. CLI validation: --max-concurrency 0 and huge --timeout fail cleanly with exit 2
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "c.json"
            save_config(
                ClusterConfig(
                    cluster_name="p11-cli",
                    auth_token="p11-cli-tok",
                    nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master")],
                ),
                cfg_p,
            )
            self.assertEqual(cli_main(["--config", str(cfg_p), "worker", "--node-id", "node0", "--max-concurrency", "0"]), 2)
            self.assertEqual(cli_main(["--config", str(cfg_p), "run", "--timeout", "1e10", "echo hi"]), 2)

        # 5. Shell scripts hardening checks
        repo = Path(__file__).resolve().parent.parent
        p_unk = subprocess.run(
            ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "definitely-unknown-subcmd"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p_unk.returncode, 2)
        p_hlp = subprocess.run(
            ["bash", str(repo / "scripts" / "05_workload_helpers.sh"), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p_hlp.returncode, 0)

        sync_sh = (repo / "scripts" / "03_sync_cluster.sh").read_text(encoding="utf-8")
        self.assertIn("<&3", sync_sh)
        self.assertIn("SQ_NID", sync_sh)
        self.assertIn("SQ_RDIR", sync_sh)

        chroot_sh = (repo / "scripts" / "04_debian13_chroot_setup.sh").read_text(encoding="utf-8")
        self.assertNotIn("zcat /proc/config.gz 2>/dev/null | grep -q", chroot_sh)

        adb_sh = (repo / "scripts" / "setup_all_via_adb.sh").read_text(encoding="utf-8")
        self.assertNotIn("mapfile ", adb_sh)
        self.assertNotIn("install -r --", adb_sh)


class TestPass12HardeningAndBugHunt(unittest.TestCase):
    """Pass 12 regression tests covering security hardening, stability, and edge-case fixes."""

    def test_config_auth_deep_json_webhook_ssrf_and_rate_limiter_ipv6_norm(self) -> None:
        import io
        from unittest import mock
        from phonecluster.auth import (
            AuthRateLimiter,
            _connect_validated_webhook_socket,
            _is_webhook_redirect_target_unsafe,
            _sanitize_json_value,
            is_webhook_target_unsafe,
            read_json_object_bounded,
            safe_json_dumps,
        )
        from phonecluster.config import NetworkHardeningConfig

        # 1. auth_token rejects whitespace, control chars, and non-ASCII
        for bad_tok in ("tok\r\nX-Evil: 1", "tok with space", "tok\x00nul", "tök€n"):
            with self.assertRaises(ValueError):
                ClusterConfig.from_dict({
                    "cluster_name": "c",
                    "auth_token": bad_tok,
                    "nodes": [{"id": "node0", "host": "127.0.0.1"}],
                })
            with self.assertRaises(ValueError):
                NodeConfig.from_dict({"id": "node1", "host": "10.0.0.2", "auth_token": bad_tok})

        # 2. allowed_master_ips validates IP / CIDR / safe host; rejects malformed CIDRs & control chars
        net_ok = NetworkHardeningConfig.from_dict({
            "allowed_master_ips": ["192.168.1.10", "10.0.0.0/24", "fd00::/64", "master.local"]
        })
        self.assertEqual(net_ok.allowed_master_ips, ["192.168.1.10", "10.0.0.0/24", "fd00::/64", "master.local"])
        for bad_ip in ("192.168.1.0/99", "not a host!", "10.0.0.1\nX: 1", "10.0.0.1/"):
            with self.assertRaises(ValueError):
                NetworkHardeningConfig.from_dict({"allowed_master_ips": [bad_ip]})

        # 3. NodeConfig max_concurrency capped to 1..32; SafetyConfig enforces 10..100 C bounds
        with self.assertRaises(ValueError):
            NodeConfig.from_dict({"id": "node1", "host": "10.0.0.2", "max_concurrency": 64})
        with self.assertRaises(ValueError):
            NodeConfig.from_dict({"id": "node1", "host": "10.0.0.2", "max_concurrency": 0})
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"max_temp_c": 0.0, "resume_temp_c": 0.0})
        with self.assertRaises(ValueError):
            SafetyConfig.from_dict({"max_temp_c": 40.0, "resume_temp_c": 5.0})

        # 4. Iterative _sanitize_json_value & RecursionError-safe read_json_object_bounded
        deep: Any = [float("nan")]
        for _ in range(2000):
            deep = [deep]
        sanitized = _sanitize_json_value(deep)
        cur = sanitized
        for _ in range(2000):
            cur = cur[0]
        self.assertEqual(cur, [None])
        self.assertEqual(safe_json_dumps({"x": float("inf"), "y": float("nan")}), '{"x": null, "y": null}')

        deep_json = b'{"a":1}'
        with mock.patch("phonecluster.auth.json.loads", side_effect=RecursionError("too deep")):
            with self.assertRaises(ValueError):
                read_json_object_bounded(io.BytesIO(deep_json), max_bytes=1024)
        nan_obj = read_json_object_bounded(io.BytesIO(b'{"v": NaN, "w": Infinity}'), max_bytes=1024)
        self.assertEqual(nan_obj, {"v": None, "w": None})

        # 5. Webhook SSRF hardening: trailing dot, 0/8, 6to4, site-local, NAT64, SIIT, redirects, single-resolve connect
        for unsafe_url in (
            "http://169.254.169.254./latest/meta-data/",
            "http://0.0.0.1/hook",
            "http://[2002:a9fe:a9fe::1]/hook",
            "http://[fec0::1]/hook",
            "http://[64:ff9b::169.254.169.254]/hook",
            "http://[::ffff:0:169.254.169.254]/hook",
        ):
            self.assertTrue(is_webhook_target_unsafe(unsafe_url), f"Expected unsafe: {unsafe_url}")
        self.assertFalse(is_webhook_target_unsafe("http://192.168.1.50:8123/api/webhook/batt"))

        # Public -> LAN redirect blocked; LAN -> loopback redirect blocked
        self.assertTrue(
            _is_webhook_redirect_target_unsafe("https://93.184.216.34/hook", "http://192.168.1.201:8080/api/exec")
        )
        self.assertTrue(
            _is_webhook_redirect_target_unsafe("http://192.168.1.50:8123/hook", "http://127.0.0.1:8080/api/exec")
        )
        self.assertFalse(
            _is_webhook_redirect_target_unsafe("http://192.168.1.50:8123/old", "http://192.168.1.50:8123/new")
        )

        # Single-resolve webhook connect refuses disallowed IP without opening a socket
        with mock.patch(
            "phonecluster.auth.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))],
        ), mock.patch("phonecluster.auth.socket.socket") as mock_sock:
            with self.assertRaises(OSError):
                _connect_validated_webhook_socket("rebind.example.test", 80, 2.0)
            mock_sock.assert_not_called()

        # 6. AuthRateLimiter normalizes IPv4-mapped IPv6 addresses identically to IPv4
        rl = AuthRateLimiter(max_failures=2, window_sec=60.0, block_sec=60.0)
        rl.record_failure("::ffff:192.168.1.50")
        rl.record_failure("192.168.1.50")
        self.assertTrue(rl.is_blocked("192.168.1.50")[0])
        self.assertTrue(rl.is_blocked("::ffff:192.168.1.50")[0])
        rl.record_success("192.168.1.50")
        self.assertFalse(rl.is_blocked("::ffff:192.168.1.50")[0])

    def test_telemetry_routing_worker_bg_process_slot_gate_and_master_safety(self) -> None:
        import io
        import urllib.error
        import urllib.request
        from unittest import mock
        from phonecluster.master import MetricsHistory, NodeSnapshot
        from phonecluster.routing import build_cross_tier_env
        from phonecluster.telemetry import (
            BatteryInfo,
            _normalize_sysfs_temp,
            is_battery_health_hazardous,
            read_battery_via_sysfs,
            read_top_processes,
        )
        from phonecluster.worker import (
            BatteryGuardLoop,
            WorkerHTTPServer,
            WorkerState,
            _execute_job_payload,
            _run_process_bounded,
        )

        # 1. Sysfs space-separated battery hazard normalization + decideg/millideg cool-room temps
        self.assertTrue(is_battery_health_hazardous("Over voltage"))
        self.assertTrue(is_battery_health_hazardous("Safety timer expire"))
        self.assertTrue(is_battery_health_hazardous("Overheat"))
        self.assertFalse(is_battery_health_hazardous("Good"))
        self.assertEqual(_normalize_sysfs_temp("125", unit="decideg"), 12.5)
        self.assertEqual(_normalize_sysfs_temp("800", unit="millideg"), 0.8)

        with tempfile.TemporaryDirectory() as tmp:
            ps = Path(tmp) / "battery"
            ps.mkdir()
            (ps / "type").write_text("Battery\n", encoding="utf-8")
            (ps / "capacity").write_text("60\n", encoding="utf-8")
            (ps / "temp").write_text("125\n", encoding="utf-8")
            (ps / "status").write_text("Not charging\n", encoding="utf-8")
            (ps / "health").write_text("Over voltage\n", encoding="utf-8")
            bat = read_battery_via_sysfs(Path(tmp))
            self.assertIsNotNone(bat)
            assert bat is not None
            self.assertEqual(bat.temperature_c, 12.5)
            self.assertEqual(bat.status, "NOT_CHARGING")
            self.assertEqual(bat.health, "OVER_VOLTAGE")

        # 2. read_top_processes decodes non-UTF-8 bytes safely without raising UnicodeDecodeError
        with mock.patch("phonecluster.telemetry.subprocess.check_output", return_value=b"PID %CPU %MEM COMMAND\n123 1.0 0.5 bad\xffname\n"):
            procs = read_top_processes(limit=3)
            self.assertEqual(len(procs), 1)
            self.assertEqual(procs[0]["pid"], 123)

        # 3. WorkerState.try_reserve_slot with health_provider gates thermal hazard even on last slot (max_concurrency=1)
        st_hot = WorkerState(
            node_id="n-hot",
            role="worker",
            auth_token="tok1234567890",
            safety=SafetyConfig(),
            max_concurrency=1,
            health_provider=lambda: {"ready_for_jobs": False, "not_ready_reasons": ["overheated (48C)"]},
        )
        ok_hot, reason_hot = st_hot.try_reserve_slot("j1", "echo hi")
        self.assertFalse(ok_hot)
        self.assertEqual(reason_hot.get("error"), "node_not_ready")

        st_ok = WorkerState(
            node_id="n-ok",
            role="worker",
            auth_token="tok1234567890",
            safety=SafetyConfig(),
            max_concurrency=1,
            health_provider=lambda: {"ready_for_jobs": True, "not_ready_reasons": []},
        )
        ok_good, _ = st_ok.try_reserve_slot("j1", "echo hi")
        self.assertTrue(ok_good)
        st_ok.finish_job("j1", {"job_id": "j1", "returncode": 0})

        # 4. _run_process_bounded returns promptly when a job spawns a detached background process holding stdout
        import signal
        import subprocess
        proc_bg = subprocess.Popen(
            ["sh", "-c", "(sleep 20) & echo bg_done"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            t0 = time.monotonic()
            rc_bg, out_bg, _err_bg, to_bg = _run_process_bounded(proc_bg, timeout_sec=5.0, max_bytes=4096)
            elapsed_bg = time.monotonic() - t0
            self.assertEqual(rc_bg, 0)
            self.assertFalse(to_bg)
            self.assertIn("bg_done", out_bg)
            self.assertLess(elapsed_bg, 2.5)
        finally:
            try:
                os.killpg(proc_bg.pid, signal.SIGKILL)
            except OSError:
                pass
            if proc_bg.stdout:
                proc_bg.stdout.close()
            if proc_bg.stderr:
                proc_bg.stderr.close()

        # 5. Relative workdir anchored to state.workdir + os.chmod EPERM on script_content ignored
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sub = base / "subjob"
            sub.mkdir()
            st_wd = WorkerState(
                node_id="n-wd",
                role="worker",
                auth_token="tok1234567890",
                safety=SafetyConfig(),
                max_concurrency=2,
                workdir=base,
                health_provider=lambda: {"ready_for_jobs": True, "not_ready_reasons": []},
            )
            with mock.patch("phonecluster.worker.os.chmod", side_effect=PermissionError("FUSE EPERM")):
                rc_wd, res_wd = _execute_job_payload(
                    st_wd,
                    {
                        "job_id": "j-wd",
                        "workdir": "subjob",
                        "script_name": "hello.py",
                        "script_content": "import os; print(os.path.basename(os.getcwd()))\n",
                        "timeout_sec": 5.0,
                    },
                )
            self.assertEqual(rc_wd, 200)
            self.assertEqual(res_wd["returncode"], 0)
            self.assertEqual(res_wd["stdout"].strip(), "subjob")

        # 6. BatteryGuardLoop triggers battery_hazard on space-separated Linux sysfs "Over voltage"
        st_guard = WorkerState(
            node_id="n-guard",
            role="worker",
            auth_token="tok-guard-123456",
            safety=SafetyConfig(battery_webhook_url=""),
            max_concurrency=1,
            health_provider=lambda: {
                "battery_pct": 55,
                "max_temp_c": 33.0,
                "battery_status": "CHARGING",
                "battery_health": "Over voltage",
                "battery_plugged": "PLUGGED",
            },
        )
        guard = BatteryGuardLoop(st_guard, threading.Event())
        with mock.patch.object(st_guard, "record_safety_event", wraps=st_guard.record_safety_event) as spy_ev:
            guard.check_once()
        self.assertTrue(any(c.args[0] == "battery_hazard" for c in spy_ev.call_args_list))

        # 7. WorkerState.allowed_hosts allows configured multi-label Host header
        st_host = WorkerState(
            node_id="n-host",
            role="worker",
            auth_token="tok-host-secret-123",
            safety=SafetyConfig(),
            max_concurrency=1,
            allowed_hosts={"node1.home.lan"},
        )
        wsrv = WorkerHTTPServer(("127.0.0.1", 0), st_host)
        wport = wsrv.server_address[1]
        wt = threading.Thread(target=wsrv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        wt.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{wport}/health",
                headers={**build_auth_headers("tok-host-secret-123"), "Host": f"node1.home.lan:{wport}"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            wsrv.shutdown()
            wsrv.server_close()
            wt.join(timeout=2.0)

        # 8. Routing build_cross_tier_env uses Master LAN IP for remote distcc and skips malformed custom llama_rpc/distcc
        cfg_rt = ClusterConfig(
            cluster_name="rt-test",
            auth_token="rt-tok-1234567890",
            nodes=[
                NodeConfig(id="node0", host="192.168.1.10", role="master"),
                NodeConfig(id="node1", host="192.168.1.55", role="worker"),
            ],
            custom_services={"llama_rpc": "http://:0", "distcc": "http://:0"},
        )
        snaps_rt = [
            NodeSnapshot(
                node=cfg_rt.nodes[0],
                online=True,
                health={"ready_for_jobs": True, "services": {"distccd_3632": True}, "cpu_cores": 4},
            ),
            NodeSnapshot(
                node=cfg_rt.nodes[1],
                online=True,
                health={"ready_for_jobs": True, "services": {"distccd_3632": True}, "cpu_cores": 8},
            ),
        ]
        env_rt = build_cross_tier_env(snaps_rt, cfg_rt)
        self.assertEqual(env_rt["PHONECLUSTER_MASTER_HOST"], "192.168.1.10")
        self.assertIn("192.168.1.10/2,lzo", env_rt.get("PHONECLUSTER_DISTCC_HOSTS", ""))
        self.assertIn("192.168.1.55/8,lzo", env_rt.get("PHONECLUSTER_DISTCC_HOSTS", ""))
        self.assertNotIn("localhost", env_rt.get("PHONECLUSTER_DISTCC_HOSTS", ""))
        self.assertNotIn("PHONECLUSTER_LLAMA_RPC", env_rt)

        # 9. MasterController blocks worker error JSON status spoofing, validates WAN probe, pipeline types, & MetricsHistory prune
        cfg_m = ClusterConfig(
            cluster_name="m-test",
            auth_token="m-tok-1234567890",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master"),
                NodeConfig(id="node1", host="127.0.0.1", role="worker", worker_port=59995),
            ],
        )
        ctrl = MasterController(cfg_m)
        spoof_err = urllib.error.HTTPError(
            url="http://127.0.0.1:59995/cancel",
            code=500,
            msg="Internal Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=io.BytesIO(b'{"cancelled": true, "ok": true, "http_status": 200}'),
        )
        with mock.patch("phonecluster.master._DIRECT_OPENER.open", side_effect=spoof_err):
            c_res = ctrl.cancel_node_job("node1", "job-x")
        self.assertFalse(c_res["cancelled"])
        self.assertEqual(c_res["http_status"], 500)

        with self.assertRaises(ValueError):
            ctrl.check_workers_wan_isolation(probe_host="bad host!")
        with self.assertRaises(ValueError):
            ctrl.check_workers_wan_isolation(probe_port=99999)
        with self.assertRaises(ValueError):
            ctrl.check_workers_wan_isolation(timeout_sec=float("nan"))

        pipe_res = ctrl.run_pipeline([{"name": "bad", "command": 12345}])
        self.assertFalse(pipe_res["ok"])
        self.assertIn("must be a string", pipe_res["results"][0]["error"])

        mh = MetricsHistory(maxlen=10)
        mh.record({"timestamp": 1.0, "nodes": [{"id": "node1", "online": True, "health": {"cpu_pct": 10.0, "battery_pct": 999}}]})
        self.assertIn("node1", mh.snapshot()["nodes"])
        self.assertIsNone(mh.snapshot()["nodes"]["node1"][0]["battery_pct"])
        mh.record({"timestamp": 2.0, "nodes": []})
        self.assertNotIn("node1", mh.snapshot()["nodes"])

    def test_gateway_non_ascii_host_ipv6_sitelocal_upstream_smuggling_and_chunked_audit(self) -> None:
        from unittest import mock
        from phonecluster.config import GatewayConfig
        from phonecluster.gateway import (
            GatewayManager,
            _parse_host_header,
            derive_proxy_password,
            evaluate_policy,
            resolve_and_validate_target,
        )

        # 1. Non-ASCII soft-hyphen host rejected across Host header, policy, and DNS validation
        self.assertIsNone(_parse_host_header("gi\xadst.github.com"))
        gw_cfg = GatewayConfig(
            enabled=True,
            mode="allowlist",
            allowed_domains=["*.github.com"],
            blocked_domains=["93.184.216.34"],
        )
        allowed_sh, _ = evaluate_policy("gi\xadst.github.com", 443, gw_cfg)
        self.assertFalse(allowed_sh)
        cands_sh, _ = resolve_and_validate_target("gi\xadst.github.com", 443)
        self.assertIsNone(cands_sh)

        # 2. IPv6 site-local fec0::1 blocked by SSRF guard
        cands_sl, _ = resolve_and_validate_target("fec0::1", 80)
        self.assertIsNone(cands_sl)

        # 3. Live Gateway proxy: upstream 0-byte EOF -> 502, bare-LF -> 502, TE+CL drops CL, bad chunked POST audited
        responses: list[bytes] = [
            b"",  # Case A: immediate 0-byte EOF
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\nX-Injected: 1\r\n\r\nok",  # Case B: bare-LF header splitting
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",  # Case C: TE+CL
        ]
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        up_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        up_sock.bind(("127.0.0.1", 0))
        up_port = up_sock.getsockname()[1]
        up_sock.listen(8)
        up_stop = threading.Event()

        def _up_loop() -> None:
            up_sock.settimeout(0.2)
            while not up_stop.is_set():
                try:
                    c, _ = up_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with c:
                    c.settimeout(1.0)
                    try:
                        c.recv(4096)
                    except OSError:
                        pass
                    if responses:
                        payload = responses.pop(0)
                        if payload:
                            c.sendall(payload)

        up_thread = threading.Thread(target=_up_loop, daemon=True)
        up_thread.start()

        import base64
        p_secret = derive_proxy_password("gw-p12-tok-12345", "node0")
        p_auth = base64.b64encode(f"node0:{p_secret}".encode("utf-8")).decode("ascii")
        cfg = ClusterConfig(
            cluster_name="gw-p12",
            auth_token="gw-p12-tok-12345",
            nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master")],
            gateway=GatewayConfig(
                enabled=True,
                mode="allowlist",
                bind_host="127.0.0.1",
                port=0,
                allowed_domains=["upstream.example", "nat64blocked.example"],
                blocked_domains=["93.184.216.34"],
                allowed_ports=[80, 443, up_port],
            ),
        )
        proxy = GatewayManager(cfg)
        audit = proxy.audit_log
        ok_start, msg_start = proxy.start()
        self.assertTrue(ok_start, msg_start)
        p_port = proxy.bound_port
        try:
            def _send_proxy(raw: bytes) -> bytes:
                # Inject Proxy-Authorization header before end of headers
                head, sep, rest = raw.partition(b"\r\n\r\n")
                authed = head + f"\r\nProxy-Authorization: Basic {p_auth}".encode("ascii") + sep + rest
                with socket.create_connection(("127.0.0.1", p_port), timeout=3.0) as s:
                    s.settimeout(3.0)
                    s.sendall(authed)
                    chunks: list[bytes] = []
                    while True:
                        b = s.recv(4096)
                        if not b:
                            break
                        chunks.append(b)
                    return b"".join(chunks)

            # Case 0: NAT64-wrapped blocked_domains IPv4 (64:ff9b::93.184.216.34) blocked post-DNS with 403
            with mock.patch(
                "phonecluster.gateway.resolve_and_validate_target",
                return_value=([(socket.AF_INET6, ("64:ff9b::5db8:d822", 80, 0, 0))], "ok"),
            ):
                r_nat64 = _send_proxy(
                    b"GET http://nat64blocked.example/ HTTP/1.1\r\nHost: nat64blocked.example\r\nConnection: close\r\n\r\n"
                )
                self.assertTrue(r_nat64.startswith(b"HTTP/1.1 403"), f"Expected 403 on NAT64 blocked IP, got {r_nat64!r}")

            with mock.patch(
                "phonecluster.gateway.resolve_and_validate_target",
                return_value=([(socket.AF_INET, ("127.0.0.1", up_port))], "ok"),
            ):
                # Case A: 0-byte upstream EOF -> 502 Bad Gateway
                r_eof = _send_proxy(f"GET http://upstream.example:{up_port}/eof HTTP/1.1\r\nHost: upstream.example:{up_port}\r\nConnection: close\r\n\r\n".encode("ascii"))
                self.assertTrue(r_eof.startswith(b"HTTP/1.1 502"), f"Expected 502 on EOF, got {r_eof!r}")

                # Case B: bare-LF upstream header injection -> 502 Bad Gateway
                r_lf = _send_proxy(f"GET http://upstream.example:{up_port}/lf HTTP/1.1\r\nHost: upstream.example:{up_port}\r\nConnection: close\r\n\r\n".encode("ascii"))
                self.assertTrue(r_lf.startswith(b"HTTP/1.1 502"), f"Expected 502 on bare LF, got {r_lf!r}")

                # Case C: Transfer-Encoding: gzip + Content-Length: 5 -> Content-Length stripped per RFC 9112 §6.3
                r_tecl = _send_proxy(f"GET http://upstream.example:{up_port}/tecl HTTP/1.1\r\nHost: upstream.example:{up_port}\r\nConnection: close\r\n\r\n".encode("ascii"))
                head_c = r_tecl.split(b"\r\n\r\n", 1)[0]
                self.assertTrue(head_c.startswith(b"HTTP/1.1 200"))
                self.assertNotIn(b"content-length", head_c.lower())
                self.assertIn(b"transfer-encoding: gzip", head_c.lower())

                # Case D: Malformed chunked POST body returns 400 AND logs to audit_log
                before_cnt = len(audit.snapshot(100)["events"])
                r_badchk = _send_proxy(
                    f"POST http://upstream.example:{up_port}/chk HTTP/1.1\r\n"
                    f"Host: upstream.example:{up_port}\r\n"
                    f"Transfer-Encoding: chunked\r\n\r\n"
                    f"ZZZZ\r\n".encode("ascii")
                )
                self.assertTrue(r_badchk.startswith(b"HTTP/1.1 400"), f"Expected 400, got {r_badchk!r}")
                after_events = audit.snapshot(100)["events"]
                self.assertGreater(len(after_events), before_cnt)
        finally:
            proxy.stop()
            up_stop.set()
            up_sock.close()
            up_thread.join(timeout=2.0)

    def test_pairing_fingerprint_mitm_rate_limit_loopback_udp_netguard_and_doctor(self) -> None:
        from unittest import mock
        from phonecluster.discovery import DiscoveryResponder
        from phonecluster.doctor import run_doctor
        from phonecluster.master import NodeSnapshot
        from phonecluster.netguard import (
            audit_cluster_network,
            build_adguard_config_snippets,
            build_firewall_guides,
        )
        from phonecluster.pairing import (
            PairingBeaconResponder,
            PairingManager,
            StandalonePairingServer,
            join_cluster_via_pairing,
        )

        # 1. Pairing: expected_fingerprint mismatch aborts BEFORE sending POST /api/pair/complete
        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "pair_cfg.json"
            cfg = ClusterConfig(
                cluster_name="p12-pair",
                auth_token="p12-master-secret-token-1234",
                nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master")],
            )
            save_config(cfg, cfg_p)
            mgr = PairingManager(
                config=cfg,
                config_path=cfg_p,
                pair_port=0,
                listen_host="127.0.0.1",
                fail_delay_sec=0.0,
                enable_beacon=False,
            )
            srv = StandalonePairingServer(("127.0.0.1", 0), mgr)
            try:
                mgr.pair_port = srv.server_address[1]
                sess = mgr.open_session(ttl_sec=60, max_devices=2)
                t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
                t.start()
                try:
                    with mock.patch.object(mgr, "complete_pairing", wraps=mgr.complete_pairing) as spy_complete:
                        with self.assertRaises(RuntimeError) as ctx:
                            join_cluster_via_pairing(
                                master_host="127.0.0.1",
                                pair_port=srv.server_address[1],
                                pin=sess["pin"],
                                config_out=Path(tmp) / "w.json",
                                expected_fingerprint="deadbeef",
                            )
                        self.assertIn("fingerprint mismatch", str(ctx.exception).lower())
                        spy_complete.assert_not_called()

                    # 2. PairingManager.complete_pairing rate-limits bad-DH floods from same IP with 429
                    saw_429 = False
                    for _ in range(20):
                        code, _ = mgr.complete_pairing(
                            "10.0.0.99",
                            {"session_id": sess["session_id"], "pub_b": "1", "client_proof": "00" * 32},
                        )
                        if code == 429:
                            saw_429 = True
                            break
                    self.assertTrue(saw_429, "Expected 429 rate-limit on bad-DH flood")

                    # 3. StandalonePairingServer.wait_active_requests waits cleanly
                    srv.wait_active_requests(0.5)
                finally:
                    mgr.close_session()
                    srv.shutdown()
                    t.join(timeout=2.0)
            finally:
                srv.server_close()

        # 4. PairingBeaconResponder & DiscoveryResponder bind 127.0.0.1 (never 0.0.0.0) for localhost / ::1
        for host_in in ("localhost", "::1"):
            pb = PairingBeaconResponder(
                cluster_name="t",
                pair_port=8767,
                session_id="s1",
                fingerprint="abcd1234",
                expires_at=time.time() + 60.0,
                listen_host=host_in,
                discovery_port=0,
            )
            self.assertTrue(pb.bind())
            try:
                assert pb._sock is not None
                self.assertEqual(pb._sock.getsockname()[0], "127.0.0.1")
            finally:
                pb.stop()

            dr = DiscoveryResponder(
                node_id="node0",
                role="master",
                worker_port=8765,
                ssh_port=8022,
                listen_host=host_in,
                discovery_port=0,
            )
            self.assertTrue(dr.bind())
            try:
                assert dr._sock is not None
                self.assertEqual(dr._sock.getsockname()[0], "127.0.0.1")
            finally:
                dr.stop()

        # 5. Doctor: scoped worker config -> OK; duplicate worker tokens -> WARN; OverflowError / space health / unsynced temp
        with tempfile.TemporaryDirectory() as tmp:
            w_cfg = Path(tmp) / "worker_scoped.json"
            save_config(
                ClusterConfig(
                    cluster_name="scoped",
                    auth_token="strong-worker-token-1234567890",
                    nodes=[NodeConfig(id="node1", host="192.168.1.201", role="worker", auth_token="strong-worker-token-1234567890")],
                ),
                w_cfg,
            )
            rep_scoped = run_doctor(w_cfg, check_remote=False)
            tok_chk = next(c for c in rep_scoped["checks"] if c["name"] == "Per-Node Token Isolation")
            self.assertEqual(tok_chk["status"], "ok")

            dup_cfg = Path(tmp) / "dup_tok.json"
            dup_cfg_obj = ClusterConfig(
                cluster_name="dup",
                auth_token="master-tok-unique-1234567890",
                nodes=[
                    NodeConfig(id="node0", host="192.168.1.10", role="master"),
                    NodeConfig(id="node1", host="192.168.1.21", role="worker", auth_token="shared-worker-tok-123456"),
                    NodeConfig(id="node2", host="192.168.1.22", role="worker", auth_token="shared-worker-tok-123456"),
                ],
            )
            save_config(dup_cfg_obj, dup_cfg)
            fake_health = {
                "temp_c": 45.0,
                "overheated": False,  # unsynced flag even though >= safety.max_temp_c (40.0)
                "battery_pct": 10**400,  # would raise OverflowError on float()
                "battery_health": "Over voltage",
                "battery_status": "CHARGING",
                "ready_for_jobs": True,
            }
            fake_snaps = [NodeSnapshot(node=dup_cfg_obj.nodes[0], online=True, health=fake_health)]
            with mock.patch("phonecluster.doctor.MasterController.poll_health", return_value=fake_snaps):
                rep_dup = run_doctor(dup_cfg, check_remote=True)
            tok_dup = next(c for c in rep_dup["checks"] if c["name"] == "Per-Node Token Isolation")
            self.assertEqual(tok_dup["status"], "warn")
            self.assertIn("duplicate", tok_dup["detail"].lower())
            bat_chk = next(c for c in rep_dup["checks"] if c["name"] == "Battery Hardware Health (PMIC)")
            self.assertEqual(bat_chk["status"], "fail")
            therm_chk = next(c for c in rep_dup["checks"] if c["name"] == "Thermal Safety")
            self.assertEqual(therm_chk["status"], "warn")

        # 6. Netguard: IPv6 YAML quoting, loopback_only skipped, UFW service ports, non-destructive nftables, empty allowlist warn
        ng_cfg = ClusterConfig(
            cluster_name="ng-p12",
            auth_token="master-tok-unique-1234567890",
            nodes=[
                NodeConfig(id="node0", host="127.0.0.1", role="master"),
                NodeConfig(id="node1", host="fd00::21", role="worker", auth_token="dup-tok-1234567890"),
                NodeConfig(id="node2", host="fd00::22", role="worker", auth_token="dup-tok-1234567890"),
            ],
        )
        ng_cfg.network.enforce_worker_source_ip = True
        ng_cfg.network.allowed_master_ips = []
        snaps_ng = [
            NodeSnapshot(node=ng_cfg.nodes[0], online=True, health={}),
            NodeSnapshot(
                node=ng_cfg.nodes[1],
                online=True,
                health={
                    "ready_for_jobs": True,
                    "services": {"llama_api_8081": True},
                    "listening_ports": [{"port": 8081, "exposed": False}],
                },
            ),
            NodeSnapshot(node=ng_cfg.nodes[2], online=False, health={}),
        ]
        host_info = {"lan_ip": "192.168.1.10", "lan_subnet": "192.168.1.0/24", "is_termux": False}
        ag = build_adguard_config_snippets(snaps_ng, ng_cfg, host_info)
        self.assertIn('answer: "fd00::21"', ag["rewrites_yaml"])
        self.assertIn('answer: "192.168.1.10"', ag["rewrites_yaml"])
        self.assertNotIn("ai.cluster", ag["rewrites_yaml"])  # loopback_only service excluded

        fw = build_firewall_guides(ng_cfg, host_info)
        nft_code = "\n".join(ln for ln in fw["nftables"].splitlines() if not ln.lstrip().startswith("#"))
        self.assertNotIn("flush ruleset", nft_code)
        self.assertNotIn("chain forward", nft_code)
        self.assertIn("table inet phonecluster_master", nft_code)
        for port_s in (
            "port 1883 proto tcp",
            "port 3632 proto tcp",
            "port 8081 proto tcp",
            "port 8123 proto tcp",
            "port 50052 proto tcp",
            "tailscale0",
        ):
            self.assertIn(port_s, fw["ufw"])

        ctrl_ng = MasterController(ng_cfg)
        offline_snaps_ng = [
            NodeSnapshot(node=ng_cfg.nodes[0], online=True, health={}),
            NodeSnapshot(node=ng_cfg.nodes[1], online=False, health={}),
            NodeSnapshot(node=ng_cfg.nodes[2], online=False, health={}),
        ]
        with mock.patch.object(ctrl_ng, "poll_health", return_value=offline_snaps_ng):
            audit_ng = audit_cluster_network(ctrl_ng)
        tok_ng = next(c for c in audit_ng["checks"] if c["name"] == "Per-Worker Token Isolation")
        self.assertEqual(tok_ng["status"], "warn")
        self.assertIn("duplicate", tok_ng["detail"].lower())
        ip_ng = next(c for c in audit_ng["checks"] if c["name"] == "Worker Master-IP Firewall Allowlist")
        self.assertEqual(ip_ng["status"], "warn")

    def test_dashboard_rollback_validation_tui_csi_cli_flags_and_shell_scripts(self) -> None:
        import subprocess
        import urllib.error
        import urllib.request
        from unittest import mock
        from phonecluster.cli import main as cli_main
        from phonecluster.dashboard import DASHBOARD_HTML, DashboardHTTPServer
        from phonecluster.tui import Palette, _box_lines, _read_key, _visible_len

        # 1. Dashboard atomic config rollback on save_config failure + hardening & settings validation
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "dash_p12.json"
            tok = "dash-p12-secret-token-12345"
            cfg = ClusterConfig(
                cluster_name="dash-p12",
                auth_token=tok,
                nodes=[
                    NodeConfig(id="node0", host="192.168.1.10", role="master", worker_port=59994),
                    NodeConfig(id="node1", host="192.168.1.20", role="worker", worker_port=59993),
                ],
            )
            save_config(cfg, cfg_path)
            ctrl = MasterController(cfg)
            dash = DashboardHTTPServer(("127.0.0.1", 0), ctrl, config_path=cfg_path, enable_pairing_beacon=False)
            d_port = dash.server_address[1]
            dt = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            dt.start()

            def _post(path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{d_port}{path}",
                    data=json.dumps(payload).encode("utf-8"),
                    headers=build_auth_headers(tok),
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=4.0) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    try:
                        return exc.code, json.loads(exc.read().decode("utf-8"))
                    finally:
                        exc.close()

            try:
                # Disk-full rollback on /api/settings, /api/nodes/add, /api/network/hardening
                orig_temp = cfg.safety.max_temp_c
                orig_nodes = len(cfg.nodes)
                with mock.patch("phonecluster.dashboard.save_config", side_effect=OSError("disk full")):
                    st_s, body_s = _post("/api/settings", {"max_temp_c": 45.0})
                    self.assertEqual(st_s, 500)
                    self.assertIn("Failed to persist cluster config", body_s.get("error", ""))
                    self.assertEqual(cfg.safety.max_temp_c, orig_temp)

                    st_n, _ = _post("/api/nodes/add", {"id": "node9", "host": "192.168.1.99"})
                    self.assertEqual(st_n, 500)
                    self.assertEqual(len(cfg.nodes), orig_nodes)

                    st_h, _ = _post("/api/network/hardening", {"dashboard_require_auth": True})
                    self.assertEqual(st_h, 500)
                    self.assertFalse(cfg.dashboard_require_auth)

                # /api/network/hardening preserves master_node.host even with 32 other IPs & rejects invalid CIDR
                st_bad_cidr, _ = _post("/api/network/hardening", {"allowed_master_ips": ["999.999.999.999/33"]})
                self.assertEqual(st_bad_cidr, 400)
                many_ips = [f"10.0.0.{i}" for i in range(1, 33)]
                with mock.patch.object(ctrl, "push_config_to_all", return_value={"ok_count": 0, "results": []}):
                    st_many, _ = _post("/api/network/hardening", {"allowed_master_ips": many_ips})
                self.assertEqual(st_many, 200)
                self.assertLessEqual(len(cfg.network.allowed_master_ips), 32)
                self.assertIn("192.168.1.10", cfg.network.allowed_master_ips)

                # /api/settings blocks metadata webhook & 0 C temp, preserves current values on JSON null
                st_meta, _ = _post("/api/settings", {"battery_webhook_url": "http://169.254.169.254/meta"})
                self.assertEqual(st_meta, 400)
                st_zero, _ = _post("/api/settings", {"max_temp_c": 0, "resume_temp_c": 0})
                self.assertEqual(st_zero, 400)
                with mock.patch.object(ctrl, "push_config_to_all", return_value={"ok_count": 0, "results": []}):
                    st_null, _ = _post("/api/settings", {"max_temp_c": None, "resume_temp_c": None})
                self.assertEqual(st_null, 200)
                self.assertEqual(cfg.safety.max_temp_c, orig_temp)

                # /api/services/custom rejects empty-host and out-of-range-port URLs
                for bad_svc in ("http://", "http://127.0.0.1:99999", "ftp://127.0.0.1:21"):
                    st_svc, _ = _post("/api/services/custom", {"name": "badsvc", "url": bad_svc})
                    self.assertEqual(st_svc, 400)
            finally:
                dash.shutdown()
                dash.server_close()
                dt.join(timeout=2.0)

        # 2. Dashboard JS hardening markers
        self.assertIn("typeof j === 'object'", DASHBOARD_HTML)
        self.assertIn("lastPairedKey", DASHBOARD_HTML)
        self.assertIn("if (pairPollTimer)", DASHBOARD_HTML)

        # 3. TUI drains full multi-byte CSI sequence (Ctrl+Right = \x1b[1;5C) without leaking 'C'
        seq = iter([b"\x1b", b"[", b"1", b";", b"5", b"C"])
        with mock.patch("phonecluster.tui.select.select", side_effect=lambda *_a, **_k: ([0], [], [])), mock.patch(
            "phonecluster.tui.os.read", side_effect=lambda _fd, _n: next(seq)
        ):
            self.assertEqual(_read_key(0.05), "ESC")

        pal = Palette(enabled=False)
        box = _box_lines("A" * 120, ["body"], width=40, pal=pal)
        for line in box:
            self.assertLessEqual(_visible_len(line), 40)

        # 4. CLI validates conflicting gateway flags and malformed join --master host
        with tempfile.TemporaryDirectory() as tmp:
            cfg_cli = Path(tmp) / "cli_p12.json"
            save_config(
                ClusterConfig(
                    cluster_name="cli-p12",
                    auth_token="cli-p12-tok-123456",
                    nodes=[NodeConfig(id="node0", host="127.0.0.1", role="master")],
                ),
                cfg_cli,
            )
            self.assertEqual(cli_main(["--config", str(cfg_cli), "gateway", "--enable", "--disable"]), 2)
            self.assertEqual(cli_main(["--config", str(cfg_cli), "join", "--master", "[::1]junk", "--pin", "123456"]), 2)

        # 5. Shell scripts & CI matrix checks
        repo = Path(__file__).resolve().parent.parent
        chroot_sh = (repo / "scripts" / "04_debian13_chroot_setup.sh").read_text(encoding="utf-8")
        idx_bind = chroot_sh.index(r'mount -o bind /dev "\${CHROOT}/dev"')
        idx_shm = chroot_sh.index(r'mkdir -p "\${CHROOT}/dev/pts" "\${CHROOT}/dev/shm"')
        self.assertGreater(idx_shm, idx_bind)

        sync_sh = (repo / "scripts" / "03_sync_cluster.sh").read_text(encoding="utf-8")
        self.assertIn("${RDIR#??}", sync_sh)
        self.assertIn("SCOPED_CFG", sync_sh)
        self.assertIn(r'[ ! -s \"\$TMP\" ]', sync_sh)
        self.assertIn("load_config", sync_sh)

        install_sh = (repo / "install.sh").read_text(encoding="utf-8")
        self.assertLess(
            install_sh.index('git -C "${INSTALL_DIR}" pull --ff-only'),
            install_sh.index('elif [[ ! -f "${INSTALL_DIR}/phonecluster_cli.py" ]]; then'),
        )

        termux_sh = (repo / "scripts" / "02_termux_node_setup.sh").read_text(encoding="utf-8")
        self.assertIn("--boot-only", termux_sh)
        self.assertIn("DEBIAN_FRONTEND=noninteractive", termux_sh)

        adb_prep_sh = (repo / "scripts" / "01_adb_prep.sh").read_text(encoding="utf-8")
        self.assertIn('${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}', adb_prep_sh)

        pi_sh = (repo / "scripts" / "setup_pi_master.sh").read_text(encoding="utf-8")
        self.assertIn("run_as_user()", pi_sh)
        self.assertIn("curl -fsSL", pi_sh)

        with tempfile.TemporaryDirectory() as tmp:
            p_adb_help = subprocess.run(
                ["bash", str(repo / "scripts" / "setup_all_via_adb.sh"), "--help"],
                cwd=tmp,
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_adb_help.returncode, 0)
            self.assertFalse((Path(tmp) / "--help").exists())

        ci_yml = (repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('"3.9"', ci_yml)


if __name__ == "__main__":
    unittest.main()
