"""End-to-end and unit tests for PhoneCluster (zero external test dependencies)."""

from __future__ import annotations

import base64
import json
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


if __name__ == "__main__":
    unittest.main()
