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


if __name__ == "__main__":
    unittest.main()
