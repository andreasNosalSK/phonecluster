"""End-to-end and unit tests for PhoneCluster (zero external test dependencies)."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from phonecluster.auth import build_auth_headers, extract_bearer_token, verify_token
from phonecluster.config import (
    ClusterConfig,
    NodeConfig,
    SafetyConfig,
    create_default_config,
    load_config,
    save_config,
)
from phonecluster.dashboard import DashboardHTTPServer
from phonecluster.discovery import DiscoveryResponder, discover_lan_nodes
from phonecluster.doctor import run_doctor
from phonecluster.master import (
    JobSpec,
    MasterController,
    NodeSnapshot,
    score_node,
)
from phonecluster.wizard import run_setup_wizard
from phonecluster.telemetry import (
    ThermalGate,
    _normalize_sysfs_temp,
    read_battery_via_sysfs,
    read_memory_info,
)
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
                        "cpu_cores": 8,
                        "load_1m": 0.4,
                        "mem_total_mb": 3512,
                        "mem_available_mb": 1900,
                        "disk_free_gb": 42.0,
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
            finally:
                dash.shutdown()
                dash.server_close()

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


if __name__ == "__main__":
    unittest.main()
