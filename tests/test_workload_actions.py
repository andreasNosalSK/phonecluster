"""Verify workload probe results and the worker RPC maintenance path."""

import contextlib
import io
import json
import shutil
import subprocess
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from phonecluster.auth import MAX_EXEC_RESPONSE_BYTES, safe_json_dumps
from phonecluster.config import ClusterConfig, NodeConfig, SafetyConfig
from phonecluster.dashboard import DashboardHTTPServer
from phonecluster.master import JobSpec, MasterController, NodeSnapshot
from phonecluster.worker import MAX_OUTPUT_BYTES, WorkerHTTPServer, WorkerState, _decode_capped

TOKEN = "workload-regression-fixture"


@contextlib.contextmanager
def serve(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def docker_probe(spec, docker):
    output = io.StringIO()
    with contextlib.redirect_stdout(output), patch("shutil.which", return_value="/test/docker"), patch(
        "subprocess.run", side_effect=docker
    ), patch.dict("os.environ", spec.env):
        try:
            exec(compile(spec.script_content, spec.script_name, "exec"), {})
        except SystemExit as exit_status:
            returncode = exit_status.code
        else:
            returncode = 0
    return "ok", {"returncode": returncode, "stdout": output.getvalue()}


class WorkloadActionTests(unittest.TestCase):
    def test_successful_job_receipt_stays_within_the_encoded_response_limit(self):
        state = WorkerState("phone", "worker", TOKEN, SafetyConfig(),
                            health_provider=lambda: {"ready_for_jobs": True})
        # A captured binary stream may expand when replacement characters are escaped as JSON.
        output = _decode_capped(b"\xff" * MAX_OUTPUT_BYTES)
        with serve(WorkerHTTPServer(("127.0.0.1", 0), state)) as port, patch(
            "phonecluster.worker._run_process_bounded", return_value=(0, output, output, False)
        ):
            node = NodeConfig("phone", "127.0.0.1", worker_port=port)
            ctrl = MasterController(ClusterConfig("test", TOKEN, [node]))
            kind, result = ctrl.exec_on_node(node, JobSpec(0, "wire-size", command="true"))
        self.assertEqual(kind, "ok", result.get("error"))
        self.assertEqual(result["returncode"], 0)
        for stream in ("stdout", "stderr"):
            self.assertIn("truncated to fit job response", result[stream])
            self.assertTrue(result[stream].startswith(output[:100]))
        self.assertLessEqual(len(safe_json_dumps(result).encode()), MAX_EXEC_RESPONSE_BYTES)

    def test_temporary_listing_error_keeps_engine_counts_and_marks_inventory_unavailable(self):
        node = NodeConfig("docker", "192.0.2.11", tier=3)
        ctrl = MasterController(ClusterConfig("test", TOKEN, [node]))
        snap = NodeSnapshot(node, online=True, health={"tools": {"docker": True}})

        def docker(argv, **kwargs):
            if argv[1] == "info":
                return subprocess.CompletedProcess(argv, 0, json.dumps({"ContainersRunning": 1, "Containers": 1}), "")
            self.assertEqual(argv[1], "ps")
            return subprocess.CompletedProcess(argv, 1, "", "temporary listing error")

        with patch.object(ctrl, "poll_health", return_value=[snap]), patch.object(
            ctrl, "exec_on_node", side_effect=lambda node, spec: docker_probe(spec, docker)
        ):
            result = ctrl.docker_cluster_status()
        row = result["nodes"][0]
        self.assertEqual(result["engine_ready_nodes"], 1)
        self.assertEqual(result["total_running_containers"], 1)
        self.assertEqual(result["ready_nodes"], 0)
        self.assertFalse(row["inventory_ok"])
        self.assertFalse(row["ok"])
        self.assertIn("temporary listing error", row["error"])

    def test_already_active_swarm_workers_are_checked_against_the_selected_manager(self):
        nodes = [NodeConfig("manager", "192.0.2.11", role="master", tier=3),
                 NodeConfig("local", "192.0.2.12", tier=3),
                 NodeConfig("foreign", "192.0.2.13", tier=3)]
        ctrl = MasterController(ClusterConfig("test", TOKEN, nodes))
        snapshots = [NodeSnapshot(node, online=True, health={"tools": {"docker": True}}) for node in nodes]

        def exec_on_node(node, spec):
            def docker(argv, **kwargs):
                if argv[1:3] == ["node", "ls"]:
                    self.assertEqual(node.id, "manager")
                    print("manager-swarm-id\nlocal-swarm-id")
                    return subprocess.CompletedProcess(argv, 0)
                if argv[1:3] == ["swarm", "join-token"]:
                    return subprocess.CompletedProcess(argv, 0, "swarm-fixture-token\n", "")
                self.assertEqual(argv[1], "info")
                stdout = "active|true" if node.role == "master" else f"active|{node.id}-swarm-id"
                return subprocess.CompletedProcess(argv, 0, stdout, "")

            return docker_probe(spec, docker)

        with patch.object(ctrl, "poll_health", return_value=snapshots), patch.object(
            ctrl, "exec_on_node", side_effect=exec_on_node
        ):
            result = ctrl.docker_swarm_setup()
        self.assertFalse(result["ok"])
        self.assertEqual(result["joined_count"], 1)
        local, foreign = result["workers"]
        self.assertTrue(local["ok"])
        self.assertFalse(foreign["ok"])
        self.assertIn("absent from the selected manager", foreign["error"])
        self.assertNotIn("swarm-fixture-token", json.dumps(result))

    def test_rpc_start_targets_ready_workers_and_skips_a_master_only_inventory(self):
        master = NodeConfig("pi", "192.0.2.11", role="master")
        phone = NodeConfig("phone", "192.0.2.12")
        ctrl = MasterController(ClusterConfig("test", TOKEN, [master, phone]))
        spec = JobSpec(0, "rpc-start", script_content="fixture")
        snapshots = [NodeSnapshot(node, online=True, health={"ready_for_jobs": True}) for node in [master, phone]]
        with patch.object(ctrl, "poll_health", side_effect=[snapshots[:1], snapshots]), patch.object(
            ctrl, "exec_on_node", return_value=("ok", {"returncode": 0, "job_id": spec.job_id})
        ) as dispatch:
            self.assertFalse(ctrl.start_llama_rpc(spec)[0].ok)
            dispatch.assert_not_called()
            self.assertTrue(ctrl.start_llama_rpc(spec)[0].ok)
            self.assertEqual(dispatch.call_args.args[0].id, phone.id)

    def test_dashboard_stops_rpc_on_busy_hot_workers_without_admitting_jobs(self):
        state = WorkerState(
            "phone", "worker", TOKEN, SafetyConfig(), max_concurrency=1,
            health_provider=lambda: {"ready_for_jobs": False},
        )
        self.assertTrue(state.try_reserve_slot("fixture-busy", "fixture", force=True)[0])
        with serve(WorkerHTTPServer(("127.0.0.1", 0), state)) as worker_port:
            node = NodeConfig("phone", "127.0.0.1", worker_port=worker_port)
            ctrl = MasterController(ClusterConfig("test", TOKEN, [node]))
            with serve(DashboardHTTPServer(("127.0.0.1", 0), ctrl, enable_pairing_beacon=False)) as port, patch(
                "phonecluster.worker.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="Stopped one managed process"),
            ) as stop:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/workloads/action",
                    data=b'{"action":"llama-rpc-stop"}',
                    headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    row = json.load(response)["results"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(row["node_id"], "phone")
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[0][2:], ["llama-rpc-stop"])
        self.assertEqual(set(state.active_jobs), {"fixture-busy"})

    def test_rpc_flag_excludes_adb_control_forwards(self):
        worker = NodeConfig("usb", "127.0.0.1", tags=["usb-mode:adb"])
        direct = NodeConfig("lan", "192.0.2.11")
        unrelated = NodeConfig("other", "192.0.2.12")
        ctrl = MasterController(ClusterConfig("test", TOKEN, [worker, direct, unrelated]))
        health = {"ready_for_jobs": True, "listening_ports": [{"port": 50052, "exposed": True}]}
        snapshots = [NodeSnapshot(node, online=True, health=health) for node in [worker, direct]]
        snapshots.append(NodeSnapshot(unrelated, online=True, health={**health, "tools": {"llama_rpc": False}}))
        self.assertEqual(ctrl.build_llama_rpc_arg(snapshots=snapshots), "192.0.2.11:50052")

    @unittest.skipUnless(shutil.which("node"), "Node is needed for dashboard JavaScript checks")
    def test_dashboard_browser_action_state(self):
        repo = Path(__file__).resolve().parents[1]
        subprocess.run(["node", "tests/check_dashboard_actions.mjs"], cwd=repo, check=True, timeout=10)
