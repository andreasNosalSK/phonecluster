"""Regression tests for configuration, routing, and telemetry behavior."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from phonecluster.cli import main
from phonecluster.config import (
    AdbNodeConfig,
    ClusterConfig,
    ConfigConflictError,
    NodeConfig,
    SafetyConfig,
    config_revision,
    create_default_config,
    load_config,
    save_config,
)
from phonecluster.master import JobOutcome, MasterController, NodeSnapshot
from phonecluster.routing import build_cross_tier_env, classify_workload, select_snapshots_for_target
from phonecluster.worker import WorkerState


class TestConfigurationWrites(unittest.TestCase):
    def test_policy_cannot_persist_to_an_inventory_with_the_wrong_worker_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "worker.json"
            cfg = create_default_config(worker_hosts=["192.0.2.11"])
            node = cfg.get_node("node1")
            worker_token = cfg.token_for_node(node)
            state = WorkerState("node1", "worker", worker_token, cfg.safety, config_path=path)
            payload = {"target_node_id": "node1", "max_concurrency": 5, "safety": {"max_temp_c": 39}}

            cfg.nodes.remove(node)
            save_config(cfg, path)
            original = path.read_bytes()
            with self.assertLogs("phonecluster.worker", level="WARNING"):
                status, result = state.apply_live_config(payload)
            self.assertEqual(status, 200)
            self.assertTrue(result["updated"])
            self.assertFalse(result["persisted"])
            self.assertEqual(path.read_bytes(), original)

            node.auth_token = "new-worker-credential"
            cfg.nodes.append(node)
            save_config(cfg, path)
            original = path.read_bytes()
            with self.assertLogs("phonecluster.worker", level="WARNING"):
                _, result = state.apply_live_config(payload)
            self.assertFalse(result["persisted"])
            self.assertEqual(path.read_bytes(), original)

    def test_policy_receipt_confirms_the_target_and_uses_a_boolean_saved_flag(self) -> None:
        cfg = create_default_config(worker_hosts=["192.0.2.11"])
        node = cfg.get_node("node1")
        ctrl = MasterController(cfg)
        for receipt, expected in [
            ({"updated": True, "node_id": "different-id", "persisted": True}, (False, False)),
            ({"updated": False, "node_id": node.id, "persisted": True}, (False, False)),
            ({"updated": True, "node_id": node.id, "persisted": "true"}, (True, False)),
            ({"updated": True, "node_id": node.id, "persisted": True}, (True, True)),
        ]:
            with self.subTest(receipt=receipt), patch(
                "phonecluster.master._DIRECT_OPENER.open", return_value=io.BytesIO(json.dumps(receipt).encode())
            ):
                result = ctrl.push_config_to_node(node)
                self.assertEqual((result["ok"], result.get("persisted", False)), expected)

    def test_stale_writer_preserves_new_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cluster.json"
            save_config(create_default_config(worker_hosts=[]), path)
            dashboard_config = load_config(path)
            cli_config = load_config(path)
            cli_config.nodes.append(NodeConfig("new-phone", "192.0.2.11"))
            save_config(cli_config, path)

            dashboard_config.cluster_name = "Edited from dashboard"
            with self.assertRaises(ConfigConflictError):
                save_config(dashboard_config, path)
            self.assertIn("new-phone", {node.id for node in load_config(path).nodes})

    def test_config_transfer_rejects_empty_input_without_truncating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cluster.json"
            save_config(create_default_config(worker_hosts=[]), path)
            original = path.read_bytes()
            result = subprocess.run(
                [sys.executable, "-m", "phonecluster.config_transfer", str(path),
                 "--expect", config_revision(path)],
                input=b"", capture_output=True, timeout=5,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(path.read_bytes(), original)

    def test_policy_reports_live_and_saved_counts(self) -> None:
        controller = MasterController(create_default_config(worker_hosts=["192.0.2.11"]))

        def push(node: NodeConfig, _timeout: float) -> dict:
            return {"node_id": node.id, "ok": True, "persisted": node.role == "master"}

        with patch.object(controller, "push_config_to_node", side_effect=push):
            outcome = controller.push_config_to_all()
        self.assertEqual(outcome["ok_count"], 2)
        self.assertEqual(outcome["persisted_count"], 1)

    def test_cli_policy_verifies_target_and_can_require_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cluster.json"
            cfg = create_default_config(worker_hosts=["192.0.2.11"])
            save_config(cfg, path)
            command = ["--config", str(path), "push-config", "--json", "--node-id"]
            outcome = {"total": 1, "ok_count": 1, "persisted_count": 0, "results": []}
            with patch.object(MasterController, "push_config_to_all", return_value=outcome) as push:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(command + ["missing"]), 2)
                    push.assert_not_called()
                    self.assertEqual(main(command + ["node1"]), 0)
                    self.assertEqual(main(command + ["node1", "--require-persisted"]), 1)
                    outcome["persisted_count"] = 1
                    self.assertEqual(main(command + ["node1", "--require-persisted"]), 0)


class TestWorkloadAndServiceRouting(unittest.TestCase):
    def test_auto_routing_checks_executable_and_runtime(self) -> None:
        self.assertEqual(classify_workload('echo "use docker later"').category, "compute")
        self.assertEqual(classify_workload('echo status && /usr/bin/docker ps').category, "docker")
        self.assertEqual(classify_workload('echo status # docker ps').category, "compute")
        node = NodeConfig("containers", "192.0.2.11", tier=3)
        missing = NodeSnapshot(node, online=True, health={"ready_for_jobs": True, "tools": {"docker": False}})
        route = classify_workload("docker ps")
        eligible, reason = select_snapshots_for_target([missing], "auto", route)
        self.assertFalse(eligible)
        self.assertIn("usable docker", reason)

    def test_adb_services_use_endpoint_for_requesting_worker(self) -> None:
        broker = NodeConfig("usb1", "127.0.0.1", adb=AdbNodeConfig("A", 8765, 8022, 25000))
        client = NodeConfig("usb2", "127.0.0.1", adb=AdbNodeConfig("B", 8765, 8022, 25005))
        lan_node = NodeConfig("lan", "192.0.2.12", role="master")
        cfg = ClusterConfig("test", "local-test-token", [broker, client, lan_node])
        snapshots = [
            NodeSnapshot(broker, online=True, health={
                "ready_for_jobs": True, "services": {"mosquitto_1883": True},
            }),
            NodeSnapshot(client, online=True, health={"ready_for_jobs": True}),
        ]
        self.assertEqual(
            build_cross_tier_env(snapshots, cfg, for_node=broker)["PHONECLUSTER_MQTT_URL"],
            "mqtt://127.0.0.1:1883",
        )
        self.assertEqual(
            build_cross_tier_env(snapshots, cfg, for_node=client)["PHONECLUSTER_MQTT_URL"],
            "mqtt://127.0.0.1:25003",
        )
        self.assertNotIn("PHONECLUSTER_MQTT_URL", build_cross_tier_env(snapshots, cfg, for_node=lan_node))

    def test_docker_ps_cli_dispatches_successfully(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cluster.json"
            save_config(create_default_config(worker_hosts=[]), path)
            result = JobOutcome(0, "test-ps", "docker ps", "node0", 0, 0.5)
            with patch.object(MasterController, "run_single", return_value=[result]) as run:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["--config", str(path), "docker", "ps", "--json"]), 0)
            self.assertTrue(run.call_args.args[0].command.startswith("docker ps "))
            self.assertEqual(run.call_args.kwargs["target"], "tier:3")


class TestHealthSampling(unittest.TestCase):
    def test_running_sampler_keeps_health_responsive_before_first_reading(self) -> None:
        worker = WorkerState("node0", "master", "local-test-token", SafetyConfig())
        reading_started = threading.Event()
        release_reading = threading.Event()
        shutdown = threading.Event()

        def collect() -> dict:
            reading_started.set()
            release_reading.wait(3)
            return {"ready_for_jobs": True, "not_ready_reasons": []}

        with patch.object(worker, "_collect_health", side_effect=collect) as slow_collect:
            worker.start_health_sampler(shutdown)
            try:
                self.assertTrue(reading_started.wait(1))
                health = worker.get_health()
                self.assertTrue(health["telemetry_stale"])
                self.assertFalse(health["ready_for_jobs"])
                self.assertIn("telemetry unavailable", health["not_ready_reasons"])
                self.assertEqual(slow_collect.call_count, 1)
            finally:
                shutdown.set()
                release_reading.set()


if __name__ == "__main__":
    unittest.main()
