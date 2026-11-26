"""ADB inventory and listener port regressions using simulated devices."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from phonecluster.cli import main
from phonecluster.config import create_default_config, load_config, save_config
from phonecluster.usbhub import UsbHubWatchdog, apply_adb_usb_hub, plan_adb_usb_hub, sync_usb_hub_into_config


class TestUsbAssignments(unittest.TestCase):
    def test_adb_preserves_conflicts_and_leaves_matching_routes_in_place(self) -> None:
        plan = {
            "forward_rules": [
                {"serial": "A", "local_port": 18761, "remote_port": 8765},
                {"serial": "A", "local_port": 18021, "remote_port": 8022},
                {"serial": "A", "local_port": 25000, "remote_port": 1883},
            ],
            "reverse_rules": [
                {"serial": "A", "remote_port": 8888, "local_port": 8888},
                {"serial": "A", "remote_port": 25005, "local_port": 25005},
            ],
        }
        forwards = {"tcp:18761": ("B", "tcp:9876"), "tcp:18021": ("A", "tcp:8022")}
        reverses = {"tcp:8888": ("UsbFfs", "tcp:7777")}
        created = []

        def adb(command, **kwargs):
            args = command[1:]
            if args == ["forward", "--list"]:
                stdout = "\n".join(f"{serial} {port} {dest}" for port, (serial, dest) in forwards.items())
            elif args == ["-s", "A", "reverse", "--list"]:
                stdout = "\n".join(f"{kind} {port} {dest}" for port, (kind, dest) in reverses.items())
            else:
                _, serial, direction, option, port, dest = args
                self.assertEqual(option, "--no-rebind")
                routes = forwards if direction == "forward" else reverses
                self.assertNotIn(port, routes)
                routes[port] = (serial if direction == "forward" else "UsbFfs", dest)
                created.append(args)
                stdout = ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch("phonecluster.usbhub.subprocess.run", side_effect=adb):
            result = apply_adb_usb_hub(plan, adb_bin="/fixture/adb")
            retry = apply_adb_usb_hub(plan, adb_bin="/fixture/adb")
        self.assertFalse(result["ok"])
        self.assertEqual((result["applied"], result["unchanged"], result["failed"]), (2, 1, 2))
        self.assertEqual((retry["applied"], retry["unchanged"], retry["failed"]), (0, 3, 2))
        self.assertEqual(forwards["tcp:18761"], ("B", "tcp:9876"))
        self.assertEqual(reverses["tcp:8888"], ("UsbFfs", "tcp:7777"))
        self.assertEqual(len(created), 2)

    def test_watchdog_keeps_saved_ports_and_skips_unenrolled_phone(self) -> None:
        initial = [{"serial": "A", "state": "device"}, {"serial": "B", "state": "device"}]
        config = create_default_config(worker_hosts=[])
        first = plan_adb_usb_hub(initial, remote_worker_port=9876, remote_ssh_port=8022)
        sync_usb_hub_into_config(config, first)
        remaining = [initial[1], {"serial": "C", "state": "device"}]
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "cluster.json"
            save_config(config, config_path)
            with (
                patch("phonecluster.usbhub.list_adb_devices", side_effect=[remaining, initial]),
                patch("phonecluster.usbhub.apply_adb_usb_hub", return_value={"ok": True}),
            ):
                watchdog = UsbHubWatchdog(config_path=config_path)
                after = watchdog.sync_once()["plan"]
                reconnected = watchdog.sync_once()["plan"]
            self.assertEqual(after["nodes"], [first["nodes"][1]])
            self.assertEqual(reconnected["nodes"], first["nodes"])
            self.assertEqual(load_config(config_path).get_node("usb2").adb.serial, "B")
            self.assertEqual(
                next(rule for rule in after["forward_rules"] if rule["label"] == "worker")["remote_port"],
                9876,
            )
            self.assertEqual(
                next(rule for rule in after["forward_rules"] if rule["label"] == "mesh-export:1883")["local_port"],
                next(rule for rule in first["forward_rules"] if rule["label"] == "mesh-export:1883" and rule["serial"] == "B")["local_port"],
            )

    def test_failed_tunnel_setup_preserves_config(self) -> None:
        config = create_default_config(worker_hosts=[])
        topo = {"adb_devices": [{"serial": "A", "state": "device"}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cluster.json"
            save_config(config, path)
            before = path.read_bytes()
            with (
                patch("phonecluster.cli.detect_usb_hub_topology", return_value=topo),
                patch("phonecluster.cli.apply_adb_usb_hub", return_value={"ok": False, "applied": 0, "failed": 1}),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                result = main(["--config", str(path), "usb-hub", "setup", "--mode", "adb", "--write-config"])
            self.assertEqual(result, 1)
            self.assertEqual(path.read_bytes(), before)

    def test_sync_sends_listener_ports_through_controller_ssh_port(self) -> None:
        repo = Path(__file__).resolve().parent.parent
        config = create_default_config(worker_hosts=[])
        plan = plan_adb_usb_hub([{"serial": "A", "state": "device"}], remote_worker_port=8766, remote_ssh_port=8022)
        sync_usb_hub_into_config(config, plan)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cluster.json"
            save_config(config, path)
            ssh = root / "ssh"
            ssh.write_text(
                '#!/bin/sh\n'
                'case "$*" in\n'
                '  *config_transfer*--expect*) printf "%s\\n" "$2" > "$PC_TEST_SSH_PORT"; cat > "$PC_TEST_WORKER_CONFIG" ;;\n'
                '  *) cat > /dev/null ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            ssh.chmod(0o700)
            scoped_path = root / "worker.json"
            ssh_port_path = root / "ssh_port"
            env = {
                **os.environ,
                "PATH": os.pathsep.join([str(root), os.environ["PATH"]]),
                "PC_TEST_WORKER_CONFIG": str(scoped_path),
                "PC_TEST_SSH_PORT": str(ssh_port_path),
            }
            result = subprocess.run(
                ["bash", str(repo / "scripts/03_sync_cluster.sh"), "--config", str(path), "--skip-node", "node0"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            scoped = json.loads(scoped_path.read_text(encoding="utf-8"))["nodes"][0]
            self.assertEqual(ssh_port_path.read_text(encoding="utf-8").strip(), "18021")
            self.assertEqual(scoped["worker_port"], 8766)
            self.assertEqual(scoped["ssh_port"], 8022)
            self.assertNotIn("adb", scoped)
