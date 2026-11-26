"""Exercise the installer and the commands in its generated service units."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from phonecluster.cli import build_parser
from phonecluster.config import create_default_config, save_config

REPO = Path(__file__).resolve().parents[1]


class MobileInstallationTests(unittest.TestCase):
    def test_custom_master_from_installer_to_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            checkout = home / "cluster checkout"
            shutil.copytree(REPO, checkout, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "logs", "build", "*.egg-info", "cluster.json",
            ))
            bin_dir = home / "bin"
            bin_dir.mkdir()
            # Simulate healthy phone services without touching the host's systemd or Docker.
            for name in ["systemctl", "loginctl", "sudo"]:
                command = bin_dir / name
                command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                command.chmod(0o755)
            env = dict(os.environ, HOME=str(home), USER="phablet", UBUNTU_TOUCH="1",
                       PATH=f"{bin_dir}:{os.environ['PATH']}", TERMUX_VERSION="", PREFIX="")
            env.pop("PHONECLUSTER_CONFIG", None)
            install = ["bash", str(checkout / "install.sh"), "--master", "--node-id", "node1"]
            # A master named node1 exercises both custom IDs and worker ID allocation.
            answers = "\n127.0.0.1\nphablet\n22\nn\n192.0.2.15\n40\n\n"
            result = subprocess.run(install, env=env, input=answers, capture_output=True, text=True,
                                    start_new_session=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            config_path = checkout / "config/cluster.json"
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual([node["id"] for node in cfg["nodes"]], ["node1", "node2"])

            unit_dir = home / ".config/systemd/user"
            for command in ("worker", "dashboard"):
                unit = (unit_dir / f"phonecluster-{command}.service").read_text(encoding="utf-8")
                exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
                program = shlex.split(exec_start.removeprefix("ExecStart="))
                self.assertEqual(Path(program[2]), checkout / "phonecluster_cli.py")
                args = build_parser().parse_args(program[3:])
                self.assertEqual(args.config, str(config_path))
                self.assertEqual(args.subcommand, command)
                if command == "worker":
                    self.assertEqual(args.node_id, "node1")

            # Reinstall using the existing config without spelling out the ID again.
            subprocess.run(["bash", str(checkout / "install.sh"), "--master", "--non-interactive"],
                           env=env, check=True, capture_output=True, timeout=30)
            self.assertIn("--node-id node1", (unit_dir / "phonecluster-worker.service").read_text())


class SyncRolloutTests(unittest.TestCase):
    def test_sync_runs_only_for_selected_workers_and_preview_does_not_use_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cluster.json"
            cfg = create_default_config(master_host="192.0.2.10", worker_hosts=["192.0.2.11", "192.0.2.12"])
            cfg.get_node("node2").auth_token = ""
            save_config(cfg, path)
            trace = root / "ssh.log"
            ssh = root / "ssh"
            ssh.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$4" >> "$PC_TEST_SSH_LOG"\ncat >/dev/null\n',
                encoding="utf-8",
            )
            ssh.chmod(0o755)
            for name in ("ssh-copy-id", "ssh-keygen"):
                (root / name).symlink_to(ssh)
            env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}", "PC_TEST_SSH_LOG": str(trace)}
            cmd = [sys.executable, str(REPO / "phonecluster_cli.py"), "--config", str(path), "sync"]

            preview = subprocess.run(cmd + ["--node-id", "node1", "--dry-run", "--setup-keys"],
                                     env=env, capture_output=True, text=True, check=True, timeout=10)
            self.assertIn("Would transfer code", preview.stdout)
            self.assertIn("node1", preview.stdout)
            self.assertNotIn("node2", preview.stdout)
            self.assertFalse(trace.exists())
            missing = subprocess.run(cmd + ["--node-id", "bad", "--setup-keys"],
                                     env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("Unknown sync node ID", missing.stderr)
            self.assertFalse(trace.exists())
            subprocess.run(cmd + ["--node-id", "node1", "--node-id", "node1"], env=env,
                           capture_output=True, text=True, check=True, timeout=10)
            self.assertEqual([line.rsplit("@", 1)[-1] for line in trace.read_text().splitlines()], ["192.0.2.11"] * 3)

    def test_interrupted_sync_archive_is_verified_before_live_code_is_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cluster.json"
            remote = root / "mock phone"
            old_code = remote / "phonecluster" / "__init__.py"
            old_code.parent.mkdir(parents=True)
            old_code.write_text("# previous installed code\n", encoding="utf-8")
            save_config(create_default_config(worker_hosts=["192.0.2.11"]), path)
            ssh = root / "ssh"
            ssh.write_text(
                f"#!{sys.executable}\n"
                "import os, subprocess, sys\n"
                "command = sys.argv[-1]\n"
                "archive = sys.stdin.buffer.read()\n"
                "truncated = os.environ['PC_TEST_TRUNCATE'] == '1'\n"
                "if truncated and 'tar -xf ' not in command:\n"
                "    raise SystemExit('worker config or restart was attempted after the archive failed')\n"
                "if truncated:\n"
                "    archive = archive[:len(archive)//2]\n"
                "if 'tar -xf ' in command or '--expect' in command:\n"
                "    raise SystemExit(subprocess.run(['sh', '-c', command], input=archive).returncode)\n",
                encoding="utf-8",
            )
            ssh.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}", "PC_TEST_TRUNCATE": "1"}
            cmd = ["bash", str(REPO / "scripts" / "03_sync_cluster.sh"), "--config", str(path),
                   "--node-id", "node1", "--remote-dir", str(remote)]
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("archive checksum mismatch", result.stderr)
            self.assertEqual(old_code.read_text(encoding="utf-8"), "# previous installed code\n")
            self.assertFalse(list(remote.glob(".phonecluster-sync.*")))
            env["PC_TEST_TRUNCATE"] = "0"
            retry = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(old_code.read_bytes(), (REPO / "phonecluster" / "__init__.py").read_bytes())
            worker_cfg = json.loads((remote / "config" / "cluster.json").read_text(encoding="utf-8"))
            self.assertEqual([node["id"] for node in worker_cfg["nodes"]], ["node1"])
