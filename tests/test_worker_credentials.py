import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from phonecluster import cli
from phonecluster.config import create_default_config, load_config, save_config


class WorkerCredentialTests(unittest.TestCase):
    def test_sync_migrates_only_on_explicit_rotation_and_sends_individual_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "cluster.json"
            hosts = [f"127.0.0.{i}" for i in range(2, 7)]
            config = create_default_config(master_host="127.0.0.1", worker_hosts=hosts)
            workers = config.nodes[1:]
            self.assertEqual(config.workers_needing_tokens(), [])
            admin = config.auth_token
            preserved = workers[4].auth_token
            workers[0].auth_token = ""
            workers[1].auth_token = admin
            workers[2].auth_token = workers[3].auth_token = "shared-between-two-workers"
            save_config(config, path)

            # Record the JSON passed to SSH without making any remote connections.
            ssh = root / "ssh"
            ssh.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "root = pathlib.Path(os.environ['SYNC_CAPTURE'])\n"
                "(root / 'ssh-called').touch()\n"
                "data = sys.stdin.buffer.read()\n"
                "if data.startswith(b'{'):\n"
                "    node_id = json.loads(data)['nodes'][0]['id']\n"
                "    (root / (node_id + '.json')).write_bytes(data)\n",
                encoding="utf-8",
            )
            ssh.chmod(0o700)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"], "SYNC_CAPTURE": str(root)}
            repo = Path(__file__).resolve().parents[1]
            cmd = ["bash", str(repo / "scripts/03_sync_cluster.sh"), "--config", str(path), "--skip-node", "node0"]
            blocked = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("pc token --rotate", blocked.stderr)
            self.assertFalse((root / "ssh-called").exists())
            self.assertEqual(load_config(path).auth_token, admin)

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--config", str(path), "token", "--rotate"]), 0)
            updated = load_config(path)
            self.assertNotEqual(admin, updated.auth_token)
            self.assertEqual(updated.get_node("node5").auth_token, preserved)
            self.assertEqual(updated.workers_needing_tokens(), [])
            self.assertTrue(all(n.auth_token not in {admin, "shared-between-two-workers"} for n in updated.nodes[1:]))

            sent = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(sent.returncode, 0, sent.stderr)
            for worker in updated.nodes[1:]:
                payload = (root / (worker.id + ".json")).read_text(encoding="utf-8")
                scoped = json.loads(payload)
                self.assertEqual([n["id"] for n in scoped["nodes"]], [worker.id])
                self.assertEqual(scoped["auth_token"], worker.auth_token)
                self.assertEqual(scoped["nodes"][0]["auth_token"], worker.auth_token)
                self.assertNotIn(updated.auth_token, payload)
