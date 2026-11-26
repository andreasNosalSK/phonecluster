"""Check the installed sync payload and workload dashboard helper."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.request
from unittest.mock import patch


def main(pc):
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        ssh = dest / "ssh"
        ssh.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            '  *"tar -xf "*) cat > "$PC_WHEEL_SMOKE_ARCHIVE" ;;\n'
            "  *) cat >/dev/null ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        ssh.chmod(0o755)
        archive = dest / "payload.tar"
        config = dest / "cluster.json"
        env = dict(os.environ, PATH=f"{dest}:{pc.parent}:{os.environ['PATH']}",
                   PC_WHEEL_SMOKE_ARCHIVE=str(archive))
        env.pop("PYTHONPATH", None)
        subprocess.run([pc, "init-config", "--workers", "192.0.2.11", "-o", config],
                       cwd=dest, env=env, check=True)
        subprocess.run([pc, "--config", config, "sync", "--node-id", "node1"],
                       cwd=dest, env=env, check=True)
        with tarfile.open(archive) as tar:
            for member in ["phonecluster_cli.py", "phonecluster/cli.py",
                           "scripts/03_sync_cluster.sh", "examples/sample_job.py"]:
                if not tar.getmember(member).isfile():
                    raise RuntimeError(f"Missing file in worker payload: {member}")
        subprocess.run(
            [pc.with_name("python"), Path(__file__).resolve(), "--check-workload-helper", config],
            cwd=dest, env=env, check=True, timeout=10,
        )


def check_workload_helper(config):
    from phonecluster.config import load_config
    from phonecluster.dashboard import DashboardHTTPServer
    from phonecluster.master import MasterController

    ctrl = MasterController(load_config(config))
    with DashboardHTTPServer(("127.0.0.1", 0), ctrl, enable_pairing_beacon=False) as dash:
        thread = threading.Thread(target=dash.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            port = dash.server_address[1]
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/workloads/action",
                data=b'{"action":"distcc-stop"}',
                headers={"Authorization": "Bearer " + ctrl.config.auth_token, "Content-Type": "application/json"},
            )
            with patch.object(ctrl, "run_single", return_value=[]) as run:
                with urllib.request.urlopen(request, timeout=3) as reply:
                    assert json.load(reply)["action"] == "distcc-stop"
                spec = run.call_args.args[0]
                assert spec.script_name == "05_workload_helpers.sh"
                assert "distcc-stop)" in spec.script_content
                assert spec.command is None
        finally:
            dash.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    if sys.argv[1] == "--check-workload-helper":
        check_workload_helper(sys.argv[2])
    else:
        main(Path(sys.argv[1]).resolve())
