"""Friendly guided setup wizard and interactive terminal menu for PhoneCluster."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    ClusterConfig,
    NodeConfig,
    SafetyConfig,
    load_config,
    resolve_config_path,
    save_config,
)
from .discovery import detect_local_ip, discover_lan_nodes
from .doctor import run_doctor
from .master import JobSpec, MasterController
from .telemetry import detect_os_environment, read_memory_info


def _prompt(
    question: str,
    default: str = "",
    input_fn: Callable[[str], str] = input,
) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input_fn(f"{question}{suffix}: ").strip()
    except EOFError:
        return default
    return answer if answer else default


def _prompt_yes_no(
    question: str,
    default: bool = True,
    input_fn: Callable[[str], str] = input,
) -> bool:
    hint = "Y/n" if default else "y/N"
    ans = _prompt(f"{question} ({hint})", "", input_fn=input_fn).lower()
    if not ans:
        return default
    return ans in {"y", "yes", "1", "true"}


def run_setup_wizard(
    config_path: str | Path | None = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    """Walk the user step-by-step through creating a working cluster config."""
    out_path = resolve_config_path(config_path)
    local_ip = detect_local_ip()
    os_env = detect_os_environment()
    mem = read_memory_info()
    user = os.environ.get("USER", "")
    default_ssh_port = 8022 if os_env == "termux" else 22

    print("=" * 60)
    print("  PhoneCluster Guided Setup Wizard")
    print("=" * 60)
    print(f"Detected device : {os_env} | IP {local_ip} | {os.cpu_count() or 1} cores | {mem['total_mb']} MB RAM")
    print(f"Config target   : {out_path}")
    print()

    if out_path.exists():
        if not _prompt_yes_no(f"Config already exists at '{out_path}'. Overwrite it?", default=False, input_fn=input_fn):
            print("Keeping existing config.")
            return 0

    cluster_name = _prompt("1. Name your cluster", "phone-cluster", input_fn=input_fn)
    master_host = _prompt("2. Static LAN IP of your Master phone (node0)", local_ip, input_fn=input_fn)
    ssh_user = _prompt("3. Default SSH username on phones (from `whoami`)", user, input_fn=input_fn)
    ssh_port_str = _prompt("4. Default SSH port (8022 for Termux, 22 for Debian)", str(default_ssh_port), input_fn=input_fn)
    ssh_port = int(ssh_port_str) if ssh_port_str.isdigit() else DEFAULT_SSH_PORT

    nodes: list[NodeConfig] = [
        NodeConfig(
            id="node0",
            host=master_host,
            role="master",
            worker_port=DEFAULT_WORKER_PORT,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            max_concurrency=2,
            weight=1.2,
            tags=["master"],
            notes="Master phone (+ local worker)",
        )
    ]

    print("\n5. Finding Worker phones...")
    discovered = []
    if _prompt_yes_no("Scan your Wi-Fi now for phones already running PhoneCluster?", default=True, input_fn=input_fn):
        print("Scanning LAN (2 seconds)...")
        discovered = [d for d in discover_lan_nodes(timeout_sec=2.0) if d["host"] != master_host]
        if discovered:
            print(f"Found {len(discovered)} phone(s) on your Wi-Fi:")
            for idx, item in enumerate(discovered, start=1):
                print(
                    f"  {idx}) {item['host']}  ({item['os_env']}, {item['cpu_cores']} cores, "
                    f"{item['mem_total_mb']} MB RAM, user={item['ssh_user'] or '?'})"
                )
            if _prompt_yes_no("Add all discovered phones as Workers?", default=True, input_fn=input_fn):
                for item in discovered:
                    nid = f"node{len(nodes)}"
                    nodes.append(
                        NodeConfig(
                            id=nid,
                            host=item["host"],
                            role="worker",
                            worker_port=item["worker_port"],
                            ssh_port=item["ssh_port"],
                            ssh_user=item["ssh_user"] or ssh_user,
                            max_concurrency=2,
                            weight=1.0,
                            tags=["worker"],
                            notes=f"Auto-discovered ({item['os_env']})",
                        )
                    )
        else:
            print("No other phones replied yet (that's normal if you haven't started workers yet).")

    manual_default = "" if len(nodes) > 1 else "192.168.1.202,192.168.1.203"
    extra_ips = _prompt(
        "Enter any additional Worker phone IPs (comma-separated, or blank to skip)",
        manual_default,
        input_fn=input_fn,
    )
    existing_hosts = {n.host for n in nodes}
    for raw_ip in extra_ips.split(","):
        ip = raw_ip.strip()
        if ip and ip not in existing_hosts:
            nid = f"node{len(nodes)}"
            nodes.append(
                NodeConfig(
                    id=nid,
                    host=ip,
                    role="worker",
                    worker_port=DEFAULT_WORKER_PORT,
                    ssh_port=ssh_port,
                    ssh_user=ssh_user,
                    max_concurrency=2,
                    weight=1.0,
                    tags=["worker"],
                    notes=f"Worker phone {len(nodes)}",
                )
            )
            existing_hosts.add(ip)

    print("\n6. Thermal & 24/7 Battery Safety Guard:")
    max_temp = float(_prompt("Pause jobs on a phone if temperature reaches (°C)", "40.0", input_fn=input_fn))
    webhook = _prompt(
        "Optional battery/smart-plug webhook URL (Home Assistant / ntfy.sh, or blank)",
        "",
        input_fn=input_fn,
    )

    cfg = ClusterConfig(
        cluster_name=cluster_name,
        auth_token=secrets.token_urlsafe(32),
        nodes=nodes,
        safety=SafetyConfig(
            max_temp_c=max_temp,
            resume_temp_c=max(25.0, round(max_temp - 3.0, 1)),
            battery_webhook_url=webhook,
        ),
    )
    saved = save_config(cfg, out_path)

    print("\n" + "=" * 60)
    print(f"  Setup Saved: {saved}")
    print("=" * 60)
    print(f"Cluster : {cfg.cluster_name} ({len(cfg.nodes)} nodes)")
    print(f"Token   : {cfg.auth_token}")
    print("  (Copy this token when unlocking controls in the Web Dashboard!)")
    print("\nNext easy steps:")
    print("  1. Sync code & start workers on all phones:")
    print(f"       pc --config {saved} sync --setup-keys")
    print("  2. Check your cluster health:")
    print(f"       pc --config {saved} doctor")
    print("  3. Open the friendly Web Control Center:")
    print(f"       pc --config {saved} dashboard")
    print(f"       -> http://{master_host}:{cfg.dashboard_port}")
    return 0


def run_interactive_menu(
    config_path: str | Path | None = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    """Friendly numbered terminal menu so users never need to memorize flags."""
    from .cli import _cmd_jobs, _cmd_status
    from .dashboard import serve_dashboard
    from .pairing import DEFAULT_PAIR_PORT, run_cli_pairing_host
    from .tui import run_top_tui
    import argparse

    cfg_path = resolve_config_path(config_path)

    while True:
        print("\n" + "=" * 52)
        print("  PhoneCluster Control Menu")
        print("=" * 52)
        print("  1) Shared Multi-Device btop (Live Terminal Control)")
        print("  2) Cluster Status (Quick Summary Table)")
        print("  3) Run a Command (Best Phone or All Phones)")
        print("  4) Run Parallel Jobs (Ship & Run a Script / File)")
        print("  5) Pair a New Phone (Secure 6-Digit PIN Window)")
        print("  6) Cluster Doctor (Health, Security & Battery Check)")
        print("  7) Start Web Control Center (Browser btop + Terminal)")
        print("  8) Workloads Helper (distcc / llama.cpp / OpenMPI)")
        print("  9) Guided Setup Wizard (Create/Edit cluster.json)")
        print("  t) View Active/Recent Jobs & Show Auth Token")
        print("  0) Exit")
        print("-" * 52)

        choice = _prompt("Choose an option", "1", input_fn=input_fn).lower()

        if choice == "0":
            print("Goodbye!")
            return 0
        elif choice == "9":
            run_setup_wizard(cfg_path, input_fn=input_fn)
            continue
        elif choice == "6":
            report = run_doctor(cfg_path)
            _print_doctor_report(report)
            continue

        if not cfg_path.exists():
            print(f"\nNo config found at '{cfg_path}'. Let's run the Setup Wizard first!")
            run_setup_wizard(cfg_path, input_fn=input_fn)
            continue

        if choice == "5":
            cfg = load_config(cfg_path)
            run_cli_pairing_host(cfg, cfg_path, port=DEFAULT_PAIR_PORT, ttl_sec=120, max_devices=1)
        elif choice == "1":
            cfg = load_config(cfg_path)
            run_top_tui(MasterController(cfg))
        elif choice == "2":
            ns = argparse.Namespace(config=str(cfg_path), json=False)
            _cmd_status(ns)
        elif choice == "3":
            cfg = load_config(cfg_path)
            ctrl = MasterController(cfg)
            target = _prompt("Target ('best', 'all', or node id like 'node1')", "best", input_fn=input_fn)
            cmd = _prompt("Shell command to run", "uname -a && nproc", input_fn=input_fn)
            spec = JobSpec(index=0, job_id="menu-run", command=cmd, timeout_sec=cfg.default_job_timeout_sec)
            for o in ctrl.run_single(spec, target=target):
                print(f"\n=== [{o.node_id}] {'OK' if o.ok else 'FAIL'} ({o.duration_sec:.2f}s) ===")
                if o.stdout:
                    print(o.stdout.rstrip())
                if o.stderr:
                    print(o.stderr.rstrip(), file=sys.stderr)
                if o.error:
                    print(f"ERROR: {o.error}", file=sys.stderr)
        elif choice == "4":
            script = _prompt("Local script path (or blank to use a commands file)", "examples/sample_job.py", input_fn=input_fn)
            if script:
                args_file = _prompt("Arguments file (one arg list per line)", "examples/sample_args.txt", input_fn=input_fn)
                subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).resolve().parent.parent / "phonecluster_cli.py"),
                        "--config",
                        str(cfg_path),
                        "map",
                        "--script",
                        script,
                        "--args-file",
                        args_file,
                    ],
                    check=False,
                )
            else:
                jobs_file = _prompt("Jobs file path (one shell command per line)", "", input_fn=input_fn)
                if jobs_file:
                    subprocess.run(
                        [
                            sys.executable,
                            str(Path(__file__).resolve().parent.parent / "phonecluster_cli.py"),
                            "--config",
                            str(cfg_path),
                            "map",
                            "--jobs-file",
                            jobs_file,
                        ],
                        check=False,
                    )
        elif choice == "7":
            cfg = load_config(cfg_path)
            ctrl = MasterController(cfg)
            ip = detect_local_ip()
            print(f"\nStarting Web Dashboard at: http://{ip}:{cfg.dashboard_port}")
            print("Press Ctrl+C to return to the menu.")
            serve_dashboard("0.0.0.0", cfg.dashboard_port, ctrl, config_path=cfg_path)
        elif choice == "8":
            cfg = load_config(cfg_path)
            ctrl = MasterController(cfg)
            print("\n--- Live Workload Endpoints ---")
            print(f"distcc    : export DISTCC_HOSTS=\"{ctrl.build_distcc_hosts()}\"")
            print(f"llama.cpp : --rpc {ctrl.build_llama_rpc_arg() or '(no rpc-server detected on port 50052)'}")
            mpi = ctrl.build_mpi_hostfile().strip()
            print(f"OpenMPI   :\n{mpi or '(no healthy nodes)'}")
            if _prompt_yes_no("Start distccd compiler workers on all ready phones now?", default=False, input_fn=input_fn):
                cidr = _prompt("Allowed LAN subnet CIDR", "192.168.1.0/24", input_fn=input_fn)
                helper_sh = Path(__file__).resolve().parent.parent / "scripts" / "05_workload_helpers.sh"
                if helper_sh.exists():
                    spec = JobSpec(
                        index=0,
                        job_id="menu-distcc",
                        script_content=helper_sh.read_text(encoding="utf-8"),
                        script_name="05_workload_helpers.sh",
                        interpreter="bash",
                        args=["distcc-start", cidr],
                        timeout_sec=30.0,
                    )
                else:
                    spec = JobSpec(
                        index=0,
                        job_id="menu-distcc",
                        command=f"bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start {cidr}",
                        timeout_sec=30.0,
                    )
                for o in ctrl.run_single(spec, target="all"):
                    print(f"[{o.node_id}] {'OK' if o.ok else 'FAIL'}: {(o.stdout or o.stderr or o.error).strip()}")
        elif choice == "t":
            cfg = load_config(cfg_path)
            print(f"\nCluster auth_token (for Web UI Unlock): {cfg.auth_token}\n")
            _cmd_jobs(argparse.Namespace(config=str(cfg_path), limit=5, json=False))
        else:
            print("Please enter a valid option (0-9 or t).")


def _print_doctor_report(report: dict[str, Any]) -> None:
    icons = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}
    print()
    for item in report["checks"]:
        badge = icons.get(item["status"], "[INFO]")
        print(f"  {badge} {item['name']}: {item['detail']}")
        if item.get("fix_hint"):
            print(f"         -> Fix: {item['fix_hint']}")
    s = report["summary"]
    print(f"\nDoctor Summary: {s['ok']} passed, {s['warn']} warnings, {s['fail']} failed.")
