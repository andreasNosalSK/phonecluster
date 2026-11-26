"""Friendly guided setup wizard and interactive terminal menu for PhoneCluster."""

from __future__ import annotations

import ipaddress
import math
import os
import shlex
import shutil
import subprocess
import sys
import uuid
from itertools import count
from pathlib import Path
from typing import Any, Callable

from .auth import is_webhook_target_unsafe
from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    ClusterConfig,
    NodeConfig,
    SafetyConfig,
    config_revision,
    format_host_port,
    generate_auth_token,
    is_loopback_or_unspecified_host,
    load_config,
    resolve_config_path,
    save_config,
    validate_host,
    validate_node_id,
    validate_ssh_user,
)
from .discovery import detect_local_ip, discover_lan_nodes
from .doctor import run_doctor
from .master import JobSpec, MasterController
from .netguard import infer_lan_subnet
from .telemetry import detect_docker_runtime, detect_os_environment, is_ubuntu_touch_os, read_memory_info


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
    *,
    master_id: str = "node0",
) -> int:
    """Walk the user step-by-step through creating a working cluster config."""
    master_id = validate_node_id(master_id)
    out_path = resolve_config_path(config_path)
    local_ip = detect_local_ip()
    os_env = detect_os_environment()
    is_ut = is_ubuntu_touch_os(os_env)
    docker_rt = detect_docker_runtime()
    mem = read_memory_info()
    user = os.environ.get("USER", "") or ("phablet" if is_ut else "")
    default_ssh_port = DEFAULT_SSH_PORT if os_env == "termux" else 22

    print("=" * 60)
    print("  PhoneCluster Guided Setup Wizard")
    print("=" * 60)
    dk_note = ""
    if docker_rt.get("installed"):
        dk_note = " | Docker (Snap)" if docker_rt.get("is_snap") else " | Docker"
    print(f"Detected device : {os_env} | IP {local_ip} | {os.cpu_count() or 1} cores | {mem['total_mb']} MB RAM{dk_note}")
    print(f"Config target   : {out_path}")
    print()

    previous_revision = config_revision(out_path)
    if previous_revision:
        if not _prompt_yes_no(f"Config already exists at '{out_path}'. Overwrite it?", default=False, input_fn=input_fn):
            print("Keeping existing config.")
            return 0

    cluster_name = _prompt("1. Name your cluster", "phone-cluster", input_fn=input_fn)
    raw_master = _prompt(f"2. Static LAN IP of your Master phone ({master_id})", local_ip, input_fn=input_fn)
    try:
        master_host = validate_host(raw_master)
    except ValueError:
        print(f"  (Invalid master host '{raw_master}', falling back to detected IP {local_ip})")
        master_host = validate_host(local_ip)
    raw_user = _prompt("3. Default SSH username on phones (e.g. 'phablet' on Ubuntu Touch, or `whoami`)", user, input_fn=input_fn)
    try:
        ssh_user = validate_ssh_user(raw_user)
    except ValueError:
        print(f"  (Invalid SSH username '{raw_user}', leaving blank)")
        ssh_user = ""
    ssh_port_str = _prompt("4. Default SSH port (8022 for Termux, 22 for Ubuntu Touch / Debian)", str(default_ssh_port), input_fn=input_fn)
    ssh_port = (
        int(ssh_port_str)
        if ssh_port_str.isascii() and ssh_port_str.isdigit() and 1 <= int(ssh_port_str) <= 65535
        else default_ssh_port
    )

    nodes: list[NodeConfig] = [
        NodeConfig(
            id=master_id,
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

    worker_ids = (f"node{i}" for i in count(1) if f"node{i}" != master_id)
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
                    try:
                        disc_host = validate_host(str(item["host"]))
                    except ValueError:
                        continue
                    try:
                        disc_user = validate_ssh_user(str(item.get("ssh_user") or "")) or ssh_user
                    except ValueError:
                        disc_user = ssh_user
                    nid = next(worker_ids)
                    nodes.append(
                        NodeConfig(
                            id=nid,
                            host=disc_host,
                            role="worker",
                            auth_token=generate_auth_token(),
                            worker_port=item["worker_port"],
                            ssh_port=item["ssh_port"],
                            ssh_user=disc_user,
                            max_concurrency=2,
                            weight=1.0,
                            tags=["worker"],
                            notes=f"Auto-discovered ({item['os_env']})",
                        )
                    )
        else:
            print("No other phones replied yet (that's normal if you haven't started workers yet).")

    extra_ips = _prompt(
        "Enter any additional Worker phone IPs (comma-separated, e.g. 192.168.1.202,192.168.1.203, or blank to skip)",
        "",
        input_fn=input_fn,
    )
    existing_hosts = {n.host for n in nodes}
    for raw_ip in extra_ips.split(","):
        cand = raw_ip.strip()
        if not cand:
            continue
        try:
            ip = validate_host(cand)
        except ValueError:
            print(f"  Skipping invalid worker host/IP '{cand}'.")
            continue
        if ip not in existing_hosts:
            nid = next(worker_ids)
            nodes.append(
                NodeConfig(
                    id=nid,
                    host=ip,
                    role="worker",
                    auth_token=generate_auth_token(),
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
    raw_temp = _prompt("Pause jobs on a phone if temperature reaches (°C)", "40.0", input_fn=input_fn)
    try:
        parsed_t = float(raw_temp.rstrip("cC° "))
        if not math.isfinite(parsed_t):
            raise ValueError("non-finite")
        max_temp = max(25.0, min(85.0, parsed_t))
    except ValueError:
        max_temp = 40.0
    resume_temp = round(max(20.0, max_temp - 3.0), 1)
    webhook = _prompt(
        "Optional battery/smart-plug webhook URL (Home Assistant / ntfy.sh, or blank)",
        "",
        input_fn=input_fn,
    )
    try:
        safety_cfg = SafetyConfig.from_dict(
            {
                "max_temp_c": max_temp,
                "resume_temp_c": resume_temp,
                "battery_webhook_url": webhook,
            }
        )
        if safety_cfg.battery_webhook_url and is_webhook_target_unsafe(safety_cfg.battery_webhook_url):
            raise ValueError("webhook target IP/host is not allowed")
    except ValueError as exc:
        print(f"  (Invalid webhook URL ignored: {exc})")
        safety_cfg = SafetyConfig(max_temp_c=max_temp, resume_temp_c=resume_temp, battery_webhook_url="")

    cfg = ClusterConfig(
        cluster_name=cluster_name,
        auth_token=generate_auth_token(),
        nodes=nodes,
        safety=safety_cfg,
    )
    saved = save_config(cfg, out_path, expected_revision=previous_revision)

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
    print(f"       -> http://{format_host_port(master_host, cfg.dashboard_port)}")
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

        try:
            raw_choice = input_fn("Choose an option [1]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return 0
        choice = raw_choice or "1"

        if choice == "0":
            print("Goodbye!")
            return 0

        try:
            if choice == "9":
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
                spec = JobSpec(index=0, job_id=f"menu-run-{uuid.uuid4().hex[:6]}", command=cmd, timeout_sec=cfg.default_job_timeout_sec)
                for o in ctrl.run_single(spec, target=target):
                    print(f"\n=== [{o.node_id}] {'OK' if o.ok else 'FAIL'} ({o.duration_sec:.2f}s) ===")
                    if o.stdout:
                        print(o.stdout.rstrip())
                    if o.stderr:
                        print(o.stderr.rstrip(), file=sys.stderr)
                    if o.error:
                        print(f"ERROR: {o.error}", file=sys.stderr)
            elif choice == "4":
                cli_entry = Path(__file__).resolve().parent.parent / "phonecluster_cli.py"
                cli_cmd = [sys.executable, str(cli_entry)] if cli_entry.is_file() else [sys.executable, "-m", "phonecluster.cli"]
                script = _prompt("Local script path (e.g. examples/sample_job.py, or blank to use a commands file)", "", input_fn=input_fn)
                if script:
                    args_file = _prompt("Arguments file (one arg list per line)", "examples/sample_args.txt", input_fn=input_fn)
                    subprocess.run(
                        cli_cmd
                        + [
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
                            cli_cmd
                            + [
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
                    master_n = next((n for n in cfg.nodes if n.role == "master"), cfg.nodes[0])
                    seed_h = detect_local_ip() if is_loopback_or_unspecified_host(master_n.host) else master_n.host
                    default_cidr = infer_lan_subnet(seed_h, cfg.network.lan_subnet)
                    raw_cidr = _prompt("Allowed LAN subnet CIDR", default_cidr, input_fn=input_fn)
                    try:
                        cidr = str(ipaddress.ip_network(raw_cidr, strict=False))
                    except ValueError:
                        print(f"Invalid CIDR subnet '{raw_cidr}' — cancelled.")
                        continue
                    helper_sh = Path(__file__).resolve().parent.parent / "scripts" / "05_workload_helpers.sh"
                    if helper_sh.exists():
                        spec = JobSpec(
                            index=0,
                            job_id=f"menu-distcc-{uuid.uuid4().hex[:6]}",
                            script_content=helper_sh.read_text(encoding="utf-8"),
                            script_name="05_workload_helpers.sh",
                            interpreter="bash",
                            args=["distcc-start", cidr],
                            timeout_sec=30.0,
                        )
                    else:
                        spec = JobSpec(
                            index=0,
                            job_id=f"menu-distcc-{uuid.uuid4().hex[:6]}",
                            command=f"bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start {shlex.quote(cidr)}",
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
        except KeyboardInterrupt:
            print("\nReturned to menu.")
        except (OSError, ValueError, FileNotFoundError) as exc:
            print(f"\nError: {exc}", file=sys.stderr)


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
