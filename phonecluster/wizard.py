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
from .bundled import bundled_script
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
from .usbhub import (
    DEFAULT_USB_SUBNET_PREFIX,
    apply_adb_usb_hub,
    build_rndis_router_commands,
    detect_usb_hub_topology,
    plan_adb_usb_hub,
    plan_rndis_usb_hub,
    probe_adb_device_profile,
    sync_usb_hub_into_config,
    validate_subnet_prefix,
    verify_usb_hub_connectivity,
)


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
    transport: str = "ask",
) -> int:
    """Walk the user step-by-step through creating a working cluster config (Wireless Wi-Fi/LAN or USB 3.0 Hub)."""
    master_id = validate_node_id(master_id)
    clean_transport = str(transport or "ask").strip().lower()
    if clean_transport not in {"ask", "wifi", "usb", "usb-adb", "usb-rndis"}:
        raise ValueError("transport must be 'ask', 'wifi', 'usb', 'usb-adb', or 'usb-rndis'")
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
    if clean_transport != "ask":
        print(f"Connection mode : {clean_transport}")
    print()

    previous_revision = config_revision(out_path)
    if previous_revision:
        if not _prompt_yes_no(f"Config already exists at '{out_path}'. Overwrite it?", default=False, input_fn=input_fn):
            print("Keeping existing config.")
            return 0

    cluster_name = _prompt("1. Name your cluster", "phone-cluster", input_fn=input_fn)
    default_master_host = "127.0.0.1" if clean_transport == "usb-adb" else (
        "10.77.1.1" if clean_transport == "usb-rndis" else local_ip
    )
    raw_master = _prompt(
        f"2. Master host IP ({master_id}; LAN IP for Wi-Fi, 127.0.0.1 for ADB USB hub, or 10.77.1.1 for RNDIS USB hub)",
        default_master_host,
        input_fn=input_fn,
    )
    try:
        master_host = validate_host(raw_master)
    except ValueError:
        print(f"  (Invalid master host '{raw_master}', falling back to detected IP {default_master_host})")
        master_host = validate_host(default_master_host)
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
    chosen_usb_mode = ""
    chosen_rndis_prefix = DEFAULT_USB_SUBNET_PREFIX
    usb_plan: dict[str, Any] | None = None
    usb_rndis_cmds: dict[str, Any] | None = None

    print("\n5. Worker Connection Mode (Wireless Wi-Fi/LAN vs USB 3.0 Hub):")
    if clean_transport == "ask":
        print("   [w] Wireless (Wi-Fi / LAN — scan Wi-Fi for phones, or type 'n' to enter IPs manually)")
        print("   [u] USB 3.0 Hub (Zero Wi-Fi — auto-detect ADB or RNDIS /30 phones plugged into hub)")
        mode_ans = _prompt("Connect workers via Wireless [w], USB Hub [u], or manual IPs [n]", "w", input_fn=input_fn).lower()
    elif clean_transport == "wifi":
        mode_ans = "w"
    else:
        mode_ans = clean_transport

    if mode_ans in {"u", "usb", "adb", "usb-adb", "rndis", "usb-rndis"}:
        print("Scanning local USB 3.0 hub for attached phones...")
        topo = detect_usb_hub_topology()
        ready_adb = [d for d in topo.get("adb_devices") or [] if d.get("state") == "device"]
        usb_nets = list(topo.get("usb_net_interfaces") or [])
        rec_mode = str(topo.get("recommended_mode") or "adb")
        print(f"  Detected: {len(ready_adb)} authorized ADB phone(s), {len(usb_nets)} USB-Ethernet gadget(s) (recommended: {rec_mode})")
        if topo.get("subnet_collisions"):
            print("  Notice: USB subnet collision detected — RNDIS /30 router will isolate each phone cleanly.")
        if mode_ans in {"adb", "usb-adb"}:
            chosen_usb_mode = "adb"
        elif mode_ans in {"rndis", "usb-rndis"}:
            chosen_usb_mode = "rndis"
        else:
            picked = _prompt("USB Hub mode: 'adb' (zero-root peer mesh) or 'rndis' (Layer-3 /30 for Ubuntu Touch/Docker)", rec_mode, input_fn=input_fn).lower()
            chosen_usb_mode = "rndis" if picked == "rndis" else "adb"

        if chosen_usb_mode == "adb":
            if ready_adb:
                enriched_adb = []
                for dev in ready_adb:
                    prof = probe_adb_device_profile(dev["serial"])
                    merged = dict(dev)
                    if prof.get("os_env") != "unknown":
                        merged["os_env"] = prof["os_env"]
                        merged["remote_ssh_port"] = prof["remote_ssh_port"]
                    if prof.get("ssh_user"):
                        merged["ssh_user"] = prof["ssh_user"]
                    if prof.get("usb_power_warning"):
                        print(f"  WARNING: {dev['serial']} is discharging on USB — ensure your USB 3.0 hub has external 12V/3A-5A power!")
                    enriched_adb.append(merged)
                usb_plan = plan_adb_usb_hub(
                    enriched_adb,
                    remote_ssh_port=ssh_port,
                    enable_gateway_reverse=False,
                    enable_peer_mesh=True,
                    existing_nodes=nodes,
                )
                for n_item in usb_plan["nodes"]:
                    print(
                        f"  + {n_item['node_id']} ({n_item['serial']}, {n_item.get('os_env', 'adb')}) -> "
                        f"127.0.0.1:{n_item['worker_port']} (worker), 127.0.0.1:{n_item['ssh_port']} (ssh->{n_item['remote_ssh_port']})"
                    )
                if _prompt_yes_no("Create ADB USB hub forwards & peer-mesh tunnels now?", default=True, input_fn=input_fn):
                    res = apply_adb_usb_hub(usb_plan)
                    print(f"  ADB tunnels: {res.get('applied', 0)} created, {res.get('unchanged', 0)} matched, {res.get('failed', 0)} failed.")
                    for err in res.get("errors") or []:
                        print(f"    ERR: {err}", file=sys.stderr)
                    if not res.get("ok"):
                        if not _prompt_yes_no("Some ADB tunnels failed. Save these USB nodes to cluster.json anyway?", default=False, input_fn=input_fn):
                            usb_plan = None
            else:
                print("  No authorized ADB phones detected right now (plug phones into USB hub, enable USB debugging, then run `pc usb-hub setup --mode adb --write-config`).")
        else:
            raw_pref = _prompt("USB /16 private subnet prefix for /30 links", DEFAULT_USB_SUBNET_PREFIX, input_fn=input_fn)
            try:
                prefix = validate_subnet_prefix(raw_pref)
            except ValueError:
                print(f"  (Invalid prefix '{raw_pref}', using {DEFAULT_USB_SUBNET_PREFIX})")
                prefix = DEFAULT_USB_SUBNET_PREFIX
            chosen_rndis_prefix = prefix
            if usb_nets:
                usb_plan = plan_rndis_usb_hub(usb_nets, subnet_prefix=prefix, ssh_port=ssh_port, ssh_user=ssh_user or "phablet", existing_nodes=nodes)
                usb_rndis_cmds = build_rndis_router_commands(usb_plan)
                for n_item in usb_plan["nodes"]:
                    print(
                        f"  + {n_item['node_id']} ({n_item['iface']}, mac={n_item.get('mac') or '-'}): "
                        f"Master {n_item['host_ip']}/30 <-> Phone {n_item['phone_ip']}/30"
                    )
            else:
                print("  No USB-Ethernet / RNDIS gadgets detected yet (plug in Ubuntu Touch phones or enable Android USB Tethering, then run `sudo bash scripts/07_usb_hub_router.sh setup-rndis`).")
    else:
        discovered = []
        if mode_ans in {"w", "wifi", "wireless", "y", "yes", "1"}:
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
    if usb_plan is not None and usb_plan.get("nodes"):
        sync_usb_hub_into_config(cfg, usb_plan)
    saved = save_config(cfg, out_path, expected_revision=previous_revision)

    print("\n" + "=" * 60)
    print(f"  Setup Saved: {saved}")
    print("=" * 60)
    print(f"Cluster : {cfg.cluster_name} ({len(cfg.nodes)} nodes)")
    print(f"Token   : {cfg.auth_token}")
    print("  (Copy this token when unlocking controls in the Web Dashboard!)")
    print("\nNext easy steps:")
    if chosen_usb_mode == "rndis":
        print("  1. Configure Master Layer-3 USB Hub air-gap router:")
        print(f"       sudo bash scripts/07_usb_hub_router.sh setup-rndis --prefix {usb_plan['subnet_prefix'] if usb_plan else chosen_rndis_prefix}")
        if usb_rndis_cmds:
            for nid, pcmds in usb_rndis_cmds["phone_commands"].items():
                print(f"     On phone {nid}: {pcmds[1]}")
        print("  2. Sync code & verify USB hub peer-to-peer communication:")
        print(f"       pc --config {saved} sync --skip-node {master_id}")
        print(f"       pc --config {saved} usb-hub verify")
        print("  3. Open the Web Control Center:")
        print(f"       pc --config {saved} dashboard")
    elif chosen_usb_mode == "adb":
        print("  1. Sync code & start workers over USB (Wi-Fi can stay OFF!):")
        print(f"       pc --config {saved} sync --skip-node {master_id}")
        print("  2. Verify USB hub & peer-mesh communication:")
        print(f"       pc --config {saved} usb-hub verify")
        print("  3. Open the Web Control Center (auto-heals ADB USB tunnels automatically!):")
        print(f"       pc --config {saved} dashboard")
    else:
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
        print("  9) Guided Setup Wizard (Wireless Wi-Fi or USB 3.0 Hub)")
        print("  u) USB 3.0 Hub Manager (Scan, Setup, Verify Peer Links)")
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
                print(f"\nStarting Web Dashboard at: http://{format_host_port(ip, cfg.dashboard_port)}")
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
                    master_n = next((n for n in cfg.nodes if n.role == "master"), cfg.nodes[0] if cfg.nodes else None)
                    seed_h = detect_local_ip() if (master_n is None or is_loopback_or_unspecified_host(master_n.host)) else master_n.host
                    default_cidr = infer_lan_subnet(seed_h, cfg.network.lan_subnet)
                    raw_cidr = _prompt("Allowed LAN subnet CIDR", default_cidr, input_fn=input_fn)
                    try:
                        cidr = str(ipaddress.ip_network(raw_cidr, strict=False))
                    except ValueError:
                        print(f"Invalid CIDR subnet '{raw_cidr}' — cancelled.")
                        continue
                    helper_sh = bundled_script("05_workload_helpers.sh")
                    if helper_sh is not None:
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
            elif choice == "u":
                cfg = load_config(cfg_path)
                prev_rev = config_revision(cfg_path)
                topo = detect_usb_hub_topology()
                print(
                    f"\nUSB 3.0 Hub: ADB ready={topo['adb_ready_count']}, "
                    f"USB-Net={topo['usb_net_count']}, IPv4 forward={'ON' if topo['ipv4_forwarding_enabled'] else 'OFF'}, "
                    f"Recommended={topo['recommended_mode']}"
                )
                sub_c = _prompt("USB Hub action: [s]etup ADB & save, [v]erify hub & peer links, [b]ack", "v", input_fn=input_fn).lower()
                if sub_c in {"s", "setup"}:
                    ready_adb = [d for d in topo["adb_devices"] if d.get("state") == "device"]
                    if not ready_adb:
                        print("No authorized ADB phones found. For RNDIS /30 mode run: sudo bash scripts/07_usb_hub_router.sh setup-rndis")
                    else:
                        enriched_adb = []
                        for dev in ready_adb:
                            prof = probe_adb_device_profile(dev["serial"])
                            item = dict(dev)
                            if prof.get("os_env") != "unknown":
                                item["os_env"] = prof["os_env"]
                                item["remote_ssh_port"] = prof["remote_ssh_port"]
                            if prof.get("ssh_user"):
                                item["ssh_user"] = prof["ssh_user"]
                            if prof.get("usb_power_warning"):
                                print(f"  WARNING: {dev['serial']} is discharging on USB — check your powered USB 3.0 hub PSU!")
                            enriched_adb.append(item)
                        plan = plan_adb_usb_hub(
                            enriched_adb,
                            gateway_port=cfg.gateway.port,
                            enable_gateway_reverse=bool(cfg.gateway.enabled),
                            existing_nodes=cfg.nodes,
                            quarantined_nodes=cfg.gateway.quarantined_nodes,
                        )
                        res = apply_adb_usb_hub(plan)
                        if res.get("ok"):
                            updated = sync_usb_hub_into_config(cfg, plan)
                            save_config(cfg, cfg_path, expected_revision=prev_rev)
                            print(f"Saved USB hub phone(s): {', '.join(updated)} ({res.get('applied', 0)} tunnels created)")
                        else:
                            print(f"USB tunnel setup had errors: {res.get('errors')}")
                elif sub_c in {"v", "verify"}:
                    rep = verify_usb_hub_connectivity(MasterController(cfg))
                    print(f"Result: {rep['summary']}")
                    for row in rep["nodes"]:
                        print(f"  - {row['node_id']} ({row['mode']}) -> {'ONLINE' if row['online'] else 'OFFLINE'} ({row['latency_ms']}ms)")
                    for lk in rep["peer_links"]:
                        print(f"  - Peer {lk['from']} -> {lk['to']} ({lk['mode']}): {'OK' if lk['ok'] else 'FAIL'} {lk.get('error', '')}")
                    for w in rep["warnings"]:
                        print(f"  WARN: {w}")
            elif choice == "t":
                cfg = load_config(cfg_path)
                print(f"\nCluster auth_token (for Web UI Unlock): {cfg.auth_token}\n")
                _cmd_jobs(argparse.Namespace(config=str(cfg_path), limit=5, json=False))
            else:
                print("Please enter a valid option (0-9, u, or t).")
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
