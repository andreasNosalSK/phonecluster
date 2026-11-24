"""Unified CLI for PhoneCluster (worker daemon, master scheduler, workload helpers, web UI)."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import math
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from . import __version__
from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SSH_PORT,
    create_default_config,
    format_host_for_url,
    generate_auth_token,
    load_config,
    normalize_host,
    resolve_config_path,
    save_config,
)
from .dashboard import serve_dashboard
from .discovery import discover_lan_nodes
from .doctor import run_doctor
from .gateway import GatewayManager
from .master import JobOutcome, JobSpec, MasterController
from .netguard import apply_security_profile, audit_cluster_network
from .pairing import (
    DEFAULT_PAIR_PORT,
    discover_pairing_masters,
    join_cluster_via_pairing,
    run_cli_pairing_host,
)
from .tui import run_top_tui
from .wizard import _print_doctor_report, run_interactive_menu, run_setup_wizard
from .worker import WorkerState, serve_worker

REPO_ROOT = Path(__file__).resolve().parent.parent


def _configure_logging(verbose: bool, is_daemon: bool = False) -> None:
    if verbose:
        level = logging.DEBUG
    elif is_daemon:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _cmd_init_config(args: argparse.Namespace) -> int:
    out_path = Path(args.output)
    if out_path.exists() and not args.force:
        print(
            f"Config already exists at '{out_path}'. Pass --force to overwrite.",
            file=sys.stderr,
        )
        return 1
    workers = [w.strip() for w in args.workers.split(",") if w.strip()]
    cfg = create_default_config(
        cluster_name=args.name,
        master_host=args.master_host,
        worker_hosts=workers,
        ssh_user=args.ssh_user,
        ssh_port=args.ssh_port,
    )
    saved = save_config(cfg, out_path)
    print(f"Created cluster config at: {saved}")
    print(f"Cluster name : {cfg.cluster_name}")
    print(f"Master node  : node0 ({cfg.nodes[0].host})")
    print(f"Worker nodes : {len(cfg.nodes) - 1}")
    print("Auth token   : generated (stored inside config with 0600 permissions)")
    print("Next step    : Edit node IPs/ssh_user if needed, then run scripts/03_sync_cluster.sh")
    return 0


def _cmd_worker(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    try:
        node = cfg.get_node(args.node_id)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    port = args.port if args.port else node.worker_port
    if not (0 <= int(port) <= 65535):
        print(f"Error: worker port must be 0..65535 (got {port})", file=sys.stderr)
        return 2
    max_conc = args.max_concurrency if args.max_concurrency else node.max_concurrency
    if not (1 <= int(max_conc) <= 32):
        print(f"Error: --max-concurrency must be 1..32 (got {max_conc})", file=sys.stderr)
        return 2
    workdir = Path(args.workdir).expanduser()
    if not workdir.exists() or not workdir.is_dir():
        print(f"Error: --workdir does not exist or is not a directory: {workdir}", file=sys.stderr)
        return 2
    allowed_ips: set[str] = set()
    if cfg.network.enforce_worker_source_ip:
        allowed_ips = {"127.0.0.1", "::1"} | set(cfg.network.allowed_master_ips)
        for n in cfg.nodes:
            if n.role == "master" and n.host:
                allowed_ips.add(n.host)
    state = WorkerState(
        node_id=node.id,
        role=node.role,
        auth_token=cfg.token_for_node(node),
        safety=cfg.safety,
        max_concurrency=int(max_conc),
        workdir=workdir,
        allowed_client_ips=allowed_ips,
        require_signed_requests=bool(cfg.network.require_signed_requests),
        config_path=cfg_path,
    )
    serve_worker(
        args.bind,
        port,
        state,
        ssh_port=node.ssh_port,
        ssh_user=node.ssh_user,
        enable_discovery=bool(args.discover),
    )
    return 0


def _fmt_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "  "
    out = [
        sep.join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        sep.join("-" * widths[i] for i in range(len(headers))),
    ]
    for row in rows:
        out.append(sep.join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(out)


def _render_status_once(ctrl: MasterController, as_json: bool) -> None:
    summary = ctrl.cluster_summary()
    if as_json:
        print(json.dumps(summary, indent=2))
        return

    print(
        f"Cluster: {summary['cluster_name']}  |  "
        f"Nodes Ready: {summary['nodes_ready']}/{summary['nodes_total']} "
        f"(Online: {summary['nodes_online']})  |  "
        f"CPU: {summary['total_cores']} cores  |  "
        f"RAM Free: {summary['mem_available_mb']/1024:.2f}/"
        f"{summary['mem_total_mb']/1024:.2f} GB"
    )
    print()

    rows: list[list[str]] = []
    for n in summary["nodes"]:
        h = n["health"]
        tp_str = f"T{n.get('tier', 1)}:{n.get('pool', 'compute')}"
        if not n["online"]:
            state_str = f"OFFLINE ({n['error'][:28]})"
            rows.append([n["id"], n["role"], tp_str, n["host"], "-", state_str, "-", "-", "-", "-", "-"])
            continue
        if n.get("quarantined"):
            state_str = "QUARANTINED"
        elif n["ready_for_jobs"]:
            state_str = f"READY ({h.get('active_jobs', 0)}/{h.get('max_concurrency', '?')})"
        else:
            raw_r = h.get("not_ready_reasons")
            reasons = ",".join(str(x) for x in raw_r) if isinstance(raw_r, list) and raw_r else "paused"
            state_str = f"PAUSED ({reasons})"
        try:
            load_v = float(h.get("load_1m", 0) or 0)
            load_txt = f"{load_v:.2f}" if load_v == load_v else "0.00"
        except (TypeError, ValueError):
            load_txt = "0.00"
        cpu_str = f"{h.get('cpu_cores', '?')}c / {load_txt}"
        ram_str = f"{h.get('mem_available_mb', 0)}/{h.get('mem_total_mb', 0)} MB"
        bat = h.get("battery_pct")
        bat_str = f"{bat}% {str(h.get('battery_status', ''))[:4]}" if bat is not None else "N/A"
        temp = h.get("temp_c")
        try:
            temp_f = float(temp) if temp is not None else None
            temp_str = f"{temp_f:.1f}C" if (temp_f is not None and temp_f == temp_f) else "N/A"
        except (TypeError, ValueError):
            temp_str = "N/A"
        raw_svcs = h.get("services") if isinstance(h, dict) else None
        svcs = [k.split("_")[0] for k, v in (raw_svcs.items() if isinstance(raw_svcs, dict) else ()) if v]
        svc_str = ",".join(svcs) if svcs else "-"
        rows.append(
            [
                n["id"],
                n["role"],
                tp_str,
                n["host"],
                str(h.get("os_env", "-")),
                state_str,
                cpu_str,
                ram_str,
                bat_str,
                temp_str,
                svc_str,
            ]
        )

    print(
        _fmt_table(
            ["NODE", "ROLE", "TIER/POOL", "HOST", "OS", "STATE", "CPU/LOAD", "RAM FREE", "BAT", "TEMP", "SERVICES"],
            rows,
        )
    )


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    watch_sec = getattr(args, "watch", 0.0)
    if watch_sec is None:
        watch_sec = 0.0
    if not math.isfinite(watch_sec) or watch_sec < 0:
        print(f"Error: --watch must be a finite number >= 0 (got {watch_sec})", file=sys.stderr)
        return 2
    if watch_sec == 0:
        _render_status_once(ctrl, args.json)
        return 0
    try:
        while True:
            if sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            print(f"Live Cluster Monitor (every {watch_sec:g}s · Ctrl+C to exit) — {time.strftime('%H:%M:%S')}\n")
            _render_status_once(ctrl, args.json)
            time.sleep(max(0.5, watch_sec))
    except KeyboardInterrupt:
        print()
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)

    if not math.isfinite(args.timeout) or args.timeout < 0:
        print(f"Error: --timeout must be a finite number >= 0 (got {args.timeout})", file=sys.stderr)
        return 2
    if not args.command and not args.script:
        print("Provide a shell command or --script <path>.", file=sys.stderr)
        return 2

    script_content = None
    script_name = None
    if args.script:
        sp = Path(args.script)
        if not sp.is_file():
            print(f"Script not found or not a file: {sp}", file=sys.stderr)
            return 2
        script_content = sp.read_text(encoding="utf-8")
        script_name = sp.name

    spec = JobSpec(
        index=0,
        job_id=f"run-{int(time.time())}-{uuid.uuid4().hex[:6]}",
        command=" ".join(args.command) if args.command else None,
        script_content=script_content,
        script_name=script_name,
        interpreter=args.interpreter,
        args=args.script_args or [],
        timeout_sec=args.timeout or cfg.default_job_timeout_sec,
        workdir=args.workdir,
        force=args.force,
    )
    tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
    outcomes = ctrl.run_single(
        spec,
        target=args.target,
        tags=tags,
        workload_hint=getattr(args, "workload", "") or "",
    )

    if args.json:
        print(json.dumps([o.to_dict() for o in outcomes], indent=2))
    else:
        for o in outcomes:
            status = "OK" if o.ok else f"FAIL(rc={o.returncode})"
            tier_tag = f" · T{o.node_tier}:{o.node_pool}" if o.node_tier else ""
            why_tag = f" — {o.routing_reason}" if o.routing_reason else ""
            print(f"=== [{o.node_id}{tier_tag}] {status} ({o.duration_sec:.2f}s){why_tag} ===")
            if o.error:
                print(f"ERROR: {o.error}", file=sys.stderr)
            if o.stdout:
                print(o.stdout, end="" if o.stdout.endswith("\n") else "\n")
            if o.stderr:
                print(o.stderr, end="" if o.stderr.endswith("\n") else "\n", file=sys.stderr)

    return 0 if all(o.ok for o in outcomes) else 1


def _load_lines(source: str) -> list[str]:
    if source == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(source).read_text(encoding="utf-8")
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _cmd_map(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    if not math.isfinite(args.timeout) or args.timeout < 0:
        print(f"Error: --timeout must be a finite number >= 0 (got {args.timeout})", file=sys.stderr)
        return 2
    if args.retries < 0:
        print(f"Error: --retries must be >= 0 (got {args.retries})", file=sys.stderr)
        return 2
    if not math.isfinite(args.wait_ready) or args.wait_ready < 0:
        print(f"Error: --wait-ready must be a finite number >= 0 (got {args.wait_ready})", file=sys.stderr)
        return 2
    if args.repeat < 0:
        print(f"Error: --repeat must be >= 0 (got {args.repeat})", file=sys.stderr)
        return 2
    timeout = args.timeout or cfg.default_job_timeout_sec

    jobs: list[JobSpec] = []
    batch_id = uuid.uuid4().hex[:6]
    if args.script:
        sp = Path(args.script)
        if not sp.is_file():
            print(f"Script not found or not a file: {sp}", file=sys.stderr)
            return 2
        content = sp.read_text(encoding="utf-8")
        if args.args_file:
            try:
                arg_lines = _load_lines(args.args_file)
            except OSError as exc:
                print(f"Could not read --args-file '{args.args_file}': {exc}", file=sys.stderr)
                return 2
            for idx, line in enumerate(arg_lines):
                try:
                    parsed_args = shlex.split(line)
                except ValueError as exc:
                    print(f"Invalid arguments in --args-file on line {idx + 1}: {exc}", file=sys.stderr)
                    return 2
                jobs.append(
                    JobSpec(
                        index=idx,
                        job_id=f"map-{batch_id}-{idx:04d}",
                        script_content=content,
                        script_name=sp.name,
                        interpreter=args.interpreter,
                        args=parsed_args,
                        timeout_sec=timeout,
                        workdir=args.workdir,
                        env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                        force=args.force,
                    )
                )
        elif args.repeat > 0:
            for idx in range(args.repeat):
                jobs.append(
                    JobSpec(
                        index=idx,
                        job_id=f"map-{batch_id}-{idx:04d}",
                        script_content=content,
                        script_name=sp.name,
                        interpreter=args.interpreter,
                        args=args.script_args or [],
                        timeout_sec=timeout,
                        workdir=args.workdir,
                        env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                        force=args.force,
                    )
                )
        else:
            print("With --script, provide either --args-file <file> or --repeat <N>.", file=sys.stderr)
            return 2
    elif args.jobs_file:
        try:
            cmd_lines = _load_lines(args.jobs_file)
        except OSError as exc:
            print(f"Could not read --jobs-file '{args.jobs_file}': {exc}", file=sys.stderr)
            return 2
        for idx, cmd in enumerate(cmd_lines):
            jobs.append(
                JobSpec(
                    index=idx,
                    job_id=f"map-{batch_id}-{idx:04d}",
                    command=cmd,
                    timeout_sec=timeout,
                    workdir=args.workdir,
                    env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                    force=args.force,
                )
            )
    elif args.command and args.repeat > 0:
        cmd_str = " ".join(args.command)
        for idx in range(args.repeat):
            jobs.append(
                JobSpec(
                    index=idx,
                    job_id=f"map-{batch_id}-{idx:04d}",
                    command=cmd_str,
                    timeout_sec=timeout,
                    workdir=args.workdir,
                    env={"PHONECLUSTER_TASK_INDEX": str(idx)},
                    force=args.force,
                )
            )
    else:
        print(
            "Provide --jobs-file <file|->, or --script with --args-file/--repeat, or --repeat N -- <cmd>.",
            file=sys.stderr,
        )
        return 2

    if not jobs:
        print("No jobs to run.", file=sys.stderr)
        return 0

    tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
    t0 = time.monotonic()

    def _on_result(o: JobOutcome, done: int, total: int) -> None:
        if args.quiet:
            return
        tag = "OK" if o.ok else f"FAIL({o.returncode})"
        tier_col = f"T{o.node_tier}:{o.node_pool}" if o.node_tier else "-"
        first_line = (o.stdout.strip().splitlines()[0] if o.stdout.strip() else o.error or "")[:80]
        print(f"[{done}/{total}] {tag:9s} {o.node_id:7s} {tier_col:11s} {o.duration_sec:5.2f}s | {o.label[:36]} -> {first_line}")

    outcomes = ctrl.map_jobs(
        jobs,
        retries=args.retries,
        tags=tags,
        wait_for_ready_sec=args.wait_ready,
        on_result=_on_result,
        target=getattr(args, "target", "auto") or "auto",
        workload_hint=getattr(args, "workload", "") or "",
    )
    wall = round(time.monotonic() - t0, 2)

    if args.output_jsonl:
        out_p = Path(args.output_jsonl)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with out_p.open("w", encoding="utf-8") as fh:
            for o in outcomes:
                fh.write(json.dumps(o.to_dict()) + "\n")

    ok_count = sum(1 for o in outcomes if o.ok)
    fail_count = len(outcomes) - ok_count
    per_node: dict[str, int] = {}
    for o in outcomes:
        per_node[o.node_id] = per_node.get(o.node_id, 0) + 1
    dist_str = ", ".join(f"{k}:{v}" for k, v in sorted(per_node.items()))
    print(
        f"\nCompleted {len(outcomes)} jobs in {wall}s | "
        f"OK={ok_count} FAIL={fail_count} | Distribution: {dist_str}"
    )
    if args.output_jsonl:
        print(f"Full results saved to: {args.output_jsonl}")
    return 0 if fail_count == 0 else 1


def _cmd_distcc_env(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    hosts = ctrl.build_distcc_hosts(include_stopped=args.include_stopped)
    if not hosts:
        print("# No healthy nodes with distccd detected.", file=sys.stderr)
        return 1
    print(f'export DISTCC_HOSTS="{hosts}"')
    return 0


def _cmd_llama_rpc(args: argparse.Namespace) -> int:
    if not (1 <= int(args.port) <= 65535):
        print(f"Error: --port must be between 1 and 65535 (got {args.port})", file=sys.stderr)
        return 2
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    rpc = ctrl.build_llama_rpc_arg(port=args.port, include_master=args.include_master)
    if not rpc:
        print("# No healthy nodes listening on llama.cpp RPC port detected.", file=sys.stderr)
        return 1
    print(f"--rpc {rpc}")
    return 0


def _cmd_mpi_hostfile(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    content = ctrl.build_mpi_hostfile()
    if not content:
        print("# No healthy nodes available for OpenMPI.", file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        print(f"Wrote OpenMPI hostfile to {args.output}")
    else:
        print(content, end="")
    return 0


def _cmd_gateway(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)

    if args.port is not None and not (0 <= int(args.port) <= 65535):
        print(f"Error: --port must be between 0 and 65535 (got {args.port})", file=sys.stderr)
        return 2
    if args.enable or args.disable or args.mode or args.port:
        if args.enable:
            cfg.gateway.enabled = True
        if args.disable:
            cfg.gateway.enabled = False
        if args.mode:
            cfg.gateway.mode = args.mode
        if args.port:
            cfg.gateway.port = int(args.port)
        save_config(cfg, cfg_path)
        state_txt = "ENABLED" if cfg.gateway.enabled else "DISABLED"
        print(
            f"Saved Network Guard config ({state_txt}, mode={cfg.gateway.mode}, "
            f"port={cfg.gateway.port}) -> {cfg_path}"
        )
        if not args.serve:
            return 0

    if args.check_isolation:
        ctrl = MasterController(cfg)
        rows = ctrl.check_workers_wan_isolation()
        if args.json:
            print(json.dumps({"workers": rows}, indent=2))
            return 0
        if not rows:
            print("No worker phones configured.")
            return 0
        tbl_rows = [
            [
                w["node_id"],
                w["host"],
                "WAN BLOCKED" if w["wan_blocked"] is True else ("DIRECT WAN OPEN" if w["wan_blocked"] is False else "UNKNOWN"),
                w["detail"],
            ]
            for w in rows
        ]
        print(_fmt_table(["NODE", "HOST", "ISOLATION", "DETAIL"], tbl_rows))
        return 0

    if args.status:
        gw = cfg.gateway
        if args.json:
            print(json.dumps(cfg.to_dict().get("gateway", {}), indent=2))
        else:
            print(f"Network Guard : {'ENABLED' if gw.enabled else 'DISABLED (OFF by default)'}")
            print(f"Policy Mode   : {gw.mode}")
            print(f"Proxy Listen  : {gw.bind_host}:{gw.port}")
            print(f"SSRF Guard    : {'ON' if gw.block_private_ips else 'OFF'}")
            print(f"Auto Proxy Env: {'ON' if gw.inject_proxy_env else 'OFF'}")
            print(f"Allowlist ({len(gw.allowed_domains)}): {', '.join(gw.allowed_domains[:8])}" + (" ..." if len(gw.allowed_domains) > 8 else ""))
        return 0

    # Standalone foreground proxy mode (great for Master phone or Raspberry Pi Zero 2 W!)
    cfg.gateway.enabled = True
    if args.bind:
        cfg.gateway.bind_host = args.bind
    if args.port:
        cfg.gateway.port = args.port
    mgr = GatewayManager(cfg)
    ok, msg = mgr.start()
    if not ok:
        print(f"Failed to start Network Guard: {msg}", file=sys.stderr)
        return 1
    stop_ev = threading.Event()

    def _on_sigterm(_signum: int, _frame: Any) -> None:
        stop_ev.set()

    try:
        signal.signal(signal.SIGTERM, _on_sigterm)
    except ValueError:
        pass

    print(f"PhoneCluster Master Network Guard listening on {cfg.gateway.bind_host}:{mgr.bound_port}")
    print(f"Policy mode: {cfg.gateway.mode} | SSRF guard: {'ON' if cfg.gateway.block_private_ips else 'OFF'} | Allowlist: {len(cfg.gateway.allowed_domains)} domains")
    print("Press Ctrl+C to stop.")
    try:
        while not stop_ev.is_set():
            stop_ev.wait(0.5)
    except KeyboardInterrupt:
        print("\nStopping Network Guard...")
    finally:
        mgr.stop()
    return 0


def _cmd_net_audit(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    if getattr(args, "lan_subnet", ""):
        raw_sub = str(args.lan_subnet).strip()
        try:
            cfg.network.lan_subnet = str(ipaddress.ip_network(raw_sub, strict=False))
        except ValueError:
            print(f"Error: invalid --lan-subnet CIDR '{raw_sub}' (example: 192.168.1.0/24)", file=sys.stderr)
            return 2
        save_config(cfg, cfg_path)
    if args.profile:
        res = apply_security_profile(cfg, args.profile)
        save_config(cfg, cfg_path)
        ctrl = MasterController(cfg)
        pushed = ctrl.push_config_to_all()
        print(f"Applied security profile '{res['profile']}': {res['description']}")
        print(f"Saved -> {cfg_path} (live-synced to {pushed['ok_count']}/{pushed['total']} online node(s))")
        return 0

    ctrl = MasterController(cfg)
    report = audit_cluster_network(ctrl)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    if args.firewall:
        print(report["firewall_guides"]["nftables"], end="")
        return 0
    if args.ufw:
        print(report["firewall_guides"]["ufw"], end="")
        return 0
    if args.router:
        print(report["firewall_guides"]["router_checklist"], end="")
        return 0
    if args.adguard:
        print(report["adguard_snippets"]["rewrites_yaml"], end="")
        print()
        print(report["adguard_snippets"]["worker_block_rules"], end="")
        return 0

    hi = report["host_info"]
    print(f"Master Controller : {hi['friendly_name']} ({hi['master_host']} | LAN {hi['lan_subnet']})")
    print(f"Hardening Score   : {report['score']}/100 ({report['grade']})")
    print(f"AdGuard Home      : {report['adguard_url'] or 'Not detected (runs natively — NO Docker required!)'}")
    print()
    for c in report["checks"]:
        badge = {"ok": "[OK]  ", "warn": "[WARN]", "info": "[TIP] "}.get(c["status"], "[INFO]")
        print(f"  {badge} {c['name']}: {c['detail']}")
        if c["fix"]:
            print(f"         -> {c['fix']}")
    print()
    rows = [
        [
            n["id"],
            f"T{n['tier']}:{n['pool']}",
            "YES" if n["token_isolated"] else "NO",
            "ON" if n["source_ip_allowlist_active"] else "off",
            "QUARANTINED" if n["quarantined"] else ("ONLINE" if n["online"] else "OFFLINE"),
            ",".join(str(p) for p in n["unexpected_ports"]) or "clean",
        ]
        for n in report["nodes"]
    ]
    print(_fmt_table(["NODE", "TIER/POOL", "TOK-ISO", "IP-LOCK", "STATUS", "UNEXPECTED PORTS"], rows))
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    if not (0 <= int(args.port) <= 65535):
        print(f"Error: --port must be between 0 and 65535 (got {args.port})", file=sys.stderr)
        return 2
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    if args.require_auth:
        cfg.dashboard_require_auth = True
    ctrl = MasterController(cfg)
    port = args.port or cfg.dashboard_port
    serve_dashboard(args.bind, port, ctrl, config_path=cfg_path)
    return 0


def _cmd_pair(args: argparse.Namespace) -> int:
    if not (0 <= int(args.port) <= 65535):
        print(f"Error: --port must be between 0 and 65535 (got {args.port})", file=sys.stderr)
        return 2
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    return run_cli_pairing_host(
        config=cfg,
        config_path=cfg_path,
        port=args.port,
        ttl_sec=args.ttl,
        max_devices=args.count,
    )


def _cmd_join(args: argparse.Namespace) -> int:
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print(f"Error: --timeout must be a finite number > 0 (got {args.timeout})", file=sys.stderr)
        return 2
    if not (1 <= int(args.worker_port) <= 65535):
        print(f"Error: --worker-port must be between 1 and 65535 (got {args.worker_port})", file=sys.stderr)
        return 2
    if not (1 <= int(args.max_concurrency) <= 32):
        print(f"Error: --max-concurrency must be between 1 and 32 (got {args.max_concurrency})", file=sys.stderr)
        return 2
    cfg_path = resolve_config_path(args.config)
    master_host = ""
    pair_port = DEFAULT_PAIR_PORT
    fingerprint = ""
    cluster_name = ""

    if args.master:
        raw_m = args.master.strip()
        if raw_m.lower().startswith(("http://", "https://")):
            parsed_m = urllib.parse.urlsplit(raw_m)
            master_host = normalize_host(parsed_m.hostname or "")
            try:
                if parsed_m.port is not None:
                    pair_port = parsed_m.port
            except ValueError:
                print(f"Error: invalid port in --master '{raw_m}'", file=sys.stderr)
                return 2
        elif raw_m.startswith("["):
            if "]:" in raw_m:
                h_part, p_str = raw_m.rsplit("]:", 1)
                master_host = normalize_host(h_part.lstrip("["))
                try:
                    pair_port = int(p_str.rstrip("/"))
                except ValueError:
                    print(f"Error: invalid port in --master '{raw_m}'", file=sys.stderr)
                    return 2
            else:
                master_host = normalize_host(raw_m.rstrip("/"))
        elif raw_m.count(":") == 1:
            h_part, p_str = raw_m.rsplit(":", 1)
            master_host = normalize_host(h_part)
            try:
                pair_port = int(p_str.rstrip("/"))
            except ValueError:
                print(f"Error: invalid port in --master '{raw_m}'", file=sys.stderr)
                return 2
        else:
            # Hostname, IPv4 without port, or bare IPv6 literal (multiple ':')
            master_host = normalize_host(raw_m.rstrip("/"))
        if not master_host or not (1 <= pair_port <= 65535):
            print(f"Error: invalid --master address '{raw_m}' (expected host[:port] with port 1..65535)", file=sys.stderr)
            return 2
    else:
        print("Searching local Wi-Fi for a Master phone with an open Pairing Window...")
        found = discover_pairing_masters(timeout_sec=args.timeout)
        if not found:
            print(
                "No Master phone with an open Pairing Window was found on Wi-Fi.\n"
                "  1. On your Master phone, open Pairing first (`pc pair` or Web UI -> Tab 6 -> Open Pairing Window).\n"
                "  2. If your router blocks Wi-Fi broadcast (or you use Tailscale), pass `--master <ip>:<port>`.",
                file=sys.stderr,
            )
            return 1
        if len(found) == 1:
            chosen = found[0]
        else:
            print("Found multiple Masters with open pairing windows:")
            for i, m in enumerate(found, start=1):
                print(
                    f"  {i}) {m['cluster_name']} at {m['host']}:{m['pair_port']} "
                    f"(fingerprint: {m['fingerprint']}, {m['expires_in_sec']}s left)"
                )
            sel = input("Select Master [1]: ").strip() or "1"
            idx = max(0, min(len(found) - 1, int(sel) - 1)) if sel.isdigit() else 0
            chosen = found[idx]
        master_host = chosen["host"]
        pair_port = int(chosen["pair_port"])
        fingerprint = chosen["fingerprint"]
        cluster_name = chosen["cluster_name"]
        print(
            f"\nFound Master on Wi-Fi:\n"
            f"  Cluster     : {cluster_name}\n"
            f"  Address     : {master_host}:{pair_port}\n"
            f"  Fingerprint : {fingerprint}  (verify this matches your Master screen!)\n"
        )

    pin = args.pin or input("Enter the 6-digit Pairing PIN shown on Master: ").strip()
    if not pin:
        print("Pairing cancelled (no PIN entered).", file=sys.stderr)
        return 1

    trust_ssh = bool(args.trust_ssh)
    if not trust_ssh and not args.no_ssh_key and sys.stdin.isatty():
        ans = input("Trust Master's SSH public key for passwordless `pc ssh` / `pc sync`? [Y/n]: ").strip().lower()
        trust_ssh = ans in {"", "y", "yes"}

    try:
        res = join_cluster_via_pairing(
            master_host=master_host,
            pair_port=pair_port,
            pin=pin,
            config_out=cfg_path,
            worker_port=args.worker_port,
            max_concurrency=args.max_concurrency,
            trust_ssh_key=trust_ssh,
            tier=args.tier,
            pool=args.pool,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"Pairing failed: {exc}", file=sys.stderr)
        return 1

    print("\n" + "=" * 58)
    print(f"  ✓ Securely Joined Cluster '{res['cluster_name']}'!")
    print("=" * 58)
    print(f"  Assigned Node ID : {res['node_id']} ({res['node_host']})")
    print(f"  Tier / Pool      : Tier {res.get('tier', 1)} ({res.get('pool', 'compute')})")
    print(f"  Scoped Config    : {res['config_path']} (0600, unique per-node token)")
    if res["ssh_key_trusted"]:
        print("  Master SSH Key   : Added to ~/.ssh/authorized_keys")

    # Configure Termux:Boot automatically if running inside Termux
    if "com.termux" in os.environ.get("PREFIX", ""):
        setup_sh = REPO_ROOT / "scripts" / "02_termux_node_setup.sh"
        if setup_sh.exists():
            print("  Updating Termux:Boot startup script for your new node ID...")
            subprocess.call(["bash", str(setup_sh), "--node-id", res["node_id"], "--repo-dir", str(REPO_ROOT)])

    if not args.no_start:
        log_dir = REPO_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"worker-{res['node_id']}.log"
        pid_file = log_dir / f"worker-{res['node_id']}.pid"
        # Stop any previously running local worker PID (e.g. when re-pairing) so port 8765 is free
        for old_pid_file in log_dir.glob("worker-*.pid"):
            try:
                old_pid = int(old_pid_file.read_text(encoding="utf-8").strip())
                if old_pid > 1 and old_pid != os.getpid():
                    os.kill(old_pid, signal.SIGTERM)
                    for _ in range(15):
                        time.sleep(0.1)
                        try:
                            os.kill(old_pid, 0)
                        except OSError:
                            break
            except (OSError, ValueError):
                pass
            if old_pid_file != pid_file:
                try:
                    old_pid_file.unlink(missing_ok=True)
                except OSError:
                    pass
        with log_file.open("a", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(REPO_ROOT / "phonecluster_cli.py"),
                    "--config",
                    str(cfg_path),
                    "worker",
                    "--node-id",
                    res["node_id"],
                ],
                stdout=lf,
                stderr=lf,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
        print(f"  Worker Daemon    : Started in background (PID {proc.pid})")
        print(f"  Worker Log       : {log_file}")

    print("\nYour phone is now live in the Master Web Control Center & `pc top`!")
    return 0


def _cmd_wizard(args: argparse.Namespace) -> int:
    return run_setup_wizard(args.config)


def _cmd_menu(args: argparse.Namespace) -> int:
    return run_interactive_menu(args.config)


def _cmd_discover(args: argparse.Namespace) -> int:
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print(f"Error: --timeout must be a finite number > 0 (got {args.timeout})", file=sys.stderr)
        return 2
    found = discover_lan_nodes(timeout_sec=args.timeout)
    if args.json:
        print(json.dumps(found, indent=2))
        return 0
    if not found:
        print("No PhoneCluster nodes replied on Wi-Fi/LAN (UDP port 8766).")
        return 0
    rows = [
        [
            n["host"],
            str(n["worker_port"]),
            n["node_id"] or "-",
            n["role"],
            n["os_env"],
            str(n["cpu_cores"]),
            f"{n['mem_total_mb']} MB",
            n["ssh_user"] or "-",
        ]
        for n in found
    ]
    print(_fmt_table(["HOST", "PORT", "NODE", "ROLE", "OS", "CORES", "RAM", "SSH USER"], rows))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = run_doctor(args.config, check_remote=not args.local_only)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_doctor_report(report)
    return 0 if report["overall"] != "fail" else 1


def _cmd_top(args: argparse.Namespace) -> int:
    if not math.isfinite(args.interval) or args.interval <= 0:
        print(f"Error: --interval must be a finite number > 0 (got {args.interval})", file=sys.stderr)
        return 2
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    return run_top_tui(ctrl, refresh_sec=args.interval, once=args.once)


def _cmd_jobs(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    all_nodes = ctrl.get_all_jobs()
    if args.json:
        print(json.dumps({"nodes": all_nodes}, indent=2))
        return 0
    limit = max(0, int(args.limit))
    rows: list[list[str]] = []
    for n in all_nodes:
        nid = n["node_id"]
        for j in n.get("active", []):
            rows.append([nid, j["job_id"], "RUNNING", f"{j['running_sec']}s", str(j.get("command", ""))[:50]])
        for j in n.get("recent", [])[:limit]:
            st = (
                "CANCELLED"
                if j.get("cancelled")
                else ("TIMEOUT" if j.get("timed_out") else ("OK" if j.get("returncode") == 0 else f"FAIL({j.get('returncode')})"))
            )
            rows.append([nid, j["job_id"], st, f"{j['duration_sec']}s", str(j.get("command", ""))[:50]])
    if not rows:
        print("No active or recent jobs across the cluster.")
        return 0
    print(_fmt_table(["NODE", "JOB ID", "STATUS", "DURATION", "COMMAND"], rows))
    return 0


def _cmd_cancel(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    try:
        res = ctrl.cancel_node_job(args.node_id, args.job_id)
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if res.get("cancelled"):
        print(f"Cancelled job '{args.job_id}' on '{args.node_id}'.")
        return 0
    print(f"Could not cancel job '{args.job_id}' on '{args.node_id}': {res.get('error', res)}", file=sys.stderr)
    return 1


def _cmd_token(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    if args.rotate:
        cfg.auth_token = generate_auth_token()
        save_config(cfg, cfg_path)
        print(f"Rotated auth_token in {cfg_path}. Run `pc sync` to update worker phones.", file=sys.stderr)
    print(cfg.auth_token)
    return 0


def _cmd_ssh(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    try:
        node = cfg.get_node(args.node_id)
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    target = f"{node.ssh_user}@{node.host}" if node.ssh_user else node.host
    cmd = ["ssh", "-p", str(node.ssh_port), "--", target] + (args.remote_cmd or [])
    return subprocess.call(cmd)


def _cmd_copy(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    src = Path(args.source)
    if not src.exists():
        print(f"Error: local path not found: {src}", file=sys.stderr)
        return 2
    if args.target == "all":
        nodes = list(cfg.nodes)
    elif args.target == "workers":
        nodes = [n for n in cfg.nodes if n.role != "master"]
    else:
        try:
            nodes = [cfg.get_node(args.target)]
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    rc_all = 0
    for node in nodes:
        host_scp = format_host_for_url(node.host)
        target = f"{node.ssh_user}@{host_scp}" if node.ssh_user else host_scp
        scp_cmd = ["scp", "-P", str(node.ssh_port)]
        if src.is_dir():
            scp_cmd.append("-r")
        scp_cmd.extend(["--", str(src), f"{target}:{args.dest}"])
        print(f"Copying {src} -> {node.id} ({target}:{args.dest})...")
        rc = subprocess.call(scp_cmd)
        if rc != 0:
            print(f"  FAILED on {node.id} (exit {rc})", file=sys.stderr)
            rc_all = 1
    return rc_all


def _cmd_push_config(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    node_ids = [args.node_id] if args.node_id else None
    res = ctrl.push_config_to_all(node_ids=node_ids)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res["ok_count"] == res["total"] else 1
    rows = [
        [
            r["node_id"],
            "OK" if r.get("ok") else "FAIL",
            str(r.get("max_concurrency", "-")),
            f"{r.get('max_temp_c', '-')}C" if r.get("ok") else "-",
            "ON" if r.get("source_ip_allowlist_active") else ("off" if r.get("ok") else "-"),
            "saved" if r.get("persisted") else (r.get("error", "memory-only")[:42]),
        ]
        for r in res["results"]
    ]
    print(_fmt_table(["NODE", "STATUS", "MAX-JOBS", "TEMP-LIMIT", "IP-LOCK", "DETAIL"], rows))
    print(f"\nLive policy pushed to {res['ok_count']}/{res['total']} node(s) over authenticated HTTP.")
    return 0 if res["ok_count"] == res["total"] else 1


def _cmd_sync(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    script = REPO_ROOT / "scripts" / "03_sync_cluster.sh"
    if not script.exists():
        print(f"Error: sync script not found at {script}", file=sys.stderr)
        return 2
    cmd = ["bash", str(script), "--config", str(cfg_path)]
    if args.setup_keys:
        cmd.append("--setup-keys")
    if args.skip_node:
        cmd.extend(["--skip-node", args.skip_node])
    return subprocess.call(cmd, cwd=str(REPO_ROOT))


def _cmd_pools(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    summary = ctrl.cluster_summary(record_history=False)
    pools = summary.get("pools", [])
    if args.json:
        print(json.dumps({"cluster_name": summary["cluster_name"], "pools": pools}, indent=2))
        return 0
    if not pools:
        print("No nodes configured in cluster.")
        return 0
    rows = [
        [
            f"Tier {p['tier']}",
            p["pool"],
            f"{p['nodes_ready']}/{p['nodes_total']} (online {p['nodes_online']})",
            str(p["total_cores"]),
            f"{p['mem_available_mb']/1024:.2f}/{p['mem_total_mb']/1024:.2f} GB",
            str(p["active_jobs"]),
            ", ".join(p["node_ids"]),
        ]
        for p in pools
    ]
    print(_fmt_table(["TIER", "POOL", "READY", "CORES", "RAM FREE/TOTAL", "ACTIVE", "PHONES"], rows))
    return 0


def _cmd_services(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    info = ctrl.get_services_info()
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    if args.env:
        for k, v in sorted(info.get("env", {}).items()):
            print(f'export {k}={shlex.quote(str(v))}')
        return 0
    if args.hosts:
        print(info.get("dns_hosts", ""), end="")
        return 0
    svcs = info.get("services", [])
    if not svcs:
        print("No live cross-tier services detected yet.")
        print("Start Mosquitto, AdGuard Home, Home Assistant, llama.cpp, distcc, or Docker on any tier.")
        return 0
    rows = [
        [
            s["name"],
            s["node_id"],
            f"T{s['tier']}:{s['pool']}" if s.get("tier") else "custom",
            s["url"],
            "READY" if s.get("ready") else "BUSY/HOT",
        ]
        for s in svcs
    ]
    print(_fmt_table(["SERVICE", "NODE", "TIER/POOL", "ENDPOINT", "STATUS"], rows))
    print('\nTip: Run `eval "$(pc services --env)"` to export PHONECLUSTER_* service URLs into your shell,')
    print("     or `pc services --hosts` for AdGuard Home / `/etc/hosts` `.cluster` DNS rewrites.")
    return 0


def _cmd_pipeline(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    path = Path(args.pipeline_file)
    if not path.is_file():
        print(f"Pipeline file not found or not a file: {path}", file=sys.stderr)
        return 2
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not parse pipeline JSON: {exc}", file=sys.stderr)
        return 2
    steps = raw.get("steps") if isinstance(raw, dict) else raw
    if not isinstance(steps, list) or not steps or not all(isinstance(s, dict) for s in steps):
        print("Pipeline JSON must be a non-empty list of step objects (or {'steps': [...]}).", file=sys.stderr)
        return 2

    res = ctrl.run_pipeline(steps, stop_on_error=not args.continue_on_error)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for r in res["results"]:
            status = "OK" if r["ok"] else f"FAIL(rc={r['returncode']})"
            tier_tag = f" · T{r['node_tier']}:{r['node_pool']}" if r.get("node_tier") else ""
            why = f" — {r['routing_reason']}" if r.get("routing_reason") else ""
            print(f"=== Step {r['step_index']}/{res['steps_total']}: {r['name']} [{r['node_id']}{tier_tag}] {status} ({r['duration_sec']:.2f}s){why} ===")
            if r.get("error"):
                print(f"ERROR: {r['error']}", file=sys.stderr)
            if r.get("stdout"):
                out_s = r["stdout"]
                print(out_s, end="" if out_s.endswith("\n") else "\n")
            if r.get("stderr"):
                err_s = r["stderr"]
                print(err_s, end="" if err_s.endswith("\n") else "\n", file=sys.stderr)
        overall = "SUCCESS" if res["ok"] else "FAILED"
        print(f"\nPipeline {overall}: {res['steps_completed']}/{res['steps_total']} steps in {res['duration_sec']}s")
    return 0 if res["ok"] else 1


def _cmd_update(args: argparse.Namespace) -> int:
    print(f"Updating PhoneCluster in {REPO_ROOT}...")
    rc = subprocess.call(["git", "-C", str(REPO_ROOT), "pull", "--ff-only"])
    if rc != 0:
        return rc
    if args.sync:
        cfg_path = resolve_config_path(args.config)
        if cfg_path.exists():
            return subprocess.call(
                ["bash", str(REPO_ROOT / "scripts" / "03_sync_cluster.sh"), "--config", str(cfg_path)],
                cwd=str(REPO_ROOT),
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phonecluster",
        description="Unified Master-Worker toolkit for Android (Termux / Debian 13) phone clusters.",
    )
    parser.add_argument("--version", action="version", version=f"phonecluster {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help=f"Path to cluster.json (default: $PHONECLUSTER_CONFIG or {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="subcommand", required=False)

    # pair & join (security-first zero-config phone onboarding)
    p_pair = sub.add_parser(
        "pair",
        help="Open a temporary 2-minute encrypted pairing window on Master to add a new phone",
    )
    p_pair.add_argument("--ttl", type=int, default=120, help="Pairing window duration in seconds (default: 120)")
    p_pair.add_argument("--count", type=int, default=1, help="Number of phones allowed to pair (default: 1)")
    p_pair.add_argument("--port", type=int, default=DEFAULT_PAIR_PORT, help=f"Temporary pairing port (default: {DEFAULT_PAIR_PORT})")
    p_pair.set_defaults(func=_cmd_pair)

    p_join = sub.add_parser(
        "join",
        help="Auto-search Wi-Fi for your Master phone and securely join the cluster using its 6-digit PIN",
    )
    p_join.add_argument("--master", default="", help="Manual Master host:port (e.g. 192.168.1.201:8080) if Wi-Fi blocks broadcast")
    p_join.add_argument("--pin", default="", help="6-digit Pairing PIN (prompted interactively if omitted)")
    p_join.add_argument("--timeout", type=float, default=2.5, help="Wi-Fi search timeout in seconds (default: 2.5)")
    p_join.add_argument("--worker-port", type=int, default=8765, help="Local worker HTTP port (default: 8765)")
    p_join.add_argument("--max-concurrency", type=int, default=2, help="Max parallel jobs on this phone (default: 2)")
    p_join.add_argument(
        "--tier",
        type=int,
        choices=[0, 1, 2, 3],
        default=0,
        help="Device tier: 0=auto-detect (default), 1=Termux compute, 2=Debian 13 services, 3=Docker/Droidspaces",
    )
    p_join.add_argument(
        "--pool",
        default="auto",
        help="Workload pool name (default: auto -> compute/services/docker based on tier)",
    )
    p_join.add_argument("--trust-ssh", action="store_true", help="Automatically trust Master's SSH public key")
    p_join.add_argument("--no-ssh-key", action="store_true", help="Do not install Master's SSH public key")
    p_join.add_argument("--no-start", action="store_true", help="Save config only; do not auto-start worker daemon")
    p_join.set_defaults(func=_cmd_join)

    # wizard
    p_wiz = sub.add_parser("wizard", help="Guided interactive setup wizard (easiest way to configure)")
    p_wiz.set_defaults(func=_cmd_wizard)

    # menu
    p_menu = sub.add_parser("menu", help="Interactive numbered terminal menu (no flags to memorize)")
    p_menu.set_defaults(func=_cmd_menu)

    # discover
    p_disc = sub.add_parser("discover", help="Auto-discover phones running PhoneCluster on your Wi-Fi")
    p_disc.add_argument("--timeout", type=float, default=2.0, help="Discovery listen duration in seconds")
    p_disc.add_argument("--json", action="store_true", help="Output raw JSON")
    p_disc.set_defaults(func=_cmd_discover)

    # doctor
    p_doc = sub.add_parser("doctor", help="Run automated health, SSH, thermal, and 24/7 battery checks")
    p_doc.add_argument("--local-only", action="store_true", help="Skip polling remote worker phones")
    p_doc.add_argument("--json", action="store_true", help="Output raw JSON")
    p_doc.set_defaults(func=_cmd_doctor)

    # init-config
    p_init = sub.add_parser("init-config", help="Generate cluster.json with a fresh secret auth token")
    p_init.add_argument("--name", default="redmi-cluster", help="Cluster display name")
    p_init.add_argument("--master-host", default="192.168.1.201", help="Static LAN IP of the Master phone")
    p_init.add_argument(
        "--workers",
        default="192.168.1.202,192.168.1.203",
        help="Comma-separated static LAN IPs of Worker phones",
    )
    p_init.add_argument("--ssh-user", default="", help="Default Termux/Debian SSH username (from `whoami`)")
    p_init.add_argument("--ssh-port", type=int, default=DEFAULT_SSH_PORT, help=f"Default SSH port (default: {DEFAULT_SSH_PORT}; use 22 for Raspberry Pi/Debian)")
    p_init.add_argument("-o", "--output", default=str(DEFAULT_CONFIG_PATH), help="Output JSON path")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config file")
    p_init.set_defaults(func=_cmd_init_config)

    # worker
    p_worker = sub.add_parser("worker", help="Run the worker HTTP agent + thermal/battery guard")
    p_worker.add_argument("--node-id", required=True, help="Node ID from cluster.json (e.g. node0)")
    p_worker.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_worker.add_argument("--port", type=int, default=0, help="Override worker HTTP port")
    p_worker.add_argument("--max-concurrency", type=int, default=0, help="Override max concurrent jobs")
    p_worker.add_argument("--workdir", default=".", help="Default working directory for jobs")
    p_worker.add_argument(
        "--discover",
        action="store_true",
        help="Opt-in: broadcast presence on UDP port 8766 (OFF by default for LAN privacy)",
    )
    p_worker.set_defaults(func=_cmd_worker)

    # status
    p_status = sub.add_parser("status", help="Show unified 'one PC' cluster health & telemetry")
    p_status.add_argument("--json", action="store_true", help="Output raw JSON")
    p_status.add_argument(
        "-w",
        "--watch",
        nargs="?",
        const=3.0,
        type=float,
        default=0.0,
        help="Live-refresh every N seconds (default 3s when flag is given)",
    )
    p_status.set_defaults(func=_cmd_status)

    # top (multi-device btop terminal control)
    p_top = sub.add_parser("top", help="Pretty multi-device btop-style Terminal Control UI")
    p_top.add_argument(
        "-i",
        "--interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds (default: 2.0)",
    )
    p_top.add_argument(
        "--once",
        action="store_true",
        help="Render one snapshot frame and exit (non-interactive)",
    )
    p_top.set_defaults(func=_cmd_top)

    # jobs & cancel
    p_jobs = sub.add_parser("jobs", help="Show active and recent jobs across all phones")
    p_jobs.add_argument("--limit", type=int, default=5, help="Recent finished jobs per phone (default: 5)")
    p_jobs.add_argument("--json", action="store_true", help="Output raw JSON")
    p_jobs.set_defaults(func=_cmd_jobs)

    p_cancel = sub.add_parser("cancel", help="Cancel a running job on a specific phone")
    p_cancel.add_argument("node_id", help="Node ID (e.g. node1)")
    p_cancel.add_argument("job_id", help="Job ID from `pc jobs`")
    p_cancel.set_defaults(func=_cmd_cancel)

    # token
    p_tok = sub.add_parser("token", help="Show (or rotate) the cluster auth_token for unlocking the Web UI")
    p_tok.add_argument("--rotate", action="store_true", help="Generate and save a fresh auth_token")
    p_tok.set_defaults(func=_cmd_token)

    # ssh & copy
    p_ssh = sub.add_parser("ssh", help="Open an SSH session to a phone by node ID (e.g. `pc ssh node1`)")
    p_ssh.add_argument("node_id", help="Node ID from cluster.json")
    p_ssh.add_argument("remote_cmd", nargs="*", help="Optional command to run over SSH")
    p_ssh.set_defaults(func=_cmd_ssh)

    p_cp = sub.add_parser("copy", help="Copy a file or folder (e.g. dataset or AI model) to phones via SCP")
    p_cp.add_argument("source", help="Local file or folder path")
    p_cp.add_argument("dest", help="Remote destination path (e.g. ~/models/)")
    p_cp.add_argument("--target", default="workers", help="'workers' (default), 'all', or a node_id")
    p_cp.set_defaults(func=_cmd_copy)

    # push-config (live HTTP policy push to workers without SSH)
    p_push = sub.add_parser(
        "push-config",
        help="Push live safety, concurrency, and Master-IP allowlist policy to online workers over HTTP (no SSH needed)",
    )
    p_push.add_argument("--node-id", default="", help="Optional single node ID to push to (default: all)")
    p_push.add_argument("--json", action="store_true", help="Output raw JSON")
    p_push.set_defaults(func=_cmd_push_config)

    # sync & update
    p_sync = sub.add_parser("sync", help="Push code & cluster.json to all phones and restart workers")
    p_sync.add_argument("--setup-keys", action="store_true", help="Copy SSH keys with ssh-copy-id first")
    p_sync.add_argument("--skip-node", default="", help="Skip syncing one node ID (e.g. node0)")
    p_sync.set_defaults(func=_cmd_sync)

    p_upd = sub.add_parser("update", help="Pull latest PhoneCluster updates from GitHub")
    p_upd.add_argument("--sync", action="store_true", help="Also sync the update to all worker phones")
    p_upd.set_defaults(func=_cmd_update)

    # pools, services, pipeline (heterogeneous multi-tier orchestration)
    p_pools = sub.add_parser("pools", help="Show Tier 1/2/3 device pools and aggregated cores/RAM")
    p_pools.add_argument("--json", action="store_true", help="Output raw JSON")
    p_pools.set_defaults(func=_cmd_pools)

    p_svcs = sub.add_parser("services", help="Discover live cross-tier services (MQTT, AdGuard, HA, AI, Docker)")
    p_svcs.add_argument("--env", action="store_true", help="Output `export PHONECLUSTER_*=...` shell vars")
    p_svcs.add_argument("--hosts", action="store_true", help="Output `.cluster` DNS rewrites for AdGuard / /etc/hosts")
    p_svcs.add_argument("--json", action="store_true", help="Output raw JSON")
    p_svcs.set_defaults(func=_cmd_services)

    p_pipe = sub.add_parser("pipeline", help="Run a multi-step cross-tier JSON workflow (Tier 1 -> Tier 2 -> Tier 3)")
    p_pipe.add_argument("pipeline_file", help="Path to pipeline JSON file (see examples/cross_tier_pipeline.json)")
    p_pipe.add_argument("--continue-on-error", action="store_true", help="Continue remaining steps if a step fails")
    p_pipe.add_argument("--json", action="store_true", help="Output raw JSON")
    p_pipe.set_defaults(func=_cmd_pipeline)

    # run
    p_run = sub.add_parser("run", help="Run a command or script (auto-routes to ideal Tier/Pool by default)")
    p_run.add_argument(
        "--target",
        default="auto",
        help="Target: 'auto' (default smart tier), 'tier:1|2|3', 'pool:<name>', 'best', 'all', or a node_id",
    )
    p_run.add_argument(
        "--workload",
        default="",
        help="Optional routing hint when --target=auto: compute, ai, service, docker",
    )
    p_run.add_argument("--script", default=None, help="Local Python/Shell script to ship & execute")
    p_run.add_argument("--interpreter", default=None, help="Interpreter override (e.g. python3, bash)")
    p_run.add_argument("--script-args", nargs="*", default=None, help="Arguments passed to --script")
    p_run.add_argument("--tags", default=None, help="Comma-separated node tags filter")
    p_run.add_argument("--timeout", type=float, default=0, help="Job timeout in seconds")
    p_run.add_argument("--workdir", default=None, help="Remote working directory")
    p_run.add_argument("--force", action="store_true", help="Bypass thermal/RAM gate")
    p_run.add_argument("--json", action="store_true", help="Output raw JSON")
    p_run.add_argument("command", nargs="*", help="Shell command to execute")
    p_run.set_defaults(func=_cmd_run)

    # map
    p_map = sub.add_parser("map", help="Run many commands/scripts in parallel with smart Tier/Pool routing")
    p_map.add_argument(
        "--target",
        default="auto",
        help="Target: 'auto' (default smart routing per job), 'tier:1|2|3', 'pool:<name>', 'all', or node_id",
    )
    p_map.add_argument(
        "--workload",
        default="",
        help="Optional routing hint for all batch jobs: compute, ai, service, docker",
    )
    p_map.add_argument("--jobs-file", default=None, help="File with one shell command per line (or '-' for stdin)")
    p_map.add_argument("--script", default=None, help="Local script to ship & execute in parallel")
    p_map.add_argument("--args-file", default=None, help="File with one arg list per line for --script (or '-')")
    p_map.add_argument("--interpreter", default=None, help="Interpreter override for --script")
    p_map.add_argument("--script-args", nargs="*", default=None, help="Args passed to --script when using --repeat")
    p_map.add_argument("--repeat", type=int, default=0, help="Repeat command or --script N times across cluster")
    p_map.add_argument("--retries", type=int, default=1, help="Retries on thermal throttle or disconnect")
    p_map.add_argument("--wait-ready", type=float, default=30.0, help="Seconds to wait if all nodes are hot/busy")
    p_map.add_argument("--tags", default=None, help="Comma-separated node tags filter")
    p_map.add_argument("--timeout", type=float, default=0, help="Per-job timeout in seconds")
    p_map.add_argument("--workdir", default=None, help="Remote working directory")
    p_map.add_argument("--force", action="store_true", help="Bypass thermal/RAM gate")
    p_map.add_argument("--output-jsonl", default=None, help="Write per-job JSONL results to path")
    p_map.add_argument("-q", "--quiet", action="store_true", help="Suppress per-job progress lines")
    p_map.add_argument("command", nargs="*", help="Shell command (used with --repeat)")
    p_map.set_defaults(func=_cmd_map)

    # distcc-env
    p_distcc = sub.add_parser("distcc-env", help="Print `export DISTCC_HOSTS=...` for healthy distccd phones")
    p_distcc.add_argument(
        "--include-stopped",
        action="store_true",
        help="Include healthy phones where distccd is installed even if port 3632 is not currently open",
    )
    p_distcc.set_defaults(func=_cmd_distcc_env)

    # llama-rpc
    p_llama = sub.add_parser("llama-rpc", help="Print `--rpc host:port,...` for healthy llama.cpp RPC phones")
    p_llama.add_argument("--port", type=int, default=50052, help="llama.cpp rpc-server port (default: 50052)")
    p_llama.add_argument("--include-master", action="store_true", help="Include master phone in RPC list")
    p_llama.set_defaults(func=_cmd_llama_rpc)

    # mpi-hostfile
    p_mpi = sub.add_parser("mpi-hostfile", help="Generate an OpenMPI hostfile from healthy phones")
    p_mpi.add_argument("-o", "--output", default=None, help="Write hostfile to path instead of stdout")
    p_mpi.set_defaults(func=_cmd_mpi_hostfile)

    # gateway (optional Master Network Guard / Watchguard proxy)
    p_gw = sub.add_parser(
        "gateway",
        help="Optional Master Network Guard (allowlist HTTP/HTTPS proxy & WAN isolation check for old workers)",
    )
    p_gw.add_argument("--enable", action="store_true", help="Enable Network Guard in cluster.json")
    p_gw.add_argument("--disable", action="store_true", help="Disable Network Guard in cluster.json (OFF by default)")
    p_gw.add_argument(
        "--mode",
        choices=["allowlist", "monitor", "block_all"],
        default="",
        help="Policy mode: allowlist (default-deny), monitor (log-all), or block_all (air-gap)",
    )
    p_gw.add_argument("--bind", default="", help="Override bind address when running standalone")
    p_gw.add_argument("--port", type=int, default=0, help="Proxy port (default: 8888)")
    p_gw.add_argument("--serve", action="store_true", help="Also run standalone proxy in foreground after saving")
    p_gw.add_argument("--status", action="store_true", help="Show Network Guard configuration")
    p_gw.add_argument("--check-isolation", action="store_true", help="Test if router blocks direct WAN on workers")
    p_gw.add_argument("--json", action="store_true", help="Output raw JSON")
    p_gw.set_defaults(func=_cmd_gateway)

    # net-audit (Master & Worker network hardening, Raspberry Pi, AdGuard & Firewall generator)
    p_net = sub.add_parser(
        "net-audit",
        help="Audit Master/Worker network security, apply security profiles, or generate AdGuard & nftables/UFW rules",
    )
    p_net.add_argument(
        "--profile",
        choices=["standard", "airgap_workers", "lockdown"],
        default="",
        help="Apply a 1-click security profile to cluster.json",
    )
    p_net.add_argument(
        "--lan-subnet",
        default="",
        help="Save a custom LAN CIDR (e.g. 192.168.1.0/24) to cluster.json before generating rules",
    )
    p_net.add_argument("--firewall", action="store_true", help="Print hardened nftables rules for Raspberry Pi / Debian Master")
    p_net.add_argument("--ufw", action="store_true", help="Print hardened UFW commands for Raspberry Pi / Debian Master")
    p_net.add_argument("--router", action="store_true", help="Print personalized Home Router WAN-block checklist")
    p_net.add_argument("--adguard", action="store_true", help="Print native AdGuard Home .cluster YAML rewrites & telemetry block rules")
    p_net.add_argument("--json", action="store_true", help="Output full audit as JSON")
    p_net.set_defaults(func=_cmd_net_audit)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Start the Master web dashboard UI")
    p_dash.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_dash.add_argument("--port", type=int, default=0, help="Dashboard HTTP port (default from config: 8080)")
    p_dash.add_argument(
        "--require-auth",
        action="store_true",
        help="Require Bearer auth_token even for read-only stats (recommended on shared/dorm Wi-Fi)",
    )
    p_dash.set_defaults(func=_cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    subcmd = getattr(args, "subcommand", None)
    _configure_logging(args.verbose, is_daemon=subcmd in {"worker", "dashboard", "gateway"})
    if not subcmd:
        if sys.stdin.isatty():
            return run_interactive_menu(args.config)
        parser.print_help()
        return 0
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
