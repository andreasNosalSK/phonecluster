"""Unified CLI for PhoneCluster (worker daemon, master scheduler, workload helpers, web UI)."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .config import (
    DEFAULT_CONFIG_PATH,
    create_default_config,
    generate_auth_token,
    load_config,
    resolve_config_path,
    save_config,
)
from .dashboard import serve_dashboard
from .discovery import discover_lan_nodes
from .doctor import run_doctor
from .master import JobOutcome, JobSpec, MasterController
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
    cfg = load_config(args.config)
    try:
        node = cfg.get_node(args.node_id)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    port = args.port or node.worker_port
    max_conc = args.max_concurrency or node.max_concurrency
    state = WorkerState(
        node_id=node.id,
        role=node.role,
        auth_token=cfg.auth_token,
        safety=cfg.safety,
        max_concurrency=max_conc,
        workdir=Path(args.workdir),
    )
    serve_worker(
        args.bind,
        port,
        state,
        ssh_port=node.ssh_port,
        ssh_user=node.ssh_user,
        enable_discovery=not args.no_discover,
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
        if not n["online"]:
            state_str = f"OFFLINE ({n['error'][:28]})"
            rows.append([n["id"], n["role"], n["host"], "-", state_str, "-", "-", "-", "-", "-"])
            continue
        if n["ready_for_jobs"]:
            state_str = f"READY ({h.get('active_jobs', 0)}/{h.get('max_concurrency', '?')})"
        else:
            reasons = ",".join(h.get("not_ready_reasons", ["paused"]))
            state_str = f"PAUSED ({reasons})"
        cpu_str = f"{h.get('cpu_cores', '?')}c / {h.get('load_1m', 0):.2f}"
        ram_str = f"{h.get('mem_available_mb', 0)}/{h.get('mem_total_mb', 0)} MB"
        bat = h.get("battery_pct")
        bat_str = f"{bat}% {h.get('battery_status', '')[:4]}" if bat is not None else "N/A"
        temp = h.get("temp_c")
        temp_str = f"{temp:.1f}C" if temp is not None else "N/A"
        svcs = [k.split("_")[0] for k, v in (h.get("services") or {}).items() if v]
        svc_str = ",".join(svcs) if svcs else "-"
        rows.append(
            [
                n["id"],
                n["role"],
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
            ["NODE", "ROLE", "HOST", "OS", "STATE", "CPU/LOAD", "RAM FREE", "BAT", "TEMP", "SERVICES"],
            rows,
        )
    )


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    ctrl = MasterController(cfg)
    watch_sec = getattr(args, "watch", 0.0) or 0.0
    if watch_sec <= 0:
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

    if not args.command and not args.script:
        print("Provide a shell command or --script <path>.", file=sys.stderr)
        return 2

    script_content = None
    script_name = None
    if args.script:
        sp = Path(args.script)
        if not sp.exists():
            print(f"Script not found: {sp}", file=sys.stderr)
            return 2
        script_content = sp.read_text(encoding="utf-8")
        script_name = sp.name

    spec = JobSpec(
        index=0,
        job_id=f"run-{int(time.time())}",
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
    outcomes = ctrl.run_single(spec, target=args.target, tags=tags)

    if args.json:
        print(json.dumps([o.to_dict() for o in outcomes], indent=2))
    else:
        for o in outcomes:
            status = "OK" if o.ok else f"FAIL(rc={o.returncode})"
            print(f"=== [{o.node_id}] {status} ({o.duration_sec:.2f}s) ===")
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
    timeout = args.timeout or cfg.default_job_timeout_sec

    jobs: list[JobSpec] = []
    if args.script:
        sp = Path(args.script)
        if not sp.exists():
            print(f"Script not found: {sp}", file=sys.stderr)
            return 2
        content = sp.read_text(encoding="utf-8")
        if args.args_file:
            arg_lines = _load_lines(args.args_file)
            for idx, line in enumerate(arg_lines):
                jobs.append(
                    JobSpec(
                        index=idx,
                        job_id=f"map-{idx:04d}",
                        script_content=content,
                        script_name=sp.name,
                        interpreter=args.interpreter,
                        args=shlex.split(line),
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
                        job_id=f"map-{idx:04d}",
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
        cmd_lines = _load_lines(args.jobs_file)
        for idx, cmd in enumerate(cmd_lines):
            jobs.append(
                JobSpec(
                    index=idx,
                    job_id=f"map-{idx:04d}",
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
                    job_id=f"map-{idx:04d}",
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
        first_line = (o.stdout.strip().splitlines()[0] if o.stdout.strip() else o.error or "")[:80]
        print(f"[{done}/{total}] {tag:9s} {o.node_id:7s} {o.duration_sec:5.2f}s | {o.label[:40]} -> {first_line}")

    outcomes = ctrl.map_jobs(
        jobs,
        retries=args.retries,
        tags=tags,
        wait_for_ready_sec=args.wait_ready,
        on_result=_on_result,
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


def _cmd_dashboard(args: argparse.Namespace) -> int:
    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)
    ctrl = MasterController(cfg)
    port = args.port or cfg.dashboard_port
    serve_dashboard(args.bind, port, ctrl, config_path=cfg_path)
    return 0


def _cmd_wizard(args: argparse.Namespace) -> int:
    return run_setup_wizard(args.config)


def _cmd_menu(args: argparse.Namespace) -> int:
    return run_interactive_menu(args.config)


def _cmd_discover(args: argparse.Namespace) -> int:
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
    rows: list[list[str]] = []
    for n in all_nodes:
        nid = n["node_id"]
        for j in n.get("active", []):
            rows.append([nid, j["job_id"], "RUNNING", f"{j['running_sec']}s", j["command"][:50]])
        for j in n.get("recent", [])[: args.limit]:
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
    cmd = ["ssh", "-p", str(node.ssh_port), target] + (args.remote_cmd or [])
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
        target = f"{node.ssh_user}@{node.host}" if node.ssh_user else node.host
        scp_cmd = ["scp", "-P", str(node.ssh_port)]
        if src.is_dir():
            scp_cmd.append("-r")
        scp_cmd.extend([str(src), f"{target}:{args.dest}"])
        print(f"Copying {src} -> {node.id} ({target}:{args.dest})...")
        rc = subprocess.call(scp_cmd)
        if rc != 0:
            print(f"  FAILED on {node.id} (exit {rc})", file=sys.stderr)
            rc_all = 1
    return rc_all


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
        "--no-discover",
        action="store_true",
        help="Disable UDP LAN auto-discovery responder (port 8766)",
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

    # sync & update
    p_sync = sub.add_parser("sync", help="Push code & cluster.json to all phones and restart workers")
    p_sync.add_argument("--setup-keys", action="store_true", help="Copy SSH keys with ssh-copy-id first")
    p_sync.add_argument("--skip-node", default="", help="Skip syncing one node ID (e.g. node0)")
    p_sync.set_defaults(func=_cmd_sync)

    p_upd = sub.add_parser("update", help="Pull latest PhoneCluster updates from GitHub")
    p_upd.add_argument("--sync", action="store_true", help="Also sync the update to all worker phones")
    p_upd.set_defaults(func=_cmd_update)

    # run
    p_run = sub.add_parser("run", help="Run one command or script on best/all/specific phone")
    p_run.add_argument(
        "--target",
        default="best",
        help="Target node: 'best' (default), 'all', or a specific node_id (e.g. node1)",
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
    p_map = sub.add_parser("map", help="Run many commands/scripts in parallel across all healthy phones")
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

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Start the Master web dashboard UI")
    p_dash.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_dash.add_argument("--port", type=int, default=0, help="Dashboard HTTP port (default from config: 8080)")
    p_dash.set_defaults(func=_cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    subcmd = getattr(args, "subcommand", None)
    _configure_logging(args.verbose, is_daemon=subcmd in {"worker", "dashboard"})
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
