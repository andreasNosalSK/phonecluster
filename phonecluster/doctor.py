"""Automated self-diagnostics (`phonecluster doctor`) for local & cluster health."""

from __future__ import annotations

import collections
import math
import os
import shutil
import socket
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import ClusterConfig, is_loopback_or_unspecified_host, load_config, normalize_host, resolve_config_path
from .master import MasterController
from .telemetry import (
    _read_listening_tcp_map,
    detect_capabilities,
    detect_os_environment,
    is_battery_health_hazardous,
    is_local_port_open,
    read_battery_via_termux,
)


@dataclass
class CheckResult:
    """Single diagnostic check result with actionable remediation hint."""

    name: str
    status: str  # "ok", "warn", "fail"
    detail: str
    fix_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_doctor(config_path: str | Path | None = None, check_remote: bool = True) -> dict[str, Any]:
    """Run local environment, safety, and optional live cluster connectivity checks."""
    checks: list[CheckResult] = []
    os_env = detect_os_environment()

    # 1. Python runtime check
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 9):
        checks.append(CheckResult("Python Runtime", "ok", f"Python {py_ver} on {os_env}"))
    else:
        checks.append(
            CheckResult(
                "Python Runtime",
                "fail",
                f"Python {py_ver} is too old (need 3.9+)",
                "Upgrade Python via `pkg upgrade python` (Termux) or `apt install python3` (Debian).",
            )
        )

    # 2. SSH daemon check (uses /proc/net/tcp* when readable to avoid sshd log spam and detect LAN-only ListenAddress)
    lmap_ssh = _read_listening_tcp_map()
    if lmap_ssh is not None:
        ssh_8022 = 8022 in lmap_ssh
        ssh_22 = 22 in lmap_ssh
    else:
        ssh_8022 = is_local_port_open(8022)
        ssh_22 = is_local_port_open(22)
    custom_ssh_port: int | None = None
    if not (ssh_8022 or ssh_22):
        probe_cfg_path = resolve_config_path(config_path)
        if probe_cfg_path.exists():
            try:
                probe_cfg = load_config(probe_cfg_path)
                cand_ports = sorted({n.ssh_port for n in probe_cfg.nodes if n.ssh_port not in {22, 8022}})
                for cp in cand_ports:
                    if (lmap_ssh is not None and cp in lmap_ssh) or (lmap_ssh is None and is_local_port_open(cp)):
                        custom_ssh_port = cp
                        break
            except Exception:
                pass
    if ssh_8022 or ssh_22 or custom_ssh_port is not None:
        if ssh_8022:
            port_txt = "8022 (Termux)"
        elif ssh_22:
            port_txt = "22 (Linux)"
        else:
            port_txt = f"{custom_ssh_port} (custom)"
        checks.append(CheckResult("SSH Server", "ok", f"Listening on port {port_txt}"))
    else:
        checks.append(
            CheckResult(
                "SSH Server",
                "warn",
                "No local sshd detected on port 8022 or 22",
                "Run `sshd` in Termux (or `systemctl start ssh` in Debian) so nodes can sync cleanly.",
            )
        )

    # 3. Termux-specific checks (Termux:API, Termux:Boot, wake-lock)
    if os_env == "termux":
        if shutil.which("termux-battery-status"):
            bat = read_battery_via_termux(timeout_sec=3.0)
            if bat is not None:
                checks.append(
                    CheckResult(
                        "Termux:API Telemetry",
                        "ok",
                        f"Working ({bat.percentage}%, {bat.temperature_c}C, {bat.status})",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        "Termux:API Telemetry",
                        "warn",
                        "termux-battery-status timed out or failed",
                        "Install Termux and Termux:API from the EXACT SAME source (both F-Droid or both GitHub) and disable Battery Optimization.",
                    )
                )
        else:
            checks.append(
                CheckResult(
                    "Termux:API Telemetry",
                    "warn",
                    "termux-api package not installed",
                    "Run `pkg install -y termux-api` and install the Termux:API app from F-Droid.",
                )
            )

        try:
            boot_dir = Path.home() / ".termux" / "boot"
            boot_scripts = list(boot_dir.glob("*.sh")) if boot_dir.exists() else []
        except (OSError, RuntimeError) as exc:
            boot_scripts = []
            checks.append(
                CheckResult(
                    "Termux:Boot Auto-Start",
                    "warn",
                    f"Could not inspect ~/.termux/boot: {exc}",
                    "Ensure HOME is set and ~/.termux/boot is readable.",
                )
            )
            boot_dir = None
        if boot_dir is not None and boot_scripts:
            checks.append(
                CheckResult(
                    "Termux:Boot Auto-Start",
                    "ok",
                    f"Found startup script(s): {', '.join(s.name for s in boot_scripts)}",
                )
            )
        elif boot_dir is not None:
            checks.append(
                CheckResult(
                    "Termux:Boot Auto-Start",
                    "warn",
                    "No ~/.termux/boot/*.sh startup script found",
                    "Run `bash scripts/02_termux_node_setup.sh --node-id <id>` and open the Termux:Boot app once.",
                )
            )

    # 4. Compute capabilities summary
    caps = detect_capabilities()
    installed_tools = [k for k, v in caps["tools"].items() if v]
    checks.append(
        CheckResult(
            "Local Tools",
            "ok",
            f"Detected: {', '.join(installed_tools) if installed_tools else 'basic shell'}",
        )
    )

    # 5. Configuration file & security checks
    resolved_cfg = resolve_config_path(config_path)
    cfg: ClusterConfig | None = None
    if not resolved_cfg.exists():
        checks.append(
            CheckResult(
                "Cluster Config",
                "fail",
                f"Not found at {resolved_cfg}",
                "Run `phonecluster wizard` or `phonecluster init-config` to create it.",
            )
        )
    else:
        try:
            cfg = load_config(resolved_cfg)
            if "REPLACE_ME" in cfg.auth_token or len(cfg.auth_token) < 16:
                checks.append(
                    CheckResult(
                        "Cluster Auth Token",
                        "fail",
                        "auth_token looks like a placeholder or is too short",
                        f"Run `phonecluster init-config --force --output {resolved_cfg}` to generate a secure random token.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        "Cluster Config",
                        "ok",
                        f"Loaded '{cfg.cluster_name}' with {len(cfg.nodes)} node(s) from {resolved_cfg}",
                    )
                )
            has_master = any(n.role == "master" for n in cfg.nodes)
            worker_nodes = [n for n in cfg.nodes if n.role != "master"]
            if worker_nodes:
                if not has_master:
                    checks.append(
                        CheckResult(
                            "Per-Node Token Isolation",
                            "ok",
                            "Scoped worker config (isolated per-node token; no Master admin token stored)",
                        )
                    )
                else:
                    tok_counts = collections.Counter(n.auth_token for n in worker_nodes if n.auth_token)
                    shared_master = [n.id for n in worker_nodes if not n.auth_token or n.auth_token == cfg.auth_token]
                    dup_workers = [
                        n.id
                        for n in worker_nodes
                        if n.auth_token and n.auth_token != cfg.auth_token and tok_counts[n.auth_token] > 1
                    ]
                    weak_workers = [
                        n.id
                        for n in worker_nodes
                        if n.auth_token and ("REPLACE_ME" in n.auth_token or len(n.auth_token) < 16)
                    ]
                    if not shared_master and not dup_workers and not weak_workers:
                        checks.append(
                            CheckResult(
                                "Per-Node Token Isolation",
                                "ok",
                                f"All {len(worker_nodes)} worker(s) use unique least-privilege tokens",
                            )
                        )
                    else:
                        issues: list[str] = []
                        if shared_master:
                            issues.append(f"sharing master token: {', '.join(shared_master)}")
                        if dup_workers:
                            issues.append(f"sharing duplicate worker token: {', '.join(dup_workers)}")
                        if weak_workers:
                            issues.append(f"weak/placeholder token: {', '.join(weak_workers)}")
                        checks.append(
                            CheckResult(
                                "Per-Node Token Isolation",
                                "warn",
                                f"Worker(s) {'; '.join(issues)}",
                                "Re-pair workers with `pc pair` + `pc join` so each phone gets its own strong unique token.",
                            )
                        )
            try:
                mode = stat.S_IMODE(os.stat(resolved_cfg).st_mode)
                if mode & 0o077:
                    checks.append(
                        CheckResult(
                            "Config Permissions",
                            "warn",
                            f"{resolved_cfg} is readable by group/others ({oct(mode)})",
                            f"Tighten permissions with: chmod 600 {resolved_cfg}",
                        )
                    )
            except OSError:
                pass

            if cfg.gateway.enabled:
                gw_port = int(cfg.gateway.port or 0)
                if gw_port <= 0:
                    checks.append(
                        CheckResult(
                            "Master Network Guard",
                            "warn",
                            f"Enabled in config (mode={cfg.gateway.mode}, ephemeral port=0) — cannot verify listening port offline",
                            "Set an explicit fixed port (e.g. 8888) in config/cluster.json so doctor and firewall rules can verify it.",
                        )
                    )
                else:
                    lmap = _read_listening_tcp_map()
                    if lmap is not None:
                        gw_live = gw_port in lmap
                    else:
                        bind_h = normalize_host(cfg.gateway.bind_host)
                        gw_live = False
                        if bind_h and not is_loopback_or_unspecified_host(bind_h):
                            try:
                                with socket.create_connection((bind_h, gw_port), timeout=0.25):
                                    gw_live = True
                            except OSError:
                                gw_live = False
                        if not gw_live:
                            gw_live = is_local_port_open(gw_port)
                    if gw_live:
                        checks.append(
                            CheckResult(
                                "Master Network Guard",
                                "ok",
                                f"Enabled & listening (mode={cfg.gateway.mode}, port={gw_port}, SSRF guard={'ON' if cfg.gateway.block_private_ips else 'OFF'})",
                            )
                        )
                    else:
                        checks.append(
                            CheckResult(
                                "Master Network Guard",
                                "warn",
                                f"Enabled in config (mode={cfg.gateway.mode}, port={gw_port}) but proxy is NOT currently listening on port {gw_port}",
                                "Start Master Dashboard (`pc dashboard`) or standalone proxy (`pc gateway`) so worker jobs can reach allowlisted sites.",
                            )
                        )
            else:
                checks.append(
                    CheckResult(
                        "Master Network Guard",
                        "ok",
                        "Disabled (default direct LAN mode). Optional: enable in Web UI Tab 5 or `pc gateway --enable` to proxy & filter old worker WAN traffic.",
                    )
                )
        except Exception as exc:
            checks.append(
                CheckResult(
                    "Cluster Config",
                    "fail",
                    f"Invalid config at {resolved_cfg}: {exc}",
                    "Fix JSON syntax or regenerate with `phonecluster wizard`.",
                )
            )

    # 6. Live cluster connectivity & 24/7 battery safety audit
    if cfg is not None and check_remote:
        ctrl = MasterController(cfg)
        snaps = ctrl.poll_health()
        quarantined = set(cfg.gateway.quarantined_nodes)
        online = [s for s in snaps if s.online]
        ready = [s for s in snaps if s.ready_for_jobs and s.node.id not in quarantined]
        q_online = [s.node.id for s in online if s.node.id in quarantined]
        q_suffix = f"; quarantined: {', '.join(q_online)}" if q_online else ""
        if not online:
            checks.append(
                CheckResult(
                    "Cluster Nodes",
                    "fail",
                    f"0/{len(snaps)} nodes reachable",
                    "Ensure worker daemons are started (`./scripts/03_sync_cluster.sh`) and IPs in cluster.json match your phones.",
                )
            )
        elif len(online) < len(snaps):
            offline_ids = [s.node.id for s in snaps if not s.online]
            checks.append(
                CheckResult(
                    "Cluster Nodes",
                    "warn",
                    f"{len(online)}/{len(snaps)} online ({len(ready)} ready{q_suffix}); offline: {', '.join(offline_ids)}",
                    "Check Wi-Fi connection and start worker on offline phone(s).",
                )
            )
        else:
            checks.append(
                CheckResult(
                    "Cluster Nodes",
                    "ok",
                    f"All {len(snaps)}/{len(snaps)} nodes online ({len(ready)} ready for jobs{q_suffix})",
                )
            )

        # Battery swelling, PMIC hazard, and thermal safety check across online phones
        high_bat_nodes: list[str] = []
        hazard_bat_nodes: list[str] = []
        hot_nodes: list[str] = []
        for s in online:
            h = s.health if isinstance(s.health, dict) else {}
            pct_raw = h.get("battery_pct")
            pct_val: float | None = None
            if pct_raw is not None and not isinstance(pct_raw, bool):
                try:
                    pf = float(pct_raw)
                    if math.isfinite(pf):
                        pct_val = pf
                except (TypeError, ValueError, OverflowError):
                    pct_val = None
            st = str(h.get("battery_status") or "").strip().upper().replace(" ", "_")
            b_health = str(h.get("battery_health") or "").strip().upper().replace(" ", "_")
            temp_raw = h.get("temp_c")
            temp_val: float | None = None
            if temp_raw is not None and not isinstance(temp_raw, bool):
                try:
                    tf = float(temp_raw)
                    if math.isfinite(tf):
                        temp_val = tf
                except (TypeError, ValueError, OverflowError):
                    temp_val = None
            if is_battery_health_hazardous(b_health):
                hazard_bat_nodes.append(f"{s.node.id} ({b_health})")
            if pct_val is not None and pct_val >= cfg.safety.battery_high_pct and st in {"CHARGING", "FULL"}:
                high_bat_nodes.append(f"{s.node.id} ({int(pct_val)}% {st})")
            if h.get("overheated") or (temp_val is not None and temp_val >= cfg.safety.max_temp_c):
                hot_nodes.append(f"{s.node.id} ({temp_val if temp_val is not None else temp_raw}C)")

        if hazard_bat_nodes:
            checks.append(
                CheckResult(
                    "Battery Hardware Health (PMIC)",
                    "fail",
                    f"Hardware PMIC battery hazard reported on: {', '.join(hazard_bat_nodes)}",
                    "Disconnect charger power immediately and inspect the phone battery for heat or swelling.",
                )
            )

        if hot_nodes:
            checks.append(
                CheckResult(
                    "Thermal Safety",
                    "warn",
                    f"Thermal throttle active on: {', '.join(hot_nodes)}",
                    "Stand phones vertically with airflow gaps; PhoneCluster automatically pauses jobs until cooled.",
                )
            )
        elif online:
            checks.append(
                CheckResult(
                    "Thermal Safety",
                    "ok",
                    f"All online nodes below {cfg.safety.max_temp_c:.1f}C limit",
                )
            )

        if high_bat_nodes:
            checks.append(
                CheckResult(
                    "24/7 Battery Safety",
                    "warn",
                    f"Charging above {cfg.safety.battery_high_pct}%: {', '.join(high_bat_nodes)}",
                    "Avoid pinning Li-Po batteries at 100% 24/7. Set `safety.battery_webhook_url` for a smart plug or use rooted `vr-25/acc`.",
                )
            )
        elif online:
            checks.append(
                CheckResult(
                    "24/7 Battery Safety",
                    "ok",
                    f"No online phone charging above {cfg.safety.battery_high_pct}%",
                )
            )

    ok_n = sum(1 for c in checks if c.status == "ok")
    warn_n = sum(1 for c in checks if c.status == "warn")
    fail_n = sum(1 for c in checks if c.status == "fail")
    overall = "fail" if fail_n else ("warn" if warn_n else "ok")
    return {
        "overall": overall,
        "summary": {"ok": ok_n, "warn": warn_n, "fail": fail_n},
        "checks": [c.to_dict() for c in checks],
    }
