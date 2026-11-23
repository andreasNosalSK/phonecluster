"""Automated self-diagnostics (`phonecluster doctor`) for local & cluster health."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import ClusterConfig, load_config, resolve_config_path
from .master import MasterController
from .telemetry import (
    detect_capabilities,
    detect_os_environment,
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

    # 2. SSH daemon check
    ssh_8022 = is_local_port_open(8022)
    ssh_22 = is_local_port_open(22)
    if ssh_8022 or ssh_22:
        port_txt = "8022 (Termux)" if ssh_8022 else "22 (Linux)"
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

        boot_dir = Path.home() / ".termux" / "boot"
        boot_scripts = list(boot_dir.glob("*.sh")) if boot_dir.exists() else []
        if boot_scripts:
            checks.append(
                CheckResult(
                    "Termux:Boot Auto-Start",
                    "ok",
                    f"Found startup script(s): {', '.join(s.name for s in boot_scripts)}",
                )
            )
        else:
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
        online = [s for s in snaps if s.online]
        ready = [s for s in snaps if s.ready_for_jobs]
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
                    f"{len(online)}/{len(snaps)} online ({len(ready)} ready); offline: {', '.join(offline_ids)}",
                    "Check Wi-Fi connection and start worker on offline phone(s).",
                )
            )
        else:
            checks.append(
                CheckResult(
                    "Cluster Nodes",
                    "ok",
                    f"All {len(snaps)}/{len(snaps)} nodes online ({len(ready)} ready for jobs)",
                )
            )

        # Battery swelling safety check across online phones
        high_bat_nodes: list[str] = []
        hot_nodes: list[str] = []
        for s in online:
            h = s.health
            pct = h.get("battery_pct")
            st = str(h.get("battery_status", "")).upper()
            temp = h.get("temp_c")
            if pct is not None and pct >= cfg.safety.battery_high_pct and st in {"CHARGING", "FULL"}:
                high_bat_nodes.append(f"{s.node.id} ({pct}% {st})")
            if h.get("overheated"):
                hot_nodes.append(f"{s.node.id} ({temp}C)")

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
