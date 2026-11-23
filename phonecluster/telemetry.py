"""OS-agnostic hardware telemetry, thermal gating, and capability discovery.

Works seamlessly on:
- Unrooted Android via Termux + Termux:API (`termux-battery-status`)
- Rooted Debian 13 ARM64 chroot / Droidspaces (`/sys/class/power_supply/*`)
- Standard Linux PCs / Raspberry Pis (gracefully handles missing battery)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SafetyConfig

POWER_SUPPLY_DIR = Path("/sys/class/power_supply")
THERMAL_DIR = Path("/sys/class/thermal")
MEMINFO_PATH = Path("/proc/meminfo")
OS_RELEASE_PATH = Path("/etc/os-release")


@dataclass
class BatteryInfo:
    """Normalized battery and thermal reading."""

    percentage: int | None = None
    temperature_c: float | None = None
    status: str = "UNKNOWN"  # CHARGING, DISCHARGING, FULL, NOT_CHARGING, UNKNOWN
    health: str = "UNKNOWN"
    plugged: str = "UNKNOWN"
    source: str = "none"


class ThermalGate:
    """Thermal throttle gate with hysteresis to avoid rapid on/off flapping."""

    def __init__(self, max_temp_c: float = 40.0, resume_temp_c: float = 37.0) -> None:
        self.max_temp_c = max_temp_c
        self.resume_temp_c = resume_temp_c
        self._overheated = False

    def evaluate(self, temp_c: float | None) -> bool:
        """Update state and return True if the node is currently overheated."""
        if temp_c is None:
            return self._overheated
        if self._overheated:
            if temp_c <= self.resume_temp_c:
                self._overheated = False
        else:
            if temp_c >= self.max_temp_c:
                self._overheated = True
        return self._overheated

    @property
    def is_overheated(self) -> bool:
        return self._overheated


def detect_os_environment() -> str:
    """Identify whether we are running in Termux, Debian 13, or generic Linux."""
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    if OS_RELEASE_PATH.exists():
        try:
            text = OS_RELEASE_PATH.read_text(encoding="utf-8", errors="ignore")
            kv: dict[str, str] = {}
            for line in text.splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip().strip('"')
            distro_id = kv.get("ID", "linux")
            ver = kv.get("VERSION_ID", "")
            return f"{distro_id}-{ver}" if ver else distro_id
        except OSError:
            pass
    return platform.system().lower()


def _read_text_safe(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None


def _normalize_sysfs_temp(raw_val: str) -> float | None:
    """Normalize Linux sysfs temperatures (tenths of °C or millidegrees °C)."""
    try:
        val = float(raw_val)
    except ValueError:
        return None
    if abs(val) > 1000:
        val = val / 1000.0
    elif abs(val) > 150:
        val = val / 10.0
    if -20.0 <= val <= 130.0:
        return round(val, 2)
    return None


def read_battery_via_termux(timeout_sec: float = 4.0) -> BatteryInfo | None:
    """Read battery info using Termux:API if available."""
    cmd = shutil.which("termux-battery-status")
    if not cmd:
        return None
    try:
        raw = subprocess.check_output(
            [cmd],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_sec,
        )
        data = json.loads(raw)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None

    pct_raw = data.get("percentage")
    temp_raw = data.get("temperature")
    return BatteryInfo(
        percentage=int(pct_raw) if pct_raw is not None else None,
        temperature_c=round(float(temp_raw), 2) if temp_raw is not None else None,
        status=str(data.get("status", "UNKNOWN")).upper(),
        health=str(data.get("health", "UNKNOWN")).upper(),
        plugged=str(data.get("plugged", "UNKNOWN")).upper(),
        source="termux-api",
    )


def read_battery_via_sysfs(base_dir: Path = POWER_SUPPLY_DIR) -> BatteryInfo | None:
    """Read battery telemetry directly from Linux /sys/class/power_supply."""
    if not base_dir.exists():
        return None
    try:
        entries = sorted(base_dir.iterdir())
    except OSError:
        return None

    battery_dir: Path | None = None
    for entry in entries:
        if not entry.is_dir():
            continue
        ps_type = _read_text_safe(entry / "type")
        if ps_type and ps_type.lower() == "battery":
            battery_dir = entry
            break
        if entry.name.lower() in {"battery", "bat0", "bat1", "bms"}:
            battery_dir = entry
            break

    if battery_dir is None:
        return None

    cap_raw = _read_text_safe(battery_dir / "capacity")
    temp_raw = _read_text_safe(battery_dir / "temp")
    status_raw = _read_text_safe(battery_dir / "status") or "UNKNOWN"
    health_raw = _read_text_safe(battery_dir / "health") or "UNKNOWN"

    pct: int | None = None
    if cap_raw is not None:
        try:
            pct = int(float(cap_raw))
        except ValueError:
            pct = None

    temp_c = _normalize_sysfs_temp(temp_raw) if temp_raw is not None else None
    status_norm = status_raw.upper().replace(" ", "_")
    plugged = "PLUGGED" if status_norm in {"CHARGING", "FULL"} else "UNPLUGGED"

    return BatteryInfo(
        percentage=pct,
        temperature_c=temp_c,
        status=status_norm,
        health=health_raw.upper(),
        plugged=plugged,
        source=f"sysfs:{battery_dir.name}",
    )


def read_thermal_zone_temp(base_dir: Path = THERMAL_DIR) -> float | None:
    """Fallback temperature sensor reading from /sys/class/thermal."""
    if not base_dir.exists():
        return None
    readings: list[float] = []
    try:
        zones = sorted(base_dir.glob("thermal_zone*"))
    except OSError:
        return None
    for zone in zones:
        raw = _read_text_safe(zone / "temp")
        if raw is None:
            continue
        norm = _normalize_sysfs_temp(raw)
        if norm is not None and norm > 5.0:
            ztype = (_read_text_safe(zone / "type") or "").lower()
            if any(k in ztype for k in ("cpu", "soc", "ap", "mtk", "tsens", "x86_pkg", "acpitz")):
                return norm
            readings.append(norm)
    return max(readings) if readings else None


def read_battery_info() -> BatteryInfo:
    """Collect battery & temperature telemetry across Termux or Debian/Linux."""
    info = read_battery_via_termux()
    if info is None:
        info = read_battery_via_sysfs()
    if info is None:
        info = BatteryInfo()
    if info.temperature_c is None:
        fallback_temp = read_thermal_zone_temp()
        if fallback_temp is not None:
            info.temperature_c = fallback_temp
            if info.source == "none":
                info.source = "sysfs:thermal_zone"
    return info


def read_memory_info(meminfo_path: Path = MEMINFO_PATH) -> dict[str, int]:
    """Parse /proc/meminfo into megabytes without external dependencies."""
    if not meminfo_path.exists():
        return {"total_mb": 0, "available_mb": 0, "used_mb": 0}
    values_kb: dict[str, int] = {}
    try:
        for line in meminfo_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                values_kb[key.strip()] = int(parts[0])
    except OSError:
        return {"total_mb": 0, "available_mb": 0, "used_mb": 0}

    total_kb = values_kb.get("MemTotal", 0)
    avail_kb = values_kb.get("MemAvailable")
    if avail_kb is None:
        avail_kb = (
            values_kb.get("MemFree", 0)
            + values_kb.get("Buffers", 0)
            + values_kb.get("Cached", 0)
        )
    total_mb = total_kb // 1024
    avail_mb = avail_kb // 1024
    used_mb = max(0, total_mb - avail_mb)
    return {
        "total_mb": total_mb,
        "available_mb": avail_mb,
        "used_mb": used_mb,
    }


def read_load_average() -> tuple[float, float, float]:
    """Return (1m, 5m, 15m) system load averages."""
    try:
        l1, l5, l15 = os.getloadavg()
        return (round(l1, 2), round(l5, 2), round(l15, 2))
    except OSError:
        pass
    try:
        parts = Path("/proc/loadavg").read_text(encoding="utf-8").split()
        return (round(float(parts[0]), 2), round(float(parts[1]), 2), round(float(parts[2]), 2))
    except (OSError, ValueError, IndexError):
        return (0.0, 0.0, 0.0)


def is_local_port_open(port: int, timeout: float = 0.15) -> bool:
    """Return True if a local TCP daemon is accepting connections on `port`."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_capabilities() -> dict[str, Any]:
    """Detect installed tools and live local compute services."""
    tools = {
        "python3": bool(shutil.which("python3")),
        "clang": bool(shutil.which("clang")),
        "gcc": bool(shutil.which("gcc")),
        "distccd": bool(shutil.which("distccd")),
        "mpirun": bool(shutil.which("mpirun")),
        "llama_rpc": bool(
            shutil.which("rpc-server")
            or Path.home().joinpath("llama.cpp/build/bin/rpc-server").exists()
        ),
        "docker": bool(shutil.which("docker")),
        "homeassistant": bool(shutil.which("hass")),
        "tmux": bool(shutil.which("tmux")),
    }
    services = {
        "sshd_8022": is_local_port_open(8022),
        "sshd_22": is_local_port_open(22),
        "distccd_3632": is_local_port_open(3632),
        "llama_rpc_50052": is_local_port_open(50052),
        "homeassistant_8123": is_local_port_open(8123),
    }
    return {"tools": tools, "services": services}


def collect_node_health(
    node_id: str,
    role: str,
    safety: SafetyConfig,
    thermal_gate: ThermalGate,
    active_jobs: int = 0,
    max_concurrency: int = 2,
    workdir: str | Path = ".",
) -> dict[str, Any]:
    """Assemble full node health payload for `/health` and master scheduling."""
    battery = read_battery_info()
    mem = read_memory_info()
    l1, l5, l15 = read_load_average()
    overheated = thermal_gate.evaluate(battery.temperature_c)

    try:
        disk = shutil.disk_usage(workdir)
        disk_free_gb = round(disk.free / (1024**3), 2)
    except OSError:
        disk_free_gb = 0.0

    low_ram = (
        mem["total_mb"] > 0 and mem["available_mb"] < safety.min_free_ram_mb
    )
    caps = detect_capabilities()

    reasons: list[str] = []
    if overheated:
        reasons.append(
            f"overheated ({battery.temperature_c}C >= {safety.max_temp_c}C)"
        )
    if low_ram:
        reasons.append(
            f"low_ram ({mem['available_mb']}MB < {safety.min_free_ram_mb}MB)"
        )
    if active_jobs >= max_concurrency:
        reasons.append(f"busy ({active_jobs}/{max_concurrency})")

    ready_for_jobs = (not overheated) and (not low_ram) and (active_jobs < max_concurrency)

    return {
        "node_id": node_id,
        "role": role,
        "hostname": socket.gethostname(),
        "os_env": detect_os_environment(),
        "arch": platform.machine(),
        "cpu_cores": os.cpu_count() or 1,
        "load_1m": l1,
        "load_5m": l5,
        "load_15m": l15,
        "mem_total_mb": mem["total_mb"],
        "mem_available_mb": mem["available_mb"],
        "mem_used_mb": mem["used_mb"],
        "disk_free_gb": disk_free_gb,
        "battery_pct": battery.percentage,
        "temp_c": battery.temperature_c,
        "battery_status": battery.status,
        "battery_health": battery.health,
        "battery_source": battery.source,
        "overheated": overheated,
        "ready_for_jobs": ready_for_jobs,
        "not_ready_reasons": reasons,
        "active_jobs": active_jobs,
        "max_concurrency": max_concurrency,
        "tools": caps["tools"],
        "services": caps["services"],
        "timestamp": int(time.time()),
    }
