"""OS-agnostic hardware telemetry, thermal gating, and capability discovery.

Works seamlessly on:
- Unrooted Android via Termux + Termux:API (`termux-battery-status`)
- Rooted Debian 13 ARM64 chroot / Droidspaces (`/sys/class/power_supply/*`)
- Standard Linux PCs / Raspberry Pis (gracefully handles missing battery)
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SafetyConfig

POWER_SUPPLY_DIR = Path("/sys/class/power_supply")
THERMAL_DIR = Path("/sys/class/thermal")
MEMINFO_PATH = Path("/proc/meminfo")
PROC_STAT_PATH = Path("/proc/stat")
PROC_NET_DEV_PATH = Path("/proc/net/dev")
PROC_UPTIME_PATH = Path("/proc/uptime")
SYS_NET_DIR = Path("/sys/class/net")
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
    """Thread-safe thermal throttle gate with hysteresis to avoid rapid on/off flapping."""

    def __init__(self, max_temp_c: float = 40.0, resume_temp_c: float = 37.0) -> None:
        self._lock = threading.Lock()
        self.max_temp_c = max_temp_c
        self.resume_temp_c = resume_temp_c
        self._overheated = False

    def update_limits(self, max_temp_c: float, resume_temp_c: float) -> None:
        """Update thermal thresholds live (e.g. from Master `/config` push)."""
        with self._lock:
            self.max_temp_c = float(max_temp_c)
            self.resume_temp_c = float(resume_temp_c)

    def evaluate(self, temp_c: float | None) -> bool:
        """Update state and return True if the node is currently overheated."""
        with self._lock:
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
        with self._lock:
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


def read_uptime_sec(uptime_path: Path = PROC_UPTIME_PATH) -> int | None:
    """Return system uptime in whole seconds from /proc/uptime."""
    try:
        first = uptime_path.read_text(encoding="utf-8").split()[0]
        return max(0, int(float(first)))
    except (OSError, ValueError, IndexError):
        return None


def _parse_proc_stat(stat_path: Path = PROC_STAT_PATH) -> dict[str, tuple[int, int]] | None:
    """Parse /proc/stat CPU lines into `{name: (idle_ticks, total_ticks)}`."""
    try:
        text = stat_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    out: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        if not line.startswith("cpu"):
            if out:
                break
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[0]
        try:
            vals = [int(x) for x in parts[1:]]
        except ValueError:
            continue
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        out[name] = (idle, total)
    return out if out else None


class CpuSampler:
    """Thread-safe delta sampler for total and per-core CPU percentages."""

    def __init__(self, stat_path: Path = PROC_STAT_PATH) -> None:
        self._stat_path = stat_path
        self._lock = threading.Lock()
        self._prev: dict[str, tuple[int, int]] | None = _parse_proc_stat(stat_path)
        self._last_result: tuple[float | None, list[float]] = (None, [])

    def sample(self, load_1m: float = 0.0, cpu_cores: int = 1) -> tuple[float, list[float]]:
        """Return `(total_cpu_pct, per_core_pct_list)` using /proc/stat or load fallback."""
        with self._lock:
            curr = _parse_proc_stat(self._stat_path)
            if curr is not None and self._prev is not None:
                total_pct = self._calc_delta(self._prev.get("cpu"), curr.get("cpu"))
                core_names = sorted(
                    (k for k in curr if k != "cpu" and k[3:].isdigit()),
                    key=lambda k: int(k[3:]),
                )
                per_core: list[float] = []
                for cname in core_names:
                    pct = self._calc_delta(self._prev.get(cname), curr.get(cname))
                    if pct is not None:
                        per_core.append(pct)
                self._prev = curr
                if total_pct is not None:
                    self._last_result = (total_pct, per_core)
                    return total_pct, per_core
            elif curr is not None:
                self._prev = curr

            if self._last_result[0] is not None:
                return self._last_result[0], list(self._last_result[1])

        # Graceful fallback (e.g. first sample or strict Android SELinux blocking /proc/stat)
        est = min(100.0, round((max(0.0, load_1m) / max(1, cpu_cores)) * 100.0, 1))
        return est, []

    @staticmethod
    def _calc_delta(
        prev: tuple[int, int] | None, curr: tuple[int, int] | None
    ) -> float | None:
        if prev is None or curr is None:
            return None
        d_idle = curr[0] - prev[0]
        d_total = curr[1] - prev[1]
        if d_total <= 0:
            return None
        busy = max(0.0, min(100.0, (1.0 - (d_idle / d_total)) * 100.0))
        return round(busy, 1)


def _read_net_bytes(
    proc_net_path: Path = PROC_NET_DEV_PATH, sys_net_dir: Path = SYS_NET_DIR
) -> tuple[int, int] | None:
    """Return total non-loopback `(rx_bytes, tx_bytes)` across active interfaces."""
    if proc_net_path.exists():
        try:
            rx_total = 0
            tx_total = 0
            found = False
            for line in proc_net_path.read_text(encoding="utf-8", errors="ignore").splitlines()[2:]:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo" or iface.startswith("dummy"):
                    continue
                cols = rest.split()
                if len(cols) >= 9 and cols[0].isdigit() and cols[8].isdigit():
                    rx_total += int(cols[0])
                    tx_total += int(cols[8])
                    found = True
            if found:
                return rx_total, tx_total
        except OSError:
            pass

    if sys_net_dir.exists():
        try:
            rx_total = 0
            tx_total = 0
            found = False
            for iface_dir in sys_net_dir.iterdir():
                if iface_dir.name == "lo":
                    continue
                rx_s = _read_text_safe(iface_dir / "statistics" / "rx_bytes")
                tx_s = _read_text_safe(iface_dir / "statistics" / "tx_bytes")
                if rx_s and tx_s and rx_s.isdigit() and tx_s.isdigit():
                    rx_total += int(rx_s)
                    tx_total += int(tx_s)
                    found = True
            if found:
                return rx_total, tx_total
        except OSError:
            pass
    return None


class NetSampler:
    """Thread-safe delta sampler for network throughput in KB/s."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._prev_bytes = _read_net_bytes()
        self._prev_ts = time.monotonic()

    def sample(self) -> tuple[float | None, float | None]:
        """Return `(rx_kbps, tx_kbps)` or `(None, None)` if unavailable."""
        with self._lock:
            now = time.monotonic()
            curr = _read_net_bytes()
            if curr is None:
                return None, None
            if self._prev_bytes is None or now - self._prev_ts < 0.2:
                self._prev_bytes = curr
                self._prev_ts = now
                return 0.0, 0.0
            dt = max(0.2, now - self._prev_ts)
            d_rx = max(0, curr[0] - self._prev_bytes[0])
            d_tx = max(0, curr[1] - self._prev_bytes[1])
            self._prev_bytes = curr
            self._prev_ts = now
            return round((d_rx / 1024.0) / dt, 1), round((d_tx / 1024.0) / dt, 1)


def read_top_processes(limit: int = 5, timeout_sec: float = 1.5) -> list[dict[str, Any]]:
    """Return top running user-visible processes (gracefully works on Termux & Debian)."""
    ps_bin = shutil.which("ps")
    if not ps_bin:
        return []
    candidates = [
        [ps_bin, "-eo", "pid,pcpu,pmem,comm", "--sort=-pcpu"],
        [ps_bin, "-eo", "pid,pcpu,pmem,comm"],
    ]
    output = ""
    for cmd in candidates:
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout_sec
            )
            if output.strip():
                break
        except (subprocess.SubprocessError, OSError):
            continue
    if not output:
        return []

    procs: list[dict[str, Any]] = []
    for line in output.splitlines()[1:]:
        parts = line.split(None, 3)
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        name = parts[3].strip()
        if name in {"ps", "sh"}:
            continue
        try:
            cpu = float(parts[1])
            mem = float(parts[2])
        except ValueError:
            cpu = 0.0
            mem = 0.0
        procs.append(
            {
                "pid": int(parts[0]),
                "cpu_pct": round(cpu, 1),
                "mem_pct": round(mem, 1),
                "name": name[:32],
            }
        )
    procs.sort(key=lambda p: (p["cpu_pct"], p["mem_pct"]), reverse=True)
    return procs[:limit]


def is_local_port_open(port: int, timeout: float = 0.15) -> bool:
    """Return True if a local TCP daemon is accepting connections on `port` (IPv4 or IPv6 loopback)."""
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _is_proc_addr_loopback(addr_hex: str, is_v6: bool) -> bool:
    """Decode `/proc/net/tcp*` host-endian hex IP cleanly without `.127` false positives."""
    clean = addr_hex.strip().upper()
    try:
        if is_v6:
            if len(clean) != 32:
                return False
            words = [int(clean[i : i + 8], 16) for i in range(0, 32, 8)]
            addr6 = ipaddress.IPv6Address(struct.pack("=4I", *words))
            if addr6.ipv4_mapped is not None:
                return bool(addr6.ipv4_mapped.is_loopback)
            return bool(addr6.is_loopback)
        if len(clean) != 8:
            return False
        addr4 = ipaddress.IPv4Address(struct.pack("=I", int(clean, 16)))
        return bool(addr4.is_loopback)
    except (ValueError, struct.error):
        return False


def _read_listening_tcp_map(
    tcp_path: Path = Path("/proc/net/tcp"),
    tcp6_path: Path = Path("/proc/net/tcp6"),
) -> dict[int, bool] | None:
    """Parse `/proc/net/tcp*` into `{port: exposed}`. Returns `None` if unreadable."""
    ports: dict[int, bool] = {}
    read_any = False
    for path, is_v6 in ((tcp_path, False), (tcp6_path, True)):
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
            read_any = True
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3].upper() != "0A":  # 0A = TCP_LISTEN
                continue
            local = parts[1]
            if ":" not in local:
                continue
            addr_hex, port_hex = local.split(":", 1)
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            if port <= 0:
                continue
            exposed = not _is_proc_addr_loopback(addr_hex, is_v6=is_v6)
            ports[port] = ports.get(port, False) or exposed
    return ports if read_any else None


def read_listening_tcp_ports(
    tcp_path: Path = Path("/proc/net/tcp"),
    tcp6_path: Path = Path("/proc/net/tcp6"),
) -> list[dict[str, Any]]:
    """List listening TCP ports from `/proc/net/tcp*` (zero deps, works unrooted on Linux/Termux).

    Returns sorted dicts: `{"port": int, "exposed": bool}` where `exposed=True` means bound
    to a non-loopback address (e.g. `0.0.0.0`, `::`, or a LAN interface).
    """
    ports = _read_listening_tcp_map(tcp_path=tcp_path, tcp6_path=tcp6_path)
    if not ports:
        return []
    return [{"port": p, "exposed": exp} for p, exp in sorted(ports.items())][:64]


def detect_capabilities(listening_map: dict[int, bool] | None = None) -> dict[str, Any]:
    """Detect installed tools and live local services across Tier 1/2/3 nodes.

    Uses `/proc/net/tcp*` when readable (detecting services bound to `0.0.0.0`, `::`,
    `127.0.0.1`, `::1`, OR a specific LAN IP without spamming daemon logs with dummy TCP
    probes), and falls back to `is_local_port_open()` on platforms where `/proc/net/tcp*`
    is restricted (e.g. strict Android SELinux).
    """
    adguard_installed = bool(
        shutil.which("AdGuardHome")
        or Path("/opt/AdGuardHome/AdGuardHome").exists()
        or shutil.which("pihole")
    )
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
        "llama_cli": bool(
            shutil.which("llama-cli")
            or shutil.which("llama-server")
            or Path.home().joinpath("llama.cpp/build/bin/llama-cli").exists()
        ),
        "docker": bool(shutil.which("docker") or shutil.which("podman")),
        "k3s": bool(shutil.which("k3s") or shutil.which("kubectl")),
        "homeassistant": bool(shutil.which("hass")),
        "mosquitto": bool(shutil.which("mosquitto") or shutil.which("mosquitto_pub")),
        "adguard": adguard_installed,
        "apt": bool(shutil.which("apt-get")),
        "tmux": bool(shutil.which("tmux")),
    }
    lmap = listening_map if listening_map is not None else _read_listening_tcp_map()

    def _port_active(port: int) -> bool:
        if lmap is not None:
            return port in lmap
        return is_local_port_open(port)

    services = {
        "sshd_8022": _port_active(8022),
        "sshd_22": _port_active(22),
        "distccd_3632": _port_active(3632),
        "llama_rpc_50052": _port_active(50052),
        "llama_api_8081": _port_active(8081),
        "homeassistant_8123": _port_active(8123),
        "mosquitto_1883": _port_active(1883),
        "adguard_3000": _port_active(3000),
        "adguard_80": adguard_installed and _port_active(80),
        "dns_53": _port_active(53),
        "redis_6379": _port_active(6379),
        "postgres_5432": _port_active(5432),
    }
    return {"tools": tools, "services": services}


def detect_node_tier(os_env: str, tools: dict[str, bool]) -> tuple[int, str]:
    """Classify a device into Tier 1 (Termux/compute), Tier 2 (Debian/services), or Tier 3 (Docker).

    Respects explicit `PHONECLUSTER_TIER` env var (`1`, `2`, or `3`) when set.
    """
    override = os.environ.get("PHONECLUSTER_TIER", "").strip()
    if override in {"1", "2", "3"}:
        tier = int(override)
        return tier, {1: "compute", 2: "services", 3: "docker"}[tier]

    if os_env == "termux":
        return 1, "compute"

    docker_ready = bool(tools.get("docker")) and (
        Path("/var/run/docker.sock").exists()
        or Path("/run/podman/podman.sock").exists()
        or bool(tools.get("k3s"))
    )
    if docker_ready:
        return 3, "docker"

    return 2, "services"


def collect_node_health(
    node_id: str,
    role: str,
    safety: SafetyConfig,
    thermal_gate: ThermalGate,
    active_jobs: int = 0,
    max_concurrency: int = 2,
    workdir: str | Path = ".",
    cpu_sampler: CpuSampler | None = None,
    net_sampler: NetSampler | None = None,
    active_job_list: list[dict[str, Any]] | None = None,
    include_processes: bool = True,
    safety_only: bool = False,
) -> dict[str, Any]:
    """Assemble full btop-grade node health payload for `/health` and master scheduling.

    When `safety_only=True` (used by `/exec` slot reservation), evaluates thermal & RAM
    safety fast without spawning `ps`, probing ports, or disturbing `cpu_sampler`/`net_sampler`.
    """
    battery = read_battery_info()
    mem = read_memory_info()
    overheated = thermal_gate.evaluate(battery.temperature_c)
    low_ram = (
        mem["total_mb"] > 0 and mem["available_mb"] < safety.min_free_ram_mb
    )

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

    if safety_only:
        return {
            "node_id": node_id,
            "role": role,
            "mem_total_mb": mem["total_mb"],
            "mem_available_mb": mem["available_mb"],
            "mem_used_mb": mem["used_mb"],
            "battery_pct": battery.percentage,
            "temp_c": battery.temperature_c,
            "battery_status": battery.status,
            "overheated": overheated,
            "ready_for_jobs": ready_for_jobs,
            "not_ready_reasons": reasons,
            "active_jobs": active_jobs,
            "max_concurrency": max_concurrency,
            "timestamp": int(time.time()),
        }

    l1, l5, l15 = read_load_average()
    cpu_cores = os.cpu_count() or 1
    if cpu_sampler is not None:
        cpu_pct, per_core_pct = cpu_sampler.sample(load_1m=l1, cpu_cores=cpu_cores)
    else:
        cpu_pct = min(100.0, round((max(0.0, l1) / cpu_cores) * 100.0, 1))
        per_core_pct = []

    net_rx_kbps, net_tx_kbps = (
        net_sampler.sample() if net_sampler is not None else (None, None)
    )

    try:
        disk = shutil.disk_usage(workdir)
        disk_free_gb = round(disk.free / (1024**3), 2)
        disk_total_gb = round(disk.total / (1024**3), 2)
    except OSError:
        disk_free_gb = 0.0
        disk_total_gb = 0.0

    listening_map = _read_listening_tcp_map()
    listening_ports = (
        [{"port": p, "exposed": exp} for p, exp in sorted(listening_map.items())][:64]
        if listening_map
        else []
    )
    caps = detect_capabilities(listening_map=listening_map)
    os_env = detect_os_environment()
    detected_tier, detected_pool = detect_node_tier(os_env, caps["tools"])

    return {
        "node_id": node_id,
        "role": role,
        "hostname": socket.gethostname(),
        "os_env": os_env,
        "tier": detected_tier,
        "pool": detected_pool,
        "arch": platform.machine(),
        "uptime_sec": read_uptime_sec(),
        "cpu_cores": cpu_cores,
        "cpu_pct": cpu_pct,
        "per_core_pct": per_core_pct,
        "load_1m": l1,
        "load_5m": l5,
        "load_15m": l15,
        "mem_total_mb": mem["total_mb"],
        "mem_available_mb": mem["available_mb"],
        "mem_used_mb": mem["used_mb"],
        "disk_free_gb": disk_free_gb,
        "disk_total_gb": disk_total_gb,
        "net_rx_kbps": net_rx_kbps,
        "net_tx_kbps": net_tx_kbps,
        "battery_pct": battery.percentage,
        "temp_c": battery.temperature_c,
        "battery_status": battery.status,
        "battery_health": battery.health,
        "battery_source": battery.source,
        "overheated": overheated,
        "ready_for_jobs": ready_for_jobs,
        "not_ready_reasons": reasons,
        "active_jobs": active_jobs,
        "active_job_list": list(active_job_list) if active_job_list else [],
        "max_concurrency": max_concurrency,
        "top_processes": read_top_processes(limit=5) if include_processes else [],
        "listening_ports": listening_ports,
        "tools": caps["tools"],
        "services": caps["services"],
        "timestamp": int(time.time()),
    }
