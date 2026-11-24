"""Pretty multi-device btop-style Terminal Control UI (`pc top`).

Zero external dependencies: uses standard Python ANSI 256-color rendering,
Unicode rounded box-drawing, block sparklines, and non-blocking `termios`/`select`
keyboard control (works on Android Termux, Debian 13, and desktop SSH terminals).
"""

from __future__ import annotations

import math
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid
from typing import Any

from .master import JobSpec, MasterController

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX fallback
    termios = None  # type: ignore[assignment]
    tty = None  # type: ignore[assignment]

SPARK_CHARS = " ▁▂▃▄▅▆▇█"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TERM_ESCAPE_RE = re.compile(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-9;?]*[ -/]*[@-~]|[@-Z\\-_])")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _clean_term_text(val: Any, max_len: int = 120) -> str:
    """Strip terminal ANSI/OSC escape sequences and C0 control chars from untrusted worker text."""
    s = _TERM_ESCAPE_RE.sub("", str(val if val is not None else ""))
    return _CTRL_CHARS_RE.sub("", s)[:max_len]


def _safe_num(val: Any, default: float = 0.0) -> float:
    try:
        if isinstance(val, bool):
            return default
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        if isinstance(val, bool):
            return default
        f = float(val)
        return int(f) if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


class Palette:
    """btop-inspired 256-color palette (auto-disables when NO_COLOR is set)."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and not os.environ.get("NO_COLOR")

    def c(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self.c("1", text)

    def dim(self, text: str) -> str:
        return self.c("38;5;244", text)

    def border(self, text: str) -> str:
        return self.c("38;5;240", text)

    def accent(self, text: str) -> str:
        return self.c("1;38;5;75", text)

    def cyan(self, text: str) -> str:
        return self.c("38;5;81", text)

    def purple(self, text: str) -> str:
        return self.c("1;38;5;141", text)

    def ok(self, text: str) -> str:
        return self.c("1;38;5;78", text)

    def warn(self, text: str) -> str:
        return self.c("1;38;5;221", text)

    def bad(self, text: str) -> str:
        return self.c("1;38;5;203", text)

    def sel_bg(self, text: str) -> str:
        return self.c("1;38;5;117", text)


def _visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def _pad_visible(text: str, width: int) -> str:
    vis = _visible_len(text)
    if vis > width:
        # Strip ANSI only when truncation is necessary so escape codes stay balanced
        plain = ANSI_RE.sub("", text)
        return plain[: max(0, width - 1)] + ("…" if width >= 1 else "")
    return text + (" " * (width - vis))


def _format_uptime(sec: int | None) -> str:
    if sec is None:
        return "-"
    sec = max(0, sec)
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def make_sparkline(values: list[float], width: int = 14, max_val: float = 100.0) -> str:
    """Render a smooth Unicode block sparkline for a time-series."""
    if width <= 0:
        return ""
    tail = values[-width:] if values else []
    chars: list[str] = []
    for v in tail:
        ratio = max(0.0, min(1.0, _safe_num(v, 0.0) / max(1.0, max_val)))
        idx = int(round(ratio * (len(SPARK_CHARS) - 1)))
        chars.append(SPARK_CHARS[idx])
    return "".join(chars).rjust(width, "▁" if tail else "·")


def make_bar(pct: float, width: int, pal: Palette, warn_at: float = 70.0, bad_at: float = 88.0) -> str:
    """Render a colored Unicode meter bar like btop."""
    clamped = max(0.0, min(100.0, pct))
    filled = int(round((clamped / 100.0) * width))
    empty = max(0, width - filled)
    fill_str = "━" * filled
    empty_str = "─" * empty
    if clamped >= bad_at:
        colored = pal.bad(fill_str)
    elif clamped >= warn_at:
        colored = pal.warn(fill_str)
    else:
        colored = pal.ok(fill_str)
    return colored + pal.dim(empty_str)


def make_core_bars(per_core: list[float], pal: Palette) -> str:
    """Render compact per-core heat blocks (e.g. 8 ARM64 cores at a glance)."""
    if not per_core:
        return ""
    blocks: list[str] = []
    for pct in per_core[:16]:
        idx = int(round(max(0.0, min(100.0, pct)) / 100.0 * (len(SPARK_CHARS) - 1)))
        ch = SPARK_CHARS[max(1, idx)]
        if pct >= 85:
            blocks.append(pal.bad(ch))
        elif pct >= 60:
            blocks.append(pal.warn(ch))
        else:
            blocks.append(pal.ok(ch))
    return "[" + "".join(blocks) + "]"


def _box_lines(title: str, body_lines: list[str], width: int, pal: Palette) -> list[str]:
    inner_w = max(20, width - 2)
    clean_t = _clean_term_text(title, max(1, inner_w - 4)) if title else ""
    title_str = f" {clean_t} " if clean_t else ""
    t_vis = _visible_len(title_str)
    right_dashes = max(1, inner_w - t_vis - 1)
    top = pal.border("╭─") + pal.accent(title_str) + pal.border("─" * right_dashes + "╮")
    bottom = pal.border("╰" + "─" * inner_w + "╯")
    out = [top]
    for line in body_lines:
        padded = _pad_visible(line, inner_w - 2)
        out.append(pal.border("│") + " " + padded + " " + pal.border("│"))
    out.append(bottom)
    return out


def _tier_badge(tier: int, pool: str, pal: Palette) -> str:
    label = f"T{tier}:{pool}"
    if tier == 3:
        return pal.warn(label)
    if tier == 2:
        return pal.purple(label)
    if tier == 1:
        return pal.cyan(label)
    return pal.dim(label)


def render_top_frame(
    summary: dict[str, Any],
    history: dict[str, Any],
    all_jobs: list[dict[str, Any]],
    selected_idx: int = 0,
    view_mode: str = "tasks",
    refresh_sec: float = 2.0,
    paused: bool = False,
    last_command_banner: str = "",
    width: int | None = None,
    use_color: bool = True,
    pool_filter: str = "all",
) -> str:
    """Render one complete multi-device btop frame as a string."""
    pal = Palette(enabled=use_color)
    cols = width or max(78, min(140, shutil.get_terminal_size((100, 32)).columns))

    # 1. Unified Cluster Overview Header ("One Computer" btop summary)
    cluster_hist = history.get("cluster", [])
    cpu_series = [float(p.get("cpu_pct", 0.0)) for p in cluster_hist]
    cpu_pct = float(summary.get("cluster_cpu_pct", 0.0))
    ram_pct = float(summary.get("cluster_ram_pct", 0.0))
    mem_tot_mb = max(0, int(summary.get("mem_total_mb", 0) or 0))
    mem_avail_mb = max(0, int(summary.get("mem_available_mb", 0) or 0))
    mem_used_gb = max(0, mem_tot_mb - mem_avail_mb) / 1024.0
    mem_tot_gb = mem_tot_mb / 1024.0
    max_temp = summary.get("max_temp_c")
    safety = summary.get("safety", {})
    max_temp_limit = float(safety.get("max_temp_c", 40.0))
    bat_high = int(safety.get("battery_high_pct", 60))

    temp_str = f"{max_temp:.1f}°C" if max_temp is not None else "N/A"
    if max_temp is not None and max_temp >= max_temp_limit:
        temp_styled = pal.bad(temp_str)
    elif max_temp is not None and max_temp >= max_temp_limit - 3.0:
        temp_styled = pal.warn(temp_str)
    else:
        temp_styled = pal.ok(temp_str)

    live_tag = pal.warn("⏸ PAUSED") if paused else pal.ok(f"● LIVE {refresh_sec:g}s")
    spark_cluster = pal.cyan(make_sparkline(cpu_series, width=12 if cols < 100 else 16, max_val=100.0))

    net_rx_tot = float(summary.get("total_net_rx_kbps", 0.0))
    net_tx_tot = float(summary.get("total_net_tx_kbps", 0.0))
    cpu_bar_w = 12 if cols < 100 else 16
    mem_bar_w = 12 if cols < 100 else 16

    top_row = (
        f"{pal.purple(_clean_term_text(summary.get('cluster_name', 'phonecluster'), 36))}  "
        f"{live_tag}  "
        f"Ready: {pal.ok(str(summary.get('nodes_ready', 0)))}/{summary.get('nodes_total', 0)}  "
        f"Tasks: {pal.accent(str(summary.get('total_active_jobs', 0)))}  "
        f"Ping: {pal.dim(str(summary.get('avg_latency_ms', 0.0)) + 'ms')}  "
        f"{pal.dim(time.strftime('%H:%M:%S'))}"
    )
    cpu_part = f"CPU  {pal.bold(f'{cpu_pct:5.1f}%')} {make_bar(cpu_pct, cpu_bar_w, pal)} {spark_cluster} ({summary.get('total_cores', 0)}c)"
    mem_part = f"MEM  {pal.bold(f'{ram_pct:4.1f}%')} {make_bar(ram_pct, mem_bar_w, pal)} {mem_used_gb:.2f}/{mem_tot_gb:.2f} GB"
    meta_row = (
        f"TEMP Peak {temp_styled} (limit {max_temp_limit:.0f}°C)   "
        f"NET ↓{pal.cyan(f'{net_rx_tot:.1f}')} "
        f"↑{pal.purple(f'{net_tx_tot:.1f}')} KB/s"
    )
    if cols >= 106:
        header_lines = [top_row, f"{cpu_part}   {mem_part}", meta_row]
    else:
        header_lines = [top_row, cpu_part, mem_part, meta_row]

    # Show heterogeneous Tier/Pool overview & live cross-tier Service Mesh in header
    pools = summary.get("pools") or []
    if pools:
        pool_chips: list[str] = []
        for p in pools:
            badge = _tier_badge(int(p.get("tier", 1)), str(p.get("pool", "compute")), pal)
            chip = f"{badge} {p.get('nodes_ready', 0)}/{p.get('nodes_total', 0)} ({p.get('total_cores', 0)}c)"
            pool_chips.append(chip)
        header_lines.append("POOLS " + " · ".join(pool_chips))

    svcs_reg = summary.get("services_registry") or []
    if svcs_reg:
        svc_items: list[str] = []
        seen_svc: set[tuple[str, str]] = set()
        for entry in svcs_reg:
            pair = (str(entry.get("name", "")), str(entry.get("node_id", "")))
            if pair in seen_svc:
                continue
            seen_svc.add(pair)
            svc_items.append(f"{pal.ok(pair[0])}@{pair[1]}")
            if len(svc_items) >= 6:
                break
        if svc_items:
            header_lines.append("SVCS  " + " · ".join(svc_items))

    frames: list[str] = []
    frames.extend(_box_lines("PHONECLUSTER · UNIFIED MULTI-DEVICE BTOP", header_lines, cols, pal))

    # 2. Per-Device Shared btop Panel
    all_nodes = summary.get("nodes", [])
    if pool_filter and pool_filter != "all":
        nodes = [n for n in all_nodes if str(n.get("pool", "")) == pool_filter]
    else:
        nodes = all_nodes
    node_hist_map = history.get("nodes", {})
    device_lines: list[str] = []
    for idx, n in enumerate(nodes):
        is_sel = idx == selected_idx
        pointer = pal.sel_bg("▶") if is_sel else " "
        h = n.get("health") or {}
        role_badge = pal.purple("MASTER") if n.get("role") == "master" else pal.dim("WORKER")
        tier_num = int(n.get("tier", 1) or 1)
        pool_name = str(n.get("pool", "compute") or "compute")
        t_badge = _tier_badge(tier_num, pool_name, pal)
        nid_styled = pal.sel_bg(f"{n['id']:<6s}") if is_sel else pal.bold(f"{n['id']:<6s}")

        if not n.get("online"):
            err = _clean_term_text(n.get("error", "unreachable"), 42)
            device_lines.append(
                f"{pointer} {nid_styled} [{role_badge} {t_badge}] {n['host']:<15s}  {pal.bad('✕ OFFLINE')}  {pal.dim(err)}"
            )
            continue

        if n.get("quarantined"):
            st_badge = pal.bad("✕ QUARANTINED")
        elif n.get("ready_for_jobs"):
            st_badge = pal.ok(
                f"✓ READY {_safe_int(h.get('active_jobs', 0), 0)}/{max(1, _safe_int(h.get('max_concurrency', n.get('max_concurrency', 2)), 2))}"
            )
        else:
            raw_reasons = h.get("not_ready_reasons")
            reasons_list = raw_reasons if isinstance(raw_reasons, list) and raw_reasons else ["paused"]
            reasons = ",".join(_clean_term_text(r, 32) for r in reasons_list)
            st_badge = pal.warn(f"⚠ {reasons[:26]}")

        up_raw = h.get("uptime_sec")
        up_s = _format_uptime(_safe_int(up_raw, 0) if up_raw is not None else None)
        os_s = _clean_term_text(h.get("os_env", "linux"), 10)
        lat_txt = f"{_safe_num(n.get('latency_ms', 0), 0.0):.1f}ms"
        device_lines.append(
            f"{pointer} {nid_styled} [{role_badge} {t_badge}] {n['host']:<15s} {pal.dim(f'{os_s:<10s}')} "
            f"up {up_s:<6s} {st_badge}  {pal.dim(lat_txt)}"
        )

        # CPU + sparkline + per-core bars + RAM
        n_cpu = min(100.0, max(0.0, _safe_num(h.get("cpu_pct"), 0.0)))
        n_hist = [_safe_num(p.get("cpu_pct", 0.0), 0.0) for p in node_hist_map.get(n["id"], []) if isinstance(p, dict)]
        n_spark = pal.cyan(make_sparkline(n_hist, width=10, max_val=100.0))
        raw_pc = h.get("per_core_pct")
        per_core_clean = [_safe_num(x, 0.0) for x in raw_pc] if isinstance(raw_pc, list) else []
        cores_vis = make_core_bars(per_core_clean, pal)
        mem_tot = max(0, _safe_int(h.get("mem_total_mb", 0), 0))
        mem_avail = max(0, _safe_int(h.get("mem_available_mb", 0), 0))
        mem_used = max(0, mem_tot - mem_avail)
        mem_pct = (mem_used / mem_tot) * 100.0 if mem_tot else 0.0
        device_lines.append(
            f"    CPU {n_cpu:5.1f}% {n_spark} {cores_vis}  "
            f"RAM {make_bar(mem_pct, 10, pal)} {mem_used}/{mem_tot}MB ({mem_pct:4.0f}%)"
        )

        # Temp + Battery + Net + Services
        temp_raw = h.get("temp_c")
        temp_v = _safe_num(temp_raw, -999.0) if temp_raw is not None else None
        if temp_v is not None and temp_v <= -500.0:
            temp_v = None
        t_bar = make_bar((temp_v / 50.0) * 100.0, 8, pal, warn_at=(max_temp_limit - 3) * 2, bad_at=max_temp_limit * 2) if temp_v is not None else pal.dim("────────")
        t_txt = f"{temp_v:4.1f}°C" if temp_v is not None else "  N/A "

        bat_raw = h.get("battery_pct")
        bat_v = _safe_int(bat_raw, -1) if bat_raw is not None else None
        if bat_v is not None and bat_v < 0:
            bat_v = None
        bat_st = _clean_term_text(h.get("battery_status", ""), 4)
        if bat_v is not None:
            b_warn = bat_v >= bat_high and bat_st in {"CHAR", "FULL"}
            bat_txt = pal.warn(f"{bat_v:3d}% {bat_st}") if b_warn else f"{bat_v:3d}% {bat_st}"
        else:
            bat_txt = pal.dim("N/A")

        rx_raw = h.get("net_rx_kbps")
        tx_raw = h.get("net_tx_kbps")
        rx_v = _safe_num(rx_raw, -1.0) if rx_raw is not None else -1.0
        tx_v = _safe_num(tx_raw, -1.0) if tx_raw is not None else -1.0
        net_txt = f"↓{rx_v:.0f} ↑{tx_v:.0f}KB/s" if rx_v >= 0.0 and tx_v >= 0.0 else ""
        raw_svcs = h.get("services") if isinstance(h, dict) else None
        svcs = ",".join(_clean_term_text(k.split("_")[0], 20) for k, v in (raw_svcs.items() if isinstance(raw_svcs, dict) else ()) if v)
        device_lines.append(
            f"    TMP {t_txt} {t_bar}  BAT {bat_txt}  "
            f"{pal.cyan(net_txt)}  {pal.dim(svcs)}"
        )

        # Show inline running task or top processes briefly
        raw_active = h.get("active_job_list")
        active_list = [j for j in raw_active if isinstance(j, dict)] if isinstance(raw_active, list) else []
        if active_list:
            running_txt = " · ".join(
                f"[{_clean_term_text(j.get('job_id', '?'), 20)} {_safe_num(j.get('running_sec', 0), 0.0):.1f}s] "
                f"{_clean_term_text(j.get('command', ''), 28)}"
                for j in active_list[:2]
            )
            device_lines.append(f"    {pal.accent('RUN')} {running_txt}")

        if idx < len(nodes) - 1:
            device_lines.append(pal.border("  " + "·" * max(10, cols - 8)))

    if not device_lines:
        if pool_filter and pool_filter != "all":
            device_lines.append(pal.dim(f"No phones in pool '{pool_filter}' — press [p] to show all."))
        else:
            device_lines.append(pal.dim("No nodes configured in cluster.json."))

    dev_title = (
        "DEVICES · SHARED CLUSTER VIEW"
        if not pool_filter or pool_filter == "all"
        else f"DEVICES · POOL FILTER: {pool_filter.upper()} (press 'p' for all)"
    )
    frames.extend(_box_lines(dev_title, device_lines, cols, pal))

    # 3. Bottom Panel: Running Tasks & Recent History OR Shared Top Processes
    bottom_lines: list[str] = []
    if view_mode == "procs":
        panel_title = "SHARED TOP PROCESSES ACROSS ALL PHONES (press 'd' for Tasks)"
        proc_rows: list[tuple[float, str]] = []
        for n in nodes:
            if not n.get("online"):
                continue
            nid_col = pal.bold(f"{n['id']:<6s}")
            raw_procs = (n.get("health") or {}).get("top_processes")
            for p in (raw_procs if isinstance(raw_procs, list) else []):
                if not isinstance(p, dict):
                    continue
                p_cpu = _safe_num(p.get("cpu_pct", 0.0), 0.0)
                p_mem = _safe_num(p.get("mem_pct", 0.0), 0.0)
                line = (
                    f"{nid_col}  PID {_safe_int(p.get('pid', 0), 0):<6d}  "
                    f"CPU {p_cpu:5.1f}%  MEM {p_mem:4.1f}%  {_clean_term_text(p.get('name', '?'), 32)}"
                )
                proc_rows.append((p_cpu, line))
        proc_rows.sort(key=lambda r: r[0], reverse=True)
        bottom_lines = [r[1] for r in proc_rows[:7]] or [pal.dim("No process info reported by workers.")]
    else:
        panel_title = "RUNNING & RECENT CLUSTER TASKS (press 'd' for Processes)"
        active_rows: list[str] = []
        recent_rows: list[str] = []
        for node_jobs in all_jobs:
            nid = _clean_term_text(node_jobs.get("node_id", "?"), 20)
            for j in (node_jobs.get("active") if isinstance(node_jobs.get("active"), list) else []):
                if not isinstance(j, dict):
                    continue
                active_rows.append(
                    f"{pal.warn('● RUN ')} {pal.bold(f'{nid:<6s}')} {_clean_term_text(j.get('job_id', '?'), 14):<14s} "
                    f"{_safe_num(j.get('running_sec', 0), 0.0):5.1f}s  {_clean_term_text(j.get('command', ''), 44)}"
                )
            for j in (node_jobs.get("recent") if isinstance(node_jobs.get("recent"), list) else [])[:3]:
                if not isinstance(j, dict):
                    continue
                rc_val = _safe_int(j.get("returncode", -1), -1)
                st = (
                    pal.warn("CANCEL")
                    if j.get("cancelled")
                    else (
                        pal.bad("TIMOUT")
                        if j.get("timed_out")
                        else (pal.ok("✓ OK  ") if rc_val == 0 else pal.bad(f"✕ {rc_val:<4d}"))
                    )
                )
                recent_rows.append(
                    f"{st} {pal.dim(f'{nid:<6s}')} {_clean_term_text(j.get('job_id', '?'), 14):<14s} "
                    f"{_safe_num(j.get('duration_sec', 0), 0.0):5.2f}s  {_clean_term_text(j.get('command', ''), 44)}"
                )
        bottom_lines = (active_rows + recent_rows)[:7] or [
            pal.dim("Idle — press [r] to run on selected phone or [a] to broadcast to all.")
        ]

    frames.extend(_box_lines(panel_title, bottom_lines, cols, pal))

    # 4. Last Interactive Command Result (if any)
    if last_command_banner:
        cmd_lines = [_clean_term_text(line, max_len=max(80, cols)) for line in last_command_banner.splitlines()[:5]]
        frames.extend(_box_lines("LAST COMMAND OUTPUT", cmd_lines, cols, pal))

    # 5. Keybinding Footer Bar
    footer = (
        f" {pal.accent('[↑/↓]')} Sel  "
        f"{pal.accent('[x]')} Auto-Run  "
        f"{pal.accent('[p]')} Pool({pool_filter})  "
        f"{pal.accent('[r]')} Run  "
        f"{pal.accent('[a]')} All  "
        f"{pal.accent('[s]')} SSH  "
        f"{pal.accent('[c]')} Cancel  "
        f"{pal.accent('[d]')} Tasks/Procs  "
        f"{pal.accent('[Space]')} Pause  "
        f"{pal.accent('[q]')} Quit"
    )
    frames.append(footer)
    return "\n".join(frames)


def _read_key(timeout_sec: float) -> str | None:
    """Non-blocking key reader handling arrow-key escape sequences."""
    if not sys.stdin.isatty():
        time.sleep(timeout_sec)
        return None
    ready, _, _ = select.select([sys.stdin], [], [], max(0.05, timeout_sec))
    if not ready:
        return None
    raw = os.read(sys.stdin.fileno(), 1)
    if not raw:
        return "EOF"
    ch = raw.decode("utf-8", errors="ignore")
    if ch == "\x1b":
        # Drain complete CSI (`ESC [ ... <0x40-0x7E>`) or SS3 (`ESC O <byte>`) sequences
        # so multi-byte keys like Ctrl+Right (`\x1b[1;5C`) NEVER leak `C` (cancel job) into stdin!
        r2, _, _ = select.select([sys.stdin], [], [], 0.03)
        if not r2:
            return "ESC"
        b2 = os.read(sys.stdin.fileno(), 1)
        if not b2:
            return "ESC"
        if b2 == b"[":
            seq_bytes = bytearray(b2)
            for _ in range(16):
                rn, _, _ = select.select([sys.stdin], [], [], 0.02)
                if not rn:
                    break
                bn = os.read(sys.stdin.fileno(), 1)
                if not bn:
                    break
                seq_bytes.extend(bn)
                if 0x40 <= bn[0] <= 0x7E:
                    break
            seq = seq_bytes.decode("utf-8", errors="ignore")
            if seq == "[A":
                return "UP"
            if seq == "[B":
                return "DOWN"
            return "ESC"
        if b2 == b"O":
            rn, _, _ = select.select([sys.stdin], [], [], 0.02)
            if rn:
                bn = os.read(sys.stdin.fileno(), 1)
                if bn == b"A":
                    return "UP"
                if bn == b"B":
                    return "DOWN"
            return "ESC"
        return "ESC"
    return ch


def _prompt_line(prompt_text: str, old_termios: Any) -> str:
    """Temporarily restore normal cooked terminal mode to read one command line."""
    fd = sys.stdin.fileno()
    if termios is not None and old_termios is not None:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_termios)
    sys.stdout.write("\033[?25h\n" + prompt_text)
    sys.stdout.flush()
    try:
        ans = sys.stdin.readline().strip()
    except KeyboardInterrupt:
        ans = ""
    finally:
        if tty is not None:
            tty.setcbreak(fd)
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
    return ans


def run_top_tui(
    controller: MasterController,
    refresh_sec: float = 2.0,
    once: bool = False,
) -> int:
    """Launch the interactive multi-device btop Terminal Control UI."""
    if once or not sys.stdin.isatty() or not sys.stdout.isatty() or termios is None or tty is None:
        summary = controller.cluster_summary()
        all_jobs = controller.get_all_jobs()
        frame = render_top_frame(
            summary=summary,
            history=controller.metrics_history.snapshot(),
            all_jobs=all_jobs,
            refresh_sec=refresh_sec,
            use_color=sys.stdout.isatty(),
        )
        print(frame)
        return 0

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    selected_idx = 0
    view_mode = "tasks"
    pool_filter = "all"
    paused = False
    last_banner = ""
    speed = max(0.5, refresh_sec)

    summary = controller.cluster_summary()
    all_jobs = controller.get_all_jobs()
    last_poll = time.monotonic()

    stop_requested = False
    prev_handlers: dict[int, Any] = {}

    def _on_stop_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    for sig_name in ("SIGTERM", "SIGHUP"):
        sig_num = getattr(signal, sig_name, None)
        if sig_num is not None:
            try:
                prev_handlers[sig_num] = signal.signal(sig_num, _on_stop_signal)
            except ValueError:
                pass  # Not on main thread

    try:
        tty.setcbreak(fd)
        sys.stdout.write("\033[?1049h\033[?25l")
        sys.stdout.flush()

        while not stop_requested:
            now = time.monotonic()
            if not paused and (now - last_poll >= speed):
                summary = controller.cluster_summary()
                all_jobs = controller.get_all_jobs()
                last_poll = now

            all_nodes = summary.get("nodes", [])
            nodes = (
                [n for n in all_nodes if str(n.get("pool", "")) == pool_filter]
                if pool_filter != "all"
                else all_nodes
            )
            if nodes:
                selected_idx = max(0, min(selected_idx, len(nodes) - 1))

            frame = render_top_frame(
                summary=summary,
                history=controller.metrics_history.snapshot(),
                all_jobs=all_jobs,
                selected_idx=selected_idx,
                view_mode=view_mode,
                refresh_sec=speed,
                paused=paused,
                last_command_banner=last_banner,
                use_color=True,
                pool_filter=pool_filter,
            )
            sys.stdout.write("\033[H\033[J" + frame)
            sys.stdout.flush()

            wait_t = 0.25 if paused else min(0.25, max(0.05, speed - (time.monotonic() - last_poll)))
            key = _read_key(wait_t)
            if key is None:
                continue

            if key in {"q", "Q", "\x03", "EOF"}:
                break
            elif key in {"UP", "k"}:
                if nodes:
                    selected_idx = (selected_idx - 1) % len(nodes)
            elif key in {"DOWN", "j"}:
                if nodes:
                    selected_idx = (selected_idx + 1) % len(nodes)
            elif key == " ":
                paused = not paused
            elif key in {"d", "D"}:
                view_mode = "procs" if view_mode == "tasks" else "tasks"
            elif key in {"p", "P"}:
                avail_pools = ["all"] + sorted({str(n.get("pool", "compute")) for n in all_nodes})
                cur_pos = avail_pools.index(pool_filter) if pool_filter in avail_pools else 0
                pool_filter = avail_pools[(cur_pos + 1) % len(avail_pools)]
                selected_idx = 0
            elif key == "+":
                speed = max(0.5, round(speed - 0.5, 1))
            elif key == "-":
                speed = min(15.0, round(speed + 0.5, 1))
            elif key in {"x", "X"} and all_nodes:
                cmd = _prompt_line("Auto-Route (Smart Tier)> ", old_settings)
                if cmd:
                    spec = JobSpec(index=0, job_id=f"auto-{int(time.time())}-{uuid.uuid4().hex[:6]}", command=cmd, timeout_sec=60.0)
                    outcomes = controller.run_single(spec, target="auto")
                    parts = []
                    for o in outcomes:
                        first_raw = (o.stdout.strip() or o.stderr.strip() or o.error or "(no output)").splitlines()[0]
                        first = _clean_term_text(first_raw, 80)
                        tier_tag = f"T{o.node_tier}:{o.node_pool}" if o.node_tier else "none"
                        status_str = "OK" if o.ok else "FAIL"
                        parts.append(
                            f"[{o.node_id} · {tier_tag}] {status_str} ({o.duration_sec:.2f}s) — {_clean_term_text(o.routing_reason, 60)}\n  {first}"
                        )
                    last_banner = "\n".join(parts)
                    last_poll = 0.0
            elif key in {"r", "R", "a", "A"} and nodes:
                target = "all" if key in {"a", "A"} else nodes[selected_idx]["id"]
                cmd = _prompt_line(f"Run on [{target}]> ", old_settings)
                if cmd:
                    spec = JobSpec(index=0, job_id=f"top-{int(time.time())}-{uuid.uuid4().hex[:6]}", command=cmd, timeout_sec=60.0)
                    outcomes = controller.run_single(spec, target=target)
                    parts = []
                    for o in outcomes:
                        first_raw = (o.stdout.strip() or o.stderr.strip() or o.error or "(no output)").splitlines()[0]
                        first = _clean_term_text(first_raw, 80)
                        tier_tag = f"T{o.node_tier}:{o.node_pool}" if o.node_tier else ""
                        status_str = "OK" if o.ok else "FAIL"
                        parts.append(f"[{o.node_id} {tier_tag}] {status_str} ({o.duration_sec:.2f}s): {first}")
                    last_banner = "\n".join(parts)
                    last_poll = 0.0  # force immediate refresh
            elif key in {"c", "C"} and nodes:
                sel_id = nodes[selected_idx]["id"]
                node_entry = next((n for n in all_jobs if n.get("node_id") == sel_id), None)
                active = (node_entry or {}).get("active") or []
                first_act = active[0] if (isinstance(active, list) and active and isinstance(active[0], dict)) else None
                jid = str(first_act.get("job_id") or "") if first_act else ""
                if jid:
                    try:
                        res = controller.cancel_node_job(sel_id, jid)
                        last_banner = f"Cancel {_clean_term_text(jid, 32)} on {sel_id}: {'OK' if res.get('cancelled') else _clean_term_text(res.get('error', ''), 80)}"
                    except KeyError as exc:
                        last_banner = f"Cancel failed: {exc}"
                    last_poll = 0.0
                else:
                    last_banner = f"No running job on {sel_id} to cancel."
            elif key in {"s", "S"} and nodes:
                try:
                    sel_node = controller.config.get_node(nodes[selected_idx]["id"])
                except KeyError as exc:
                    last_banner = f"SSH failed: {exc}"
                    continue
                target_ssh = f"{sel_node.ssh_user}@{sel_node.host}" if sel_node.ssh_user else sel_node.host
                # Temporarily exit alternate screen for clean interactive SSH session
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                sys.stdout.write("\033[?25h\033[?1049l")
                sys.stdout.flush()
                try:
                    subprocess.call(["ssh", "-p", str(sel_node.ssh_port), "--", target_ssh])
                except OSError as exc:
                    last_banner = f"SSH failed: {exc}"
                finally:
                    tty.setcbreak(fd)
                    sys.stdout.write("\033[?1049h\033[?25l")
                    sys.stdout.flush()
                last_poll = 0.0
    except KeyboardInterrupt:
        pass
    finally:
        for sig_num, old_h in prev_handlers.items():
            try:
                signal.signal(sig_num, old_h)
            except ValueError:
                pass
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except (OSError, termios.error):
            pass
        try:
            sys.stdout.write("\033[?25h\033[?1049l")
            sys.stdout.flush()
        except OSError:
            pass
    return 0
