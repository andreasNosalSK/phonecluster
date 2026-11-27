"""USB 3.0 Hub networking & zero-Wi-Fi phone-to-phone routing for PhoneCluster.

Supports two proven multi-phone USB hub topologies (for 2–6+ phones plugged into
a powered USB 3.0 hub connected to a Master Host such as a Raspberry Pi or Linux PC):

1. **ADB USB Hub Mesh (`mode="adb"`, zero root):**
   - Uses each phone's unique USB serial (`adb devices`) — zero IP/subnet collisions.
   - Maps unique local Master ports (`127.0.0.1:18761..18766`) -> each phone's `:8765`
     worker daemon and (`127.0.0.1:18021..18026`) -> SSH (`8022` or `22`).
   - Optionally sets up `adb reverse` for Master's Network Guard proxy (`:8888`) and
     a **phone-to-phone USB peer service mesh** (`adb forward` + `adb reverse`) so
     phones reach each other's `distcc`, `llama-rpc`, `mqtt`, or `llama-api` ports
     purely over USB with Wi-Fi turned OFF.

2. **Layer-3 IP-over-USB `/30` Subnet Router (`mode="rndis"`, Ubuntu Touch & Linux/Docker):**
   - Solves the classic RNDIS/CDC-ECM collision where every Ubuntu Touch phone claims
     `10.15.19.82/24` (or Android claims `192.168.42.129/24`).
   - Assigns each phone (stably sorted by MAC address) its own dedicated `/30` subnet
     (`10.77.<k>.1/30` on Master host, `10.77.<k>.2/30` on Phone `<k>`), enables
     scoped `10.77.0.0/16 <-> 10.77.0.0/16` IPv4 forwarding on Master, and keeps
     phones air-gapped from WAN by default. Full IP/UDP/TCP works over USB — including
     Snap Docker containers, Docker Swarm, OpenMPI, and Cross-Tier Service Mesh!
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .config import (
    AdbNodeConfig,
    ClusterConfig,
    NodeConfig,
    is_loopback_or_unspecified_host,
    load_config,
    validate_ssh_user,
)

LOG = logging.getLogger("phonecluster.usbhub")

SYS_NET_DIR = Path("/sys/class/net")
IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")

DEFAULT_USB_SUBNET_PREFIX = "10.77"
DEFAULT_ADB_WORKER_BASE_PORT = 18760
DEFAULT_ADB_SSH_BASE_PORT = 18020
DEFAULT_ADB_MESH_BASE_PORT = 25000
USB_MESH_DEFAULT_PORTS: tuple[int, ...] = (3632, 50052, 8081, 1883, 8123)

_SAFE_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
_SAFE_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_SAFE_PREFIX_RE = re.compile(r"^(?:10\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)$")
# Restrict to phone USB gadget drivers (exclude host USB-Ethernet LAN/WAN dongles like r8152/asix/ax88179/smsc95xx)
_USB_NET_DRIVERS = frozenset({"rndis_host", "cdc_ether", "cdc_ncm", "cdc_eem", "ipheth"})


def validate_usb_serial(serial: str) -> str:
    clean = str(serial or "").strip()
    if not clean or clean.startswith("-") or not _SAFE_SERIAL_RE.fullmatch(clean):
        raise ValueError(f"Invalid USB/ADB device serial: {serial!r}")
    return clean


def validate_iface_name(iface: str) -> str:
    clean = str(iface or "").strip()
    if not clean or clean.startswith("-") or not _SAFE_IFACE_RE.fullmatch(clean):
        raise ValueError(f"Invalid network interface name: {iface!r}")
    return clean


def validate_subnet_prefix(prefix: str) -> str:
    """Validate an RFC1918 `/16` prefix such as `10.77`, `172.30`, or `192.168`."""
    clean = str(prefix or "").strip().rstrip(".")
    if not _SAFE_PREFIX_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid private /16 subnet prefix {prefix!r} (use e.g. '10.77', '172.30', or '192.168')"
        )
    return clean


def list_adb_devices(
    adb_bin: str | None = None,
    timeout_sec: float = 5.0,
) -> list[dict[str, str]]:
    """Return connected ADB devices parsed from `adb devices -l`."""
    cmd = adb_bin or shutil.which("adb")
    if not cmd:
        return []
    try:
        out = subprocess.check_output(
            [cmd, "devices", "-l"],
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec,
        ).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError):
        return []

    devices: list[dict[str, str]] = []
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("list of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if not _SAFE_SERIAL_RE.fullmatch(serial) or serial.startswith("-"):
            continue
        meta: dict[str, str] = {}
        for tok in parts[2:]:
            if ":" in tok:
                k, v = tok.split(":", 1)
                meta[k.strip().lower()] = v.strip()
        devices.append(
            {
                "serial": serial,
                "state": state,
                "model": meta.get("model", ""),
                "device": meta.get("device", ""),
                "product": meta.get("product", ""),
                "transport_id": meta.get("transport_id", ""),
            }
        )
    devices.sort(key=lambda d: d["serial"])
    return devices


def _read_iface_ipv4s(iface: str) -> list[str]:
    """Return IPv4 CIDR strings configured on `iface` via `ip -4 -o addr show`."""
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return []
    try:
        out = subprocess.check_output(
            [ip_bin, "-4", "-o", "addr", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError):
        return []
    cidrs: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet")
            if idx + 1 < len(parts):
                cidrs.append(parts[idx + 1])
    return cidrs


def _default_route_ifaces() -> set[str]:
    """Return interface names currently holding a default route so USB setup never hijacks host uplink."""
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return set()
    ifaces: set[str] = set()
    for family in ("-4", "-6"):
        try:
            out = subprocess.check_output(
                [ip_bin, family, "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            ).decode("utf-8", errors="replace")
        except (subprocess.SubprocessError, OSError):
            continue
        for line in out.splitlines():
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok == "dev" and i + 1 < len(parts):
                    ifaces.add(parts[i + 1])
    return ifaces


def list_usb_net_interfaces(
    sys_net_dir: Path = SYS_NET_DIR,
    include_ips: bool = True,
    exclude_default_route: bool | None = None,
) -> list[dict[str, Any]]:
    """Detect USB-Ethernet / RNDIS / CDC-ECM / CDC-NCM gadget interfaces on this Linux host."""
    if not sys_net_dir.is_dir():
        return []
    found: list[dict[str, Any]] = []
    should_exclude_uplink = (sys_net_dir == SYS_NET_DIR) if exclude_default_route is None else bool(exclude_default_route)
    uplink_ifaces = _default_route_ifaces() if should_exclude_uplink else set()
    try:
        entries = sorted(sys_net_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return []

    for entry in entries:
        name = entry.name
        if name == "lo" or name in uplink_ifaces or not _SAFE_IFACE_RE.fullmatch(name):
            continue
        is_usb = name.startswith(("usb", "rndis"))
        driver_name = ""
        dev_link = entry / "device"
        if dev_link.exists():
            try:
                drv_link = dev_link / "driver"
                if drv_link.exists():
                    driver_name = drv_link.resolve().name
                    if driver_name in _USB_NET_DRIVERS:
                        is_usb = True
            except OSError:
                pass
        if not is_usb:
            continue

        mac = ""
        operstate = "unknown"
        try:
            mac = (entry / "address").read_text(encoding="utf-8", errors="ignore").strip().lower()
        except OSError:
            pass
        try:
            operstate = (entry / "operstate").read_text(encoding="utf-8", errors="ignore").strip().lower()
        except OSError:
            pass
        ipv4_cidrs = _read_iface_ipv4s(name) if include_ips else []
        found.append(
            {
                "iface": name,
                "mac": mac,
                "driver": driver_name or "usb",
                "operstate": operstate,
                "ipv4_cidrs": ipv4_cidrs,
            }
        )
    # Sort deterministically by MAC address (then interface name) so plug order never shuffles node IDs
    found.sort(key=lambda item: (item["mac"] or "zz", item["iface"]))
    return found


def detect_subnet_collisions(interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify identical or overlapping IPv4 subnets across multiple distinct USB gadget interfaces."""
    iface_nets: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for item in interfaces:
        iface = str(item.get("iface") or "").strip()
        if not iface:
            continue
        for cidr in item.get("ipv4_cidrs") or []:
            try:
                net = ipaddress.ip_interface(cidr).network
            except ValueError:
                continue
            key = (iface, str(net))
            if key not in seen_pairs:
                seen_pairs.add(key)
                iface_nets.append((iface, net))

    grouped: dict[str, set[str]] = {}
    for i, (if_a, net_a) in enumerate(iface_nets):
        for if_b, net_b in iface_nets[i + 1 :]:
            if if_a == if_b or net_a.version != net_b.version:
                continue
            if net_a.overlaps(net_b):
                # Key by the broader overlapping prefix so exact duplicates and supernet overlaps merge cleanly
                rep = str(net_a if net_a.prefixlen <= net_b.prefixlen else net_b)
                grouped.setdefault(rep, set()).update((if_a, if_b))

    collisions: list[dict[str, Any]] = []
    for net_str, ifaces in sorted(grouped.items()):
        if len(ifaces) > 1:
            collisions.append({"subnet": net_str, "interfaces": sorted(ifaces)})
    return collisions


def read_ipv4_forwarding_enabled(path: Path = IP_FORWARD_PATH) -> bool:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip() == "1"
    except OSError:
        return False


def detect_usb_hub_topology(
    sys_net_dir: Path = SYS_NET_DIR,
    adb_bin: str | None = None,
) -> dict[str, Any]:
    """Inspect all USB-connected phones (both ADB and USB-Ethernet/RNDIS) on this host."""
    adb_devs = list_adb_devices(adb_bin=adb_bin)
    usb_ifaces = list_usb_net_interfaces(sys_net_dir=sys_net_dir)
    collisions = detect_subnet_collisions(usb_ifaces)
    ip_fwd = read_ipv4_forwarding_enabled()
    ready_adb = [d for d in adb_devs if d.get("state") == "device"]
    unauthorized_adb = [d for d in adb_devs if d.get("state") != "device"]

    if usb_ifaces and not ready_adb:
        recommended = "rndis"
    elif ready_adb and not usb_ifaces:
        recommended = "adb"
    elif usb_ifaces and ready_adb:
        recommended = "rndis"  # True L3 IP supports Docker Swarm, OpenMPI, and direct phone-to-phone traffic
    else:
        recommended = "adb"

    notes: list[str] = []
    if collisions:
        notes.append(
            "Overlapping USB tethering subnet(s) detected — run `sudo bash scripts/07_usb_hub_router.sh setup-rndis` "
            "to assign dedicated non-colliding /30 subnets (10.77.<k>.0/30) per phone."
        )
    if usb_ifaces and not ip_fwd:
        notes.append(
            "Kernel IPv4 forwarding is OFF (`/proc/sys/net/ipv4/ip_forward = 0`): phones cannot reach each other "
            "through the USB host until enabled via `07_usb_hub_router.sh setup-rndis`."
        )
    if unauthorized_adb:
        notes.append(
            f"{len(unauthorized_adb)} ADB device(s) not authorized yet — unlock the phone screen and tap 'Allow USB debugging'."
        )

    return {
        "adb_installed": bool(adb_bin or shutil.which("adb")),
        "adb_devices": adb_devs,
        "adb_ready_count": len(ready_adb),
        "usb_net_interfaces": usb_ifaces,
        "usb_net_count": len(usb_ifaces),
        "subnet_collisions": collisions,
        "ipv4_forwarding_enabled": ip_fwd,
        "recommended_mode": recommended,
        "notes": notes,
    }


def plan_adb_usb_hub(
    devices: list[dict[str, str]],
    *,
    worker_base_port: int = DEFAULT_ADB_WORKER_BASE_PORT,
    ssh_base_port: int = DEFAULT_ADB_SSH_BASE_PORT,
    remote_worker_port: int = 8765,
    remote_ssh_port: int = 8022,
    gateway_port: int = 8888,
    enable_gateway_reverse: bool = True,
    enable_peer_mesh: bool = True,
    mesh_ports: tuple[int, ...] = USB_MESH_DEFAULT_PORTS,
    mesh_base_port: int = DEFAULT_ADB_MESH_BASE_PORT,
    node_prefix: str = "usb",
    existing_nodes: list[NodeConfig] | None = None,
    registered_only: bool = False,
    quarantined_nodes: set[str] | list[str] | None = None,
) -> dict[str, Any]:
    """Deterministically plan ADB USB-hub forwards, gateway reverses, and phone-to-phone mesh tunnels."""
    ready = [d for d in devices if str(d.get("state") or "device") == "device"]
    ready.sort(key=lambda d: str(d.get("serial") or ""))
    if len(ready) > 32:
        raise ValueError(f"Too many USB devices ({len(ready)}; maximum supported per hub plan is 32)")

    quarantined = set(quarantined_nodes or ())
    nodes_plan: list[dict[str, Any]] = []
    forward_rules: list[dict[str, Any]] = []
    reverse_rules: list[dict[str, Any]] = []
    quarantined_serials: list[str] = []
    peer_mesh_ports: dict[str, dict[int, int]] = {}  # owner_node_id -> {service_port: hub_local_port}

    clean_prefix = re.sub(r"[^A-Za-z0-9_-]+", "", node_prefix) or "usb"
    target_ports = tuple(dict.fromkeys(int(port) for port in mesh_ports if 1 <= int(port) <= 65535))
    if not (1 <= remote_worker_port <= 65535 and 1 <= remote_ssh_port <= 65535):
        raise ValueError("ADB device listener ports must be between 1 and 65535")
    if worker_base_port == ssh_base_port:
        raise ValueError("ADB worker and SSH forward port ranges need different bases")

    registered: dict[str, tuple[NodeConfig, AdbNodeConfig]] = {}
    occupied_ids: set[str] = set()
    occupied_ports: set[int] = set()
    if enable_gateway_reverse and not isinstance(gateway_port, bool) and 1 <= int(gateway_port) <= 65535:
        occupied_ports.add(int(gateway_port))
    for node in existing_nodes or []:
        occupied_ids.add(node.id)
        if is_loopback_or_unspecified_host(node.host):
            occupied_ports.update((node.worker_port, node.ssh_port))
        adb = node.adb
        if adb is None and "usb-mode:adb" in node.tags:
            # Older versions recorded the serial as a tag. Preserve that
            # assignment when the legacy inventory has one unambiguous serial.
            legacy_serials = {tag.split(":", 1)[1] for tag in node.tags if tag.startswith("usb-serial:")}
            slot = re.fullmatch(re.escape(clean_prefix) + r"([1-9][0-9]*)", node.id)
            if len(legacy_serials) != 1 or slot is None:
                raise ValueError(f"Ambiguous legacy ADB mapping for {node.id}; check its USB serial before setup")
            adb = AdbNodeConfig(
                validate_usb_serial(legacy_serials.pop()), remote_worker_port, remote_ssh_port,
                mesh_base_port + (int(slot[1]) - 1) * len(target_ports),
            )
        if adb is not None:
            if node.role != "worker" or not is_loopback_or_unspecified_host(node.host):
                raise ValueError(f"ADB transport requires a loopback worker endpoint for {node.id}")
            if adb.serial in registered:
                raise ValueError(f"ADB serial {adb.serial} belongs to multiple nodes")
            registered[adb.serial] = (node, adb)
            occupied_ports.update(range(adb.mesh_base_port, adb.mesh_base_port + len(target_ports)))

    revoked_forwards: list[dict[str, Any]] = []
    revoked_mesh_ports: list[int] = []
    idx = 0
    seen_serials: set[str] = set()
    for dev in ready:
        serial = validate_usb_serial(dev["serial"])
        if serial in seen_serials:
            continue
        seen_serials.add(serial)
        previous = registered.get(serial)
        if previous is not None:
            node, prev_adb = previous
            node_id, local_w_port, local_s_port = node.id, node.worker_port, node.ssh_port
            eff_w_port = prev_adb.remote_worker_port
            raw_dw = dev.get("remote_worker_port")
            if isinstance(raw_dw, int) and not isinstance(raw_dw, bool) and 1 <= raw_dw <= 65535:
                eff_w_port = raw_dw
            eff_s_port = prev_adb.remote_ssh_port
            raw_ds = dev.get("remote_ssh_port")
            if isinstance(raw_ds, int) and not isinstance(raw_ds, bool) and 1 <= raw_ds <= 65535:
                eff_s_port = raw_ds
            adb = AdbNodeConfig(
                prev_adb.serial,
                eff_w_port,
                eff_s_port,
                prev_adb.mesh_base_port,
                prev_adb.peer_mesh,
            )
        elif registered_only:
            continue
        else:
            while True:
                idx += 1
                node_id = f"{clean_prefix}{idx}"
                local_w_port, local_s_port = worker_base_port + idx, ssh_base_port + idx
                start = mesh_base_port + (idx - 1) * max(1, len(target_ports))
                if not (1024 <= min(local_w_port, local_s_port, start)
                        and max(local_w_port, local_s_port, start + max(0, len(target_ports) - 1)) <= 65535):
                    raise ValueError("Ran out of valid ADB forward ports")
                slot_ports = {local_w_port, local_s_port, *range(start, start + len(target_ports))}
                if len(slot_ports) != len(target_ports) + 2:
                    raise ValueError("ADB worker, SSH, and service ports overlap")
                if node_id not in occupied_ids and not (slot_ports & occupied_ports):
                    occupied_ports.update(slot_ports)
                    break
            dev_w_port = remote_worker_port
            raw_dw = dev.get("remote_worker_port")
            if isinstance(raw_dw, int) and not isinstance(raw_dw, bool) and 1 <= raw_dw <= 65535:
                dev_w_port = raw_dw
            dev_s_port = remote_ssh_port
            raw_ds = dev.get("remote_ssh_port")
            if isinstance(raw_ds, int) and not isinstance(raw_ds, bool) and 1 <= raw_ds <= 65535:
                dev_s_port = raw_ds
            adb = AdbNodeConfig(serial, dev_w_port, dev_s_port, start, enable_peer_mesh)

        is_quarantined = node_id in quarantined
        if is_quarantined:
            quarantined_serials.append(serial)
            for offset, sp in enumerate(target_ports):
                hp = adb.mesh_base_port + offset
                if 1024 <= hp <= 65535:
                    revoked_mesh_ports.append(hp)
                    revoked_forwards.append(
                        {"serial": serial, "node_id": node_id, "local_port": hp, "remote_port": sp}
                    )
        peer_mesh = (not is_quarantined) and enable_peer_mesh and (adb.peer_mesh or not registered_only)

        entry: dict[str, Any] = {
            "node_id": node_id,
            "serial": serial,
            "model": str(dev.get("model") or ""),
            "host": "127.0.0.1",
            "worker_port": local_w_port,
            "ssh_port": local_s_port,
            "remote_worker_port": adb.remote_worker_port,
            "remote_ssh_port": adb.remote_ssh_port,
            "mesh_base_port": adb.mesh_base_port,
            "peer_mesh": peer_mesh,
        }
        raw_user = str(dev.get("ssh_user") or "").strip()
        if raw_user:
            try:
                clean_u = validate_ssh_user(raw_user)
                if clean_u:
                    entry["ssh_user"] = clean_u
            except ValueError:
                pass
        if dev.get("os_env"):
            entry["os_env"] = str(dev["os_env"])[:48]
        nodes_plan.append(entry)
        forward_rules.append(
            {"serial": serial, "node_id": node_id, "local_port": local_w_port, "remote_port": adb.remote_worker_port, "label": "worker"}
        )
        forward_rules.append(
            {"serial": serial, "node_id": node_id, "local_port": local_s_port, "remote_port": adb.remote_ssh_port, "label": "ssh"}
        )
        if not is_quarantined and enable_gateway_reverse and 1 <= int(gateway_port) <= 65535:
            reverse_rules.append(
                {
                    "serial": serial,
                    "node_id": node_id,
                    "remote_port": int(gateway_port),
                    "local_port": int(gateway_port),
                    "label": "network-guard-gateway",
                }
            )
        if peer_mesh:
            svc_map: dict[int, int] = {}
            for offset, sp in enumerate(target_ports):
                hub_port = adb.mesh_base_port + offset
                if not 1024 <= hub_port <= 65535:
                    raise ValueError("Ran out of TCP ports while planning USB peer mesh")
                if enable_gateway_reverse and hub_port == gateway_port:
                    raise ValueError("ADB peer mesh conflicts with the Network Guard reverse port")
                svc_map[sp] = hub_port
                forward_rules.append(
                    {
                        "serial": serial,
                        "node_id": node_id,
                        "local_port": hub_port,
                        "remote_port": sp,
                        "label": f"mesh-export:{sp}",
                    }
                )
            peer_mesh_ports[node_id] = svc_map

    # Complete phone-to-phone mesh: reverse every OTHER phone's exported mesh ports onto each phone!
    peer_mesh_map: dict[str, dict[str, dict[str, int]]] = {}
    if enable_peer_mesh and len(nodes_plan) >= 2:
        for dst in nodes_plan:
            if not dst["peer_mesh"]:
                continue
            dst_id = dst["node_id"]
            dst_serial = dst["serial"]
            peer_mesh_map[dst_id] = {}
            for src in nodes_plan:
                src_id = src["node_id"]
                if src_id == dst_id or not src["peer_mesh"]:
                    continue
                src_ports = peer_mesh_ports.get(src_id) or {}
                peer_mesh_map[dst_id][src_id] = {str(sp): hp for sp, hp in src_ports.items()}
                for sp, hp in src_ports.items():
                    reverse_rules.append(
                        {
                            "serial": dst_serial,
                            "node_id": dst_id,
                            "remote_port": hp,
                            "local_port": hp,
                            "label": f"mesh-peer:{src_id}:{sp}",
                        }
                    )

    revoked_reverses: list[dict[str, Any]] = []
    if revoked_mesh_ports:
        for dst in nodes_plan:
            if dst["node_id"] in quarantined:
                continue
            for hp in revoked_mesh_ports:
                revoked_reverses.append({"serial": dst["serial"], "node_id": dst["node_id"], "remote_port": hp})

    forward_ports = [rule["local_port"] for rule in forward_rules]
    if len(forward_ports) != len(set(forward_ports)):
        raise ValueError("ADB nodes have overlapping local forward ports")

    return {
        "mode": "adb",
        "nodes": nodes_plan,
        "forward_rules": forward_rules,
        "reverse_rules": reverse_rules,
        "peer_mesh_map": peer_mesh_map,
        "quarantined_serials": quarantined_serials,
        "revoked_forwards": revoked_forwards,
        "revoked_reverses": revoked_reverses,
    }


def revoke_adb_device_reverses(
    serial: str,
    *,
    adb_bin: str | None = None,
    timeout_sec: float = 5.0,
) -> tuple[bool, str]:
    """Immediately revoke all `adb reverse` tunnels on a quarantined USB phone."""
    cmd = adb_bin or shutil.which("adb")
    if not cmd:
        return False, "adb binary not found on PATH"
    try:
        clean_q = validate_usb_serial(str(serial))
        res = subprocess.run(
            [cmd, "-s", clean_q, "reverse", "--remove-all"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if res.returncode != 0:
            detail = (res.stderr or res.stdout or f"adb exit {res.returncode}").strip()[:120]
            return False, detail
        return True, "ok"
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return False, str(exc)[:120]


def apply_adb_usb_hub(
    plan: dict[str, Any],
    *,
    adb_bin: str | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Create missing ADB routes and preserve existing routes with other destinations."""
    cmd = adb_bin or shutil.which("adb")
    if not cmd:
        return {"ok": False, "error": "adb binary not found on PATH", "applied": 0, "unchanged": 0, "failed": 0, "errors": []}

    applied = 0
    unchanged = 0
    failed = 0
    errors: list[str] = []

    def run_adb(*args: str) -> str:
        result = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=timeout_sec)
        if result.returncode:
            detail = (result.stderr or result.stdout or f"adb exit {result.returncode}").strip()
            raise OSError(detail[:120])
        return result.stdout

    def list_active(direction: str, device: str | None = None) -> dict[str, tuple[str, str]]:
        scope = ["-s", device] if device is not None else []
        active: dict[str, tuple[str, str]] = {}
        for raw_line in run_adb(*scope, direction, "--list").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            owner, source, destination = parts[0], parts[1], parts[2].strip()
            if not source.startswith("tcp:"):
                continue
            # reverse --list is already scoped to this phone. The first field is its transport.
            target = (device or owner, destination)
            if source in active and active[source] != target:
                raise ValueError(f"ambiguous ADB route for {source}")
            active[source] = target
        return active

    def reconcile(direction: str, rules: list[dict[str, Any]], device: str | None = None) -> None:
        nonlocal applied, unchanged, failed
        if not rules:
            return
        try:
            active = list_active(direction, device=device)
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            failed += len(rules)
            label = f" for {device}" if device is not None else ""
            errors.append(f"Cannot inspect adb {direction} rules{label}: {exc}")
            return

        source_field, dest_field = ("local_port", "remote_port") if direction == "forward" else ("remote_port", "local_port")
        for rule in rules:
            serial = validate_usb_serial(rule["serial"])
            source = f"tcp:{int(rule[source_field])}"
            destination = f"tcp:{int(rule[dest_field])}"
            existing = active.get(source)
            if existing == (serial, destination):
                unchanged += 1
                continue
            if existing is not None:
                failed += 1
                errors.append(f"{direction} {serial} {source}->{destination}: occupied by {existing[0]} -> {existing[1]}")
                continue
            try:
                run_adb("-s", serial, direction, "--no-rebind", source, destination)
            except (subprocess.SubprocessError, OSError) as exc:
                failed += 1
                errors.append(f"{direction} {serial} {source}->{destination}: {exc}")
            else:
                applied += 1
                active[source] = (serial, destination)

    reconcile("forward", plan.get("forward_rules") or [])
    reverses: dict[str, list[dict[str, Any]]] = {}
    for rule in plan.get("reverse_rules") or []:
        serial = validate_usb_serial(rule["serial"])
        reverses.setdefault(serial, []).append(rule)
    for serial, rules in reverses.items():
        reconcile("reverse", rules, device=serial)

    # Actively revoke all reverse tunnels on quarantined USB devices so they cannot reach Master gateway or peer mesh
    for q_serial in plan.get("quarantined_serials") or []:
        ok_rev, rev_err = revoke_adb_device_reverses(str(q_serial), adb_bin=cmd, timeout_sec=timeout_sec)
        if not ok_rev:
            failed += 1
            errors.append(f"revoke reverse on quarantined {q_serial}: {rev_err}")

    # Actively sever quarantined nodes' mesh exports (forward) and sibling mesh reverses
    revoked_fwds = plan.get("revoked_forwards") or []
    if revoked_fwds:
        try:
            active_fwds = list_active("forward")
            for rf in revoked_fwds:
                src_spec = f"tcp:{int(rf['local_port'])}"
                if active_fwds.get(src_spec) is not None and active_fwds[src_spec][0] == str(rf["serial"]):
                    try:
                        run_adb("-s", validate_usb_serial(str(rf["serial"])), "forward", "--remove", src_spec)
                    except (subprocess.SubprocessError, OSError, ValueError) as exc:
                        failed += 1
                        errors.append(f"revoke forward {rf['serial']} {src_spec}: {exc}")
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            failed += 1
            errors.append(f"inspect forwards for quarantine revocation: {exc}")

    revoked_revs = plan.get("revoked_reverses") or []
    if revoked_revs:
        by_ser: dict[str, list[int]] = {}
        for rr in revoked_revs:
            try:
                ser = validate_usb_serial(str(rr["serial"]))
                by_ser.setdefault(ser, []).append(int(rr["remote_port"]))
            except (ValueError, TypeError):
                continue
        for ser, ports in by_ser.items():
            try:
                active_revs = list_active("reverse", device=ser)
            except (subprocess.SubprocessError, OSError, ValueError):
                continue
            for p in ports:
                r_spec = f"tcp:{p}"
                if r_spec in active_revs:
                    try:
                        run_adb("-s", ser, "reverse", "--remove", r_spec)
                    except (subprocess.SubprocessError, OSError) as exc:
                        failed += 1
                        errors.append(f"revoke peer reverse {ser} {r_spec}: {exc}")

    return {
        "ok": failed == 0,
        "applied": applied,
        "unchanged": unchanged,
        "failed": failed,
        "errors": errors[:32],
    }


def plan_rndis_usb_hub(
    interfaces: list[dict[str, Any]],
    *,
    subnet_prefix: str = DEFAULT_USB_SUBNET_PREFIX,
    worker_port: int = 8765,
    ssh_port: int = 22,
    ssh_user: str = "phablet",
    node_prefix: str = "usb",
    existing_nodes: list[NodeConfig] | None = None,
) -> dict[str, Any]:
    """Deterministically plan non-colliding `/30` subnets (`10.77.<k>.0/30`) for Layer-3 USB hub routing."""
    clean_prefix = validate_subnet_prefix(subnet_prefix)
    clean_node_prefix = re.sub(r"[^A-Za-z0-9_-]+", "", node_prefix) or "usb"
    sorted_ifaces = sorted(
        interfaces,
        key=lambda item: (str(item.get("mac") or "zz").lower(), str(item.get("iface") or "")),
    )
    if len(sorted_ifaces) > 62:
        raise ValueError(f"Too many USB interfaces ({len(sorted_ifaces)}; maximum supported per /16 plan is 62)")

    occupied_ids: set[str] = set()
    occupied_indices: set[int] = set()
    existing_by_iface: dict[str, NodeConfig] = {}
    prefix_dot = f"{clean_prefix}."
    for node in existing_nodes or []:
        occupied_ids.add(node.id)
        if node.adb is None and "usb-mode:rndis" in (node.tags or []):
            for t in node.tags:
                if t.startswith("usb-iface:"):
                    existing_by_iface[t.split(":", 1)[1]] = node
            if node.host.startswith(prefix_dot):
                parts = node.host.split(".")
                if len(parts) == 4 and parts[2].isdigit() and parts[3] == "2":
                    occupied_indices.add(int(parts[2]))

    next_idx = 1
    nodes_plan: list[dict[str, Any]] = []
    for item in sorted_ifaces:
        iface = validate_iface_name(str(item.get("iface") or ""))
        mac = str(item.get("mac") or "").strip().lower()
        prev = existing_by_iface.get(iface)
        idx: int | None = None
        node_id = ""
        if prev is not None and prev.host.startswith(prefix_dot):
            parts = prev.host.split(".")
            if len(parts) == 4 and parts[2].isdigit() and parts[3] == "2" and 1 <= int(parts[2]) <= 254:
                idx = int(parts[2])
                node_id = prev.id
        if idx is None:
            while next_idx <= 254 and (next_idx in occupied_indices or f"{clean_node_prefix}{next_idx}" in occupied_ids):
                next_idx += 1
            if next_idx > 254:
                raise ValueError("Ran out of /30 USB subnets in /16 prefix")
            idx = next_idx
            node_id = f"{clean_node_prefix}{idx}"
            occupied_indices.add(idx)
            occupied_ids.add(node_id)
            next_idx += 1
        subnet = f"{clean_prefix}.{idx}.0/30"
        host_ip = f"{clean_prefix}.{idx}.1"
        phone_ip = f"{clean_prefix}.{idx}.2"
        nodes_plan.append(
            {
                "index": idx,
                "node_id": node_id,
                "iface": iface,
                "mac": mac,
                "driver": str(item.get("driver") or "usb"),
                "subnet": subnet,
                "host_ip": host_ip,
                "phone_ip": phone_ip,
                "host": phone_ip,
                "worker_port": int(prev.worker_port) if prev is not None else int(worker_port),
                "ssh_port": int(prev.ssh_port) if prev is not None else int(ssh_port),
                "ssh_user": prev.ssh_user if (prev is not None and prev.ssh_user) else ssh_user,
            }
        )
    return {
        "mode": "rndis",
        "subnet_prefix": clean_prefix,
        "cluster_cidr": f"{clean_prefix}.0.0/16",
        "nodes": nodes_plan,
    }


def build_rndis_router_commands(
    plan: dict[str, Any],
    *,
    nat_wan: bool = False,
    wan_iface: str = "",
    gateway_port: int = 8888,
    dual_plane: bool = False,
) -> dict[str, Any]:
    """Build explicit, idempotent Linux host & phone commands for Layer-3 USB hub phone-to-phone routing."""
    cluster_cidr = str(plan.get("cluster_cidr") or f"{DEFAULT_USB_SUBNET_PREFIX}.0.0/16")
    gw_port = int(gateway_port) if 1 <= int(gateway_port) <= 65535 else 8888
    rp_mode = 2 if dual_plane else 1
    dp_flag = " --dual-plane" if dual_plane else ""
    nodes = list(plan.get("nodes") or [])
    host_cmds: list[str] = [
        "# 1. Enable kernel IPv4 forwarding so USB phones talk to each other through Master Host",
        "sudo sysctl -w net.ipv4.ip_forward=1",
    ]
    phone_cmds: dict[str, list[str]] = {}

    for n in nodes:
        iface = validate_iface_name(str(n["iface"]))
        host_ip = str(n["host_ip"])
        phone_ip = str(n["phone_ip"])
        idx = int(n["index"])
        host_cmds.extend(
            [
                f"# Phone {idx} ({n['node_id']}, mac={n.get('mac') or 'unknown'}) on {iface}",
                f"sudo nmcli dev set {iface} managed no 2>/dev/null || true",
                f"sudo sysctl -w net.ipv6.conf.{iface}.disable_ipv6=1 net.ipv6.conf.{iface}.accept_ra=0 net.ipv4.conf.{iface}.rp_filter={rp_mode}",
                f"sudo ip addr flush dev {iface}",
                f"sudo ip addr add {host_ip}/30 dev {iface}",
                f"sudo ip link set {iface} up",
            ]
        )
        route_suffix = " metric 200" if dual_plane else ""
        phone_cmds[str(n["node_id"])] = [
            f"# Run on {n['node_id']} (Ubuntu Touch / Linux phone) — or run: bash scripts/07_usb_hub_router.sh phone-setup {idx}{dp_flag}",
            f"sudo bash ~/phonecluster/scripts/07_usb_hub_router.sh phone-setup {idx} --prefix {plan['subnet_prefix']}{dp_flag}",
            f"# Equivalent manual commands (assigns {phone_ip}/30 and routes {cluster_cidr} via {host_ip}):",
            f"sudo ip addr flush dev rndis0 2>/dev/null || sudo ip addr flush dev usb0",
            f"sudo ip addr add {phone_ip}/30 dev rndis0 2>/dev/null || sudo ip addr add {phone_ip}/30 dev usb0",
            f"sudo ip route replace {cluster_cidr} via {host_ip}{route_suffix}",
        ]

    host_cmds.extend(
        [
            "# 2. Enforce strict USB hub FORWARD & INPUT air-gap (phone-to-phone only; block LAN/WAN/host admin pivot)",
            f"sudo iptables -C FORWARD -s {cluster_cidr} -d {cluster_cidr} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD 1 -s {cluster_cidr} -d {cluster_cidr} -j ACCEPT",
        ]
    )
    clean_wan = validate_iface_name(wan_iface) if (nat_wan and wan_iface) else ""
    if nat_wan and clean_wan:
        host_cmds.append(
            f"sudo iptables -t nat -C POSTROUTING -s {cluster_cidr} -o {clean_wan} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {cluster_cidr} -o {clean_wan} -j MASQUERADE"
        )
        # Block RFC1918 / CGNAT / link-local home LAN pivots on clean_wan before allowing WAN egress
        pos = 2
        for priv_net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"):
            host_cmds.append(
                f"sudo iptables -C FORWARD -s {cluster_cidr} -d {priv_net} -o {clean_wan} -j DROP 2>/dev/null || "
                f"sudo iptables -I FORWARD {pos} -s {cluster_cidr} -d {priv_net} -o {clean_wan} -j DROP"
            )
            pos += 1
        host_cmds.append(
            f"sudo iptables -C FORWARD -s {cluster_cidr} -o {clean_wan} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD {pos} -s {cluster_cidr} -o {clean_wan} -j ACCEPT"
        )
        pos += 1
        host_cmds.append(
            f"sudo iptables -C FORWARD -i {clean_wan} -d {cluster_cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD {pos} -i {clean_wan} -d {cluster_cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        )
        pos += 1
        host_cmds.append(
            f"sudo iptables -C FORWARD -s {cluster_cidr} ! -d {cluster_cidr} ! -o {clean_wan} -j DROP 2>/dev/null || "
            f"sudo iptables -I FORWARD {pos} -s {cluster_cidr} ! -d {cluster_cidr} ! -o {clean_wan} -j DROP"
        )
    else:
        host_cmds.append(
            f"sudo iptables -C FORWARD -s {cluster_cidr} ! -d {cluster_cidr} -j DROP 2>/dev/null || "
            f"sudo iptables -I FORWARD 2 -s {cluster_cidr} ! -d {cluster_cidr} -j DROP"
        )
    for n in nodes:
        iface = validate_iface_name(str(n["iface"]))
        host_ip = str(n["host_ip"])
        phone_ip = str(n["phone_ip"])
        host_cmds.extend(
            [
                f"sudo iptables -C FORWARD -i {iface} ! -s {phone_ip}/32 -j DROP 2>/dev/null || sudo iptables -I FORWARD 1 -i {iface} ! -s {phone_ip}/32 -j DROP",
                f"sudo iptables -C INPUT -i {iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 1 -i {iface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                f"sudo iptables -C INPUT -i {iface} -s {phone_ip}/32 -d {host_ip}/32 -p tcp --dport {gw_port} -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 2 -i {iface} -s {phone_ip}/32 -d {host_ip}/32 -p tcp --dport {gw_port} -j ACCEPT",
                f"sudo iptables -C INPUT -i {iface} -s {phone_ip}/32 -d {host_ip}/32 -p icmp -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 3 -i {iface} -s {phone_ip}/32 -d {host_ip}/32 -p icmp -j ACCEPT",
                f"sudo iptables -C INPUT -i {iface} -j DROP 2>/dev/null || sudo iptables -I INPUT 4 -i {iface} -j DROP",
            ]
        )
    return {
        "cluster_cidr": cluster_cidr,
        "host_commands": host_cmds,
        "phone_commands": phone_cmds,
    }


def sync_usb_hub_into_config(
    config: ClusterConfig,
    plan: dict[str, Any],
    *,
    default_tier: int = 0,
    default_pool: str = "auto",
    preserve_wifi: bool = True,
) -> list[str]:
    """Merge planned USB-hub worker nodes into `config` (preserving existing per-node tokens and Wi-Fi data hosts)."""
    mode = str(plan.get("mode") or "adb")
    updated_ids: list[str] = []
    by_id = {n.id: n for n in config.nodes}

    for item in plan.get("nodes") or []:
        nid = str(item["node_id"])
        host = str(item["host"])
        w_port = int(item["worker_port"])
        s_port = int(item.get("ssh_port", 22 if mode == "rndis" else 8022))
        s_user = str(item.get("ssh_user", ""))
        tags = ["worker", "usb-hub", f"usb-mode:{mode}"]
        if item.get("serial"):
            tags.append(f"usb-serial:{item['serial']}")
        if item.get("iface"):
            tags.append(f"usb-iface:{item['iface']}")
        adb = (
            AdbNodeConfig.from_dict(item)
            if mode == "adb" and item.get("serial")
            else None
        )

        existing = by_id.get(nid)
        if existing is not None:
            if existing.role == "master":
                raise ValueError(f"USB plan cannot overwrite master node '{nid}'")
            if existing.adb is not None and (adb is None or existing.adb.serial != adb.serial):
                raise ValueError(f"USB plan would reassign {nid} to another device")
            # Preserve an existing LAN/Wi-Fi host as `wifi_host` for Dual-Plane Split when attaching USB
            if preserve_wifi and not existing.wifi_host and not existing.is_usb_primary() and not is_loopback_or_unspecified_host(existing.host):
                existing.wifi_host = existing.host
                if existing.worker_port > 0 and existing.worker_port != w_port:
                    existing.wifi_worker_port = existing.worker_port
            existing.host = host
            existing.usb_host = host
            existing.worker_port = w_port
            existing.ssh_port = s_port
            existing.adb = adb
            if s_user and not existing.ssh_user:
                existing.ssh_user = s_user
            # Remove stale transport-specific tags before adding current mode/iface/serial tags
            existing.tags = [
                t for t in existing.tags
                if not t.startswith(("usb-mode:", "usb-iface:", "usb-serial:"))
            ]
            for t in tags:
                if t not in existing.tags:
                    existing.tags.append(t)
            if not existing.auth_token and existing.role != "master":
                existing.auth_token = secrets.token_urlsafe(32)
        else:
            node = NodeConfig(
                id=nid,
                host=host,
                role="worker",
                worker_port=w_port,
                ssh_port=s_port,
                ssh_user=s_user,
                max_concurrency=2,
                weight=1.0,
                tier=default_tier,
                pool=default_pool,
                tags=tags,
                notes=f"USB 3.0 Hub worker ({mode})",
                auth_token=secrets.token_urlsafe(32),
                adb=adb,
                usb_host=host,
            )
            config.nodes.append(node)
            by_id[nid] = node
        updated_ids.append(nid)

    # Allow ONLY Master's /30 host IPs (NEVER the whole /16 phone subnet!) when enforce_worker_source_ip is ON
    if mode == "rndis":
        for item in plan.get("nodes") or []:
            h_ip = str(item.get("host_ip") or "").strip()
            if h_ip and h_ip not in config.network.allowed_master_ips:
                config.network.allowed_master_ips.append(h_ip)
    elif mode == "adb":
        for item in plan.get("nodes") or []:
            h = str(item.get("host") or "")
            if h and not is_loopback_or_unspecified_host(h) and h not in config.network.allowed_master_ips:
                config.network.allowed_master_ips.append(h)

    return updated_ids


class UsbHubWatchdog(threading.Thread):
    """Background watchdog keeping ADB USB-hub forwards & peer-mesh reverses alive across reconnects."""

    def __init__(
        self,
        *,
        interval_sec: float = 5.0,
        worker_base_port: int = DEFAULT_ADB_WORKER_BASE_PORT,
        ssh_base_port: int = DEFAULT_ADB_SSH_BASE_PORT,
        remote_worker_port: int = 8765,
        remote_ssh_port: int = 8022,
        gateway_port: int = 8888,
        enable_gateway_reverse: bool = True,
        enable_peer_mesh: bool = True,
        adb_bin: str | None = None,
        config_path: Path | None = None,
        gateway_port_getter: Any | None = None,
    ) -> None:
        super().__init__(name="usb-hub-watchdog", daemon=True)
        self.interval_sec = max(1.0, float(interval_sec))
        self.worker_base_port = worker_base_port
        self.ssh_base_port = ssh_base_port
        self.remote_worker_port = remote_worker_port
        self.remote_ssh_port = remote_ssh_port
        self.gateway_port = gateway_port
        self.enable_gateway_reverse = enable_gateway_reverse
        self.enable_peer_mesh = enable_peer_mesh
        self.adb_bin = adb_bin
        self.config_path = config_path
        self.gateway_port_getter = gateway_port_getter
        self._discovered = ClusterConfig("ADB watchdog", "", [])
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self._last_serials: tuple[str, ...] = ()
        self._last_plan: dict[str, Any] = {"mode": "adb", "nodes": [], "forward_rules": [], "reverse_rules": [], "peer_mesh_map": {}}
        self._last_result: dict[str, Any] = {}
        self._last_sync_ts: float = 0.0
        self._active_gateway_port: int | None = None

    def sync_once(self) -> dict[str, Any]:
        with self._sync_lock:
            devs = list_adb_devices(adb_bin=self.adb_bin)
            ready_serials = tuple(sorted(d["serial"] for d in devs if d.get("state") == "device"))
            cfg = load_config(self.config_path) if self.config_path is not None else self._discovered
            eff_gw_rev = self.enable_gateway_reverse
            eff_gw_port = int(self.gateway_port or 0)
            if self.config_path is not None:
                eff_gw_rev = bool(self.enable_gateway_reverse and cfg.gateway.enabled)
                cfg_port = int(cfg.gateway.port or 0)
                if cfg_port <= 0 and callable(self.gateway_port_getter):
                    try:
                        cfg_port = int(self.gateway_port_getter() or 0)
                    except (TypeError, ValueError):
                        cfg_port = 0
                if cfg_port > 0:
                    eff_gw_port = cfg_port
            plan = plan_adb_usb_hub(
                devs,
                worker_base_port=self.worker_base_port,
                ssh_base_port=self.ssh_base_port,
                remote_worker_port=self.remote_worker_port,
                remote_ssh_port=self.remote_ssh_port,
                gateway_port=eff_gw_port,
                enable_gateway_reverse=eff_gw_rev,
                enable_peer_mesh=self.enable_peer_mesh,
                existing_nodes=cfg.nodes,
                registered_only=self.config_path is not None,
                quarantined_nodes=cfg.gateway.quarantined_nodes,
            )
            # If gateway was previously reversed on an old port and is now disabled or moved, prune the old reverse
            prev_gw_port = self._active_gateway_port
            new_gw_port = eff_gw_port if (eff_gw_rev and 1 <= eff_gw_port <= 65535) else None
            if prev_gw_port is not None and prev_gw_port != new_gw_port:
                rev_list = list(plan.get("revoked_reverses") or [])
                for n_item in plan.get("nodes") or []:
                    rev_list.append({"serial": n_item["serial"], "node_id": n_item["node_id"], "remote_port": prev_gw_port})
                plan["revoked_reverses"] = rev_list
            res = apply_adb_usb_hub(plan, adb_bin=self.adb_bin) if plan["nodes"] else {
                "ok": True, "applied": 0, "unchanged": 0, "failed": 0, "errors": [],
            }
            self._active_gateway_port = new_gw_port
            if self.config_path is None:
                # Keep allocations even if only part of the plan ran. A retry
                # must never reuse a host port for a different attached phone.
                sync_usb_hub_into_config(self._discovered, plan)
            with self._lock:
                if ready_serials != self._last_serials:
                    LOG.info("USB hub topology changed: %d ADB device(s) online (%s)", len(ready_serials), ", ".join(ready_serials) or "none")
                    self._last_serials = ready_serials
                self._last_plan = plan
                self._last_result = res
                self._last_sync_ts = time.time()
            return {"plan": plan, "apply": res}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.is_alive() and not self._stop_event.is_set(),
                "interval_sec": self.interval_sec,
                "last_sync_ts": int(self._last_sync_ts) if self._last_sync_ts else 0,
                "online_serials": list(self._last_serials),
                "plan": dict(self._last_plan),
                "apply": dict(self._last_result),
            }

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_once()
            except Exception as exc:
                LOG.warning("USB hub watchdog tick error: %s", exc)
            self._stop_event.wait(self.interval_sec)


def probe_adb_device_profile(
    serial: str,
    *,
    adb_bin: str | None = None,
    timeout_sec: float = 3.0,
) -> dict[str, Any]:
    """Quickly probe an ADB-connected phone to auto-detect Termux vs Ubuntu Touch SSH port, user, and USB power."""
    clean_serial = validate_usb_serial(serial)
    cmd = adb_bin or shutil.which("adb")
    base: dict[str, Any] = {
        "serial": clean_serial,
        "os_env": "unknown",
        "remote_ssh_port": 8022,
        "ssh_user": "",
        "battery_pct": None,
        "battery_status": "",
        "usb_power_warning": False,
    }
    if not cmd:
        return base
    probe_sh = (
        "if [ -f /etc/system-image/channel.ini ] || [ -f /etc/ubuntu-build ] || [ -d /etc/ubuntu-touch ] "
        "|| command -v repowerd-cli >/dev/null 2>&1 || command -v powerd-cli >/dev/null 2>&1 "
        "|| grep -qiE 'ubuntu.?touch|ubports' /etc/os-release 2>/dev/null; then "
        "  echo OS=ubuntu-touch; echo SSH_PORT=22; echo SSH_USER=phablet; "
        "elif [ -d /data/data/com.termux/files/usr ] || pm path com.termux >/dev/null 2>&1; then "
        "  echo OS=termux; echo SSH_PORT=8022; "
        "  TU=$(stat -c '%U' /data/data/com.termux/files/home 2>/dev/null || true); "
        "  if [ -z \"$TU\" ]; then "
        "    UID_RAW=$(dumpsys package com.termux 2>/dev/null | grep -m1 -oE '(userId|appId)=[0-9]+' | cut -d= -f2 || true); "
        "    if [ -n \"$UID_RAW\" ] && [ \"$UID_RAW\" -ge 10000 ] 2>/dev/null; then TU=\"u0_a$((UID_RAW - 10000))\"; fi; "
        "  fi; "
        "  echo SSH_USER=$TU; "
        "else "
        "  echo OS=android; echo SSH_PORT=8022; echo SSH_USER=; "
        "fi; "
        "for f in /sys/class/power_supply/battery/capacity /sys/class/power_supply/*/capacity; do "
        "  [ -r \"$f\" ] && { echo BAT_PCT=$(cat \"$f\" 2>/dev/null); break; }; "
        "done; "
        "for f in /sys/class/power_supply/battery/status /sys/class/power_supply/*/status; do "
        "  [ -r \"$f\" ] && { echo BAT_STATUS=$(cat \"$f\" 2>/dev/null); break; }; "
        "done; true"
    )
    try:
        res = subprocess.run(
            [cmd, "-s", clean_serial, "shell", probe_sh],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except (subprocess.SubprocessError, OSError):
        return base
    if res.returncode != 0 and "OS=" not in (res.stdout or ""):
        return base
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k == "OS" and v:
            base["os_env"] = v[:32]
        elif k == "SSH_PORT" and v.isascii() and v.isdigit() and 1 <= int(v) <= 65535:
            base["remote_ssh_port"] = int(v)
        elif k == "SSH_USER" and v:
            try:
                base["ssh_user"] = validate_ssh_user(v)
            except ValueError:
                pass
        elif k == "BAT_PCT" and v.isascii() and v.isdigit():
            pct = int(v)
            if 0 <= pct <= 100:
                base["battery_pct"] = pct
        elif k == "BAT_STATUS" and v:
            st = v.upper()[:24]
            base["battery_status"] = st
            if st in {"DISCHARGING", "NOT CHARGING", "NOT_CHARGING"}:
                base["usb_power_warning"] = True
    return base


def _tcp_probe_local(host: str, port: int, timeout_sec: float = 0.5) -> tuple[bool, float]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_sec):
            return True, round((time.monotonic() - t0) * 1000.0, 1)
    except OSError:
        return False, round((time.monotonic() - t0) * 1000.0, 1)


def verify_usb_hub_connectivity(
    controller: Any,
    *,
    adb_bin: str | None = None,
    timeout_sec: float = 3.0,
) -> dict[str, Any]:
    """Verify Master<->Phone worker reachability, ADB tunnel bindings, and live Phone<->Phone peer links over USB."""
    from .master import JobSpec

    with controller.config_lock:
        all_nodes = list(controller.config.nodes)
        quarantined = set(controller.config.gateway.quarantined_nodes)

    usb_nodes = [
        n for n in all_nodes
        if n.adb is not None or "usb-hub" in (n.tags or []) or "usb-mode:rndis" in (n.tags or []) or "usb-mode:adb" in (n.tags or [])
    ]
    if not usb_nodes:
        return {
            "ok": False,
            "usb_node_count": 0,
            "online_count": 0,
            "nodes": [],
            "peer_links": [],
            "adb_tunnels": [],
            "warnings": ["No USB hub nodes configured yet. Run `pc usb-hub setup` or Tab 6 -> USB 3.0 Hub first."],
            "summary": "No USB hub nodes configured.",
        }

    snapshots = controller.poll_health()
    snap_by_id = {s.node.id: s for s in snapshots}
    warnings: list[str] = []
    node_rows: list[dict[str, Any]] = []
    online_rndis: list[NodeConfig] = []
    adb_nodes: list[NodeConfig] = []

    for n in usb_nodes:
        snap = snap_by_id.get(n.id)
        mode = "adb" if (n.adb is not None or "usb-mode:adb" in (n.tags or [])) else "rndis"
        online = bool(snap and snap.online)
        h = snap.health if (snap and snap.online and isinstance(snap.health, dict)) else {}
        bat_status = str(h.get("battery_status") or "").strip().upper()
        bat_pct = h.get("battery_pct")
        power_warn = online and bat_status in {"DISCHARGING", "NOT_CHARGING", "NOT CHARGING"}
        if power_warn:
            warnings.append(
                f"{n.id} is discharging on USB ({bat_pct if bat_pct is not None else '?'}%) — check powered USB 3.0 hub PSU (12V/3A-5A)."
            )
        if n.id in quarantined:
            warnings.append(f"{n.id} is quarantined — peer-mesh and gateway access intentionally blocked.")
        node_rows.append(
            {
                "node_id": n.id,
                "mode": mode,
                "host": n.host,
                "worker_port": n.worker_port,
                "online": online,
                "ready": bool(snap and snap.ready_for_jobs),
                "latency_ms": snap.latency_ms if snap else None,
                "battery_pct": bat_pct,
                "battery_status": bat_status,
                "power_warning": power_warn,
                "quarantined": n.id in quarantined,
                "error": "" if online else (snap.error if snap else "unreachable"),
            }
        )
        if n.id not in quarantined:
            if mode == "rndis" and online:
                online_rndis.append(n)
            elif mode == "adb":
                # Inspect ADB tunnels even for offline phones so dropped forwards are diagnosed
                adb_nodes.append(n)

    # Check host IPv4 forwarding when >=2 RNDIS nodes exist (required for Phone <-> Phone routing)
    rndis_count = sum(1 for r in node_rows if r["mode"] == "rndis")
    if rndis_count >= 2 and not read_ipv4_forwarding_enabled():
        warnings.append("Master host net.ipv4.ip_forward=0 — RNDIS phones cannot route packets to each other. Run setup-rndis.")

    # Live Phone <-> Phone peer checks for RNDIS /30 nodes
    peer_links: list[dict[str, Any]] = []
    if len(online_rndis) >= 2:
        for src in online_rndis:
            peers = [(dst.id, dst.host, int(dst.worker_port)) for dst in online_rndis if dst.id != src.id]
            probe_code = (
                "import json, socket, time\n"
                f"peers = {peers!r}\n"
                "out = []\n"
                "for nid, host, port in peers:\n"
                "    t0 = time.monotonic()\n"
                "    try:\n"
                f"        with socket.create_connection((host, port), timeout={min(2.5, max(0.5, float(timeout_sec)))}):\n"
                "            out.append({'to': nid, 'host': host, 'port': port, 'ok': True, 'latency_ms': round((time.monotonic()-t0)*1000.0, 1), 'error': ''})\n"
                "    except OSError as exc:\n"
                "        out.append({'to': nid, 'host': host, 'port': port, 'ok': False, 'latency_ms': round((time.monotonic()-t0)*1000.0, 1), 'error': str(exc)[:120]})\n"
                "print(json.dumps({'links': out}))\n"
            )
            spec = JobSpec(
                index=0,
                job_id=f"usb-peercheck-{src.id}-{uuid.uuid4().hex[:6]}",
                script_content=probe_code,
                script_name="usb_peer_check.py",
                interpreter="python3",
                timeout_sec=max(5.0, float(timeout_sec) * len(peers) + 3.0),
                force=True,
            )
            kind, data = controller.exec_on_node(src, spec)
            if kind == "ok" and data.get("returncode") == 0:
                try:
                    parsed = json.loads(str(data.get("stdout") or "").strip())
                    for item in parsed.get("links") or []:
                        peer_links.append({"from": src.id, "mode": "rndis", **item})
                except (json.JSONDecodeError, TypeError, ValueError):
                    for dst_id, dst_host, dst_port in peers:
                        peer_links.append({"from": src.id, "to": dst_id, "mode": "rndis", "host": dst_host, "port": dst_port, "ok": False, "latency_ms": None, "error": "invalid probe output"})
            else:
                err = str(data.get("error") or data.get("stderr") or kind)[:120]
                for dst_id, dst_host, dst_port in peers:
                    peer_links.append({"from": src.id, "to": dst_id, "mode": "rndis", "host": dst_host, "port": dst_port, "ok": False, "latency_ms": None, "error": err})

    # Live ADB tunnel verification for ADB USB-hub nodes (including offline nodes to spot dropped forwards)
    adb_tunnels: list[dict[str, Any]] = []
    adb_cmd = adb_bin or shutil.which("adb")
    if adb_nodes and not adb_cmd:
        warnings.append("ADB USB hub node(s) configured, but `adb` binary was not found on PATH.")
    if adb_nodes and adb_cmd:
        fwd_map: dict[str, tuple[str, str]] = {}
        try:
            fwd_res = subprocess.run([adb_cmd, "forward", "--list"], capture_output=True, text=True, timeout=timeout_sec)
            if fwd_res.returncode == 0:
                for raw_line in fwd_res.stdout.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("*"):
                        continue
                    parts = line.split(maxsplit=2)
                    if len(parts) >= 3:
                        fwd_map[parts[1]] = (parts[0], parts[2].strip())
        except (subprocess.SubprocessError, OSError):
            pass
        rev_by_node: dict[str, dict[str, str]] = {}
        for n in adb_nodes:
            serial = n.adb.serial if n.adb is not None else ""
            w_bind = fwd_map.get(f"tcp:{n.worker_port}")
            s_bind = fwd_map.get(f"tcp:{n.ssh_port}")
            rev_map: dict[str, str] = {}
            if serial:
                try:
                    rev_res = subprocess.run([adb_cmd, "-s", serial, "reverse", "--list"], capture_output=True, text=True, timeout=timeout_sec)
                    if rev_res.returncode == 0:
                        for raw_line in rev_res.stdout.splitlines():
                            line = raw_line.strip()
                            if not line or line.startswith("*"):
                                continue
                            parts = line.split(maxsplit=2)
                            if len(parts) >= 3:
                                rev_map[parts[1]] = parts[2].strip()
                except (subprocess.SubprocessError, OSError):
                    pass
            rev_by_node[n.id] = rev_map
            exp_w_dst = f"tcp:{n.adb.remote_worker_port}" if n.adb is not None else ""
            exp_s_dst = f"tcp:{n.adb.remote_ssh_port}" if n.adb is not None else ""
            worker_fwd_ok = bool(
                w_bind
                and (not serial or w_bind[0] == serial)
                and (not exp_w_dst or w_bind[1] == exp_w_dst)
            )
            ssh_fwd_ok = bool(
                s_bind
                and (not serial or s_bind[0] == serial)
                and (not exp_s_dst or s_bind[1] == exp_s_dst)
            )
            adb_tunnels.append(
                {
                    "node_id": n.id,
                    "serial": serial,
                    "worker_forward_ok": worker_fwd_ok,
                    "ssh_forward_ok": ssh_fwd_ok,
                    "reverse_count": len(rev_map),
                }
            )
            if not worker_fwd_ok:
                warnings.append(f"ADB worker forward missing for {n.id} (127.0.0.1:{n.worker_port}) — click 'Apply ADB Hub' or enable Auto-Heal Watchdog.")
        # Check BOTH halves of peer mesh reachability (dst forward + src reverse) between sibling ADB phones
        online_adb = [n for n in adb_nodes if snap_by_id.get(n.id) and snap_by_id[n.id].online]
        if len(online_adb) >= 2:
            for src in online_adb:
                if src.adb is None or not src.adb.peer_mesh:
                    continue
                src_revs = rev_by_node.get(src.id, {})
                for dst in online_adb:
                    if dst.id == src.id or dst.adb is None or not dst.adb.peer_mesh:
                        continue
                    missing_parts: list[str] = []
                    for offset, svc_port in enumerate(USB_MESH_DEFAULT_PORTS):
                        hp = dst.adb.mesh_base_port + offset
                        fwd_bind = fwd_map.get(f"tcp:{hp}")
                        if not (fwd_bind and fwd_bind[0] == dst.adb.serial and fwd_bind[1] == f"tcp:{svc_port}"):
                            missing_parts.append(f"fwd:{hp}")
                        if src_revs.get(f"tcp:{hp}") != f"tcp:{hp}":
                            missing_parts.append(f"rev:{hp}")
                    link_ok = not missing_parts
                    peer_links.append(
                        {
                            "from": src.id,
                            "to": dst.id,
                            "mode": "adb-mesh",
                            "host": "127.0.0.1",
                            "port": dst.adb.mesh_base_port,
                            "ok": link_ok,
                            "latency_ms": None,
                            "error": "" if link_ok else f"missing mesh tunnel(s): {', '.join(missing_parts[:4])}",
                        }
                    )

    online_count = sum(1 for r in node_rows if r["online"])
    peer_ok = all(link.get("ok") for link in peer_links) if peer_links else True
    tunnels_ok = all(t["worker_forward_ok"] for t in adb_tunnels) if adb_tunnels else True
    overall_ok = online_count == len(node_rows) and peer_ok and tunnels_ok
    peer_summary = (
        f", {sum(1 for l in peer_links if l['ok'])}/{len(peer_links)} peer link(s) OK"
        if peer_links
        else ""
    )
    return {
        "ok": overall_ok,
        "usb_node_count": len(node_rows),
        "online_count": online_count,
        "nodes": node_rows,
        "peer_links": peer_links,
        "adb_tunnels": adb_tunnels,
        "warnings": warnings,
        "summary": f"{online_count}/{len(node_rows)} USB phone(s) online{peer_summary}",
    }


def _systemd_escape_exec_arg(value: str) -> str:
    """Escape a single double-quoted argument for systemd ExecStart=/ExecStop= lines."""
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("systemd unit paths cannot contain control characters or newlines")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("%", "%%")
        .replace("$", "$$")
    )
    return f'"{escaped}"'


def _systemd_escape_workdir(value: str) -> str:
    """Format an unquoted absolute path for systemd WorkingDirectory= (systemd does NOT strip quotes)."""
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or value.endswith("\\") or '"' in value:
        raise ValueError("WorkingDirectory path contains unsupported control characters, quotes, or trailing backslash")
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = p.resolve()
    return str(p).replace("%", "%%")


def generate_usb_hub_systemd_unit(
    mode: str,
    *,
    config_path: str | Path = "config/cluster.json",
    repo_dir: str | Path = "/opt/phonecluster",
    subnet_prefix: str = DEFAULT_USB_SUBNET_PREFIX,
    nat_wan: bool = False,
    wan_iface: str = "",
    gateway_port: int = 8888,
    interval_sec: float = 5.0,
    router_script: str | Path | None = None,
    use_python_module: bool | None = None,
) -> str:
    """Generate a ready-to-install systemd service unit for persistent USB 3.0 Hub routing across Master reboots."""
    clean_mode = str(mode or "adb").strip().lower()
    if clean_mode not in {"adb", "rndis"}:
        raise ValueError("mode must be 'adb' or 'rndis'")
    clean_prefix = validate_subnet_prefix(subnet_prefix)
    gw_port = int(gateway_port) if 1 <= int(gateway_port) <= 65535 else 8888
    cfg_str = str(config_path)
    repo_str = str(repo_dir)
    if any(c in "\r\n" for c in cfg_str + repo_str):
        raise ValueError("config_path and repo_dir cannot contain newlines")

    if clean_mode == "adb":
        iv = max(1.0, min(300.0, float(interval_sec)))
        workdir_val = _systemd_escape_workdir(repo_str)
        cli_file = Path(repo_str) / "phonecluster_cli.py"
        if use_python_module is True or (use_python_module is None and Path(repo_str).exists() and not cli_file.is_file()):
            entry_part = "-m phonecluster.cli"
        else:
            entry_part = _systemd_escape_exec_arg(f"{repo_str.rstrip('/')}/phonecluster_cli.py")
        cfg_arg = _systemd_escape_exec_arg(cfg_str)
        return (
            "[Unit]\n"
            "Description=PhoneCluster USB 3.0 Hub Auto-Heal Watchdog (ADB Peer Mesh)\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={workdir_val}\n"
            f"ExecStart=/usr/bin/env python3 {entry_part} --config {cfg_arg} usb-hub serve --interval {iv:.1f} --gateway-port {gw_port}\n"
            "Restart=always\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    nat_args = ""
    if nat_wan:
        nat_args = " --nat-wan"
        if wan_iface:
            nat_args += f" --wan-iface {validate_iface_name(wan_iface)}"
    script_path = str(router_script) if router_script is not None else f"{repo_str.rstrip('/')}/scripts/07_usb_hub_router.sh"
    script_arg = _systemd_escape_exec_arg(script_path)
    return (
        "[Unit]\n"
        "Description=PhoneCluster USB 3.0 Hub Layer-3 /30 Router (RNDIS Air-Gap)\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/usr/bin/env bash {script_arg} setup-rndis --prefix {clean_prefix} --gateway-port {gw_port}{nat_args}\n"
        f"ExecStop=/usr/bin/env bash {script_arg} teardown --prefix {clean_prefix}\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
