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
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .config import AdbNodeConfig, ClusterConfig, NodeConfig, is_loopback_or_unspecified_host, load_config

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
) -> list[dict[str, Any]]:
    """Detect USB-Ethernet / RNDIS / CDC-ECM / CDC-NCM gadget interfaces on this Linux host."""
    if not sys_net_dir.is_dir():
        return []
    found: list[dict[str, Any]] = []
    uplink_ifaces = _default_route_ifaces() if include_ips else set()
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
    """Identify overlapping IPv4 subnets across multiple USB gadget interfaces."""
    by_net: dict[str, list[str]] = {}
    for item in interfaces:
        iface = str(item.get("iface") or "")
        for cidr in item.get("ipv4_cidrs") or []:
            try:
                net = str(ipaddress.ip_interface(cidr).network)
            except ValueError:
                continue
            by_net.setdefault(net, []).append(iface)
    collisions: list[dict[str, Any]] = []
    for net, ifaces in sorted(by_net.items()):
        if len(ifaces) > 1:
            collisions.append({"subnet": net, "interfaces": sorted(ifaces)})
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

    idx = 0
    seen_serials: set[str] = set()
    for dev in ready:
        serial = validate_usb_serial(dev["serial"])
        if serial in seen_serials:
            continue
        seen_serials.add(serial)
        previous = registered.get(serial)
        if previous is not None:
            node, adb = previous
            node_id, local_w_port, local_s_port = node.id, node.worker_port, node.ssh_port
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
            adb = AdbNodeConfig(serial, remote_worker_port, remote_ssh_port, start, enable_peer_mesh)

        is_quarantined = node_id in quarantined
        if is_quarantined:
            quarantined_serials.append(serial)
        peer_mesh = (not is_quarantined) and enable_peer_mesh and (adb.peer_mesh or not registered_only)

        nodes_plan.append(
            {
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
        )
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
    }


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

    def reconcile(direction: str, rules: list[dict[str, Any]], device: str | None = None) -> None:
        nonlocal applied, unchanged, failed
        if not rules:
            return
        scope = ["-s", device] if device is not None else []
        active: dict[str, tuple[str, str]] = {}
        try:
            for line in run_adb(*scope, direction, "--list").splitlines():
                if not line.strip():
                    continue
                owner, source, destination = line.split(maxsplit=2)
                if not source.startswith("tcp:"):
                    continue
                # reverse --list is already scoped to this phone. The first field is its transport.
                target = (device or owner, destination)
                if source in active and active[source] != target:
                    raise ValueError(f"ambiguous ADB route for {source}")
                active[source] = target
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
        try:
            clean_q = validate_usb_serial(str(q_serial))
            subprocess.run(
                [cmd, "-s", clean_q, "reverse", "--remove-all"],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except (subprocess.SubprocessError, OSError, ValueError):
            pass

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

    nodes_plan: list[dict[str, Any]] = []
    for idx, item in enumerate(sorted_ifaces, start=1):
        iface = validate_iface_name(str(item.get("iface") or ""))
        mac = str(item.get("mac") or "").strip().lower()
        subnet = f"{clean_prefix}.{idx}.0/30"
        host_ip = f"{clean_prefix}.{idx}.1"
        phone_ip = f"{clean_prefix}.{idx}.2"
        nodes_plan.append(
            {
                "index": idx,
                "node_id": f"{clean_node_prefix}{idx}",
                "iface": iface,
                "mac": mac,
                "driver": str(item.get("driver") or "usb"),
                "subnet": subnet,
                "host_ip": host_ip,
                "phone_ip": phone_ip,
                "host": phone_ip,
                "worker_port": int(worker_port),
                "ssh_port": int(ssh_port),
                "ssh_user": ssh_user,
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
) -> dict[str, Any]:
    """Build explicit, idempotent Linux host & phone commands for Layer-3 USB hub phone-to-phone routing."""
    cluster_cidr = str(plan.get("cluster_cidr") or f"{DEFAULT_USB_SUBNET_PREFIX}.0.0/16")
    gw_port = int(gateway_port) if 1 <= int(gateway_port) <= 65535 else 8888
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
                f"sudo sysctl -w net.ipv6.conf.{iface}.disable_ipv6=1 net.ipv6.conf.{iface}.accept_ra=0 net.ipv4.conf.{iface}.rp_filter=1",
                f"sudo ip addr flush dev {iface}",
                f"sudo ip addr add {host_ip}/30 dev {iface}",
                f"sudo ip link set {iface} up",
            ]
        )
        phone_cmds[str(n["node_id"])] = [
            f"# Run on {n['node_id']} (Ubuntu Touch / Linux phone) — or run: bash scripts/07_usb_hub_router.sh phone-setup {idx}",
            f"sudo bash ~/phonecluster/scripts/07_usb_hub_router.sh phone-setup {idx} --prefix {plan['subnet_prefix']}",
            f"# Equivalent manual commands (assigns {phone_ip}/30 and routes {cluster_cidr} via {host_ip}):",
            f"sudo ip addr flush dev rndis0 2>/dev/null || sudo ip addr flush dev usb0",
            f"sudo ip addr add {phone_ip}/30 dev rndis0 2>/dev/null || sudo ip addr add {phone_ip}/30 dev usb0",
            f"sudo ip route replace {cluster_cidr} via {host_ip}",
        ]

    host_cmds.extend(
        [
            "# 2. Enforce strict USB hub FORWARD & INPUT air-gap (phone-to-phone only; block LAN/WAN/host admin pivot)",
            f"sudo iptables -C FORWARD -s {cluster_cidr} -d {cluster_cidr} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD 1 -s {cluster_cidr} -d {cluster_cidr} -j ACCEPT",
        ]
    )
    if nat_wan:
        clean_wan = validate_iface_name(wan_iface) if wan_iface else ""
        if clean_wan:
            host_cmds.append(
                f"sudo iptables -t nat -C POSTROUTING -s {cluster_cidr} -o {clean_wan} -j MASQUERADE 2>/dev/null || "
                f"sudo iptables -t nat -A POSTROUTING -s {cluster_cidr} -o {clean_wan} -j MASQUERADE"
            )
            host_cmds.append(
                f"sudo iptables -C FORWARD -s {cluster_cidr} -o {clean_wan} -j ACCEPT 2>/dev/null || "
                f"sudo iptables -I FORWARD 2 -s {cluster_cidr} -o {clean_wan} -j ACCEPT"
            )
            host_cmds.append(
                f"sudo iptables -C FORWARD -i {clean_wan} -d {cluster_cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
                f"sudo iptables -I FORWARD 3 -i {clean_wan} -d {cluster_cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            )
            host_cmds.append(
                f"sudo iptables -C FORWARD -s {cluster_cidr} ! -d {cluster_cidr} ! -o {clean_wan} -j DROP 2>/dev/null || "
                f"sudo iptables -I FORWARD 4 -s {cluster_cidr} ! -d {cluster_cidr} ! -o {clean_wan} -j DROP"
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
) -> list[str]:
    """Merge planned USB-hub worker nodes into `config` (preserving existing per-node tokens)."""
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
            if existing.adb is not None and (adb is None or existing.adb.serial != adb.serial):
                raise ValueError(f"USB plan would reassign {nid} to another device")
            existing.host = host
            existing.worker_port = w_port
            existing.ssh_port = s_port
            existing.adb = adb
            if s_user and not existing.ssh_user:
                existing.ssh_user = s_user
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
        self._discovered = ClusterConfig("ADB watchdog", "", [])
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._last_serials: tuple[str, ...] = ()
        self._last_plan: dict[str, Any] = {"mode": "adb", "nodes": [], "forward_rules": [], "reverse_rules": [], "peer_mesh_map": {}}
        self._last_result: dict[str, Any] = {}

    def sync_once(self) -> dict[str, Any]:
        devs = list_adb_devices(adb_bin=self.adb_bin)
        ready_serials = tuple(sorted(d["serial"] for d in devs if d.get("state") == "device"))
        cfg = load_config(self.config_path) if self.config_path is not None else self._discovered
        plan = plan_adb_usb_hub(
            devs,
            worker_base_port=self.worker_base_port,
            ssh_base_port=self.ssh_base_port,
            remote_worker_port=self.remote_worker_port,
            remote_ssh_port=self.remote_ssh_port,
            gateway_port=self.gateway_port,
            enable_gateway_reverse=self.enable_gateway_reverse,
            enable_peer_mesh=self.enable_peer_mesh,
            existing_nodes=cfg.nodes,
            registered_only=self.config_path is not None,
            quarantined_nodes=cfg.gateway.quarantined_nodes,
        )
        res = apply_adb_usb_hub(plan, adb_bin=self.adb_bin) if plan["nodes"] else {
            "ok": True, "applied": 0, "unchanged": 0, "failed": 0, "errors": [],
        }
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
        return {"plan": plan, "apply": res}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"plan": dict(self._last_plan), "apply": dict(self._last_result)}

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_once()
            except Exception as exc:
                LOG.warning("USB hub watchdog tick error: %s", exc)
            self._stop_event.wait(self.interval_sec)
