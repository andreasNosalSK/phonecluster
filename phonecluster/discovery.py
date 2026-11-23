"""Zero-config UDP LAN discovery so phones find each other automatically on Wi-Fi.

Security model:
- Discovery packets announce ONLY non-sensitive presence metadata (node_id, role,
  ports, OS, CPU cores, RAM).
- Secrets (`auth_token`) are NEVER broadcast over UDP. Command execution still
  requires the shared Bearer token distributed over SSH or config/cluster.json.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

from .telemetry import detect_os_environment, read_memory_info

LOG = logging.getLogger("phonecluster.discovery")

DISCOVERY_PORT = 8766
PROBE_TYPE = "phonecluster_discover_v1"
REPLY_TYPE = "phonecluster_announce_v1"

_SIOCGIFADDR = 0x8915


def _detect_ipv4_via_sys_net() -> str | None:
    """Linux zero-dependency fallback using `SIOCGIFADDR` for air-gapped LANs without a default route."""
    try:
        import fcntl
    except ImportError:
        return None
    net_dir = Path("/sys/class/net")
    if not net_dir.exists():
        return None
    try:
        ifaces = sorted(p.name for p in net_dir.iterdir() if p.is_dir())
    except OSError:
        return None

    def _iface_priority(name: str) -> tuple[int, str]:
        if name.startswith(("wlan", "wl", "eth", "en")):
            return (0, name)
        if name.startswith(("tailscale", "wg", "usb", "rndis")):
            return (1, name)
        if name.startswith(("docker", "br-", "veth", "virbr", "cni", "flannel")):
            return (3, name)
        return (2, name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for name in sorted(ifaces, key=_iface_priority):
            if name == "lo" or name.startswith("dummy"):
                continue
            try:
                req = struct.pack("256s", name[:15].encode("utf-8"))
                res = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, req)
                ip = socket.inet_ntoa(res[20:24])
                if ip and not ip.startswith(("127.", "169.254.")):
                    return ip
            except OSError:
                continue
    finally:
        sock.close()
    return None


def detect_local_ip() -> str:
    """Best-effort detection of this device's LAN IPv4 address (works even on air-gapped LANs)."""
    for probe_ip in ("192.0.2.1", "192.168.0.1", "10.255.255.255", "172.16.0.1"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe_ip, 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith(("127.", "169.254.")):
                return ip
        except OSError:
            pass
        finally:
            sock.close()
    iface_ip = _detect_ipv4_via_sys_net()
    if iface_ip:
        return iface_ip
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith(("127.", "169.254.")):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def _candidate_broadcast_addresses(local_ip: str) -> list[str]:
    """Return broadcast targets including subnet /24 broadcast and 255.255.255.255."""
    targets = ["255.255.255.255"]
    parts = local_ip.split(".")
    if len(parts) == 4 and not local_ip.startswith("127."):
        subnet_bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        if subnet_bcast not in targets:
            targets.insert(0, subnet_bcast)
    return targets


class DiscoveryResponder(threading.Thread):
    """Lightweight UDP daemon running on each phone to answer LAN discovery probes."""

    def __init__(
        self,
        node_id: str,
        role: str,
        worker_port: int,
        ssh_port: int = 8022,
        ssh_user: str = "",
        listen_host: str = "0.0.0.0",
        discovery_port: int = DISCOVERY_PORT,
    ) -> None:
        super().__init__(name="lan-discovery", daemon=True)
        self.node_id = node_id
        self.role = role
        self.worker_port = worker_port
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user or _current_user()
        self.listen_host = listen_host
        self.discovery_port = discovery_port
        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self.bound_port: int = discovery_port

    def _build_reply(self) -> bytes:
        mem = read_memory_info()
        payload = {
            "type": REPLY_TYPE,
            "node_id": self.node_id,
            "role": self.role,
            "hostname": socket.gethostname(),
            "worker_port": self.worker_port,
            "ssh_port": self.ssh_port,
            "ssh_user": self.ssh_user,
            "os_env": detect_os_environment(),
            "cpu_cores": os.cpu_count() or 1,
            "mem_total_mb": mem["total_mb"],
            "timestamp": int(time.time()),
        }
        return json.dumps(payload).encode("utf-8")

    def bind(self) -> bool:
        """Bind the UDP socket before starting the thread."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        bind_addr = "0.0.0.0" if (not self.listen_host or ":" in self.listen_host) else self.listen_host
        try:
            sock.bind((bind_addr, self.discovery_port))
            sock.settimeout(0.5)
            self._sock = sock
            self.bound_port = sock.getsockname()[1]
            return True
        except OSError as exc:
            LOG.warning(
                "LAN discovery listener could not bind UDP port %d: %s",
                self.discovery_port,
                exc,
            )
            sock.close()
            return False

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def run(self) -> None:
        if self._sock is None and not self.bind():
            return
        assert self._sock is not None
        LOG.info("LAN discovery responder listening on UDP %s:%d", self.listen_host, self.bound_port)
        win_start = time.monotonic()
        replies = 0
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if not addr or addr[1] <= 0:
                continue
            now_m = time.monotonic()
            if now_m - win_start >= 1.0:
                win_start = now_m
                replies = 0
            if replies >= 20:
                continue
            try:
                msg = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(msg, dict) and msg.get("type") == PROBE_TYPE:
                try:
                    self._sock.sendto(self._build_reply(), addr)
                    replies += 1
                except OSError:
                    pass


def discover_lan_nodes(
    timeout_sec: float = 2.0,
    discovery_port: int = DISCOVERY_PORT,
    targets: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Broadcast a discovery probe on Wi-Fi/LAN and return discovered phones."""
    probe = json.dumps({"type": PROBE_TYPE, "ts": int(time.time())}).encode("utf-8")
    local_ip = detect_local_ip()
    dests = targets if targets is not None else _candidate_broadcast_addresses(local_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.25)

    found: dict[tuple[str, int], dict[str, Any]] = {}
    try:
        def _send_probes() -> None:
            for dest in dests:
                try:
                    sock.sendto(probe, (dest, discovery_port))
                except OSError as exc:
                    LOG.debug("Broadcast to %s:%d failed: %s", dest, discovery_port, exc)

        _send_probes()
        started = time.monotonic()
        deadline = started + max(0.2, timeout_sec)
        resent = False
        while time.monotonic() < deadline:
            if not resent and timeout_sec >= 0.8 and (time.monotonic() - started) >= (timeout_sec * 0.45):
                _send_probes()
                resent = True
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(msg, dict) or msg.get("type") != REPLY_TYPE:
                continue
            host_ip = addr[0]
            worker_port = int(msg.get("worker_port", 8765))
            key = (host_ip, worker_port)
            if key not in found:
                found[key] = {
                    "host": host_ip,
                    "node_id": str(msg.get("node_id", "")),
                    "role": str(msg.get("role", "worker")),
                    "hostname": str(msg.get("hostname", "")),
                    "worker_port": worker_port,
                    "ssh_port": int(msg.get("ssh_port", 8022)),
                    "ssh_user": str(msg.get("ssh_user", "")),
                    "os_env": str(msg.get("os_env", "unknown")),
                    "cpu_cores": int(msg.get("cpu_cores", 1)),
                    "mem_total_mb": int(msg.get("mem_total_mb", 0)),
                }
    finally:
        sock.close()

    return sorted(found.values(), key=lambda x: (x["host"], x["worker_port"]))


def _current_user() -> str:
    try:
        return os.environ.get("USER") or os.getlogin()
    except OSError:
        return os.environ.get("USER", "")
