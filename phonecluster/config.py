"""Cluster configuration loading, validation, and generation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import tempfile
import urllib.parse
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_WORKER_PORT = 8765
DEFAULT_SSH_PORT = 8022
DEFAULT_GATEWAY_PORT = 8888
DEFAULT_CONFIG_PATH = Path("config/cluster.json")


def normalize_host(host: str) -> str:
    """Normalize a host/IP string (strip whitespace/brackets and canonicalize IPv4/IPv6/IPv4-mapped literals)."""
    h = str(host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip()
    if not h:
        return ""
    if "%" not in h:
        try:
            addr = ipaddress.ip_address(h)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            pass
    return h


def is_loopback_or_unspecified_host(host: str) -> bool:
    """Return True if `host` refers to localhost, loopback, or an unspecified bind address."""
    h = normalize_host(host).lower()
    if not h or h.rstrip(".") == "localhost" or h in {"0.0.0.0", "::"}:
        return True
    try:
        addr = ipaddress.ip_address(h)
        return bool(addr.is_loopback or addr.is_unspecified)
    except ValueError:
        return False


def format_host_for_url(host: str) -> str:
    """Format a hostname, IPv4, or IPv6 literal safely for URLs (brackets IPv6)."""
    h = normalize_host(host)
    if ":" in h:
        return f"[{h}]"
    return h


_NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_POOL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def _parse_int_field(val: Any, default: int, field_name: str) -> int:
    """Strictly parse an integer config field (rejects booleans, non-finite floats, and non-integers)."""
    if val is None:
        return default
    if isinstance(val, bool):
        raise ValueError(f"{field_name} must be an integer, not a boolean")
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        if not math.isfinite(val) or not val.is_integer():
            raise ValueError(f"{field_name} must be a finite integer")
        return int(val)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return default
        try:
            return int(s)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer (got '{val}')") from exc
    raise ValueError(f"{field_name} must be an integer")


def _parse_float_field(val: Any, default: float, field_name: str) -> float:
    """Strictly parse a finite float config field (rejects booleans and NaN/Infinity)."""
    if val is None:
        return default
    if isinstance(val, bool):
        raise ValueError(f"{field_name} must be a number, not a boolean")
    if isinstance(val, str) and not val.strip():
        return default
    try:
        num = float(val)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{field_name} must be a finite number") from exc
    if not math.isfinite(num):
        raise ValueError(f"{field_name} must be a finite number")
    return num


def validate_domain_pattern(pattern: str) -> str:
    """Validate a Network Guard domain rule (`example.com`, `*.example.com`, or IP literal)."""
    raw = str(pattern or "").strip().lower()
    if not raw or len(raw) > 253 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in raw):
        raise ValueError(f"Invalid domain pattern '{pattern}'")
    if raw.startswith("*."):
        base = raw[2:].rstrip(".")
        if not base or "*" in base or not _DOMAIN_LABEL_RE.fullmatch(base):
            raise ValueError(f"Invalid wildcard domain pattern '{pattern}' (use e.g. '*.github.com')")
        return f"*.{base}"
    if "*" in raw or any(c in raw for c in "@/\\?#;'\"%"):
        raise ValueError(f"Invalid domain pattern '{pattern}'")
    clean = raw.rstrip(".")
    if not clean:
        raise ValueError(f"Invalid domain pattern '{pattern}'")
    try:
        addr = ipaddress.ip_address(clean.strip("[]"))
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        pass
    if not _DOMAIN_LABEL_RE.fullmatch(clean):
        raise ValueError(f"Invalid domain pattern '{pattern}'")
    return clean


def validate_node_id(node_id: str) -> str:
    """Validate and return a safe cluster node_id (blocks `:`, `/`, whitespace, and leading `-`)."""
    clean = str(node_id or "").strip()
    if not _NODE_ID_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid node id '{clean}' (must start with alphanumeric and contain only A-Za-z0-9._-, max 40 chars)"
        )
    return clean


def validate_host(host: str) -> str:
    """Validate and return a safe IPv4, IPv6, or RFC hostname (blocks URL/SSH/hosts/zone-ID injection)."""
    raw = str(host or "").strip()
    clean = normalize_host(raw)
    if not clean or len(clean) > 253 or clean.startswith("-"):
        raise ValueError(f"Invalid host '{raw}'")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "@/\\?#;'\"%" for c in clean):
        raise ValueError(f"Invalid characters in host '{raw}'")
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass
    host_no_dot = clean[:-1] if clean.endswith(".") else clean
    if not host_no_dot or not _DOMAIN_LABEL_RE.fullmatch(host_no_dot.lower()):
        raise ValueError(f"Invalid host/IP '{raw}'")
    return clean


def validate_ssh_user(ssh_user: str) -> str:
    """Validate optional SSH username (strictly blocks leading `-` SSH option injection)."""
    clean = str(ssh_user or "").strip()
    if not clean:
        return ""
    if not _SSH_USER_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid ssh_user '{clean}' (must start with alphanumeric/underscore, max 64 chars)"
        )
    return clean


def validate_pool_name(pool: str) -> str:
    """Validate workload pool slug (e.g. 'auto', 'compute', 'services', 'docker')."""
    clean = str(pool or "auto").strip().lower() or "auto"
    if not _POOL_NAME_RE.fullmatch(clean):
        raise ValueError(f"Invalid pool name '{pool}' (use lowercase letters, digits, '_' or '-', max 32 chars)")
    return clean


def format_host_port(host: str, port: int) -> str:
    """Format `host:port` safely for both IPv4/hostnames and IPv6 (`[addr]:port`)."""
    return f"{format_host_for_url(host)}:{int(port)}"

DEFAULT_GATEWAY_ALLOWED_DOMAINS: list[str] = [
    "github.com",
    "*.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "packages-cf.termux.dev",
    "deb.debian.org",
    "security.debian.org",
    "pypi.org",
    "files.pythonhosted.org",
]


def _validate_auth_token(raw: str, field_name: str, allow_empty: bool = False) -> str:
    """Validate an auth token contains only printable ASCII without whitespace/CRLF."""
    tok = raw.strip()
    if not tok:
        if allow_empty:
            return ""
        raise ValueError(
            "Configuration must define a non-empty 'auth_token'. "
            "Run `phonecluster init-config` to generate one."
        )
    if any(c.isspace() or ord(c) < 32 or ord(c) >= 127 for c in tok):
        raise ValueError(f"{field_name} must contain only printable ASCII characters without whitespace")
    return tok


def validate_allowed_master_entry(raw: str) -> str:
    """Validate an entry in `network.allowed_master_ips` (IP, CIDR, or safe hostname)."""
    entry = str(raw or "").strip()
    if not entry or any(c.isspace() or ord(c) < 32 or ord(c) >= 127 for c in entry):
        raise ValueError(f"Invalid allowed_master_ips entry {raw!r}")
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid allowed_master_ips CIDR {raw!r}") from exc
        if net.prefixlen == 0:
            raise ValueError(f"Wildcard /0 CIDR is not allowed in allowed_master_ips: {raw!r}")
        return str(net)
    return validate_host(entry)


@dataclass(frozen=True)
class AdbNodeConfig:
    """The stable USB identity and the ports on the device side of its tunnels."""

    serial: str
    remote_worker_port: int
    remote_ssh_port: int
    mesh_base_port: int
    peer_mesh: bool = True

    @classmethod
    def from_dict(cls, data: Any) -> "AdbNodeConfig":
        if not isinstance(data, dict):
            raise ValueError("Node adb metadata must be an object")
        serial = data.get("serial")
        if not isinstance(serial, str) or serial.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", serial):
            raise ValueError("Node adb metadata requires a valid device serial")
        ports = [
            _parse_int_field(data.get(name), 0, f"adb.{name}")
            for name in ("remote_worker_port", "remote_ssh_port", "mesh_base_port")
        ]
        if not all(1 <= port <= 65535 for port in ports):
            raise ValueError("Node adb metadata ports must be between 1 and 65535")
        peer_mesh = data.get("peer_mesh", True)
        if not isinstance(peer_mesh, bool):
            raise ValueError("Node adb peer_mesh must be a boolean")
        return cls(serial, *ports, peer_mesh=peer_mesh)


@dataclass
class NodeConfig:
    """Configuration for a single phone or Linux node in the cluster."""

    id: str
    host: str
    role: str = "worker"  # "master" or "worker"
    worker_port: int = DEFAULT_WORKER_PORT
    ssh_port: int = DEFAULT_SSH_PORT
    ssh_user: str = ""
    max_concurrency: int = 2
    weight: float = 1.0
    tier: int = 0  # 0 = auto-detect, 1 = Termux compute, 2 = Debian 13 services, 3 = Docker/Droidspaces
    pool: str = "auto"  # "auto", "compute", "services", "docker", or any custom pool name
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    auth_token: str = ""  # Optional per-node least-privilege token (recommended for workers)
    adb: AdbNodeConfig | None = None

    @property
    def base_url(self) -> str:
        return f"http://{format_host_port(self.host, self.worker_port)}"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NodeConfig":
        if "id" not in data or "host" not in data:
            raise ValueError(f"Node entry must define 'id' and 'host': {data}")
        if not isinstance(data["id"], str):
            raise ValueError(f"Node 'id' must be a non-empty string: {data}")
        if not isinstance(data["host"], str):
            raise ValueError(f"Node 'host' must be a non-empty string: {data}")
        node_id = validate_node_id(data["id"])
        host = validate_host(data["host"])
        raw_role = data.get("role", "worker")
        if raw_role is not None and not isinstance(raw_role, str):
            raise ValueError(f"Invalid role '{raw_role}' for node '{node_id}'")
        role = (raw_role or "worker").strip().lower()
        if role not in {"master", "worker"}:
            raise ValueError(f"Invalid role '{role}' for node '{node_id}'")
        worker_port = _parse_int_field(data.get("worker_port"), DEFAULT_WORKER_PORT, f"worker_port for '{node_id}'")
        ssh_port = _parse_int_field(data.get("ssh_port"), DEFAULT_SSH_PORT, f"ssh_port for '{node_id}'")
        if not (0 <= worker_port <= 65535):
            raise ValueError(f"worker_port must be 0..65535 for node '{node_id}'")
        if not (1 <= ssh_port <= 65535):
            raise ValueError(f"ssh_port must be 1..65535 for node '{node_id}'")
        max_conc = _parse_int_field(data.get("max_concurrency"), 2, f"max_concurrency for '{node_id}'")
        if not (1 <= max_conc <= 32):
            raise ValueError(f"max_concurrency must be between 1 and 32 for node '{node_id}'")
        weight = _parse_float_field(data.get("weight"), 1.0, f"weight for '{node_id}'")
        if weight <= 0:
            raise ValueError(f"weight must be a finite number > 0 for node '{node_id}'")
        tier = _parse_int_field(data.get("tier"), 0, f"tier for '{node_id}'")
        if tier not in {0, 1, 2, 3}:
            raise ValueError(f"tier must be 0 (auto), 1, 2, or 3 for node '{node_id}'")
        raw_pool = data.get("pool")
        if raw_pool is not None and not isinstance(raw_pool, str):
            raise ValueError(f"Invalid pool '{raw_pool}' for node '{node_id}'")
        pool = validate_pool_name(raw_pool or "auto")
        raw_ssh_user = data.get("ssh_user")
        if raw_ssh_user is not None and not isinstance(raw_ssh_user, str):
            raise ValueError(f"Invalid ssh_user for node '{node_id}'")
        ssh_user = validate_ssh_user(raw_ssh_user or "")
        raw_tags = data.get("tags")
        tags = [str(t) for t in raw_tags if t is not None] if isinstance(raw_tags, list) else []
        raw_tok = data.get("auth_token")
        if raw_tok is not None and not isinstance(raw_tok, str):
            raise ValueError(f"auth_token for node '{node_id}' must be a string")
        node_tok = _validate_auth_token(raw_tok or "", f"auth_token for node '{node_id}'", allow_empty=True)
        return cls(
            id=node_id,
            host=host,
            role=role,
            worker_port=worker_port,
            ssh_port=ssh_port,
            ssh_user=ssh_user,
            max_concurrency=max_conc,
            weight=weight,
            tier=tier,
            pool=pool,
            tags=tags,
            notes=str(data.get("notes") or ""),
            auth_token=node_tok,
            adb=AdbNodeConfig.from_dict(data["adb"]) if data.get("adb") is not None else None,
        )


@dataclass
class SafetyConfig:
    """Thermal throttling and 24/7 unrooted battery safety thresholds."""

    max_temp_c: float = 40.0
    resume_temp_c: float = 37.0
    min_free_ram_mb: int = 256
    battery_low_pct: int = 45
    battery_high_pct: int = 60
    battery_poll_sec: int = 60
    webhook_cooldown_sec: int = 900
    battery_webhook_url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SafetyConfig":
        raw_wb = data.get("battery_webhook_url")
        if raw_wb is not None and not isinstance(raw_wb, str):
            raise ValueError("safety.battery_webhook_url must be a string")
        cfg = cls(
            max_temp_c=_parse_float_field(data.get("max_temp_c"), 40.0, "safety.max_temp_c"),
            resume_temp_c=_parse_float_field(data.get("resume_temp_c"), 37.0, "safety.resume_temp_c"),
            min_free_ram_mb=_parse_int_field(data.get("min_free_ram_mb"), 256, "safety.min_free_ram_mb"),
            battery_low_pct=_parse_int_field(data.get("battery_low_pct"), 45, "safety.battery_low_pct"),
            battery_high_pct=_parse_int_field(data.get("battery_high_pct"), 60, "safety.battery_high_pct"),
            battery_poll_sec=_parse_int_field(data.get("battery_poll_sec"), 60, "safety.battery_poll_sec"),
            webhook_cooldown_sec=_parse_int_field(data.get("webhook_cooldown_sec"), 900, "safety.webhook_cooldown_sec"),
            battery_webhook_url=(raw_wb or ""),
        )
        if not (10.0 <= cfg.resume_temp_c <= cfg.max_temp_c <= 100.0):
            raise ValueError(
                "safety temperature thresholds must satisfy 10.0 <= resume_temp_c <= max_temp_c <= 100.0"
            )
        if cfg.min_free_ram_mb < 0 or cfg.battery_poll_sec < 1 or cfg.webhook_cooldown_sec < 0:
            raise ValueError("safety min_free_ram_mb/webhook_cooldown_sec must be >= 0 and battery_poll_sec >= 1")
        if not (0 <= cfg.battery_low_pct < cfg.battery_high_pct <= 100):
            raise ValueError(
                "safety battery thresholds must satisfy 0 <= low < high <= 100"
            )
        wb = cfg.battery_webhook_url.strip()
        if wb:
            try:
                p_wb = urllib.parse.urlsplit(wb)
                wb_port = p_wb.port
            except ValueError as exc:
                raise ValueError(
                    "safety.battery_webhook_url must be empty or a valid http:// / https:// URL"
                ) from exc
            if (
                any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in wb)
                or p_wb.scheme.lower() not in {"http", "https"}
                or not p_wb.hostname
                or (wb_port is not None and not (1 <= wb_port <= 65535))
            ):
                raise ValueError("safety.battery_webhook_url must be empty or a valid http:// / https:// URL")
            try:
                validate_host(p_wb.hostname)
            except ValueError as exc:
                raise ValueError("safety.battery_webhook_url must be empty or a valid http:// / https:// URL") from exc
        cfg.battery_webhook_url = wb
        return cfg


@dataclass
class GatewayConfig:
    """Optional Master Network Guard (authenticated allowlist HTTP/HTTPS proxy).

    Disabled by default (`enabled=False`). When enabled on an updated Master phone
    or Raspberry Pi Zero 2 W, you can block direct internet (WAN) access for older
    unrooted worker phones on your router while letting approved package/API traffic
    pass through Master with domain allowlisting, SSRF blocking, and live audit logs.
    """

    enabled: bool = False
    bind_host: str = "0.0.0.0"
    port: int = DEFAULT_GATEWAY_PORT
    mode: str = "allowlist"  # "allowlist" (default-deny), "monitor" (log-all), "block_all" (strict airgap)
    allowed_domains: list[str] = field(default_factory=lambda: list(DEFAULT_GATEWAY_ALLOWED_DOMAINS))
    blocked_domains: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443])
    block_private_ips: bool = True
    inject_proxy_env: bool = True
    max_connections: int = 32
    idle_timeout_sec: float = 30.0
    quarantined_nodes: list[str] = field(default_factory=list)
    max_requests_per_min_per_node: int = 120

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "GatewayConfig":
        if not isinstance(data, dict):
            return cls()
        raw_mode = data.get("mode")
        if raw_mode is not None and not isinstance(raw_mode, str):
            raise ValueError("gateway.mode must be 'allowlist', 'monitor', or 'block_all'")
        mode = (raw_mode or "allowlist").strip().lower()
        if mode not in {"allowlist", "monitor", "block_all"}:
            raise ValueError("gateway.mode must be 'allowlist', 'monitor', or 'block_all'")
        port = _parse_int_field(data.get("port"), DEFAULT_GATEWAY_PORT, "gateway.port")
        if not (0 <= port <= 65535):
            raise ValueError("gateway.port must be between 0 and 65535")
        raw_allowed = data.get("allowed_domains")
        allowed = (
            [validate_domain_pattern(str(d)) for d in raw_allowed if d is not None and str(d).strip()]
            if isinstance(raw_allowed, list)
            else list(DEFAULT_GATEWAY_ALLOWED_DOMAINS)
        )
        raw_blocked = data.get("blocked_domains")
        blocked = (
            [validate_domain_pattern(str(d)) for d in raw_blocked if d is not None and str(d).strip()]
            if isinstance(raw_blocked, list)
            else []
        )
        raw_ports = data.get("allowed_ports")
        if isinstance(raw_ports, list) and raw_ports:
            parsed_ports: set[int] = set()
            for p in raw_ports:
                if p is None:
                    continue
                pv = _parse_int_field(p, 0, "gateway.allowed_ports")
                if 1 <= pv <= 65535:
                    parsed_ports.add(pv)
            ports = sorted(parsed_ports) if parsed_ports else [80, 443]
        else:
            ports = [80, 443]
        raw_q = data.get("quarantined_nodes")
        quarantined = (
            sorted({str(n).strip() for n in raw_q if n is not None and str(n).strip()})
            if isinstance(raw_q, list)
            else []
        )
        max_conn = max(4, min(256, _parse_int_field(data.get("max_connections"), 32, "gateway.max_connections")))
        raw_idle = _parse_float_field(data.get("idle_timeout_sec"), 30.0, "gateway.idle_timeout_sec")
        if raw_idle <= 0:
            raise ValueError("gateway.idle_timeout_sec must be a finite number > 0")
        idle_to = max(5.0, min(3600.0, raw_idle))
        rpm = max(
            0,
            min(
                10000,
                _parse_int_field(
                    data.get("max_requests_per_min_per_node"),
                    120,
                    "gateway.max_requests_per_min_per_node",
                ),
            ),
        )
        raw_bind = data.get("bind_host")
        if raw_bind is not None and not isinstance(raw_bind, str):
            raise ValueError("gateway.bind_host must be a valid host or IP address")
        bind_host = validate_host(raw_bind) if (raw_bind and raw_bind.strip()) else "0.0.0.0"
        return cls(
            enabled=bool(data.get("enabled", False)),
            bind_host=bind_host,
            port=port,
            mode=mode,
            allowed_domains=allowed,
            blocked_domains=blocked,
            allowed_ports=ports,
            block_private_ips=True if data.get("block_private_ips") is None else bool(data["block_private_ips"]),
            inject_proxy_env=True if data.get("inject_proxy_env") is None else bool(data["inject_proxy_env"]),
            max_connections=max_conn,
            idle_timeout_sec=idle_to,
            quarantined_nodes=quarantined,
            max_requests_per_min_per_node=rpm,
        )


@dataclass
class NetworkHardeningConfig:
    """Optional Master & Worker network hardening controls (OFF by default)."""

    enforce_worker_source_ip: bool = False  # Workers only accept HTTP :8765 from allowed_master_ips
    require_signed_requests: bool = False   # Workers reject legacy Bearer and accept ONLY HMAC-SHA256 signed requests
    allowed_master_ips: list[str] = field(default_factory=list)
    adguard_url: str = ""  # Optional custom AdGuard Home URL (e.g. http://192.168.1.200:3000)
    lan_subnet: str = ""   # Optional LAN CIDR for firewall generation (e.g. 192.168.1.0/24)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "NetworkHardeningConfig":
        if not isinstance(data, dict):
            return cls()
        raw_ips = data.get("allowed_master_ips")
        ips: list[str] = []
        if isinstance(raw_ips, list):
            seen_ips: set[str] = set()
            for ip in raw_ips:
                if ip is None:
                    continue
                if not isinstance(ip, str):
                    raise ValueError("network.allowed_master_ips entries must be strings")
                cleaned = ip.strip()
                if not cleaned:
                    continue
                validated = validate_allowed_master_entry(cleaned)
                if validated not in seen_ips:
                    seen_ips.add(validated)
                    ips.append(validated)
                if len(ips) >= 32:
                    break
        raw_ag = data.get("adguard_url")
        if raw_ag is not None and not isinstance(raw_ag, str):
            raise ValueError("network.adguard_url must be a string")
        ag_url = (raw_ag or "").strip()
        if ag_url:
            try:
                p_ag = urllib.parse.urlsplit(ag_url)
                ag_port = p_ag.port
            except ValueError as exc:
                raise ValueError("network.adguard_url must be empty or a valid http:// / https:// URL") from exc
            if (
                any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in ag_url)
                or p_ag.scheme.lower() not in {"http", "https"}
                or not p_ag.hostname
                or (ag_port is not None and not (1 <= ag_port <= 65535))
            ):
                raise ValueError("network.adguard_url must be empty or a valid http:// / https:// URL")
            try:
                validate_host(p_ag.hostname)
            except ValueError as exc:
                raise ValueError("network.adguard_url must be empty or a valid http:// / https:// URL") from exc
        raw_sub = data.get("lan_subnet")
        if raw_sub is not None and not isinstance(raw_sub, str):
            raise ValueError("network.lan_subnet must be a string CIDR")
        lan_sub = (raw_sub or "").strip()
        if lan_sub:
            try:
                lan_sub = str(ipaddress.ip_network(lan_sub, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid network.lan_subnet CIDR '{lan_sub}'") from exc
        return cls(
            enforce_worker_source_ip=bool(data.get("enforce_worker_source_ip", False)),
            require_signed_requests=bool(data.get("require_signed_requests", False)),
            allowed_master_ips=ips,
            adguard_url=ag_url,
            lan_subnet=lan_sub,
        )


@dataclass
class ClusterConfig:
    """Top-level PhoneCluster configuration."""

    cluster_name: str
    auth_token: str
    nodes: list[NodeConfig]
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    network: NetworkHardeningConfig = field(default_factory=NetworkHardeningConfig)
    default_job_timeout_sec: int = 600
    health_timeout_sec: float = 3.0
    dashboard_port: int = 8080
    dashboard_require_auth: bool = False
    custom_services: dict[str, str] = field(default_factory=dict)
    _source: tuple[Path, str] | None = field(default=None, init=False, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClusterConfig":
        if not isinstance(data, dict):
            raise ValueError("Configuration root must be a JSON object.")
        raw_nodes = data.get("nodes", [])
        if not isinstance(raw_nodes, list) or not raw_nodes or not all(isinstance(item, dict) for item in raw_nodes):
            raise ValueError("Configuration must contain a non-empty 'nodes' list of node objects.")
        nodes = [NodeConfig.from_dict(item) for item in raw_nodes]
        seen_ids: set[str] = set()
        for node in nodes:
            if node.id in seen_ids:
                raise ValueError(f"Duplicate node id '{node.id}' in configuration.")
            seen_ids.add(node.id)
        raw_token = data.get("auth_token")
        if raw_token is not None and not isinstance(raw_token, str):
            raise ValueError("Configuration 'auth_token' must be a string.")
        token = _validate_auth_token(raw_token or "", "auth_token", allow_empty=False)
        raw_safety = data.get("safety")
        safety = SafetyConfig.from_dict(raw_safety if isinstance(raw_safety, dict) else {})
        gateway = GatewayConfig.from_dict(data.get("gateway"))
        network = NetworkHardeningConfig.from_dict(data.get("network"))
        raw_svcs = data.get("custom_services") or {}
        custom_services: dict[str, str] = {}
        if isinstance(raw_svcs, dict):
            for k, v in raw_svcs.items():
                if k is None or v is None:
                    continue
                k_clean = re.sub(r"[\x00-\x1f\x7f]", "", str(k)).strip()
                v_clean = re.sub(r"[\x00-\x1f\x7f]", "", str(v)).strip()
                if k_clean and v_clean:
                    custom_services[k_clean] = v_clean
        default_timeout = _parse_int_field(data.get("default_job_timeout_sec"), 600, "default_job_timeout_sec")
        health_timeout = _parse_float_field(data.get("health_timeout_sec"), 3.0, "health_timeout_sec")
        dash_port = _parse_int_field(data.get("dashboard_port"), 8080, "dashboard_port")
        if default_timeout <= 0:
            raise ValueError("default_job_timeout_sec must be > 0")
        if health_timeout <= 0:
            raise ValueError("health_timeout_sec must be a finite number > 0")
        if not (0 <= dash_port <= 65535):
            raise ValueError("dashboard_port must be between 0 and 65535")
        return cls(
            cluster_name=str(data.get("cluster_name") or "phonecluster"),
            auth_token=token,
            nodes=nodes,
            safety=safety,
            gateway=gateway,
            network=network,
            default_job_timeout_sec=default_timeout,
            health_timeout_sec=health_timeout,
            dashboard_port=dash_port,
            dashboard_require_auth=bool(data.get("dashboard_require_auth", False)),
            custom_services=custom_services,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        del data["_source"]
        return data

    def token_for_node(self, node: NodeConfig) -> str:
        """Return the least-privilege per-node token if set, else the cluster token."""
        return node.auth_token or self.auth_token

    def get_node(self, node_id: str) -> NodeConfig:
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise KeyError(f"Unknown node id: {node_id}")

    def workers_needing_tokens(self) -> list[NodeConfig]:
        """Find workers whose credential is missing or also grants access to another node."""
        counts = Counter(n.auth_token for n in self.nodes)
        return [
            n for n in self.nodes
            if n.role == "worker"
            and (not n.auth_token or n.auth_token == self.auth_token or counts[n.auth_token] > 1)
        ]


def resolve_config_path(path: str | Path | None = None) -> Path:
    """Resolve the config file path from explicit arg, env var, or default."""
    if path:
        return Path(path)
    env_path = os.environ.get("PHONECLUSTER_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


class ConfigConflictError(OSError):
    """Another writer changed the config after the caller read it."""


def _canonical_config_path(path: Path) -> Path:
    """Resolve parent directory without following a symlink on the target config filename itself."""
    expanded = path.expanduser()
    if not expanded.name or expanded.name in {".", ".."}:
        raise ValueError(f"Invalid config file path: {path}")
    parent = expanded.parent.resolve()
    candidate = parent / expanded.name
    if candidate.is_symlink():
        raise ValueError(f"Refusing to read or overwrite symlink config path: {candidate}")
    return candidate


def config_revision(path: Path) -> str:
    """Read the revision for an intentional replacement, including an absent file."""
    target = _canonical_config_path(path)
    try:
        return hashlib.sha256(target.read_bytes()).hexdigest()
    except FileNotFoundError:
        return ""


def load_config(path: str | Path | None = None) -> ClusterConfig:
    """Load and validate a ClusterConfig from JSON."""
    cfg_path = resolve_config_path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Cluster config not found at '{cfg_path}'. "
            f"Run `python3 phonecluster_cli.py init-config --output {cfg_path}` first."
        )
    target = _canonical_config_path(cfg_path)
    raw = target.read_bytes()
    config = ClusterConfig.from_dict(json.loads(raw.decode("utf-8")))
    config._source = (target, hashlib.sha256(raw).hexdigest())
    return config


def create_default_config(
    cluster_name: str = "redmi-cluster",
    master_host: str = "192.168.1.201",
    worker_hosts: list[str] | None = None,
    ssh_user: str = "",
    ssh_port: int = DEFAULT_SSH_PORT,
) -> ClusterConfig:
    """Generate a validated default cluster config with a fresh secret token."""
    clean_master = validate_host(master_host)
    clean_user = validate_ssh_user(ssh_user)
    clean_ssh_port = _parse_int_field(ssh_port, DEFAULT_SSH_PORT, "ssh_port")
    if not (1 <= clean_ssh_port <= 65535):
        raise ValueError(f"ssh_port must be between 1 and 65535 (got {ssh_port})")
    raw_workers = worker_hosts if worker_hosts is not None else [
        "192.168.1.202",
        "192.168.1.203",
    ]
    workers: list[str] = []
    for w in raw_workers:
        if w is None:
            continue
        if not isinstance(w, str):
            raise ValueError(f"Worker host must be a string (got {type(w).__name__})")
        if w.strip():
            workers.append(validate_host(w))
    nodes: list[NodeConfig] = [
        NodeConfig(
            id="node0",
            host=clean_master,
            role="master",
            ssh_port=clean_ssh_port,
            ssh_user=clean_user,
            max_concurrency=2,
            weight=1.2,
            tags=["master", "ufs", "5g"],
            notes="Master phone (highest RAM + UFS storage, e.g., Redmi Note 9T / 9 5G)",
        )
    ]
    for idx, host in enumerate(workers, start=1):
        nodes.append(
            NodeConfig(
                id=f"node{idx}",
                host=host,
                role="worker",
                auth_token=generate_auth_token(),
                ssh_port=clean_ssh_port,
                ssh_user=clean_user,
                max_concurrency=2,
                weight=1.0,
                tags=["worker"],
                notes=f"Worker phone {idx}",
            )
        )
    return ClusterConfig(
        cluster_name=str(cluster_name or "phonecluster").strip() or "phonecluster",
        auth_token=generate_auth_token(),
        nodes=nodes,
        safety=SafetyConfig(),
    )


def generate_auth_token() -> str:
    """Return a cryptographically strong URL-safe cluster bearer token."""
    return secrets.token_urlsafe(32)


def save_config(config: ClusterConfig, path: str | Path, *, expected_revision: str | None = None) -> Path:
    """Save if the file still matches the version read, or is absent for a new config."""
    out = _canonical_config_path(Path(path))
    if expected_revision is None:
        expected_revision = config._source[1] if config._source and config._source[0] == out else ""
    payload = (json.dumps(config.to_dict(), indent=2, allow_nan=False) + "\n").encode("utf-8")
    revision = replace_config_file(out, payload, expected_revision)
    config._source = (out, revision)
    return Path(path)


def replace_config_file(out: Path, payload: bytes, expected_revision: str) -> str:
    """Compare and atomically replace validated JSON, retaining the bytes sent by a sync."""
    out = _canonical_config_path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Lock a stable sibling without following symlinks. Locking the config inode itself loses the lock on replace.
    lock_path = out.with_name(f".{out.name}.lock")
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    try:
        st = os.fstat(lock_fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing non-regular config lockfile: {lock_path}")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise PermissionError(f"Config lockfile owned by unexpected UID: {lock_path}")
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(lock_fd, 0o600)
            except OSError:
                pass
    except BaseException:
        os.close(lock_fd)
        raise
    with os.fdopen(lock_fd, "r+b") as lock:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if out.is_symlink():
            raise ValueError(f"Refusing to overwrite symlink config path: {out}")
        if config_revision(out) != expected_revision:
            raise ConfigConflictError(f"Config '{out}' changed on disk. Reload the config and retry.")
        _write_config(out, payload)
    return hashlib.sha256(payload).hexdigest()


def _write_config(out: Path, payload: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", suffix=".tmp", dir=str(out.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(fh.fileno(), 0o600)
                except OSError:
                    pass
            fh.write(payload)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_path, out)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
