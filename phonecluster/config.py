"""Cluster configuration loading, validation, and generation."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_WORKER_PORT = 8765
DEFAULT_SSH_PORT = 8022
DEFAULT_GATEWAY_PORT = 8888
DEFAULT_CONFIG_PATH = Path("config/cluster.json")


def normalize_host(host: str) -> str:
    """Normalize a host/IP string (strip whitespace, brackets, and `::ffff:` IPv4-mapped prefix)."""
    h = str(host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip()
    if h.lower().startswith("::ffff:"):
        mapped = h[7:]
        try:
            ipaddress.IPv4Address(mapped)
            return mapped
        except ValueError:
            pass
    return h


def is_loopback_or_unspecified_host(host: str) -> bool:
    """Return True if `host` refers to localhost, loopback, or an unspecified bind address."""
    h = normalize_host(host).lower()
    if not h or h in {"localhost", "0.0.0.0", "::"}:
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
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def validate_node_id(node_id: str) -> str:
    """Validate and return a safe cluster node_id (blocks `:`, `/`, whitespace, and leading `-`)."""
    clean = str(node_id or "").strip()
    if not _NODE_ID_RE.fullmatch(clean):
        raise ValueError(
            f"Invalid node id '{clean}' (must start with alphanumeric and contain only A-Za-z0-9._-, max 40 chars)"
        )
    return clean


def validate_host(host: str) -> str:
    """Validate and return a safe IPv4, IPv6, or RFC hostname (blocks URL/SSH/hosts injection)."""
    raw = str(host or "").strip()
    clean = normalize_host(raw)
    if not clean or len(clean) > 253 or clean.startswith("-"):
        raise ValueError(f"Invalid host '{raw}'")
    if any(c.isspace() or ord(c) < 32 or c in "@/\\?#;'\"" for c in clean):
        raise ValueError(f"Invalid characters in host '{raw}'")
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(clean.rstrip(".")):
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

    @property
    def base_url(self) -> str:
        return f"http://{format_host_port(self.host, self.worker_port)}"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NodeConfig":
        if "id" not in data or "host" not in data:
            raise ValueError(f"Node entry must define 'id' and 'host': {data}")
        node_id = validate_node_id(str(data["id"]))
        host = validate_host(str(data["host"]))
        role = str(data.get("role", "worker")).lower()
        if role not in {"master", "worker"}:
            raise ValueError(f"Invalid role '{role}' for node '{node_id}'")
        worker_port = int(data.get("worker_port", DEFAULT_WORKER_PORT))
        ssh_port = int(data.get("ssh_port", DEFAULT_SSH_PORT))
        if not (0 <= worker_port <= 65535):
            raise ValueError(f"worker_port must be 0..65535 for node '{node_id}'")
        if not (1 <= ssh_port <= 65535):
            raise ValueError(f"ssh_port must be 1..65535 for node '{node_id}'")
        max_conc = int(data.get("max_concurrency", 2))
        if max_conc < 1:
            raise ValueError(f"max_concurrency must be >= 1 for node '{node_id}'")
        weight = float(data.get("weight", 1.0))
        if not math.isfinite(weight) or weight <= 0:
            raise ValueError(f"weight must be a finite number > 0 for node '{node_id}'")
        tier = int(data.get("tier", 0))
        if tier not in {0, 1, 2, 3}:
            raise ValueError(f"tier must be 0 (auto), 1, 2, or 3 for node '{node_id}'")
        pool = validate_pool_name(str(data.get("pool", "auto")))
        ssh_user = validate_ssh_user(str(data.get("ssh_user", "")))
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
            tags=[str(t) for t in data.get("tags", [])],
            notes=str(data.get("notes", "")),
            auth_token=str(data.get("auth_token", "")).strip(),
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
        cfg = cls(
            max_temp_c=float(data.get("max_temp_c", 40.0)),
            resume_temp_c=float(data.get("resume_temp_c", 37.0)),
            min_free_ram_mb=int(data.get("min_free_ram_mb", 256)),
            battery_low_pct=int(data.get("battery_low_pct", 45)),
            battery_high_pct=int(data.get("battery_high_pct", 60)),
            battery_poll_sec=int(data.get("battery_poll_sec", 60)),
            webhook_cooldown_sec=int(data.get("webhook_cooldown_sec", 900)),
            battery_webhook_url=str(data.get("battery_webhook_url", "")),
        )
        if not (math.isfinite(cfg.max_temp_c) and math.isfinite(cfg.resume_temp_c)):
            raise ValueError("safety temperatures must be finite numbers")
        if cfg.resume_temp_c > cfg.max_temp_c:
            raise ValueError("safety.resume_temp_c must be <= safety.max_temp_c")
        if cfg.min_free_ram_mb < 0 or cfg.battery_poll_sec < 1 or cfg.webhook_cooldown_sec < 0:
            raise ValueError("safety min_free_ram_mb/webhook_cooldown_sec must be >= 0 and battery_poll_sec >= 1")
        if not (0 <= cfg.battery_low_pct < cfg.battery_high_pct <= 100):
            raise ValueError(
                "safety battery thresholds must satisfy 0 <= low < high <= 100"
            )
        wb = cfg.battery_webhook_url.strip()
        if wb:
            if any(c.isspace() or ord(c) < 32 for c in wb) or not wb.startswith(("http://", "https://")):
                raise ValueError("safety.battery_webhook_url must be empty or a valid http:// / https:// URL")
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
        mode = str(data.get("mode", "allowlist")).strip().lower()
        if mode not in {"allowlist", "monitor", "block_all"}:
            raise ValueError("gateway.mode must be 'allowlist', 'monitor', or 'block_all'")
        port = int(data.get("port", DEFAULT_GATEWAY_PORT))
        if not (0 <= port <= 65535):
            raise ValueError("gateway.port must be between 0 and 65535")
        raw_allowed = data.get("allowed_domains")
        allowed = (
            [str(d).strip().lower() for d in raw_allowed if str(d).strip()]
            if isinstance(raw_allowed, list)
            else list(DEFAULT_GATEWAY_ALLOWED_DOMAINS)
        )
        raw_blocked = data.get("blocked_domains")
        blocked = (
            [str(d).strip().lower() for d in raw_blocked if str(d).strip()]
            if isinstance(raw_blocked, list)
            else []
        )
        raw_ports = data.get("allowed_ports")
        if isinstance(raw_ports, list) and raw_ports:
            ports = [int(p) for p in raw_ports if 1 <= int(p) <= 65535]
            if not ports:
                ports = [80, 443]
        else:
            ports = [80, 443]
        raw_q = data.get("quarantined_nodes")
        quarantined = (
            sorted({str(n).strip() for n in raw_q if str(n).strip()})
            if isinstance(raw_q, list)
            else []
        )
        max_conn = max(4, min(256, int(data.get("max_connections", 32))))
        idle_to = max(5.0, float(data.get("idle_timeout_sec", 30.0)))
        rpm = max(0, min(10000, int(data.get("max_requests_per_min_per_node", 120))))
        return cls(
            enabled=bool(data.get("enabled", False)),
            bind_host=str(data.get("bind_host", "0.0.0.0")).strip() or "0.0.0.0",
            port=port,
            mode=mode,
            allowed_domains=allowed,
            blocked_domains=blocked,
            allowed_ports=ports,
            block_private_ips=bool(data.get("block_private_ips", True)),
            inject_proxy_env=bool(data.get("inject_proxy_env", True)),
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
        ips = (
            [str(ip).strip() for ip in raw_ips if str(ip).strip()][:32]
            if isinstance(raw_ips, list)
            else []
        )
        return cls(
            enforce_worker_source_ip=bool(data.get("enforce_worker_source_ip", False)),
            require_signed_requests=bool(data.get("require_signed_requests", False)),
            allowed_master_ips=ips,
            adguard_url=str(data.get("adguard_url", "")).strip(),
            lan_subnet=str(data.get("lan_subnet", "")).strip(),
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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClusterConfig":
        raw_nodes = data.get("nodes", [])
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise ValueError("Configuration must contain a non-empty 'nodes' list.")
        nodes = [NodeConfig.from_dict(item) for item in raw_nodes]
        seen_ids: set[str] = set()
        for node in nodes:
            if node.id in seen_ids:
                raise ValueError(f"Duplicate node id '{node.id}' in configuration.")
            seen_ids.add(node.id)
        token = str(data.get("auth_token", "")).strip()
        if not token:
            raise ValueError(
                "Configuration must define a non-empty 'auth_token'. "
                "Run `phonecluster init-config` to generate one."
            )
        safety = SafetyConfig.from_dict(data.get("safety", {}))
        gateway = GatewayConfig.from_dict(data.get("gateway"))
        network = NetworkHardeningConfig.from_dict(data.get("network"))
        raw_svcs = data.get("custom_services") or {}
        custom_services = (
            {str(k): str(v) for k, v in raw_svcs.items()}
            if isinstance(raw_svcs, dict)
            else {}
        )
        default_timeout = int(data.get("default_job_timeout_sec", 600))
        health_timeout = float(data.get("health_timeout_sec", 3.0))
        dash_port = int(data.get("dashboard_port", 8080))
        if default_timeout <= 0:
            raise ValueError("default_job_timeout_sec must be > 0")
        if not math.isfinite(health_timeout) or health_timeout <= 0:
            raise ValueError("health_timeout_sec must be a finite number > 0")
        if not (0 <= dash_port <= 65535):
            raise ValueError("dashboard_port must be between 0 and 65535")
        return cls(
            cluster_name=str(data.get("cluster_name", "phonecluster")),
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
        return asdict(self)

    def token_for_node(self, node: NodeConfig) -> str:
        """Return the least-privilege per-node token if set, else the cluster token."""
        return node.auth_token or self.auth_token

    def get_node(self, node_id: str) -> NodeConfig:
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise KeyError(f"Unknown node id: {node_id}")


def resolve_config_path(path: str | Path | None = None) -> Path:
    """Resolve the config file path from explicit arg, env var, or default."""
    if path:
        return Path(path)
    env_path = os.environ.get("PHONECLUSTER_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_PATH


def load_config(path: str | Path | None = None) -> ClusterConfig:
    """Load and validate a ClusterConfig from JSON."""
    cfg_path = resolve_config_path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Cluster config not found at '{cfg_path}'. "
            f"Run `python3 phonecluster_cli.py init-config --output {cfg_path}` first."
        )
    with cfg_path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return ClusterConfig.from_dict(raw)


def create_default_config(
    cluster_name: str = "redmi-cluster",
    master_host: str = "192.168.1.201",
    worker_hosts: list[str] | None = None,
    ssh_user: str = "",
    ssh_port: int = DEFAULT_SSH_PORT,
) -> ClusterConfig:
    """Generate a ready-to-edit default cluster config with a fresh secret token."""
    workers = worker_hosts if worker_hosts is not None else [
        "192.168.1.202",
        "192.168.1.203",
    ]
    nodes: list[NodeConfig] = [
        NodeConfig(
            id="node0",
            host=master_host,
            role="master",
            ssh_port=ssh_port,
            ssh_user=ssh_user,
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
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                max_concurrency=2,
                weight=1.0,
                tags=["worker"],
                notes=f"Worker phone {idx}",
            )
        )
    return ClusterConfig(
        cluster_name=cluster_name,
        auth_token=secrets.token_urlsafe(32),
        nodes=nodes,
        safety=SafetyConfig(),
    )


def generate_auth_token() -> str:
    """Return a cryptographically strong URL-safe cluster bearer token."""
    return secrets.token_urlsafe(32)


def save_config(config: ClusterConfig, path: str | Path) -> Path:
    """Atomically write a ClusterConfig to disk with restrictive permissions (0600)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config.to_dict(), indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", suffix=".tmp", dir=str(out.parent))
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
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
    return out
