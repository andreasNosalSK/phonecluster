"""Cluster configuration loading, validation, and generation."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_WORKER_PORT = 8765
DEFAULT_SSH_PORT = 8022
DEFAULT_CONFIG_PATH = Path("config/cluster.json")


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
        return f"http://{self.host}:{self.worker_port}"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NodeConfig":
        if "id" not in data or "host" not in data:
            raise ValueError(f"Node entry must define 'id' and 'host': {data}")
        role = str(data.get("role", "worker")).lower()
        if role not in {"master", "worker"}:
            raise ValueError(f"Invalid role '{role}' for node '{data['id']}'")
        max_conc = int(data.get("max_concurrency", 2))
        if max_conc < 1:
            raise ValueError(f"max_concurrency must be >= 1 for node '{data['id']}'")
        weight = float(data.get("weight", 1.0))
        if weight <= 0:
            raise ValueError(f"weight must be > 0 for node '{data['id']}'")
        tier = int(data.get("tier", 0))
        if tier not in {0, 1, 2, 3}:
            raise ValueError(f"tier must be 0 (auto), 1, 2, or 3 for node '{data['id']}'")
        pool = str(data.get("pool", "auto")).strip().lower() or "auto"
        return cls(
            id=str(data["id"]),
            host=str(data["host"]),
            role=role,
            worker_port=int(data.get("worker_port", DEFAULT_WORKER_PORT)),
            ssh_port=int(data.get("ssh_port", DEFAULT_SSH_PORT)),
            ssh_user=str(data.get("ssh_user", "")),
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
        if cfg.resume_temp_c > cfg.max_temp_c:
            raise ValueError("safety.resume_temp_c must be <= safety.max_temp_c")
        if not (0 <= cfg.battery_low_pct < cfg.battery_high_pct <= 100):
            raise ValueError(
                "safety battery thresholds must satisfy 0 <= low < high <= 100"
            )
        return cfg


@dataclass
class ClusterConfig:
    """Top-level PhoneCluster configuration."""

    cluster_name: str
    auth_token: str
    nodes: list[NodeConfig]
    safety: SafetyConfig = field(default_factory=SafetyConfig)
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
        raw_svcs = data.get("custom_services") or {}
        custom_services = (
            {str(k): str(v) for k, v in raw_svcs.items()}
            if isinstance(raw_svcs, dict)
            else {}
        )
        return cls(
            cluster_name=str(data.get("cluster_name", "phonecluster")),
            auth_token=token,
            nodes=nodes,
            safety=safety,
            default_job_timeout_sec=int(data.get("default_job_timeout_sec", 600)),
            health_timeout_sec=float(data.get("health_timeout_sec", 3.0)),
            dashboard_port=int(data.get("dashboard_port", 8080)),
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
