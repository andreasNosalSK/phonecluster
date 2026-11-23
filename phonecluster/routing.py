"""Tier-aware auto-routing, pool management, and cross-tier service discovery.

Allows heterogeneous phone clusters (e.g., Tier 1 Termux compute/AI + Tier 2
Debian 13 services + Tier 3 Docker/Droidspaces) to operate as ONE seamless
system where jobs automatically land on the right group of phones and every
tier can talk to services hosted on every other tier without hardcoded IPs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .config import ClusterConfig, NodeConfig

TIER_LABELS: dict[int, str] = {
    1: "Tier 1 · Termux Compute",
    2: "Tier 2 · Debian 13 Services",
    3: "Tier 3 · Docker / Containers",
}

DEFAULT_POOL_BY_TIER: dict[int, str] = {
    1: "compute",
    2: "services",
    3: "docker",
}

# Keyword patterns for transparent automatic workload routing
_DOCKER_RE = re.compile(
    r"(?:^|[\s;&|])(docker|docker-compose|podman|kubectl|k3s|crictl|nerdctl)\b",
    re.IGNORECASE,
)
_SERVICE_RE = re.compile(
    r"(?:^|[\s;&|])(apt|apt-get|apt-cache|dpkg|systemctl|service|mosquitto|mosquitto_pub|mosquitto_sub|"
    r"adguardhome|pihole|hass|zigbee2mqtt|tailscale|wg|wg-quick|iptables|nomad|srun|sinfo|sbatch|"
    r"psql|redis-cli|nginx)\b",
    re.IGNORECASE,
)
_AI_RE = re.compile(
    r"(?:^|[\s;&|])(llama-cli|llama-server|rpc-server|ollama|gguf|whisper)\b",
    re.IGNORECASE,
)


@dataclass
class WorkloadRoute:
    """Routing decision produced by `classify_workload`."""

    category: str  # "docker", "service", "ai", "compute"
    preferred_tiers: list[int]
    preferred_pool: str
    strict: bool
    reason: str
    required_tool: str = ""
    preferred_service: str = ""


def resolve_node_tier_and_pool(
    node: NodeConfig, health: dict[str, Any] | None = None
) -> tuple[int, str]:
    """Resolve effective `(tier, pool)` from explicit config override or live telemetry."""
    h = health or {}
    if node.tier in {1, 2, 3}:
        tier = node.tier
    elif h.get("tier") in {1, 2, 3}:
        tier = int(h["tier"])
    else:
        os_env = str(h.get("os_env", "")).lower()
        tools = h.get("tools") or {}
        if os_env == "termux":
            tier = 1
        elif tools.get("docker"):
            tier = 3
        elif os_env:
            tier = 2
        else:
            tier = 1

    if node.pool and node.pool != "auto":
        pool = node.pool
    elif h.get("pool") and h.get("pool") != "auto" and node.tier == 0:
        pool = str(h["pool"]).lower()
    else:
        pool = DEFAULT_POOL_BY_TIER.get(tier, "compute")

    return tier, pool


def classify_workload(
    command: str | None = None,
    script_content: str | None = None,
    hint: str = "",
) -> WorkloadRoute:
    """Classify a command or script so Auto-Route sends it to the ideal Tier/Pool."""
    clean_hint = (hint or "").strip().lower()
    if clean_hint in {"docker", "container", "k3s", "tier3"}:
        return WorkloadRoute(
            category="docker",
            preferred_tiers=[3],
            preferred_pool="docker",
            strict=True,
            required_tool="docker",
            reason="Explicit Docker/container workload -> Tier 3 (docker pool)",
        )
    if clean_hint in {"service", "services", "debian", "tier2", "mqtt", "adguard"}:
        return WorkloadRoute(
            category="service",
            preferred_tiers=[2, 3],
            preferred_pool="services",
            strict=True,
            reason="Explicit Linux service workload -> Tier 2 (Debian 13 services pool)",
        )
    if clean_hint in {"ai", "llm"}:
        return WorkloadRoute(
            category="ai",
            preferred_tiers=[1, 2, 3],
            preferred_pool="compute",
            strict=False,
            reason="Explicit Local AI workload -> prefers Tier 1 (compute pool)",
        )
    if clean_hint in {"compute", "batch", "tier1", "compiler"}:
        return WorkloadRoute(
            category="compute",
            preferred_tiers=[1, 2, 3],
            preferred_pool="compute",
            strict=False,
            reason="Explicit compute workload -> prefers Tier 1 (compute pool)",
        )

    text = f"{command or ''}\n{(script_content or '')[:600]}"
    m_doc = _DOCKER_RE.search(text)
    if m_doc:
        return WorkloadRoute(
            category="docker",
            preferred_tiers=[3],
            preferred_pool="docker",
            strict=True,
            required_tool="docker",
            reason=f"Detected '{m_doc.group(1)}' -> routed to Tier 3 (docker pool)",
        )

    m_svc = _SERVICE_RE.search(text)
    if m_svc:
        kw = m_svc.group(1)
        return WorkloadRoute(
            category="service",
            preferred_tiers=[2, 3],
            preferred_pool="services",
            strict=True,
            reason=f"Detected '{kw}' (glibc/Debian service) -> routed to Tier 2 (services pool)",
        )

    m_ai = _AI_RE.search(text)
    if m_ai:
        return WorkloadRoute(
            category="ai",
            preferred_tiers=[1, 2, 3],
            preferred_pool="compute",
            strict=False,
            reason=f"Detected '{m_ai.group(1)}' -> prefers Tier 1 (compute/AI pool)",
        )

    return WorkloadRoute(
        category="compute",
        preferred_tiers=[1, 2, 3],
        preferred_pool="compute",
        strict=False,
        reason="General parallel compute -> prefers Tier 1 (compute pool), spills over if busy",
    )


def select_snapshots_for_target(
    snapshots: list[Any],
    target: str,
    route: WorkloadRoute | None = None,
    force: bool = False,
) -> tuple[list[Any], str]:
    """Select eligible `NodeSnapshot` objects for `target` + optional `WorkloadRoute`.

    Supported `target` values:
    - `"auto"`         : smart tier/pool routing based on `route`
    - `"tier:1|2|3"`   : restrict to phones in that Tier
    - `"pool:<name>"`  : restrict to phones in that Pool (e.g. `pool:compute`, `pool:docker`)
    - `"best"` / `"all"`: any ready node across all tiers
    - `"<node_id>"`    : specific node
    """
    ready = [s for s in snapshots if s.online and (s.ready_for_jobs or force)]

    if target.startswith("tier:"):
        raw_t = target.split(":", 1)[1].strip()
        want_tier = int(raw_t) if raw_t.isdigit() else 0
        matched = [
            s for s in ready if resolve_node_tier_and_pool(s.node, s.health)[0] == want_tier
        ]
        return matched, f"Targeted Tier {want_tier} ({len(matched)} ready)"

    if target.startswith("pool:"):
        want_pool = target.split(":", 1)[1].strip().lower()
        matched = [
            s for s in ready if resolve_node_tier_and_pool(s.node, s.health)[1] == want_pool
        ]
        return matched, f"Targeted pool '{want_pool}' ({len(matched)} ready)"

    if target in {"best", "all"}:
        return ready, f"Target '{target}' ({len(ready)} ready across all tiers)"

    if target != "auto":
        matched = [s for s in ready if s.node.id == target]
        return matched, f"Pinned to node '{target}' ({len(matched)} ready)"

    if route is None:
        return ready, f"Target 'auto' ({len(ready)} ready across all tiers)"

    # Smart Auto-Routing across heterogeneous tiers!
    # 1. Exact preferred pool match (also respecting required_tool if set)
    def _has_required_tool(snap: Any) -> bool:
        if not route.required_tool:
            return True
        tools = (snap.health or {}).get("tools") or {}
        t_num, p_name = resolve_node_tier_and_pool(snap.node, snap.health)
        return bool(tools.get(route.required_tool)) or (
            route.required_tool == "docker" and (t_num == 3 or p_name == "docker")
        )

    pool_matches = [
        s
        for s in ready
        if resolve_node_tier_and_pool(s.node, s.health)[1] == route.preferred_pool
        and _has_required_tool(s)
    ]
    if pool_matches:
        return pool_matches, route.reason

    # 2. Try preferred tiers in priority order
    for pref_tier in route.preferred_tiers:
        tier_matches = [
            s
            for s in ready
            if resolve_node_tier_and_pool(s.node, s.health)[0] == pref_tier
            and _has_required_tool(s)
        ]
        if tier_matches:
            return tier_matches, f"{route.reason} (using Tier {pref_tier})"

    # 3. For non-strict workloads (compute/AI), gracefully spill over to any ready phone
    if not route.strict and ready:
        return ready, f"{route.reason} (spilled over to available cluster phones)"

    # 4. Strict workload (e.g. Docker or Debian service) with no compatible ready phone
    return [], (
        f"No ready compatible phone found: {route.reason}. "
        f"Ensure a Tier {'/'.join(str(t) for t in route.preferred_tiers)} node is online and cool."
    )


# ---------------------------------------------------------------------------
# Cross-Tier Live Service Registry & Automatic Environment Injection
# ---------------------------------------------------------------------------

_SERVICE_SPEC: list[tuple[str, str, int, str]] = [
    # (logical_name, telemetry_service_key, port, scheme)
    ("mqtt", "mosquitto_1883", 1883, "mqtt"),
    ("homeassistant", "homeassistant_8123", 8123, "http"),
    ("adguard", "adguard_3000", 3000, "http"),
    ("dns", "dns_53", 53, "dns"),
    ("llama_api", "llama_api_8081", 8081, "http"),
    ("llama_rpc", "llama_rpc_50052", 50052, "tcp"),
    ("distcc", "distccd_3632", 3632, "tcp"),
    ("redis", "redis_6379", 6379, "redis"),
    ("postgres", "postgres_5432", 5432, "postgresql"),
]


def build_service_registry(
    snapshots: list[Any], config: ClusterConfig
) -> list[dict[str, Any]]:
    """Discover all live cross-tier services running across every online phone."""
    entries: list[dict[str, Any]] = []
    for snap in snapshots:
        if not snap.online:
            continue
        h = snap.health or {}
        tier, pool = resolve_node_tier_and_pool(snap.node, h)
        svcs = h.get("services") or {}
        tools = h.get("tools") or {}

        for name, key, port, scheme in _SERVICE_SPEC:
            if svcs.get(key):
                url = f"{scheme}://{snap.node.host}:{port}"
                entries.append(
                    {
                        "name": name,
                        "node_id": snap.node.id,
                        "host": snap.node.host,
                        "port": port,
                        "url": url,
                        "tier": tier,
                        "pool": pool,
                        "ready": snap.ready_for_jobs,
                        "source": "auto",
                    }
                )
        if tools.get("docker") or tier == 3:
            entries.append(
                {
                    "name": "docker",
                    "node_id": snap.node.id,
                    "host": snap.node.host,
                    "port": 0,
                    "url": f"ssh://{snap.node.host}:{snap.node.ssh_port}",
                    "tier": tier,
                    "pool": pool,
                    "ready": snap.ready_for_jobs,
                    "source": "auto",
                }
            )

    for cname, curl in sorted(config.custom_services.items()):
        entries.append(
            {
                "name": cname,
                "node_id": "custom",
                "host": "",
                "port": 0,
                "url": curl,
                "tier": 0,
                "pool": "custom",
                "ready": True,
                "source": "config",
            }
        )
    return entries


def build_cross_tier_env(
    snapshots: list[Any], config: ClusterConfig
) -> dict[str, str]:
    """Generate `PHONECLUSTER_*` service-discovery env vars injected into every job.

    Enables seamless communication across tiers (e.g. a Tier 1 AI script publishing
    to Tier 2 Mosquitto MQTT or calling Tier 3 Home Assistant without hardcoded IPs).
    """
    env: dict[str, str] = {"PHONECLUSTER_CLUSTER_NAME": config.cluster_name}
    master_node = next((n for n in config.nodes if n.role == "master"), config.nodes[0])
    env["PHONECLUSTER_MASTER_HOST"] = master_node.host

    registry = build_service_registry(snapshots, config)
    by_name: dict[str, list[dict[str, Any]]] = {}
    for item in registry:
        by_name.setdefault(item["name"], []).append(item)

    if "mqtt" in by_name:
        first = by_name["mqtt"][0]
        env["PHONECLUSTER_MQTT_HOST"] = first["host"]
        env["PHONECLUSTER_MQTT_PORT"] = str(first["port"])
        env["PHONECLUSTER_MQTT_URL"] = first["url"]
    if "homeassistant" in by_name:
        env["PHONECLUSTER_HOMEASSISTANT_URL"] = by_name["homeassistant"][0]["url"]
    if "adguard" in by_name:
        env["PHONECLUSTER_ADGUARD_URL"] = by_name["adguard"][0]["url"]
    if "dns" in by_name:
        env["PHONECLUSTER_DNS_HOST"] = by_name["dns"][0]["host"]
    if "llama_api" in by_name:
        env["PHONECLUSTER_LLAMA_API_URL"] = by_name["llama_api"][0]["url"]
    if "llama_rpc" in by_name:
        env["PHONECLUSTER_LLAMA_RPC"] = ",".join(
            f"{e['host']}:{e['port']}" for e in by_name["llama_rpc"] if e["ready"]
        )
    if "redis" in by_name:
        env["PHONECLUSTER_REDIS_URL"] = by_name["redis"][0]["url"]
    if "postgres" in by_name:
        env["PHONECLUSTER_POSTGRES_HOST"] = by_name["postgres"][0]["host"]

    # Pool host lists so any node can reach peers in other tiers
    pool_hosts: dict[str, list[str]] = {}
    for snap in snapshots:
        if not snap.online:
            continue
        _t, pool = resolve_node_tier_and_pool(snap.node, snap.health)
        pool_hosts.setdefault(pool, []).append(snap.node.host)
    for pool_name, hosts in sorted(pool_hosts.items()):
        key = re.sub(r"[^A-Z0-9]+", "_", pool_name.upper()).strip("_")
        if key:
            env[f"PHONECLUSTER_POOL_{key}_HOSTS"] = ",".join(hosts)

    for cname, curl in config.custom_services.items():
        key = re.sub(r"[^A-Z0-9]+", "_", cname.upper()).strip("_")
        if key:
            env[f"PHONECLUSTER_SVC_{key}"] = curl

    return env


def build_cluster_dns_hosts(
    snapshots: list[Any], config: ClusterConfig, domain: str = "cluster"
) -> str:
    """Generate an `/etc/hosts` or AdGuard Home DNS rewrite list for friendly cross-tier names."""
    lines: list[str] = [f"# PhoneCluster friendly DNS names (.{domain}) — paste into /etc/hosts or AdGuard Home"]
    for snap in snapshots:
        tier, pool = resolve_node_tier_and_pool(snap.node, snap.health if snap.online else None)
        lines.append(f"{snap.node.host:<16s} {snap.node.id}.{domain}  # Tier {tier} ({pool})")

    registry = build_service_registry(snapshots, config)
    seen_aliases: set[str] = set()
    alias_map = {
        "mqtt": "mqtt",
        "homeassistant": "ha",
        "adguard": "adguard",
        "dns": "dns",
        "llama_api": "ai",
        "redis": "redis",
        "postgres": "db",
    }
    for item in registry:
        alias = alias_map.get(item["name"])
        if alias and item["host"] and alias not in seen_aliases:
            seen_aliases.add(alias)
            lines.append(f"{item['host']:<16s} {alias}.{domain}  # {item['name']} on {item['node_id']} (Tier {item['tier']})")
    return "\n".join(lines) + "\n"


def summarize_pools(snapshots: list[Any]) -> list[dict[str, Any]]:
    """Aggregate cores, RAM, and readiness grouped by Tier & Pool for unified UI display."""
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    for snap in snapshots:
        tier, pool = resolve_node_tier_and_pool(snap.node, snap.health if snap.online else None)
        key = (tier, pool)
        if key not in groups:
            groups[key] = {
                "tier": tier,
                "pool": pool,
                "label": TIER_LABELS.get(tier, f"Tier {tier}") + f" ({pool})",
                "nodes_total": 0,
                "nodes_online": 0,
                "nodes_ready": 0,
                "total_cores": 0,
                "mem_total_mb": 0,
                "mem_available_mb": 0,
                "active_jobs": 0,
                "node_ids": [],
            }
        g = groups[key]
        g["nodes_total"] += 1
        g["node_ids"].append(snap.node.id)
        if snap.online:
            h = snap.health or {}
            g["nodes_online"] += 1
            if snap.ready_for_jobs:
                g["nodes_ready"] += 1
            g["total_cores"] += int(h.get("cpu_cores", 0))
            g["mem_total_mb"] += int(h.get("mem_total_mb", 0))
            g["mem_available_mb"] += int(h.get("mem_available_mb", 0))
            g["active_jobs"] += int(h.get("active_jobs", 0))
    return [groups[k] for k in sorted(groups.keys())]
