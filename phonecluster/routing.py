"""Tier-aware auto-routing, pool management, and cross-tier service discovery.

Allows heterogeneous phone clusters (e.g., Tier 1 Termux compute/AI + Tier 2
Debian 13 services + Tier 3 Docker/Droidspaces) to operate as ONE seamless
system where jobs automatically land on the right group of phones and every
tier can talk to services hosted on every other tier without hardcoded IPs.
"""

from __future__ import annotations

import ipaddress
import math
import posixpath
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .config import (
    ClusterConfig,
    NodeConfig,
    format_host_for_url,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
)
from .discovery import detect_local_ip
from .usbhub import USB_MESH_DEFAULT_PORTS

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
    r"(?:^|[\s;&|])(docker|docker-compose|docker\.compose|podman|kubectl|k3s|crictl|nerdctl|ctr)\b",
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


_SAFE_POOL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def _safe_nonneg_int(val: Any, default: int = 0) -> int:
    try:
        if isinstance(val, bool):
            return default
        f = float(val)
        return max(0, int(f)) if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def resolve_node_tier_and_pool(
    node: NodeConfig, health: dict[str, Any] | None = None
) -> tuple[int, str]:
    """Resolve effective `(tier, pool)` from explicit config override or live telemetry."""
    h = health if isinstance(health, dict) else {}
    h_tier = h.get("tier")
    if node.tier in {1, 2, 3}:
        tier = node.tier
    elif isinstance(h_tier, int) and not isinstance(h_tier, bool) and h_tier in {1, 2, 3}:
        tier = h_tier
    else:
        raw_os = h.get("os_env")
        os_env = raw_os.strip().lower() if isinstance(raw_os, str) else ""
        raw_tools = h.get("tools")
        tools = raw_tools if isinstance(raw_tools, dict) else {}
        if os_env == "termux":
            tier = 1
        elif tools.get("docker"):
            tier = 3
        elif os_env:
            tier = 2
        else:
            tier = 1

    raw_h_pool = h.get("pool")
    if node.pool and node.pool != "auto":
        pool = node.pool
    elif isinstance(raw_h_pool, str) and raw_h_pool.strip() and raw_h_pool.strip().lower() != "auto" and node.tier == 0:
        cand_pool = raw_h_pool.strip().lower()
        pool = cand_pool if _SAFE_POOL_RE.fullmatch(cand_pool) else DEFAULT_POOL_BY_TIER.get(tier, "compute")
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

    # Inline scripts can be in any language. Route complex scripts through a hint
    # and examine command positions in simple shell expressions.
    names: list[str] = []
    for line in (command or "").splitlines():
        lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        at_command = True
        try:
            tokens = list(lexer)
        except ValueError:
            continue
        for token in tokens:
            if all(char in ";&|()" for char in token):
                at_command = True
            elif at_command:
                name = token.strip("\"'")
                if name in {"sudo", "env", "command", "exec"} or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", name):
                    continue
                names.append(posixpath.basename(name))
                at_command = False
    text = " ".join(names)
    m_doc = _DOCKER_RE.search(text)
    if m_doc:
        return WorkloadRoute(
            category="docker",
            preferred_tiers=[3],
            preferred_pool="docker",
            strict=True,
            required_tool={"docker-compose": "docker_compose", "docker.compose": "docker_compose", "kubectl": "k3s"}.get(
                m_doc.group(1).lower(), m_doc.group(1).lower()
            ),
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
    busy_node_ids: set[str] | None = None,
    excluded_node_ids: set[str] | None = None,
) -> tuple[list[Any], str]:
    """Select eligible `NodeSnapshot` objects for `target` + optional `WorkloadRoute`.

    Supported `target` values:
    - `"auto"`         : smart tier/pool routing based on `route`
    - `"tier:1|2|3"`   : restrict to phones in that Tier
    - `"pool:<name>"`  : restrict to phones in that Pool (e.g. `pool:compute`, `pool:docker`)
    - `"best"` / `"all"`: any ready node across all tiers
    - `"<node_id>"`    : specific node

    `excluded_node_ids` (e.g. quarantined phones) are never picked for automatic/pool/broadcast
    routing. `busy_node_ids` allows parallel `map_jobs()` to spill non-strict compute jobs
    immediately onto idle Tier 2/3 phones once Tier 1 slots are saturated.
    """
    excluded = excluded_node_ids or set()
    busy = busy_node_ids or set()
    use_live_busy = busy_node_ids is not None
    ready = [
        s
        for s in snapshots
        if s.online
        and (
            (getattr(s, "healthy_for_scheduling", s.ready_for_jobs) if use_live_busy else s.ready_for_jobs)
            or force
        )
        and (s.node.id not in excluded or (force and target == s.node.id))
        and s.node.id not in busy
    ]

    if target.startswith("tier:"):
        raw_t = target.split(":", 1)[1].strip()
        want_tier = int(raw_t) if raw_t in {"1", "2", "3"} else 0
        if want_tier not in {1, 2, 3}:
            return [], f"Invalid tier target '{target}' (expected tier:1, tier:2, or tier:3)"
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
        raw_tools = (snap.health or {}).get("tools") if isinstance(snap.health, dict) else None
        tools = raw_tools if isinstance(raw_tools, dict) else {}
        if not tools.get(route.required_tool):
            return False
        return route.required_tool not in {"docker", "docker_compose"} or (
            (snap.health or {}).get("docker_socket_accessible") is not False
        )

    pool_matches = [
        s
        for s in ready
        if resolve_node_tier_and_pool(s.node, s.health)[1] == route.preferred_pool
        and (not route.strict or resolve_node_tier_and_pool(s.node, s.health)[0] in route.preferred_tiers)
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
    tool_message = f" with usable {route.required_tool}" if route.required_tool else ""
    return [], (
        f"No ready compatible phone found: {route.reason}. "
        f"Ensure a Tier {'/'.join(str(t) for t in route.preferred_tiers)} node{tool_message} is online and cool."
    )


# ---------------------------------------------------------------------------
# Cross-Tier Live Service Registry & Automatic Environment Injection
# ---------------------------------------------------------------------------

_SERVICE_SPEC: list[tuple[str, str, int, str]] = [
    # (logical_name, telemetry_service_key, port, scheme)
    ("mqtt", "mosquitto_1883", 1883, "mqtt"),
    ("homeassistant", "homeassistant_8123", 8123, "http"),
    ("adguard", "adguard_80", 80, "http"),
    ("adguard", "adguard_3000", 3000, "http"),
    ("dns", "dns_53", 53, "dns"),
    ("llama_api", "llama_api_8081", 8081, "http"),
    ("llama_rpc", "llama_rpc_50052", 50052, "tcp"),
    ("distcc", "distccd_3632", 3632, "tcp"),
    ("docker_swarm", "docker_swarm_2377", 2377, "tcp"),
    ("redis", "redis_6379", 6379, "redis"),
    ("postgres", "postgres_5432", 5432, "postgresql"),
]


def build_service_registry(
    snapshots: list[Any], config: ClusterConfig, *, for_node: NodeConfig | None = None, master_lan_host: str = ""
) -> list[dict[str, Any]]:
    """Discover all live cross-tier services running across every non-quarantined online phone."""
    entries: list[dict[str, Any]] = []
    quarantined = set(config.gateway.quarantined_nodes)
    has_auto_adguard = False
    for snap in snapshots:
        if not snap.online or snap.node.id in quarantined:
            continue
        h = snap.health if isinstance(snap.health, dict) else {}
        tier, pool = resolve_node_tier_and_pool(snap.node, h)
        raw_svcs = h.get("services")
        svcs = raw_svcs if isinstance(raw_svcs, dict) else {}
        raw_tools = h.get("tools")
        tools = raw_tools if isinstance(raw_tools, dict) else {}
        # Build port -> exposed map if telemetry included `/proc/net/tcp*` listening ports
        lp_exposed: dict[int, bool] = {}
        raw_lp = h.get("listening_ports")
        for item in (raw_lp if isinstance(raw_lp, list) else []):
            if isinstance(item, dict) and "port" in item:
                pv = _safe_nonneg_int(item.get("port"), 0)
                if 1 <= pv <= 65535:
                    lp_exposed[pv] = bool(item.get("exposed", True))
        node_is_local = is_loopback_or_unspecified_host(snap.node.host)
        seen_on_node: set[str] = set()

        for name, key, port, scheme in _SERVICE_SPEC:
            if not svcs.get(key) or name in seen_on_node:
                continue
            host = snap.node.host
            transport = "lan"
            loopback_only = lp_exposed.get(port) is False
            if snap.node.adb is not None:
                adb = snap.node.adb
                host = "127.0.0.1"
                if for_node is None or for_node.id != snap.node.id:
                    if not adb.peer_mesh or port not in USB_MESH_DEFAULT_PORTS:
                        continue
                    if for_node is not None and (for_node.adb is None or not for_node.adb.peer_mesh):
                        continue
                    port = adb.mesh_base_port + USB_MESH_DEFAULT_PORTS.index(port)
                    transport = "adb"
                loopback_only = False
            elif for_node is not None:
                if loopback_only and for_node.id == snap.node.id:
                    host = "127.0.0.1"
                    loopback_only = False
                elif loopback_only and not node_is_local:
                    continue
                elif node_is_local and (for_node.adb is not None or not is_loopback_or_unspecified_host(for_node.host)):
                    if snap.node.role != "master" or not master_lan_host or lp_exposed.get(port) is not True:
                        continue
                    host = master_lan_host
            seen_on_node.add(name)
            if name == "adguard":
                has_auto_adguard = True
            url = f"{scheme}://{format_host_port(host, port)}"
            entries.append(
                {
                    "name": name,
                    "node_id": snap.node.id,
                    "host": host,
                    "port": port,
                    "url": url,
                    "tier": tier,
                    "pool": pool,
                    "ready": snap.ready_for_jobs,
                    "loopback_only": loopback_only,
                    "cpu_cores": max(1, min(128, _safe_nonneg_int(h.get("cpu_cores", 4), 4))),
                    "role": snap.node.role,
                    "source": "auto",
                    "transport": transport,
                }
            )
        if tools.get("docker") or tier == 3:
            entries.append(
                {
                    "name": "docker",
                    "node_id": snap.node.id,
                    "host": snap.node.host,
                    "port": 0,
                    "url": f"ssh://{format_host_port(snap.node.host, snap.node.ssh_port)}",
                    "tier": tier,
                    "pool": pool,
                    "ready": snap.ready_for_jobs,
                    "loopback_only": False,
                    "source": "auto",
                }
            )

    if config.network.adguard_url and not has_auto_adguard:
        ag_url = config.network.adguard_url
        try:
            parsed_ag = urllib.parse.urlparse(ag_url)
            ag_host = parsed_ag.hostname or ""
            try:
                ag_port = parsed_ag.port or (443 if parsed_ag.scheme == "https" else 80)
            except ValueError:
                ag_port = 80
        except ValueError:
            ag_host = ""
            ag_port = 80
        entries.append(
            {
                "name": "adguard",
                "node_id": "configured",
                "host": ag_host,
                "port": ag_port,
                "url": ag_url,
                "tier": 0,
                "pool": "network",
                "ready": True,
                "loopback_only": False,
                "source": "network_config",
            }
        )

    for cname, curl in sorted(config.custom_services.items()):
        try:
            parsed = urllib.parse.urlparse(curl)
            c_host = parsed.hostname or ""
            try:
                c_port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else 0))
            except ValueError:
                c_port = 0
        except ValueError:
            c_host = ""
            c_port = 0
        entries.append(
            {
                "name": cname,
                "node_id": "custom",
                "host": c_host,
                "port": c_port,
                "url": curl,
                "tier": 0,
                "pool": "custom",
                "ready": True,
                "loopback_only": False,
                "source": "config",
            }
        )
    return entries


def _pick_primary_service(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer an externally reachable, cool/ready service instance over loopback-only or busy ones."""
    ranked = sorted(
        items,
        key=lambda e: (
            1 if e.get("loopback_only") else 0,
            0 if e.get("ready") else 1,
        ),
    )
    return ranked[0]


def build_cross_tier_env(
    snapshots: list[Any], config: ClusterConfig, *, for_node: NodeConfig | None = None
) -> dict[str, str]:
    """Generate `PHONECLUSTER_*` service-discovery env vars injected into every job.

    Enables seamless communication across tiers (e.g. a Tier 1 AI script publishing
    to Tier 2 Mosquitto MQTT or calling Tier 3 Home Assistant without hardcoded IPs).
    """
    env: dict[str, str] = {"PHONECLUSTER_CLUSTER_NAME": config.cluster_name}
    m_host = ""
    if config.nodes:
        master_node = next((n for n in config.nodes if n.role == "master"), config.nodes[0])
        m_host = normalize_host(master_node.host)
        has_remote_nodes = any(not is_loopback_or_unspecified_host(n.host) for n in config.nodes)
        if is_loopback_or_unspecified_host(m_host) and has_remote_nodes:
            lan_ip = normalize_host(detect_local_ip())
            if lan_ip and not is_loopback_or_unspecified_host(lan_ip):
                m_host = lan_ip
        env["PHONECLUSTER_MASTER_HOST"] = m_host or master_node.host

    registry = build_service_registry(snapshots, config, for_node=for_node, master_lan_host=m_host)
    by_name: dict[str, list[dict[str, Any]]] = {}
    for item in registry:
        by_name.setdefault(item["name"], []).append(item)

    if "mqtt" in by_name:
        first = _pick_primary_service(by_name["mqtt"])
        env["PHONECLUSTER_MQTT_HOST"] = first["host"]
        env["PHONECLUSTER_MQTT_PORT"] = str(first["port"])
        env["PHONECLUSTER_MQTT_URL"] = first["url"]
    if "homeassistant" in by_name:
        env["PHONECLUSTER_HOMEASSISTANT_URL"] = _pick_primary_service(by_name["homeassistant"])["url"]
    if "adguard" in by_name:
        env["PHONECLUSTER_ADGUARD_URL"] = _pick_primary_service(by_name["adguard"])["url"]
    if "dns" in by_name:
        env["PHONECLUSTER_DNS_HOST"] = _pick_primary_service(by_name["dns"])["host"]
    if "llama_api" in by_name:
        env["PHONECLUSTER_LLAMA_API_URL"] = _pick_primary_service(by_name["llama_api"])["url"]
    if "llama_rpc" in by_name:
        rpc_eps = [
            format_host_port(e["host"], int(e["port"]))
            for e in by_name["llama_rpc"]
            if e.get("ready") and not e.get("loopback_only") and e.get("host") and int(e.get("port") or 0) > 0
        ]
        if rpc_eps:
            env["PHONECLUSTER_LLAMA_RPC"] = ",".join(rpc_eps)
    if "distcc" in by_name:
        distcc_entries: list[str] = []
        for e in by_name["distcc"]:
            if not e.get("ready") or e.get("loopback_only"):
                continue
            host_e = str(e.get("host") or "").strip()
            if not host_e:
                continue
            cores = max(1, min(128, int(e.get("cpu_cores", 4))))
            if e.get("transport") == "adb":
                distcc_entries.append(f"{format_host_port(host_e, e['port'])}/{cores},lzo")
            elif is_loopback_or_unspecified_host(host_e):
                distcc_entries.append(f"localhost/{max(1, cores - 2)}")
            elif e.get("role") == "master":
                distcc_entries.append(f"{format_host_for_url(host_e)}/{max(1, cores - 2)},lzo")
            else:
                distcc_entries.append(f"{format_host_for_url(host_e)}/{cores},lzo")
        if distcc_entries:
            env["PHONECLUSTER_DISTCC_HOSTS"] = " ".join(distcc_entries)
    if "redis" in by_name:
        env["PHONECLUSTER_REDIS_URL"] = _pick_primary_service(by_name["redis"])["url"]
    if "postgres" in by_name:
        env["PHONECLUSTER_POSTGRES_HOST"] = _pick_primary_service(by_name["postgres"])["host"]
    if "docker_swarm" in by_name:
        sw = _pick_primary_service(by_name["docker_swarm"])
        if sw.get("host") and int(sw.get("port") or 0) > 0:
            env["PHONECLUSTER_DOCKER_SWARM_MANAGER"] = format_host_port(sw["host"], int(sw["port"]))

    # Pool host lists so any node can reach peers in other tiers (ready non-quarantined nodes listed first)
    quarantined = set(config.gateway.quarantined_nodes)
    pool_hosts: dict[str, list[str]] = {}
    ordered_snaps = sorted(
        (s for s in snapshots if s.online and s.node.id not in quarantined),
        key=lambda s: (0 if s.ready_for_jobs else 1, s.node.id),
    )
    for snap in ordered_snaps:
        if snap.node.adb is not None:
            continue
        _t, pool = resolve_node_tier_and_pool(snap.node, snap.health)
        hosts = pool_hosts.setdefault(pool, [])
        if snap.node.host not in hosts:
            hosts.append(snap.node.host)
    for pool_name, hosts in sorted(pool_hosts.items()):
        key = re.sub(r"[^A-Z0-9]+", "_", pool_name.upper()).strip("_")
        if key:
            env[f"PHONECLUSTER_POOL_{key}_HOSTS"] = ",".join(hosts)

    usb_nodes = [s.node.id for s in ordered_snaps if "usb-hub" in (s.node.tags or []) or s.node.adb is not None]
    if usb_nodes:
        env["PHONECLUSTER_USB_HUB_NODES"] = ",".join(usb_nodes)
    if for_node is not None and (for_node.adb is not None or "usb-hub" in (for_node.tags or [])):
        usb_mode = "adb" if (for_node.adb is not None or "usb-mode:adb" in (for_node.tags or [])) else "rndis"
        env["PHONECLUSTER_USB_MODE"] = usb_mode
        peer_entries: list[str] = []
        if usb_mode == "rndis":
            for snap in ordered_snaps:
                if snap.node.id == for_node.id or snap.node.adb is not None:
                    continue
                if "usb-mode:rndis" in (snap.node.tags or []) or "usb-hub" in (snap.node.tags or []):
                    peer_entries.append(f"{snap.node.id}={snap.node.host}")
        elif for_node.adb is not None and for_node.adb.peer_mesh:
            for snap in ordered_snaps:
                if snap.node.id == for_node.id or snap.node.adb is None or not snap.node.adb.peer_mesh:
                    continue
                for offset, svc_port in enumerate(USB_MESH_DEFAULT_PORTS):
                    peer_entries.append(f"{snap.node.id}:{svc_port}=127.0.0.1:{snap.node.adb.mesh_base_port + offset}")
        if peer_entries:
            env["PHONECLUSTER_USB_PEERS"] = ",".join(peer_entries)

    for cname, curl in config.custom_services.items():
        key = re.sub(r"[^A-Z0-9]+", "_", cname.upper()).strip("_")
        if key:
            env[f"PHONECLUSTER_SVC_{key}"] = curl

    return env


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def build_cluster_dns_hosts(
    snapshots: list[Any], config: ClusterConfig, domain: str = "cluster"
) -> str:
    """Generate an `/etc/hosts` or AdGuard Home DNS rewrite list for friendly cross-tier names."""
    quarantined = set(config.gateway.quarantined_nodes)
    lines: list[str] = [f"# PhoneCluster friendly DNS names (.{domain}) — paste into /etc/hosts or AdGuard Home"]
    for snap in snapshots:
        if snap.node.id in quarantined or snap.node.adb is not None:
            continue
        tier, pool = resolve_node_tier_and_pool(snap.node, snap.health if snap.online else None)
        norm_h = normalize_host(snap.node.host)
        if _is_ip_address(norm_h):
            lines.append(f"{norm_h:<16s} {snap.node.id}.{domain}  # Tier {tier} ({pool})")
        elif norm_h:
            lines.append(f"# {norm_h} -> {snap.node.id}.{domain} (hostname — resolve to IP for /etc/hosts)")

    registry = build_service_registry(snapshots, config)
    # Prefer externally reachable, cool/ready auto-discovered services before loopback/warm duplicates
    ordered_registry = sorted(
        registry,
        key=lambda e: (
            1 if e.get("loopback_only") else 0,
            0 if e.get("ready") else 1,
            0 if e.get("source") == "auto" else 1,
        ),
    )
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
    for item in ordered_registry:
        if item.get("transport") == "adb":
            continue
        alias = alias_map.get(item["name"])
        item_host = normalize_host(str(item.get("host") or ""))
        if alias and item_host and alias not in seen_aliases and _is_ip_address(item_host):
            seen_aliases.add(alias)
            lines.append(f"{item_host:<16s} {alias}.{domain}  # {item['name']} on {item['node_id']} (Tier {item['tier']})")
        elif item.get("source") == "config" and item_host and _is_ip_address(item_host):
            slug = re.sub(r"[^a-z0-9_-]+", "-", str(item["name"]).lower()).strip("-_")
            if slug and slug not in seen_aliases:
                seen_aliases.add(slug)
                safe_url = re.sub(r"[\x00-\x1f\x7f]", "", str(item.get("url") or ""))[:160]
                lines.append(f"{item_host:<16s} {slug}.{domain}  # custom service ({safe_url})")
    return "\n".join(lines) + "\n"


def summarize_pools(
    snapshots: list[Any], quarantined_nodes: set[str] | None = None
) -> list[dict[str, Any]]:
    """Aggregate cores, RAM, and readiness grouped by Tier & Pool for unified UI display."""
    quarantined = quarantined_nodes or set()
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
            h = snap.health if isinstance(snap.health, dict) else {}
            g["nodes_online"] += 1
            if snap.ready_for_jobs and snap.node.id not in quarantined:
                g["nodes_ready"] += 1
            g["total_cores"] += _safe_nonneg_int(h.get("cpu_cores", 0), 0)
            g["mem_total_mb"] += _safe_nonneg_int(h.get("mem_total_mb", 0), 0)
            g["mem_available_mb"] += _safe_nonneg_int(h.get("mem_available_mb", 0), 0)
            g["active_jobs"] += _safe_nonneg_int(h.get("active_jobs", 0), 0)
    return [groups[k] for k in sorted(groups.keys())]
