"""Master & Worker network hardening, Raspberry Pi controller detection, and native AdGuard Home helpers.

Zero external dependencies (Python 3 stdlib only). Works on Raspberry Pi / Pi Zero 2 W,
Debian 13 ARM64 chroot, unrooted Android Termux, and generic Linux hosts.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import platform
import shutil
import socket
from pathlib import Path
from typing import Any

from .config import (
    ClusterConfig,
    format_host_for_url,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
)
from .discovery import detect_local_ip
from .routing import build_service_registry, resolve_node_tier_and_pool
from .telemetry import (
    _read_listening_tcp_map,
    detect_os_environment,
    is_local_port_open,
    is_ubuntu_touch_os,
    read_memory_info,
)

KNOWN_CLUSTER_PORTS: set[int] = {
    22,
    53,
    80,
    443,
    1883,
    2377,
    3000,
    3632,
    5432,
    6379,
    7946,
    8022,
    8080,
    8081,
    8123,
    8765,
    8767,
    8888,
    50052,
}


def _read_device_tree_model() -> str:
    for p in (
        Path("/proc/device-tree/model"),
        Path("/sys/firmware/devicetree/base/model"),
    ):
        if p.exists():
            try:
                raw = p.read_text(encoding="utf-8", errors="ignore").replace("\x00", "").strip()
                if raw:
                    return raw
            except OSError:
                pass
    return ""


def infer_lan_subnet(host_ip: str, configured: str = "") -> str:
    """Return configured LAN CIDR or infer a `/24` (IPv4) / `/64` (IPv6) subnet from `host_ip`."""
    if configured:
        try:
            net = ipaddress.ip_network(configured, strict=False)
            return str(net)
        except ValueError:
            pass
    norm_ip = normalize_host(host_ip)
    if norm_ip and "%" not in norm_ip:
        try:
            ip = ipaddress.ip_address(norm_ip)
            if not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast):
                if isinstance(ip, ipaddress.IPv4Address):
                    return str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if isinstance(ip, ipaddress.IPv6Address):
                    return str(ipaddress.ip_network(f"{ip}/64", strict=False))
        except ValueError:
            pass
    return "192.168.1.0/24"


def _effective_master_lan_host(master_host: str, lan_ip: str) -> str:
    """Prefer `master_host` if it is a usable non-loopback IP; otherwise fall back to `lan_ip`."""
    norm_m = normalize_host(master_host)
    if norm_m and not is_loopback_or_unspecified_host(norm_m):
        try:
            ipaddress.ip_address(norm_m)
            return norm_m
        except ValueError:
            pass
    norm_lan = normalize_host(lan_ip)
    if norm_lan and not is_loopback_or_unspecified_host(norm_lan):
        return norm_lan
    return norm_m or norm_lan


def detect_controller_host_info(config: ClusterConfig) -> dict[str, Any]:
    """Inspect the Master machine (Raspberry Pi, Debian 13, Termux, or Linux PC)."""
    model = _read_device_tree_model()
    os_env = detect_os_environment()
    arch = platform.machine()
    mem = read_memory_info()
    lan_ip = detect_local_ip()
    is_pi = "raspberry pi" in model.lower()
    is_termux = os_env == "termux"
    is_ut = is_ubuntu_touch_os(os_env)

    nodes_list = list(config.nodes)
    master_node = next((n for n in nodes_list if n.role == "master"), nodes_list[0])
    subnet_seed = _effective_master_lan_host(master_node.host, lan_ip)
    subnet = infer_lan_subnet(subnet_seed, config.network.lan_subnet)

    adguard_bin = bool(
        shutil.which("AdGuardHome") or Path("/opt/AdGuardHome/AdGuardHome").exists()
    )
    lmap = _read_listening_tcp_map()
    if lmap is not None:
        adguard_local_3000 = adguard_bin and (3000 in lmap)
        adguard_local_53 = adguard_bin and (53 in lmap)
        adguard_local_80 = adguard_bin and (80 in lmap)
    else:
        adguard_local_3000 = adguard_bin and is_local_port_open(3000)
        adguard_local_53 = adguard_bin and is_local_port_open(53)
        adguard_local_80 = adguard_bin and is_local_port_open(80)

    if is_pi:
        kind = "raspberry_pi"
        friendly = model
    elif is_termux:
        kind = "android_termux"
        friendly = f"Android Termux ({arch})"
    elif is_ut:
        kind = "ubuntu_touch"
        friendly = f"Ubuntu Touch ({os_env}, {arch})"
    elif os_env.startswith("debian"):
        kind = "debian_linux"
        friendly = f"Debian Linux ({os_env}, {arch})"
    else:
        kind = "linux"
        friendly = f"Linux ({os_env}, {arch})"

    return {
        "kind": kind,
        "friendly_name": friendly,
        "board_model": model,
        "is_raspberry_pi": is_pi,
        "is_termux": is_termux,
        "is_ubuntu_touch": is_ut,
        "os_env": os_env,
        "arch": arch,
        "lan_ip": lan_ip,
        "master_host": master_node.host,
        "lan_subnet": subnet,
        "mem_total_mb": mem["total_mb"],
        "can_run_native_adguard": (not is_termux) and (not is_ut),
        "docker_required_for_adguard": False,
        "tools": {
            "adguard_native": adguard_bin,
            "nftables": bool(shutil.which("nft")),
            "ufw": bool(shutil.which("ufw")),
            "iptables": bool(shutil.which("iptables")),
            "tailscale": bool(shutil.which("tailscale")),
            "wireguard": bool(shutil.which("wg")),
            "systemctl": bool(shutil.which("systemctl")),
        },
        "local_adguard": {
            "installed": adguard_bin,
            "port_3000": adguard_local_3000,
            "port_80": adguard_local_80,
            "dns_53": adguard_local_53,
        },
    }


def build_adguard_config_snippets(
    snapshots: list[Any], config: ClusterConfig, host_info: dict[str, Any]
) -> dict[str, str]:
    """Generate native AdGuard Home YAML rewrites & old-phone telemetry blocking rules (NO Docker needed!)."""
    registry = build_service_registry(snapshots, config)
    quarantined = set(config.gateway.quarantined_nodes)
    nodes_list = list(config.nodes)
    master_node = next((n for n in nodes_list if n.role == "master"), nodes_list[0])
    master_answer = _effective_master_lan_host(master_node.host, str(host_info.get("lan_ip") or ""))
    rewrite_entries: list[tuple[str, str]] = [("master.cluster", master_answer)]
    seen_domains: set[str] = {"master.cluster"}
    for snap in snapshots:
        if snap.node.id in quarantined:
            continue
        dom = f"{snap.node.id}.cluster"
        raw_h = str(snap.node.host or "").strip()
        if is_loopback_or_unspecified_host(raw_h):
            if snap.node.role == "master" and not is_loopback_or_unspecified_host(master_answer):
                raw_h = master_answer
            else:
                continue
        if dom not in seen_domains and raw_h:
            seen_domains.add(dom)
            rewrite_entries.append((dom, raw_h))

    alias_map = {
        "mqtt": "mqtt.cluster",
        "homeassistant": "ha.cluster",
        "adguard": "adguard.cluster",
        "dns": "dns.cluster",
        "llama_api": "ai.cluster",
        "redis": "redis.cluster",
        "postgres": "db.cluster",
    }
    for item in registry:
        if item.get("loopback_only"):
            continue
        dom = alias_map.get(item["name"])
        raw_ih = str(item.get("host") or "").strip()
        if is_loopback_or_unspecified_host(raw_ih):
            if item.get("node_id") == master_node.id and not is_loopback_or_unspecified_host(master_answer):
                raw_ih = master_answer
            else:
                continue
        if dom and raw_ih and dom not in seen_domains:
            seen_domains.add(dom)
            rewrite_entries.append((dom, raw_ih))

    yaml_lines = [
        "# Paste under `dns:` -> `rewrites:` in /opt/AdGuardHome/AdGuardHome.yaml",
        "# (or add in AdGuard Home Web UI -> Filters -> DNS rewrites)",
        "rewrites:",
    ]
    for dom, ip in rewrite_entries:
        # Quote YAML scalars safely so IPv6 addresses (e.g. "fd00::1") remain valid YAML
        yaml_lines.append(f"  - domain: {json.dumps(dom)}")
        yaml_lines.append(f"    answer: {json.dumps(ip)}")

    worker_ips = [n.host for n in nodes_list if n.role != "master" and n.host]
    client_list = ", ".join(worker_ips) if worker_ips else "192.168.1.202, 192.168.1.203"
    block_rules = "\n".join(
        [
            "! PhoneCluster — Recommended AdGuard Home Custom Filtering Rules",
            "! Paste into AdGuard Home -> Filters -> Custom filtering rules",
            "! Blocks noisy Android / Xiaomi / MIUI / OEM telemetry & crash-upload domains",
            "||tracking.miui.com^",
            "||data.mistat.xiaomi.com^",
            "||data.mistat.intl.xiaomi.com^",
            "||api.ad.xiaomi.com^",
            "||sdkconfig.ad.xiaomi.com^",
            "||sdkconfig.ad.intl.xiaomi.com^",
            "||globalapi.ad.xiaomi.com^",
            "||logupdate.avlyun.sec.miui.com^",
            "||mazu.sec.miui.com^",
            "||diagnose.google.com^",
            "||app-measurement.com^",
            "||firebase-settings.crashlytics.com^",
            f"! Tip: In AdGuard Home -> Settings -> Client settings, add your worker IPs ({client_list})",
            "!      to monitor per-phone DNS queries and optionally block unwanted services per device.",
        ]
    )

    install_cmd = (
        "# Native AdGuard Home on Raspberry Pi / Debian 13 Master (NO Docker required — single ~12 MB Go binary!)\n"
        "sudo bash ~/phonecluster/scripts/setup_pi_master.sh --with-adguard\n"
        "# Or install AdGuard Home standalone directly:\n"
        "curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sudo sh -s -- -v"
    )

    return {
        "rewrites_yaml": "\n".join(yaml_lines) + "\n",
        "worker_block_rules": block_rules + "\n",
        "native_install_cmd": install_cmd + "\n",
    }


def build_firewall_guides(config: ClusterConfig, host_info: dict[str, Any]) -> dict[str, str]:
    """Generate tailored `nftables`, `ufw`, and Home Router WAN-block rules for this exact cluster."""
    subnet = host_info["lan_subnet"]
    dash_port = int(config.dashboard_port or 8080)
    gw_port = int(config.gateway.port or 8888)
    nodes_list = list(config.nodes)
    master_node = next((n for n in nodes_list if n.role == "master"), nodes_list[0])
    master_worker_port = int(master_node.worker_port or 8765)
    workers = [n for n in nodes_list if n.role != "master"]
    ssh_ports: list[int] = []
    if not host_info.get("is_termux"):
        ssh_ports.append(22)
    cfg_ssh = int(master_node.ssh_port or 22)
    if cfg_ssh > 0 and cfg_ssh not in ssh_ports:
        ssh_ports.append(cfg_ssh)

    has_docker_nodes = bool(host_info.get("is_ubuntu_touch")) or any(
        n.tier == 3 or n.pool == "docker" for n in nodes_list
    )
    docker_tcp = {2377, 7946} if has_docker_nodes else set()
    udp_ports = sorted({53, 8766} | ({4789, 7946} if has_docker_nodes else set()))
    udp_port_list = ", ".join(str(p) for p in udp_ports)

    tcp_ports = sorted(
        p
        for p in (
            set(ssh_ports)
            | docker_tcp
            | {
                dash_port,
                master_worker_port,
                gw_port,
                53,
                80,
                1883,
                3000,
                3632,
                8081,
                8123,
                8767,
                50052,
            }
        )
        if 1 <= p <= 65535
    )
    tcp_port_list = ", ".join(str(p) for p in tcp_ports)
    ssh_port_list = ", ".join(str(p) for p in ssh_ports)
    is_v6_subnet = ":" in subnet
    addr_match = f"ip6 saddr {subnet}" if is_v6_subnet else f"ip saddr {subnet}"
    extra_family_lines: list[str] = []
    if is_v6_subnet:
        raw_v4_lan = normalize_host(str(host_info.get("lan_ip") or ""))
        v4_lan = ""
        if raw_v4_lan and not is_loopback_or_unspecified_host(raw_v4_lan):
            try:
                v4_addr = ipaddress.ip_address(raw_v4_lan)
                if isinstance(v4_addr, ipaddress.IPv4Address) and not (v4_addr.is_link_local or v4_addr.is_multicast):
                    v4_lan = str(ipaddress.ip_network(f"{v4_addr}/24", strict=False))
            except ValueError:
                v4_lan = ""
        if v4_lan:
            extra_family_lines.append(f"    # Also allow IPv4 LAN ({v4_lan}) for IPv4 SSH, workers, and UDP discovery")
            extra_family_lines.append(f"    ip saddr {v4_lan} tcp dport {{ {tcp_port_list} }} accept")
            extra_family_lines.append(f"    ip saddr {v4_lan} udp dport {{ {udp_port_list} }} accept")
    else:
        extra_family_lines.append("    # Keep link-local IPv6 SSH reachable (prevents mDNS/.local SSH lockout)")
        extra_family_lines.append(f"    ip6 saddr fe80::/10 tcp dport {{ {ssh_port_list} }} accept")

    worker_v4_ips: list[str] = []
    worker_v6_ips: list[str] = []
    rndis_worker_v4_ips: list[str] = []
    for w in workers:
        wh = normalize_host(w.host)
        if not wh or is_loopback_or_unspecified_host(wh):
            continue
        try:
            wa = ipaddress.ip_address(wh)
            if isinstance(wa, ipaddress.IPv4Address):
                if str(wa) not in worker_v4_ips:
                    worker_v4_ips.append(str(wa))
                if "usb-mode:rndis" in (w.tags or []) and str(wa) not in rndis_worker_v4_ips:
                    rndis_worker_v4_ips.append(str(wa))
            elif isinstance(wa, ipaddress.IPv6Address) and str(wa) not in worker_v6_ips:
                worker_v6_ips.append(str(wa))
        except ValueError:
            continue
    worker_blocked_tcp = sorted(
        p for p in (set(ssh_ports) | {dash_port, master_worker_port, 80, 3000, 3632, 8767, 50052})
        if 1 <= p <= 65535 and p != gw_port and p != 53
    )
    worker_restrict_lines: list[str] = []
    if worker_blocked_tcp and (worker_v4_ips or worker_v6_ips):
        w_port_list = ", ".join(str(p) for p in worker_blocked_tcp)
        worker_restrict_lines.append("")
        worker_restrict_lines.append(
            "    # Restrict untrusted worker phones from Master admin/compute ports (allow Network Guard & DNS only)"
        )
        if worker_v4_ips:
            worker_restrict_lines.append(
                f"    ip saddr {{ {', '.join(worker_v4_ips)} }} tcp dport {{ {w_port_list} }} drop"
            )
        if worker_v6_ips:
            worker_restrict_lines.append(
                f"    ip6 saddr {{ {', '.join(worker_v6_ips)} }} tcp dport {{ {w_port_list} }} drop"
            )
    if rndis_worker_v4_ips and 1 <= gw_port <= 65535:
        extra_family_lines.append("    # Allow RNDIS /30 USB-hub phones to reach Master Network Guard proxy only")
        extra_family_lines.append(
            f"    ip saddr {{ {', '.join(rndis_worker_v4_ips)} }} tcp dport {gw_port} accept"
        )

    nft_lines = [
        "#!/usr/sbin/nft -f",
        "# Hardened PhoneCluster Master Firewall (Raspberry Pi / Debian 13 / Ubuntu Touch)",
        f"# Allows LAN ({subnet}) + Tailscale/WireGuard ONLY; drops unsolicited WAN traffic.",
        "# NOTE: Scoped to its own table (no `flush ruleset` / forward drop) so Docker/NAT chains stay intact.",
        "table inet phonecluster_master",
        "delete table inet phonecluster_master",
        "",
        "table inet phonecluster_master {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    iif lo accept",
        "    ct state established,related accept",
        "    ip protocol icmp accept",
        "    ip6 nexthdr ipv6-icmp accept",
        "",
        "    # Allow Tailscale / WireGuard overlay if used",
        '    iifname { "tailscale0", "wg0" } accept',
    ]
    nft_lines.extend(worker_restrict_lines)
    nft_lines.extend(
        [
            "",
            f"    # Allow LAN ({subnet}) access to SSH, Dashboard, Worker, Pairing, Network Guard, AdGuard & Shared Services",
            f"    {addr_match} tcp dport {{ {tcp_port_list} }} accept",
            f"    {addr_match} udp dport {{ {udp_port_list} }} accept",
        ]
    )
    nft_lines.extend(extra_family_lines)
    nft_lines.extend(
        [
            "  }",
            "  chain output {",
            "    type filter hook output priority 0; policy accept;",
            "  }",
            "}",
        ]
    )
    nft_rules = "\n".join(nft_lines)

    ufw_lines = [
        f"# Quick UFW Hardening for Raspberry Pi / Debian 13 Master (LAN: {subnet})",
        "sudo ufw default deny incoming",
        "sudo ufw default allow outgoing",
        "# Keep Tailscale / WireGuard overlay interfaces reachable so VPN SSH sessions never lock out",
        "sudo ufw allow in on tailscale0 comment 'Tailscale overlay'",
        "sudo ufw allow in on wg0 comment 'WireGuard overlay'",
    ]
    for sp in ssh_ports:
        ufw_lines.append(f"sudo ufw allow from {subnet} to any port {sp} proto tcp comment 'PhoneCluster SSH'")
    ufw_lines.extend(
        [
            f"sudo ufw allow from {subnet} to any port {dash_port} proto tcp comment 'PhoneCluster Web UI'",
            f"sudo ufw allow from {subnet} to any port {master_worker_port} proto tcp comment 'PhoneCluster Master Worker'",
            f"sudo ufw allow from {subnet} to any port 8767 proto tcp comment 'PhoneCluster Pairing Window'",
            f"sudo ufw allow from {subnet} to any port 8766 proto udp comment 'PhoneCluster LAN Discovery/Pairing Beacon'",
            f"sudo ufw allow from {subnet} to any port {gw_port} proto tcp comment 'PhoneCluster Network Guard Proxy'",
            f"sudo ufw allow from {subnet} to any port 53 comment 'Native AdGuard Home DNS'",
            f"sudo ufw allow from {subnet} to any port 80 proto tcp comment 'AdGuard Home Web UI'",
            f"sudo ufw allow from {subnet} to any port 3000 proto tcp comment 'AdGuard Home Setup UI'",
            f"sudo ufw allow from {subnet} to any port 1883 proto tcp comment 'Cluster MQTT Broker'",
            f"sudo ufw allow from {subnet} to any port 3632 proto tcp comment 'Cluster distcc'",
            f"sudo ufw allow from {subnet} to any port 8081 proto tcp comment 'Cluster llama.cpp API'",
            f"sudo ufw allow from {subnet} to any port 8123 proto tcp comment 'Cluster Home Assistant'",
            f"sudo ufw allow from {subnet} to any port 50052 proto tcp comment 'Cluster llama.cpp RPC'",
        ]
    )
    if has_docker_nodes:
        ufw_lines.extend(
            [
                f"sudo ufw allow from {subnet} to any port 2377 proto tcp comment 'Docker Swarm Management (LAN)'",
                f"sudo ufw allow from {subnet} to any port 7946 comment 'Docker Swarm Node Discovery (LAN)'",
                f"sudo ufw allow from {subnet} to any port 4789 proto udp comment 'Docker Swarm Overlay VXLAN (LAN)'",
            ]
        )
    if rndis_worker_v4_ips and 1 <= gw_port <= 65535:
        for rip in rndis_worker_v4_ips:
            ufw_lines.append(
                f"sudo ufw allow from {rip} to any port {gw_port} proto tcp comment 'RNDIS USB Hub Network Guard'"
            )
    if worker_blocked_tcp and (worker_v4_ips or worker_v6_ips):
        ufw_lines.append("# Restrict untrusted worker phones from Master admin/compute ports (prepended ahead of LAN allows)")
        for wip in (*worker_v4_ips, *worker_v6_ips):
            for bp in worker_blocked_tcp:
                ufw_lines.append(
                    f"sudo ufw insert 1 deny from {wip} to any port {bp} proto tcp comment 'Isolate worker from Master admin'"
                )
    ufw_lines.append("sudo ufw enable && sudo ufw status verbose")
    ufw_cmds = "\n".join(ufw_lines)

    eff_master_host = _effective_master_lan_host(master_node.host, str(host_info.get("lan_ip") or ""))
    router_lines = [
        "# Home Router Firewall / Parental Control Checklist (Air-Gap Old Worker Phones)",
        f"1. KEEP WAN ALLOWED for Master ({master_node.id}): {eff_master_host}",
        "2. BLOCK OUTBOUND & INBOUND WAN (keep LAN open!) for these worker phones:",
    ]
    if workers:
        for w in workers:
            router_lines.append(f"   - {w.id:<8s} -> {w.host:<16s}  (Tier {w.tier or 'auto'}, pool: {w.pool})")
    else:
        router_lines.append("   - (No worker phones added yet — pair them in Tab 6 first!)")
    router_lines.extend(
        [
            f"3. Set your router's LAN DNS server to your AdGuard Home IP (e.g. {eff_master_host}) if running AdGuard natively.",
            f"4. Turn ON Master Network Guard (port {gw_port}) in Tab 5 so approved worker jobs reach allowlisted sites via Master.",
            "5. Click 'Verify Router WAN Block on Workers' in Tab 5 to confirm direct WAN is blocked!",
        ]
    )

    return {
        "nftables": nft_rules + "\n",
        "ufw": ufw_cmds + "\n",
        "router_checklist": "\n".join(router_lines) + "\n",
    }


def apply_security_profile(config: ClusterConfig, profile: str) -> dict[str, Any]:
    """Apply a 1-click network security profile (`standard`, `airgap_workers`, or `lockdown`)."""
    clean = str(profile or "").strip().lower()
    if clean not in {"standard", "airgap_workers", "lockdown"}:
        raise ValueError("profile must be 'standard', 'airgap_workers', or 'lockdown'")
    master_node = next((n for n in config.nodes if n.role == "master"), config.nodes[0])
    m_host = normalize_host(master_node.host)
    if m_host and not is_loopback_or_unspecified_host(m_host) and m_host not in config.network.allowed_master_ips:
        config.network.allowed_master_ips.append(m_host)
    if is_loopback_or_unspecified_host(m_host):
        lan_ip = normalize_host(detect_local_ip())
        if lan_ip and not is_loopback_or_unspecified_host(lan_ip) and lan_ip not in config.network.allowed_master_ips:
            config.network.allowed_master_ips.append(lan_ip)

    if clean == "standard":
        config.gateway.enabled = False
        config.dashboard_require_auth = False
        config.network.enforce_worker_source_ip = False
        config.network.require_signed_requests = False
        desc = "Standard Home LAN — Network Guard OFF, direct LAN communication (HMAC-signed Master requests)."
    elif clean == "airgap_workers":
        config.gateway.enabled = True
        config.gateway.mode = "allowlist"
        config.gateway.block_private_ips = True
        config.gateway.inject_proxy_env = True
        config.gateway.max_requests_per_min_per_node = max(60, config.gateway.max_requests_per_min_per_node or 120)
        desc = "Air-Gapped Old Phones — Master Allowlist Proxy ON, SSRF Guard ON, Per-Worker Rate Limit ON."
    else:
        config.gateway.enabled = True
        config.gateway.mode = "block_all"
        config.gateway.block_private_ips = True
        config.gateway.inject_proxy_env = True
        config.gateway.max_requests_per_min_per_node = 60
        config.dashboard_require_auth = True
        config.network.enforce_worker_source_ip = True
        config.network.require_signed_requests = True
        desc = "Maximum Lockdown — Strict Air-Gap (block_all), Dashboard Read-Auth Lock ON, Worker Master-IP Allowlist ON, Strict Signed-Only HMAC Auth ON."

    return {"profile": clean, "description": desc}


def audit_cluster_network(
    controller: Any,
    gateway_manager: Any | None = None,
    snapshots: list[Any] | None = None,
) -> dict[str, Any]:
    """Produce a unified Master + Worker network hardening report, score, and copyable guides."""
    lock = getattr(controller, "config_lock", None)
    if lock is not None:
        with lock:
            config: ClusterConfig = ClusterConfig.from_dict(controller.config.to_dict())
    else:
        config = controller.config
    snaps = snapshots if snapshots is not None else controller.poll_health()
    host_info = detect_controller_host_info(config)

    # Detect AdGuard Home anywhere in the cluster or explicitly configured
    adguard_url = config.network.adguard_url
    adguard_node = "custom" if adguard_url else ""
    if not adguard_url:
        local_ag_host = (
            host_info.get("lan_ip") or host_info["master_host"]
            if is_loopback_or_unspecified_host(host_info["master_host"])
            else host_info["master_host"]
        )
        if host_info["local_adguard"]["port_80"]:
            adguard_url = f"http://{format_host_for_url(local_ag_host)}"
            adguard_node = "master (local)"
        elif host_info["local_adguard"]["port_3000"]:
            adguard_url = f"http://{format_host_port(local_ag_host, 3000)}"
            adguard_node = "master (local)"
        else:
            quarantined_set = set(config.gateway.quarantined_nodes)
            for s in snaps:
                if not s.online or s.node.id in quarantined_set:
                    continue
                raw_svcs = (s.health or {}).get("services") if isinstance(s.health, dict) else None
                svcs = raw_svcs if isinstance(raw_svcs, dict) else {}
                if svcs.get("adguard_80"):
                    adguard_url = f"http://{format_host_for_url(s.node.host)}"
                    adguard_node = s.node.id
                    break
                if svcs.get("adguard_3000"):
                    adguard_url = f"http://{format_host_port(s.node.host, 3000)}"
                    adguard_node = s.node.id
                    break

    checks: list[dict[str, str]] = []
    score = 0

    # 1. Per-node token isolation (20 pts)
    workers = [n for n in config.nodes if n.role != "master"]
    tok_counts = collections.Counter(n.auth_token for n in workers if n.auth_token)
    shared_master = [n.id for n in workers if not n.auth_token or n.auth_token == config.auth_token]
    dup_workers = [n.id for n in workers if n.auth_token and n.auth_token != config.auth_token and tok_counts[n.auth_token] > 1]
    if not workers or (not shared_master and not dup_workers):
        score += 20
        checks.append({
            "name": "Per-Worker Token Isolation",
            "status": "ok",
            "detail": "Every worker uses a unique least-privilege token (Master admin token stays private).",
            "fix": "",
        })
    else:
        parts: list[str] = []
        if shared_master:
            parts.append(f"sharing Master token: {', '.join(shared_master)}")
        if dup_workers:
            parts.append(f"sharing duplicate worker token: {', '.join(dup_workers)}")
        checks.append({
            "name": "Per-Worker Token Isolation",
            "status": "warn",
            "detail": f"Worker(s) {'; '.join(parts)}",
            "fix": "Re-pair via Tab 6 (`pc pair` + `pc join`) so each phone gets an isolated unique token.",
        })

    # 2. Dashboard Read-Auth Lockdown (15 pts)
    if config.dashboard_require_auth:
        score += 15
        checks.append({
            "name": "Dashboard Read-Auth Lock",
            "status": "ok",
            "detail": "Enabled — even read-only cluster metrics require your Master auth token.",
            "fix": "",
        })
    else:
        checks.append({
            "name": "Dashboard Read-Auth Lock",
            "status": "info",
            "detail": "Read-only stats visible on LAN (controls still require token).",
            "fix": "Toggle ON below if on shared/dorm Wi-Fi.",
        })

    # 3. Worker Source-IP Master Allowlist (15 pts — verifies live enforcement on non-quarantined online workers!)
    quarantined_ids = set(config.gateway.quarantined_nodes)
    online_workers = [s for s in snaps if s.online and s.node.role != "master" and s.node.id not in quarantined_ids]
    if config.network.enforce_worker_source_ip:
        unsynced = [
            s.node.id
            for s in online_workers
            if not bool((s.health if isinstance(s.health, dict) else {}).get("source_ip_allowlist_active", False))
        ]
        if unsynced:
            score += 7 if config.network.allowed_master_ips else 5
            empty_note = " (`allowed_master_ips` is also empty)" if not config.network.allowed_master_ips else ""
            checks.append({
                "name": "Worker Master-IP Firewall Allowlist",
                "status": "warn",
                "detail": f"Enabled in Master config, but not yet active on online worker(s): {', '.join(unsynced)}{empty_note}",
                "fix": "Click 'Push Live Policy to All Workers' below (or run `pc push-config`) to activate immediately without SSH.",
            })
        elif online_workers:
            score += 15
            checks.append({
                "name": "Worker Master-IP Firewall Allowlist",
                "status": "ok",
                "detail": "Active — online workers reject HTTP :8765 connections from any IP except your Master.",
                "fix": "",
            })
        elif not config.network.allowed_master_ips:
            score += 5
            checks.append({
                "name": "Worker Master-IP Firewall Allowlist",
                "status": "warn",
                "detail": "Enabled in config, but `allowed_master_ips` is empty.",
                "fix": "Add your Master LAN IP in Tab 5 and push live policy to workers.",
            })
        elif workers:
            score += 7
            checks.append({
                "name": "Worker Master-IP Firewall Allowlist",
                "status": "info",
                "detail": "Enabled in Master config — awaiting online workers to verify live enforcement.",
                "fix": "Bring worker phones online and click 'Push Live Policy to All Workers'.",
            })
        else:
            score += 15
            checks.append({
                "name": "Worker Master-IP Firewall Allowlist",
                "status": "ok",
                "detail": "Configured — new workers will enforce Master-IP allowlist upon pairing/sync.",
                "fix": "",
            })
    else:
        checks.append({
            "name": "Worker Master-IP Firewall Allowlist",
            "status": "info",
            "detail": "Disabled (workers accept token-authenticated requests from any LAN IP).",
            "fix": "Enable below once Master has a static DHCP IP — Master pushes it live to all online workers automatically.",
        })

    # 4. Master Network Guard (20 pts)
    gw = config.gateway
    gw_status_snap = gateway_manager.status(include_events=1) if gateway_manager is not None else None
    if gateway_manager is not None:
        gw_running = bool(gateway_manager.is_running)
    elif gw.enabled:
        gw_p = int(gw.port or 0)
        if gw_p > 0:
            lmap_gw = _read_listening_tcp_map()
            if lmap_gw is not None:
                gw_running = gw_p in lmap_gw
            else:
                bind_h = normalize_host(gw.bind_host)
                gw_running = False
                if bind_h and not is_loopback_or_unspecified_host(bind_h):
                    try:
                        with socket.create_connection((bind_h, gw_p), timeout=0.25):
                            gw_running = True
                    except OSError:
                        gw_running = False
                if not gw_running:
                    gw_running = is_local_port_open(gw_p)
        else:
            gw_running = False
    else:
        gw_running = False
    if gw.enabled and not gw_running:
        score += 5
        last_err_val = (gw_status_snap or {}).get("last_error") or ""
        err_note = f" ({last_err_val})" if last_err_val else ""
        checks.append({
            "name": "Master Network Guard (WAN Filter)",
            "status": "warn",
            "detail": f"Enabled in config ({gw.mode}), but proxy is NOT currently listening on port {gw.port}{err_note}.",
            "fix": "Check if another process uses that port or change the proxy port in Tab 5 and click Save & Apply.",
        })
    elif gw.enabled and gw.mode in {"allowlist", "block_all"} and gw.block_private_ips:
        score += 20
        checks.append({
            "name": "Master Network Guard (WAN Filter)",
            "status": "ok",
            "detail": f"Active ({gw.mode}, SSRF guard ON, listening={gw_running}).",
            "fix": "",
        })
    elif gw.enabled:
        score += 10
        checks.append({
            "name": "Master Network Guard (WAN Filter)",
            "status": "warn",
            "detail": f"Enabled in '{gw.mode}' mode (SSRF guard={'ON' if gw.block_private_ips else 'OFF'}).",
            "fix": "Switch to 'allowlist' (or 'block_all') and keep SSRF Guard ON for old unrooted phones.",
        })
    else:
        checks.append({
            "name": "Master Network Guard (WAN Filter)",
            "status": "info",
            "detail": "OFF (Direct LAN mode — optional).",
            "fix": "Apply the 'Air-Gapped Old Phones' profile below if blocking WAN on old workers.",
        })

    # 5. Per-worker rate quota (10 pts)
    if gw.max_requests_per_min_per_node > 0:
        score += 10
        checks.append({
            "name": "Per-Worker Proxy Rate Quota",
            "status": "ok",
            "detail": f"Capped at {gw.max_requests_per_min_per_node} requests/min per phone (blocks runaway/flooding devices).",
            "fix": "",
        })
    else:
        checks.append({
            "name": "Per-Worker Proxy Rate Quota",
            "status": "warn",
            "detail": "Unlimited proxy requests per worker.",
            "fix": "Set a per-worker quota (e.g. 60–120 req/min) to protect Master/Pi bandwidth.",
        })

    # 6. AdGuard Home / Local DNS (10 pts)
    if adguard_url:
        score += 10
        checks.append({
            "name": "Native AdGuard Home / Local DNS",
            "status": "ok",
            "detail": f"Detected on {adguard_node}: {adguard_url} (no Docker required!).",
            "fix": "",
        })
    else:
        checks.append({
            "name": "Native AdGuard Home / Local DNS",
            "status": "info",
            "detail": "Not detected yet. AdGuard Home runs natively (~12 MB Go binary, NO Docker needed) on Raspberry Pi or Tier 2 Debian.",
            "fix": "Use the 1-line native installer in the AdGuard & Pi card below.",
        })

    # 7. Per-node listening port attack-surface audit (10 pts)
    allowed_ports = KNOWN_CLUSTER_PORTS | {
        config.dashboard_port,
        config.gateway.port,
    }
    if gateway_manager is not None and gateway_manager.is_running and gateway_manager.bound_port > 0:
        allowed_ports.add(gateway_manager.bound_port)
    for n in config.nodes:
        allowed_ports.add(n.worker_port)
        allowed_ports.add(n.ssh_port)
        if n.adb is not None:
            allowed_ports.add(n.adb.remote_worker_port)
            allowed_ports.add(n.adb.remote_ssh_port)

    gw_per_node = (
        (gw_status_snap or {}).get("stats", {}).get("per_node", {})
        if gw_status_snap is not None
        else {}
    )
    worker_surface: list[dict[str, Any]] = []
    any_unexpected = False
    for snap in snaps:
        h = snap.health if (snap.online and isinstance(snap.health, dict)) else {}
        tier, pool = resolve_node_tier_and_pool(snap.node, h if snap.online else None)
        raw_ports = h.get("listening_ports")
        exposed_ports: list[int] = []
        if isinstance(raw_ports, list):
            for p in raw_ports:
                if isinstance(p, dict) and p.get("exposed"):
                    raw_pv = p.get("port", 0)
                    if isinstance(raw_pv, bool):
                        continue
                    try:
                        pv = int(raw_pv)
                        if 1 <= pv <= 65535:
                            exposed_ports.append(pv)
                    except (TypeError, ValueError, OverflowError):
                        pass
        unexpected = [p for p in exposed_ports if p not in allowed_ports]
        if unexpected:
            any_unexpected = True
        p_stats = gw_per_node.get(snap.node.id, {"allowed": 0, "blocked": 0})
        worker_surface.append(
            {
                "id": snap.node.id,
                "role": snap.node.role,
                "host": snap.node.host,
                "tier": tier,
                "pool": pool,
                "online": snap.online,
                "token_isolated": snap.node.role == "master" or bool(snap.node.auth_token and snap.node.auth_token != config.auth_token),
                "source_ip_allowlist_active": bool(h.get("source_ip_allowlist_active", False)),
                "quarantined": snap.node.id in gw.quarantined_nodes,
                "exposed_ports": exposed_ports,
                "unexpected_ports": unexpected,
                "proxy_allowed": p_stats.get("allowed", 0),
                "proxy_blocked": p_stats.get("blocked", 0),
            }
        )

    if not any_unexpected:
        score += 10
        checks.append({
            "name": "Cluster Open-Port Attack Surface",
            "status": "ok",
            "detail": "No unexpected externally-listening TCP ports detected across online nodes.",
            "fix": "",
        })
    else:
        flagged = [f"{w['id']}:{w['unexpected_ports']}" for w in worker_surface if w["unexpected_ports"]]
        checks.append({
            "name": "Cluster Open-Port Attack Surface",
            "status": "warn",
            "detail": f"Unexpected externally bound port(s) detected: {', '.join(flagged)}",
            "fix": "Inspect running services on those phones (`pc top`) or quarantine if unrecognized.",
        })

    # 8. Replay-Proof HMAC-SHA256 Master->Worker Request Signing status (informational / strict enforcement check)
    if config.network.require_signed_requests:
        unsynced_hmac = [
            s.node.id
            for s in online_workers
            if not bool((s.health if isinstance(s.health, dict) else {}).get("require_signed_requests", False))
        ]
        if unsynced_hmac:
            checks.append({
                "name": "HMAC-Signed Master->Worker Auth",
                "status": "warn",
                "detail": f"Strict HMAC-only mode enabled in Master config, pending live push to: {', '.join(unsynced_hmac)}",
                "fix": "Click 'Push Live Policy to All Workers' (or run `pc push-config`) to disable legacy Bearer fallback.",
            })
        else:
            checks.append({
                "name": "HMAC-Signed Master->Worker Auth",
                "status": "ok",
                "detail": "Strict mode active — Master signs all requests with replay-proof HMAC-SHA256 and workers reject raw Bearer tokens.",
                "fix": "",
            })
    else:
        checks.append({
            "name": "HMAC-Signed Master->Worker Auth",
            "status": "ok",
            "detail": "Master signs all worker requests with replay-proof HMAC-SHA256 (zero raw tokens on Wi-Fi; legacy Bearer fallback still allowed unless Lockdown is enabled).",
            "fix": "",
        })

    grade = "Strong" if score >= 80 else ("Good" if score >= 55 else "Basic")

    return {
        "score": score,
        "grade": grade,
        "host_info": host_info,
        "adguard_url": adguard_url,
        "adguard_node": adguard_node,
        "hardening": {
            "dashboard_require_auth": config.dashboard_require_auth,
            "enforce_worker_source_ip": config.network.enforce_worker_source_ip,
            "require_signed_requests": config.network.require_signed_requests,
            "allowed_master_ips": list(config.network.allowed_master_ips),
            "adguard_url": config.network.adguard_url,
            "lan_subnet": host_info["lan_subnet"],
        },
        "checks": checks,
        "nodes": worker_surface,
        "adguard_snippets": build_adguard_config_snippets(snaps, config, host_info),
        "firewall_guides": build_firewall_guides(config, host_info),
    }
