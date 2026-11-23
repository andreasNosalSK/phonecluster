"""Optional Master Network Guard (Watchguard HTTP/HTTPS Allowlist Proxy & Audit Monitor).

OFF by default (`gateway.enabled = False`). Designed for clusters with older unrooted
Android worker phones whose direct internet (WAN) access is blocked on the home router:

- Only the updated Master phone (or a Raspberry Pi / Pi Zero 2 W Master) has WAN access.
- Workers stay LAN-only; when a job legitimately needs an approved external package or API,
  traffic passes through Master's authenticated HTTP/HTTPS proxy.
- Every worker gets its own derived proxy password (separate from `/exec` and admin tokens),
  preventing strangers on Wi-Fi from abusing the proxy and identifying the exact phone in logs.
- Enforces default-deny domain allowlisting (or `monitor` / `block_all` modes), port limits,
  and an SSRF private/loopback IP guard so compromised workers cannot pivot through Master.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import ipaddress
import logging
import select
import socket
import socketserver
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .auth import AuthRateLimiter
from .config import ClusterConfig, GatewayConfig, NodeConfig

LOG = logging.getLogger("phonecluster.gateway")

MAX_HEADER_BYTES = 16 * 1024
MAX_HTTP_BODY_BYTES = 32 * 1024 * 1024
RELAY_CHUNK_BYTES = 16 * 1024

GATEWAY_PRESETS: dict[str, dict[str, Any]] = {
    "github": {
        "label": "GitHub & Updates",
        "domains": [
            "github.com",
            "*.github.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "codeload.github.com",
        ],
    },
    "termux_debian": {
        "label": "Termux & Debian Packages",
        "domains": [
            "packages-cf.termux.dev",
            "packages.termux.dev",
            "deb.debian.org",
            "security.debian.org",
            "ftp.debian.org",
        ],
    },
    "pypi": {
        "label": "Python / PyPI",
        "domains": ["pypi.org", "files.pythonhosted.org"],
    },
    "huggingface": {
        "label": "HuggingFace AI Models",
        "domains": ["huggingface.co", "*.huggingface.co", "cdn-lfs.huggingface.co", "*.hf.co"],
    },
    "docker": {
        "label": "Docker Hub & GHCR",
        "domains": [
            "registry-1.docker.io",
            "auth.docker.io",
            "production.cloudflare.docker.com",
            "ghcr.io",
        ],
    },
    "homeassistant": {
        "label": "Home Assistant / HACS",
        "domains": ["version.home-assistant.io", "wheels.home-assistant.io"],
    },
}


def derive_proxy_password(node_token: str, node_id: str) -> str:
    """Derive a dedicated per-node proxy secret so `/exec` and admin tokens are never exposed."""
    digest = hmac.new(
        node_token.encode("utf-8"),
        f"phonecluster-gateway-v1:{node_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:32]


def build_worker_proxy_env(
    config: ClusterConfig,
    node: NodeConfig,
    master_host: str | None = None,
    port_override: int | None = None,
) -> dict[str, str]:
    """Build `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars for a worker when Gateway is enabled.

    Returns `{}` when Gateway is disabled, `inject_proxy_env` is False, or `node` is the Master.
    `NO_PROXY` always excludes localhost, `.cluster`, and every LAN cluster node IP so
    Cross-Tier Service Mesh calls remain direct on LAN.
    """
    gw = config.gateway
    if not gw.enabled or not gw.inject_proxy_env or node.role == "master":
        return {}

    m_host = master_host
    if not m_host and config.nodes:
        master_node = next((n for n in config.nodes if n.role == "master"), config.nodes[0])
        m_host = master_node.host
    if not m_host:
        return {}

    port = int(port_override) if port_override else int(gw.port)
    if port <= 0:
        return {}

    secret = derive_proxy_password(config.token_for_node(node), node.id)
    proxy_url = f"http://{node.id}:{secret}@{m_host}:{port}"

    no_proxy_items: list[str] = ["localhost", "127.0.0.1", "::1", ".cluster"]
    for n in config.nodes:
        if n.host and n.host not in no_proxy_items:
            no_proxy_items.append(n.host)
    no_proxy = ",".join(no_proxy_items)

    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
        "PHONECLUSTER_GATEWAY_ENABLED": "1",
    }


def domain_matches(host: str, pattern: str) -> bool:
    """Match normalized hostname against an exact domain or `*.example.com` wildcard."""
    h = host.strip().lower().rstrip(".")
    p = pattern.strip().lower().rstrip(".")
    if not h or not p:
        return False
    if p.startswith("*."):
        suffix = p[1:]  # ".example.com"
        return h.endswith(suffix) and len(h) > len(suffix)
    return h == p


def evaluate_policy(host: str, port: int, gw: GatewayConfig) -> tuple[bool, str]:
    """Evaluate Network Guard port/domain/mode policy for `(host, port)`."""
    clean_host = host.strip().lower().rstrip(".")
    if not clean_host:
        return False, "empty destination host"
    if port not in gw.allowed_ports:
        return False, f"port {port} blocked (allowed: {','.join(str(p) for p in gw.allowed_ports)})"

    for pat in gw.blocked_domains:
        if domain_matches(clean_host, pat):
            return False, f"blocked domain rule '{pat}'"

    if gw.mode == "block_all":
        return False, "strict air-gap mode (block_all)"

    if gw.mode == "allowlist":
        for pat in gw.allowed_domains:
            if domain_matches(clean_host, pat):
                return True, f"allowlist match '{pat}'"
        return False, "domain not in allowlist"

    # monitor mode
    return True, "allowed (monitor mode)"


def _is_disallowed_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_and_validate_target(
    host: str, port: int, block_private_ips: bool = True
) -> tuple[list[tuple[int, tuple[Any, ...]]] | None, str]:
    """Resolve `host:port` once, enforce SSRF guard on ALL IPs, and return validated endpoints."""
    clean_host = host.strip().strip("[]")
    try:
        infos = socket.getaddrinfo(clean_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return None, f"DNS resolution failed: {exc}"
    if not infos:
        return None, "DNS returned no addresses"

    candidates: list[tuple[int, tuple[Any, ...]]] = []
    seen: set[tuple[int, tuple[Any, ...]]] = set()
    for fam, _stype, _proto, _canon, sockaddr in infos:
        ip_str = str(sockaddr[0])
        if block_private_ips and _is_disallowed_ip(ip_str):
            return None, f"private/LAN IP {ip_str} blocked by SSRF guard"
        pair = (fam, sockaddr)
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)

    return candidates, "ok"


class GatewayAuditLog:
    """Thread-safe bounded audit ring buffer for Master Network Guard traffic."""

    def __init__(self, maxlen: int = 200) -> None:
        self._lock = threading.Lock()
        self._events: collections.deque[dict[str, Any]] = collections.deque(maxlen=maxlen)
        self.total_allowed = 0
        self.total_blocked = 0
        self.auth_failures = 0
        self.bytes_total = 0

    def record(
        self,
        *,
        node_id: str,
        client_ip: str,
        method: str,
        host: str,
        port: int,
        action: str,
        reason: str,
        bytes_in: int = 0,
        bytes_out: int = 0,
    ) -> None:
        entry = {
            "ts": int(time.time()),
            "node_id": node_id,
            "client_ip": client_ip,
            "method": method,
            "host": host,
            "port": port,
            "action": action,
            "reason": reason,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
        }
        with self._lock:
            self._events.appendleft(entry)
            if action == "allow":
                self.total_allowed += 1
            elif action == "auth_denied":
                self.auth_failures += 1
                self.total_blocked += 1
            else:
                self.total_blocked += 1
            self.bytes_total += bytes_in + bytes_out

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self.total_allowed = 0
            self.total_blocked = 0
            self.auth_failures = 0
            self.bytes_total = 0

    def snapshot(self, limit: int = 60) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)[:limit]
            per_node: dict[str, dict[str, int]] = {}
            for ev in self._events:
                nid = ev["node_id"]
                bucket = per_node.setdefault(nid, {"allowed": 0, "blocked": 0})
                if ev["action"] == "allow":
                    bucket["allowed"] += 1
                else:
                    bucket["blocked"] += 1
            return {
                "total_allowed": self.total_allowed,
                "total_blocked": self.total_blocked,
                "auth_failures": self.auth_failures,
                "bytes_total": self.bytes_total,
                "per_node": per_node,
                "events": events,
            }


def _read_http_head(conn: socket.socket, timeout_sec: float = 10.0) -> bytes | None:
    """Read an HTTP request head up to `\\r\\n\\r\\n` with strict byte limit."""
    conn.settimeout(timeout_sec)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > MAX_HEADER_BYTES:
            return None
    return bytes(buf)


def _send_proxy_error(conn: socket.socket, code: int, title: str, detail: str, extra_headers: str = "") -> None:
    body = f"PhoneCluster Network Guard ({code} {title}): {detail}\n".encode("utf-8")
    head = (
        f"HTTP/1.1 {code} {title}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}\r\n"
    ).encode("utf-8")
    try:
        conn.sendall(head + body)
    except OSError:
        pass


def _parse_basic_proxy_auth(headers: dict[str, str]) -> tuple[str, str] | None:
    raw = headers.get("proxy-authorization", "").strip()
    if not raw.lower().startswith("basic "):
        return None
    b64 = raw[6:].strip()
    try:
        decoded = base64.b64decode(b64).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    user, pw = decoded.split(":", 1)
    return user.strip(), pw.strip()


def _relay_bidirectional(
    client_sock: socket.socket,
    upstream_sock: socket.socket,
    idle_timeout: float,
    stop_event: threading.Event,
) -> tuple[int, int]:
    """Relay bytes between client and upstream sockets until EOF, idle timeout, or shutdown."""
    bytes_in = 0
    bytes_out = 0
    client_sock.setblocking(False)
    upstream_sock.setblocking(False)
    last_activity = time.monotonic()
    sockets = [client_sock, upstream_sock]

    while not stop_event.is_set():
        try:
            readable, _, errored = select.select(sockets, [], sockets, 0.5)
        except (OSError, ValueError):
            break
        if errored:
            break
        if not readable:
            if time.monotonic() - last_activity >= idle_timeout:
                break
            continue
        last_activity = time.monotonic()
        done = False
        for sock in readable:
            other = upstream_sock if sock is client_sock else client_sock
            try:
                data = sock.recv(RELAY_CHUNK_BYTES)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                done = True
                break
            if not data:
                done = True
                break
            try:
                other.setblocking(True)
                other.settimeout(idle_timeout)
                other.sendall(data)
                other.setblocking(False)
            except OSError:
                done = True
                break
            if sock is client_sock:
                bytes_out += len(data)
            else:
                bytes_in += len(data)
        if done:
            break
    return bytes_in, bytes_out


class NetworkGuardServer(socketserver.ThreadingTCPServer):
    """Lightweight authenticated HTTP/HTTPS allowlist proxy running on Master."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        addr: tuple[str, int],
        config: ClusterConfig,
        audit_log: GatewayAuditLog,
    ) -> None:
        self.cluster_config = config
        self.audit_log = audit_log
        self.stop_event = threading.Event()
        self.conn_sem = threading.BoundedSemaphore(max(4, config.gateway.max_connections))
        self.rate_limiter = AuthRateLimiter(max_failures=15, window_sec=60.0, block_sec=60.0)
        super().__init__(addr, _NetworkGuardHandler)

    def authenticate_worker(self, headers: dict[str, str], client_ip: str) -> tuple[str | None, str]:
        blocked, retry = self.rate_limiter.is_blocked(client_ip)
        if blocked:
            return None, f"rate limited ({retry}s)"
        creds = _parse_basic_proxy_auth(headers)
        if creds is None:
            self.rate_limiter.record_failure(client_ip)
            return None, "missing Proxy-Authorization"
        node_id, password = creds
        node = next((n for n in self.cluster_config.nodes if n.id == node_id), None)
        if node is None:
            self.rate_limiter.record_failure(client_ip)
            return None, f"unknown node '{node_id}'"
        expected = derive_proxy_password(self.cluster_config.token_for_node(node), node.id)
        if not hmac.compare_digest(password, expected):
            self.rate_limiter.record_failure(client_ip)
            return None, "invalid proxy secret"
        self.rate_limiter.record_success(client_ip)
        return node.id, "ok"

    def shutdown(self) -> None:
        self.stop_event.set()
        super().shutdown()


class _NetworkGuardHandler(socketserver.BaseRequestHandler):
    server: NetworkGuardServer

    def handle(self) -> None:
        conn: socket.socket = self.request
        client_ip = str(self.client_address[0])
        if not self.server.conn_sem.acquire(blocking=False):
            _send_proxy_error(conn, 503, "Service Unavailable", "gateway connection limit reached")
            return
        try:
            self._handle_once(conn, client_ip)
        except OSError:
            pass
        finally:
            self.server.conn_sem.release()

    def _handle_once(self, conn: socket.socket, client_ip: str) -> None:
        raw = _read_http_head(conn, timeout_sec=10.0)
        if not raw:
            return
        sep_idx = raw.find(b"\r\n\r\n")
        head_bytes = raw[:sep_idx]
        leftover = raw[sep_idx + 4 :]

        lines = head_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines or len(lines[0].split()) < 3:
            _send_proxy_error(conn, 400, "Bad Request", "malformed HTTP proxy request")
            return

        method, target, version = lines[0].split(" ", 2)
        method_u = method.upper()
        header_pairs: list[tuple[str, str]] = []
        headers_lower: dict[str, str] = {}
        for hline in lines[1:]:
            if ":" in hline:
                k, v = hline.split(":", 1)
                header_pairs.append((k.strip(), v.strip()))
                headers_lower[k.strip().lower()] = v.strip()

        # 1. Authenticate worker phone (blocks unauthorized LAN strangers!)
        node_id, auth_reason = self.server.authenticate_worker(headers_lower, client_ip)
        if node_id is None:
            self.server.audit_log.record(
                node_id="unknown",
                client_ip=client_ip,
                method=method_u,
                host=target[:120],
                port=0,
                action="auth_denied",
                reason=auth_reason,
            )
            _send_proxy_error(
                conn,
                407,
                "Proxy Authentication Required",
                auth_reason,
                extra_headers='Proxy-Authenticate: Basic realm="PhoneCluster-Network-Guard"\r\n',
            )
            return

        gw = self.server.cluster_config.gateway

        # 2. Extract destination host & port
        if method_u == "CONNECT":
            if ":" in target:
                h_part, p_str = target.rsplit(":", 1)
                dest_host = h_part.strip("[]")
                try:
                    dest_port = int(p_str)
                except ValueError:
                    _send_proxy_error(conn, 400, "Bad Request", "invalid CONNECT port")
                    return
            else:
                dest_host = target.strip("[]")
                dest_port = 443
            forward_path = ""
        else:
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme.lower() not in {"http"} or not parsed.hostname:
                _send_proxy_error(conn, 400, "Bad Request", "only HTTP URLs or HTTPS CONNECT supported")
                return
            dest_host = parsed.hostname
            try:
                dest_port = parsed.port or 80
            except ValueError:
                _send_proxy_error(conn, 400, "Bad Request", "invalid URL port")
                return
            forward_path = parsed.path or "/"
            if parsed.query:
                forward_path = f"{forward_path}?{parsed.query}"

        # 3. Evaluate allowlist / blocklist / mode / port policy
        allowed, policy_reason = evaluate_policy(dest_host, dest_port, gw)
        if not allowed:
            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=dest_host,
                port=dest_port,
                action="block",
                reason=policy_reason,
            )
            _send_proxy_error(conn, 403, "Forbidden", policy_reason)
            return

        # 4. Resolve DNS & enforce SSRF private/loopback IP guard
        resolved, dns_reason = resolve_and_validate_target(
            dest_host, dest_port, block_private_ips=gw.block_private_ips
        )
        if resolved is None:
            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=dest_host,
                port=dest_port,
                action="block",
                reason=dns_reason,
            )
            code = 403 if "SSRF" in dns_reason else 502
            _send_proxy_error(conn, code, "Forbidden" if code == 403 else "Bad Gateway", dns_reason)
            return

        candidates = resolved
        upstream: socket.socket | None = None
        bytes_in = 0
        bytes_out = 0
        try:
            last_conn_err: OSError | None = None
            for family, sockaddr in candidates:
                sock_try: socket.socket | None = None
                try:
                    sock_try = socket.socket(family, socket.SOCK_STREAM)
                    sock_try.settimeout(min(15.0, gw.idle_timeout_sec))
                    sock_try.connect(sockaddr)
                    upstream = sock_try
                    break
                except OSError as exc:
                    last_conn_err = exc
                    if sock_try is not None:
                        try:
                            sock_try.close()
                        except OSError:
                            pass
            if upstream is None:
                raise last_conn_err or OSError("unable to connect to upstream")

            if method_u == "CONNECT":
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if leftover:
                    upstream.sendall(leftover)
                    bytes_out += len(leftover)
                r_in, r_out = _relay_bidirectional(
                    conn, upstream, idle_timeout=gw.idle_timeout_sec, stop_event=self.server.stop_event
                )
                bytes_in += r_in
                bytes_out += r_out
            else:
                # Strip Proxy-* headers so worker credentials NEVER leak upstream!
                out_headers = [
                    f"{k}: {v}"
                    for k, v in header_pairs
                    if k.lower() not in {"proxy-authorization", "proxy-connection", "connection"}
                ]
                if "host" not in headers_lower:
                    host_hdr = dest_host if dest_port == 80 else f"{dest_host}:{dest_port}"
                    out_headers.append(f"Host: {host_hdr}")
                out_headers.append("Connection: close")
                req_head = (
                    f"{method_u} {forward_path} {version}\r\n"
                    + "\r\n".join(out_headers)
                    + "\r\n\r\n"
                ).encode("iso-8859-1", errors="replace")
                upstream.sendall(req_head)
                bytes_out += len(req_head)

                content_len = 0
                if "content-length" in headers_lower:
                    try:
                        content_len = max(0, int(headers_lower["content-length"]))
                    except ValueError:
                        content_len = 0
                if content_len > MAX_HTTP_BODY_BYTES:
                    _send_proxy_error(conn, 413, "Payload Too Large", "request body exceeds limit")
                    return

                if leftover:
                    upstream.sendall(leftover)
                    bytes_out += len(leftover)
                remaining = max(0, content_len - len(leftover))
                conn.settimeout(gw.idle_timeout_sec)
                while remaining > 0 and not self.server.stop_event.is_set():
                    chunk = conn.recv(min(RELAY_CHUNK_BYTES, remaining))
                    if not chunk:
                        break
                    upstream.sendall(chunk)
                    bytes_out += len(chunk)
                    remaining -= len(chunk)

                # Relay upstream HTTP response back to worker
                upstream.settimeout(gw.idle_timeout_sec)
                while not self.server.stop_event.is_set():
                    resp_chunk = upstream.recv(RELAY_CHUNK_BYTES)
                    if not resp_chunk:
                        break
                    conn.sendall(resp_chunk)
                    bytes_in += len(resp_chunk)

            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=dest_host,
                port=dest_port,
                action="allow",
                reason=policy_reason,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
            )
        except OSError as exc:
            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=dest_host,
                port=dest_port,
                action="block",
                reason=f"upstream connect/relay error: {exc}",
                bytes_in=bytes_in,
                bytes_out=bytes_out,
            )
            _send_proxy_error(conn, 502, "Bad Gateway", str(exc))
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


class GatewayManager:
    """Lifecycle controller allowing Network Guard to be toggled ON/OFF live at runtime."""

    def __init__(self, config: ClusterConfig) -> None:
        self.config = config
        self.audit_log = GatewayAuditLog()
        self._lock = threading.Lock()
        self._server: NetworkGuardServer | None = None
        self._thread: threading.Thread | None = None
        self._last_error: str = ""

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._server is not None

    @property
    def bound_port(self) -> int:
        with self._lock:
            if self._server is not None:
                return int(self._server.server_address[1])
            return int(self.config.gateway.port)

    def start(self) -> tuple[bool, str]:
        with self._lock:
            if self._server is not None:
                return True, f"already running on port {self._server.server_address[1]}"
            gw = self.config.gateway
            try:
                srv = NetworkGuardServer((gw.bind_host, gw.port), self.config, self.audit_log)
            except OSError as exc:
                self._last_error = str(exc)
                return False, f"could not bind {gw.bind_host}:{gw.port}: {exc}"
            th = threading.Thread(
                target=srv.serve_forever,
                kwargs={"poll_interval": 0.25},
                name="network-guard-gateway",
                daemon=True,
            )
            th.start()
            self._server = srv
            self._thread = th
            self._last_error = ""
            actual_port = srv.server_address[1]
            LOG.info(
                "Master Network Guard listening on %s:%d (mode=%s, allowlist=%d domains)",
                gw.bind_host,
                actual_port,
                gw.mode,
                len(gw.allowed_domains),
            )
            return True, f"started on {gw.bind_host}:{actual_port}"

    def stop(self) -> None:
        with self._lock:
            srv = self._server
            self._server = None
            self._thread = None
        if srv is not None:
            try:
                srv.shutdown()
            finally:
                srv.server_close()
            LOG.info("Master Network Guard stopped.")

    def sync_with_config(self) -> tuple[bool, str]:
        """Start, stop, or rebind the Network Guard to match `self.config.gateway`."""
        gw = self.config.gateway
        if not gw.enabled:
            self.stop()
            return True, "disabled"
        with self._lock:
            needs_rebind = (
                self._server is not None
                and (
                    self._server.server_address[1] != gw.port
                    and gw.port != 0
                )
            )
        if needs_rebind:
            self.stop()
        if not self.is_running:
            return self.start()
        return True, f"running on port {self.bound_port}"

    def status(self, include_events: int = 60) -> dict[str, Any]:
        gw = self.config.gateway
        audit = self.audit_log.snapshot(limit=include_events)
        return {
            "enabled": gw.enabled,
            "running": self.is_running,
            "bind_host": gw.bind_host,
            "port": self.bound_port,
            "mode": gw.mode,
            "allowed_domains": list(gw.allowed_domains),
            "blocked_domains": list(gw.blocked_domains),
            "allowed_ports": list(gw.allowed_ports),
            "block_private_ips": gw.block_private_ips,
            "inject_proxy_env": gw.inject_proxy_env,
            "last_error": self._last_error,
            "presets": GATEWAY_PRESETS,
            "stats": {
                "total_allowed": audit["total_allowed"],
                "total_blocked": audit["total_blocked"],
                "auth_failures": audit["auth_failures"],
                "bytes_total": audit["bytes_total"],
                "per_node": audit["per_node"],
            },
            "events": audit["events"],
        }
