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
import re
import selectors
import socket
import socketserver
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .auth import AuthRateLimiter
from .config import (
    ClusterConfig,
    GatewayConfig,
    NodeConfig,
    format_host_for_url,
    format_host_port,
    is_loopback_or_unspecified_host,
    normalize_host,
)
from .discovery import detect_local_ip

LOG = logging.getLogger("phonecluster.gateway")

MAX_HEADER_BYTES = 16 * 1024
MAX_HTTP_BODY_BYTES = 32 * 1024 * 1024
MAX_HTTP_CHUNKS = 65536
MAX_TRAILER_BYTES = 16 * 1024
MAX_TRAILER_LINES = 64
RELAY_CHUNK_BYTES = 16 * 1024
_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_ASCII_UINT_RE = re.compile(r"^[0-9]{1,10}$")
_ASCII_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_ASCII_HEX_RE = re.compile(rb"^[0-9A-Fa-f]{1,8}$")
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_PROTECTED_END_TO_END_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})


def _sanitize_log_text(value: str, max_len: int = 200) -> str:
    """Strip ASCII control chars (including ESC/ANSI sequences, CR, LF, NUL) before audit logging."""
    return _CTRL_CHAR_RE.sub("?", str(value or ""))[:max_len]


_RESP_HEX_RE = re.compile(rb"^[0-9A-Fa-f]{1,32}$")
_MAX_RESP_CHUNK_BYTES = 128 * 1024 * 1024


def _is_safe_ascii_host(value: str) -> bool:
    """Return True iff `value` is non-empty printable ASCII (defeats ISO-8859-1 / IDNA blocklist bypasses)."""
    return bool(value) and value.isascii() and not any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in value)


def _parse_host_header(host_val: str) -> tuple[str, int | None] | None:
    """Strictly parse an HTTP `Host:` header into `(normalized_host, explicit_port_or_None)`."""
    raw = host_val.strip()
    if not _is_safe_ascii_host(raw) or any(c.isspace() or c in "@/\\?#;'\"" for c in raw):
        return None
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return None
        host_part = raw[1:end].strip()
        rest = raw[end + 1 :]
        if not host_part or "[" in host_part or "]" in host_part or "%" in host_part:
            return None
        try:
            ipaddress.IPv6Address(host_part)
        except ValueError:
            return None
        if not rest:
            port_val: int | None = None
        elif rest.startswith(":") and _ASCII_PORT_RE.fullmatch(rest[1:]):
            port_val = int(rest[1:])
            if not (1 <= port_val <= 65535):
                return None
        else:
            return None
        norm = normalize_host(host_part).lower().rstrip(".")
        return (norm, port_val) if norm else None
    if raw.count(":") > 1:
        # Unbracketed IPv6 in Host header is invalid per RFC 9110 §7.2
        return None
    if ":" in raw:
        host_part, p_str = raw.rsplit(":", 1)
        if not host_part or not _ASCII_PORT_RE.fullmatch(p_str):
            return None
        port_val = int(p_str)
        if not (1 <= port_val <= 65535):
            return None
        norm = normalize_host(host_part).lower().rstrip(".")
        return (norm, port_val) if norm else None
    norm = normalize_host(raw).lower().rstrip(".")
    return (norm, None) if norm else None

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
            "index.docker.io",
            "hub.docker.com",
            "ghcr.io",
        ],
    },
    "snap": {
        "label": "Ubuntu Touch / Snap Store",
        "domains": [
            "api.snapcraft.io",
            "*.snapcraftcontent.com",
            "dashboard.snapcraft.io",
            "login.ubuntu.com",
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

    m_host = normalize_host(master_host) if master_host else ""
    if "usb-hub" in node.tags and is_loopback_or_unspecified_host(node.host):
        # ADB USB-hub workers reach Master's gateway over `adb reverse` on 127.0.0.1 even with Wi-Fi OFF
        m_host = "127.0.0.1"
    if not m_host and config.nodes:
        master_node = next((n for n in config.nodes if n.role == "master"), config.nodes[0])
        m_host = normalize_host(master_node.host)
    if is_loopback_or_unspecified_host(m_host) and not is_loopback_or_unspecified_host(node.host):
        lan_ip = normalize_host(detect_local_ip())
        if lan_ip and not is_loopback_or_unspecified_host(lan_ip):
            m_host = lan_ip
    if not m_host:
        return {}

    if port_override is not None:
        port = int(port_override)
    else:
        port = int(gw.port)
    if port <= 0:
        return {}

    secret = derive_proxy_password(config.token_for_node(node), node.id)
    user_enc = urllib.parse.quote(node.id, safe="")
    proxy_url = f"http://{user_enc}:{secret}@{format_host_port(m_host, port)}"

    no_proxy_items: list[str] = ["localhost", "127.0.0.1", "::1", ".cluster"]

    def _add_no_proxy(host_val: str) -> None:
        h = normalize_host(host_val)
        if h and h not in no_proxy_items:
            no_proxy_items.append(h)

    _add_no_proxy(m_host)
    for n in config.nodes:
        _add_no_proxy(n.host)
    for curl in config.custom_services.values():
        try:
            parsed = urllib.parse.urlparse(curl)
            if parsed.hostname:
                _add_no_proxy(parsed.hostname)
        except ValueError:
            continue
    if config.network.adguard_url:
        try:
            parsed_ag = urllib.parse.urlparse(config.network.adguard_url)
            if parsed_ag.hostname:
                _add_no_proxy(parsed_ag.hostname)
        except ValueError:
            pass
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
    if not _is_safe_ascii_host(str(host or "").strip()):
        return False, "invalid non-ASCII or control characters in destination host"
    clean_host = normalize_host(host).lower().rstrip(".")
    if not clean_host or not _is_safe_ascii_host(clean_host):
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


_NAT64_WELL_KNOWN_NET = ipaddress.IPv6Network("64:ff9b::/96")


def _is_disallowed_addr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IPv4/IPv6 address (or embedded IPv4 via NAT64/6to4/Teredo/mapped) is non-public."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return _is_disallowed_addr(addr.ipv4_mapped)
        if addr.sixtofour is not None:
            return True  # Block deprecated 6to4 tunneling (RFC 7526) to prevent SSRF bypass
        if addr.teredo is not None:
            return True  # Block Teredo tunneling to prevent SSRF bypass
        if addr in _NAT64_WELL_KNOWN_NET:
            embedded_v4 = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
            return _is_disallowed_addr(embedded_v4)
    return bool(
        (not addr.is_global)
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or getattr(addr, "is_site_local", False)
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _is_disallowed_ip(ip_str: str) -> bool:
    """Block all non-public/internal IPs including LAN, loopback, link-local, site-local, Tailscale/CGNAT, NAT64, 6to4, Teredo, and scoped IPv6."""
    raw = str(ip_str or "").strip()
    if not raw or "%" in raw:
        return True
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return True
    return _is_disallowed_addr(addr)


def resolve_and_validate_target(
    host: str, port: int, block_private_ips: bool = True
) -> tuple[list[tuple[int, tuple[Any, ...]]] | None, str]:
    """Resolve `host:port` once, enforce SSRF guard on ALL IPs, and return validated endpoints."""
    clean_host = host.strip().strip("[]")
    if not _is_safe_ascii_host(clean_host):
        return None, "invalid non-ASCII destination host"
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
            "node_id": _sanitize_log_text(node_id, 64),
            "client_ip": _sanitize_log_text(client_ip, 64),
            "method": _sanitize_log_text(method, 24),
            "host": _sanitize_log_text(host, 160),
            "port": int(port),
            "action": _sanitize_log_text(action, 32),
            "reason": _sanitize_log_text(reason, 240),
            "bytes_in": int(bytes_in),
            "bytes_out": int(bytes_out),
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
    """Read an HTTP request head up to `\\r\\n\\r\\n` with strict header-byte limit and total deadline."""
    deadline = time.monotonic() + max(0.5, timeout_sec)
    buf = bytearray()
    while True:
        sep = buf.find(b"\r\n\r\n")
        if sep != -1:
            if sep + 4 > MAX_HEADER_BYTES:
                return None
            return bytes(buf)
        if len(buf) > MAX_HEADER_BYTES:
            return None
        rem = deadline - time.monotonic()
        if rem <= 0:
            return None
        conn.settimeout(rem)
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)


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
        conn.settimeout(5.0)
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
    abort_check: Any | None = None,
) -> tuple[int, int]:
    """Non-blocking full-duplex TCP relay using `selectors` (deadlock-free, no 1024-FD cap)."""
    bytes_in = 0
    bytes_out = 0
    max_buf = 64 * 1024
    client_sock.setblocking(False)
    upstream_sock.setblocking(False)
    last_activity = time.monotonic()

    peer = {client_sock: upstream_sock, upstream_sock: client_sock}
    out_buf = {client_sock: bytearray(), upstream_sock: bytearray()}
    eof_from = {client_sock: False, upstream_sock: False}
    shut_wr_sent = {client_sock: False, upstream_sock: False}

    sel = selectors.DefaultSelector()
    try:
        while not stop_event.is_set():
            if abort_check is not None and abort_check():
                break
            done_c2u = eof_from[client_sock] and not out_buf[upstream_sock]
            done_u2c = eof_from[upstream_sock] and not out_buf[client_sock]
            if done_c2u and done_u2c:
                break

            for s in (client_sock, upstream_sock):
                mask = 0
                if not eof_from[s] and len(out_buf[peer[s]]) < max_buf:
                    mask |= selectors.EVENT_READ
                if out_buf[s]:
                    mask |= selectors.EVENT_WRITE
                try:
                    existing = sel.get_key(s)
                except KeyError:
                    existing = None
                if mask == 0:
                    if existing is not None:
                        sel.unregister(s)
                elif existing is None:
                    sel.register(s, mask)
                elif existing.events != mask:
                    sel.modify(s, mask)

            if not sel.get_map():
                break

            try:
                events = sel.select(timeout=0.5)
            except (OSError, ValueError):
                break
            if abort_check is not None and abort_check():
                break
            if not events:
                if time.monotonic() - last_activity >= idle_timeout:
                    break
                continue

            last_activity = time.monotonic()
            abort = False
            for key, mask in events:
                sock: socket.socket = key.fileobj  # type: ignore[assignment]
                other = peer[sock]
                if mask & selectors.EVENT_WRITE and out_buf[sock]:
                    try:
                        sent = sock.send(out_buf[sock])
                    except (BlockingIOError, InterruptedError):
                        sent = 0
                    except OSError:
                        abort = True
                        break
                    if sent > 0:
                        del out_buf[sock][:sent]
                        if sock is upstream_sock:
                            bytes_out += sent
                        else:
                            bytes_in += sent
                    if not out_buf[sock] and eof_from[other] and not shut_wr_sent[sock]:
                        shut_wr_sent[sock] = True
                        try:
                            sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

                if mask & selectors.EVENT_READ and not eof_from[sock]:
                    try:
                        data = sock.recv(RELAY_CHUNK_BYTES)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        abort = True
                        break
                    if not data:
                        eof_from[sock] = True
                        if not out_buf[other] and not shut_wr_sent[other]:
                            shut_wr_sent[other] = True
                            try:
                                other.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                    else:
                        out_buf[other].extend(data)
            if abort:
                break
    finally:
        sel.close()
    return bytes_in, bytes_out


def _relay_http_response(
    conn: socket.socket,
    upstream: socket.socket,
    method_u: str,
    req_version: str,
    idle_timeout: float,
    stop_event: threading.Event,
    abort_check: Any | None = None,
) -> tuple[int, bool]:
    """Parse upstream HTTP response head(s), sanitize hop-by-hop headers, force `Connection: close`, and stream framed body."""
    bytes_in = 0
    response_started = False
    buf = bytearray()
    conn.settimeout(idle_timeout)
    upstream.settimeout(idle_timeout)

    def _check_abort() -> None:
        if stop_event.is_set():
            raise OSError("gateway shutting down")
        if abort_check is not None and abort_check():
            raise OSError("node quarantined during response relay")

    def _recv_more(limit: int = RELAY_CHUNK_BYTES) -> bytes:
        _check_abort()
        return upstream.recv(limit)

    def _fill_until(needle: bytes, max_buf: int = 65536) -> bool:
        while needle not in buf:
            if len(buf) > max_buf:
                return False
            chunk = _recv_more(4096)
            if not chunk:
                return False
            buf.extend(chunk)
        return True

    # Read response head(s), forwarding any sanitized 1xx interim responses before the final response head
    interim_count = 0
    while True:
        if not _fill_until(b"\r\n\r\n", max_buf=65536):
            # Always raise on EOF before headers so `_handle_once` returns 502 Bad Gateway
            raise OSError("unexpected EOF before upstream HTTP response headers")
        sep = buf.find(b"\r\n\r\n")
        head_bytes = bytes(buf[:sep])
        del buf[: sep + 4]

        lines = head_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
        status_line = lines[0]
        if "\r" in status_line or "\n" in status_line or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in status_line):
            raise OSError("invalid control character in upstream HTTP status line")
        sparts = status_line.split(" ", 2)
        if len(sparts) < 2 or not sparts[0].upper().startswith("HTTP/") or len(sparts[1]) != 3 or not sparts[1].isascii() or not sparts[1].isdigit():
            raise OSError("malformed upstream HTTP status line")
        status_code = int(sparts[1])

        resp_pairs: list[tuple[str, str]] = []
        for hline in lines[1:]:
            if not hline:
                continue
            if "\r" in hline or "\n" in hline or ":" not in hline:
                raise OSError("malformed upstream HTTP response header")
            rk, rv = hline.split(":", 1)
            if not rk or not _HTTP_TOKEN_RE.fullmatch(rk):
                raise OSError("invalid upstream HTTP response header name")
            if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in rv):
                raise OSError("invalid control character in upstream HTTP response header")
            resp_pairs.append((rk, rv.strip()))

        if 100 <= status_code < 200 and status_code != 101:
            interim_count += 1
            if interim_count > 8:
                raise OSError("too many interim 1xx upstream responses")
            if req_version == "HTTP/1.1":
                clean_interim_hdrs = [f"{k}: {v}" for k, v in resp_pairs if not k.lower().startswith("proxy-")]
                interim_txt = status_line + ("\r\n" + "\r\n".join(clean_interim_hdrs) if clean_interim_hdrs else "") + "\r\n\r\n"
                interim = interim_txt.encode("iso-8859-1", errors="replace")
                conn.sendall(interim)
                bytes_in += len(interim)
                response_started = True
            continue

        conn_tokens = {
            tok.strip().lower()
            for k, v in resp_pairs
            if k.lower() == "connection"
            for tok in v.split(",")
            if tok.strip()
        }
        hop_headers = (
            {"connection", "keep-alive", "te", "trailers", "upgrade"}
            | conn_tokens
        ) - {"content-length", "transfer-encoding"}

        has_transfer_encoding = False
        te_tokens: list[str] = []
        content_len: int | None = None
        for k, v in resp_pairs:
            kl = k.lower()
            if kl == "transfer-encoding":
                has_transfer_encoding = True
                for tok in v.split(","):
                    t = tok.strip().lower()
                    if t:
                        te_tokens.append(t)
            elif kl == "content-length":
                raw_parts = v.split(",")
                if not raw_parts or any(not _ASCII_UINT_RE.fullmatch(p.strip()) for p in raw_parts):
                    raise OSError("invalid upstream Content-Length")
                for p in raw_parts:
                    val = int(p.strip())
                    if content_len is not None and content_len != val:
                        raise OSError("conflicting upstream Content-Length")
                    content_len = val

        # RFC 9112 §6.3: chunked framing applies iff final Transfer-Encoding coding is "chunked";
        # whenever ANY Transfer-Encoding is present, Content-Length MUST be dropped and ignored.
        is_chunked = bool(te_tokens) and te_tokens[-1] == "chunked"
        if has_transfer_encoding:
            content_len = None

        out_hdrs = [
            f"{k}: {v}"
            for k, v in resp_pairs
            if not k.lower().startswith("proxy-")
            and k.lower() not in hop_headers
            and not (has_transfer_encoding and k.lower() == "content-length")
        ]
        out_hdrs.append("Connection: close")
        clean_head = (status_line + "\r\n" + "\r\n".join(out_hdrs) + "\r\n\r\n").encode(
            "iso-8859-1", errors="replace"
        )
        conn.sendall(clean_head)
        bytes_in += len(clean_head)
        response_started = True
        break

    # RFC 9112 §6.3: HEAD, 204, 304, and 1xx responses have zero body bytes
    if method_u == "HEAD" or status_code in (204, 304) or (100 <= status_code < 200):
        return bytes_in, response_started

    if is_chunked:
        saw_final_resp_chunk = False
        while not stop_event.is_set():
            _check_abort()
            if not _fill_until(b"\r\n", max_buf=16384):
                raise OSError("truncated upstream chunked response size line")
            line_end = buf.find(b"\r\n")
            size_line = bytes(buf[: line_end + 2])
            del buf[: line_end + 2]
            size_tok = size_line[:-2].split(b";", 1)[0].rstrip(b" \t")
            if not _RESP_HEX_RE.fullmatch(size_tok):
                raise OSError("malformed upstream chunk size")
            chunk_sz = int(size_tok, 16)
            if chunk_sz < 0 or chunk_sz > _MAX_RESP_CHUNK_BYTES:
                raise OSError("upstream chunk size exceeds safety limit")
            # Emit canonical hex chunk size ONLY after validation (strips unvalidated extensions)
            canon_line = f"{chunk_sz:x}\r\n".encode("ascii")
            conn.sendall(canon_line)
            bytes_in += len(canon_line)
            if chunk_sz == 0:
                tr_lines = 0
                tr_bytes = 0
                while not stop_event.is_set():
                    _check_abort()
                    if not _fill_until(b"\r\n", max_buf=16384):
                        raise OSError("truncated upstream chunked trailers")
                    tr_end = buf.find(b"\r\n")
                    tr_line = bytes(buf[: tr_end + 2])
                    del buf[: tr_end + 2]
                    tr_lines += 1
                    tr_bytes += len(tr_line)
                    if tr_lines > MAX_TRAILER_LINES or tr_bytes > MAX_TRAILER_BYTES:
                        raise OSError("upstream chunked trailers exceed limit")
                    if tr_line == b"\r\n":
                        conn.sendall(tr_line)
                        bytes_in += len(tr_line)
                        saw_final_resp_chunk = True
                        break
                    tr_text = tr_line[:-2].decode("iso-8859-1", errors="replace")
                    if "\r" in tr_text or "\n" in tr_text or ":" not in tr_text:
                        raise OSError("malformed upstream chunked trailer")
                    tr_k, tr_v = tr_text.split(":", 1)
                    if not tr_k or not _HTTP_TOKEN_RE.fullmatch(tr_k):
                        raise OSError("invalid upstream chunked trailer name")
                    if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in tr_v):
                        raise OSError("invalid control char in upstream chunked trailer")
                    tr_kl = tr_k.lower()
                    if tr_kl.startswith("proxy-") or tr_kl in {"content-length", "transfer-encoding", "connection", "keep-alive"}:
                        continue
                    conn.sendall(tr_line)
                    bytes_in += len(tr_line)
                break
            need = chunk_sz
            while need > 0 and not stop_event.is_set():
                _check_abort()
                if not buf:
                    more = _recv_more(min(RELAY_CHUNK_BYTES, need))
                    if not more:
                        raise OSError("unexpected EOF in upstream chunked body")
                    buf.extend(more)
                take = min(len(buf), need)
                piece = bytes(buf[:take])
                del buf[:take]
                conn.sendall(piece)
                bytes_in += take
                need -= take
            # Verify exact 2-byte CRLF after chunk payload
            while len(buf) < 2 and not stop_event.is_set():
                _check_abort()
                more = _recv_more(2 - len(buf))
                if not more:
                    raise OSError("unexpected EOF before upstream chunk CRLF")
                buf.extend(more)
            if stop_event.is_set():
                raise OSError("gateway shutting down")
            if bytes(buf[:2]) != b"\r\n":
                raise OSError("malformed upstream chunk terminator")
            del buf[:2]
            conn.sendall(b"\r\n")
            bytes_in += 2
        if not saw_final_resp_chunk:
            raise OSError("incomplete upstream chunked response")
        return bytes_in, response_started

    if content_len is not None:
        remaining = content_len
        if buf and remaining > 0:
            take = min(len(buf), remaining)
            piece = bytes(buf[:take])
            del buf[:take]
            conn.sendall(piece)
            bytes_in += take
            remaining -= take
        while remaining > 0 and not stop_event.is_set():
            more = _recv_more(min(RELAY_CHUNK_BYTES, remaining))
            if not more:
                break
            conn.sendall(more)
            bytes_in += len(more)
            remaining -= len(more)
        return bytes_in, response_started

    # Close-delimited response (HTTP/1.0 or no Content-Length/Transfer-Encoding): stream until EOF
    if buf:
        piece = bytes(buf)
        buf.clear()
        conn.sendall(piece)
        bytes_in += len(piece)
    while not stop_event.is_set():
        more = _recv_more(RELAY_CHUNK_BYTES)
        if not more:
            break
        conn.sendall(more)
        bytes_in += len(more)
    return bytes_in, response_started


def _relay_chunked_request_body(
    conn: socket.socket,
    upstream: socket.socket,
    initial: bytes,
    idle_timeout: float,
    stop_event: threading.Event,
    abort_check: Any | None = None,
    sent_counter: list[int] | None = None,
) -> int:
    """Stream an HTTP/1.1 `Transfer-Encoding: chunked` request body safely to upstream."""
    buf = bytearray(initial)
    total_body = 0
    chunk_count = 0
    bytes_forwarded = 0
    saw_final_chunk = False
    conn.settimeout(idle_timeout)
    upstream.settimeout(idle_timeout)

    def _add_sent(n: int) -> None:
        nonlocal bytes_forwarded
        bytes_forwarded += n
        if sent_counter is not None:
            sent_counter[0] += n

    def _check_abort() -> None:
        if abort_check is not None and abort_check():
            raise OSError("node quarantined during request relay")

    def _fill_until(needle: bytes, max_line: int = 8192) -> bool:
        while needle not in buf:
            _check_abort()
            if len(buf) > max_line or stop_event.is_set():
                return False
            more = conn.recv(4096)
            if not more:
                return False
            buf.extend(more)
        return True

    while not stop_event.is_set():
        _check_abort()
        chunk_count += 1
        if chunk_count > MAX_HTTP_CHUNKS:
            raise ValueError("chunk count exceeds limit")
        if not _fill_until(b"\r\n"):
            raise OSError("truncated chunked request body")
        line_end = buf.find(b"\r\n")
        size_line = bytes(buf[: line_end + 2])
        del buf[: line_end + 2]

        size_token = size_line[:-2].split(b";", 1)[0].rstrip(b" \t")
        if not _ASCII_HEX_RE.fullmatch(size_token):
            raise ValueError("malformed chunk size")
        chunk_size = int(size_token, 16)
        if chunk_size < 0 or total_body + chunk_size > MAX_HTTP_BODY_BYTES:
            raise ValueError("payload exceeds limit")

        # Forward canonical hex chunk size without unvalidated extensions (RFC 9112 §7.1.1 smuggling defense)
        canon_size_line = f"{chunk_size:x}\r\n".encode("ascii")
        upstream.sendall(canon_size_line)
        _add_sent(len(canon_size_line))

        if chunk_size == 0:
            # Forward validated trailers until terminating CRLF (with strict line, byte & header checks)
            trailer_lines = 0
            trailer_bytes = 0
            while not stop_event.is_set():
                if not _fill_until(b"\r\n"):
                    raise OSError("truncated chunked trailers")
                tr_end = buf.find(b"\r\n")
                tr_line = bytes(buf[: tr_end + 2])
                del buf[: tr_end + 2]
                trailer_lines += 1
                trailer_bytes += len(tr_line)
                if trailer_lines > MAX_TRAILER_LINES or trailer_bytes > MAX_TRAILER_BYTES:
                    raise ValueError("chunked trailers exceed limit")
                if tr_line == b"\r\n":
                    upstream.sendall(tr_line)
                    _add_sent(len(tr_line))
                    saw_final_chunk = True
                    break
                tr_text = tr_line[:-2].decode("iso-8859-1", errors="replace")
                if "\r" in tr_text or "\n" in tr_text or ":" not in tr_text:
                    raise ValueError("malformed chunked trailer line")
                tr_k, tr_v = tr_text.split(":", 1)
                if not tr_k or not _HTTP_TOKEN_RE.fullmatch(tr_k):
                    raise ValueError("invalid chunked trailer name")
                if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in tr_v):
                    raise ValueError("invalid control character in chunked trailer")
                # Never forward forbidden framing or proxy-credential headers inside chunked trailers
                tr_kl = tr_k.lower()
                if tr_kl.startswith("proxy-") or tr_kl in (
                    _PROTECTED_END_TO_END_HEADERS | {"connection", "authorization", "cookie", "te"}
                ):
                    continue
                upstream.sendall(tr_line)
                _add_sent(len(tr_line))
            break

        need = chunk_size
        total_body += chunk_size
        while need > 0 and not stop_event.is_set():
            _check_abort()
            if not buf:
                more = conn.recv(min(RELAY_CHUNK_BYTES, need))
                if not more:
                    raise OSError("unexpected EOF in chunked body")
                buf.extend(more)
            take = min(len(buf), need)
            piece = bytes(buf[:take])
            del buf[:take]
            upstream.sendall(piece)
            _add_sent(take)
            need -= take

        # Strictly verify the 2-byte CRLF terminator after chunk payload (blocks chunk framing desync)
        while len(buf) < 2 and not stop_event.is_set():
            _check_abort()
            more = conn.recv(2 - len(buf))
            if not more:
                raise OSError("unexpected EOF before chunk CRLF")
            buf.extend(more)
        if stop_event.is_set():
            raise OSError("gateway shutting down")
        if bytes(buf[:2]) != b"\r\n":
            raise ValueError("malformed chunk terminator (expected CRLF)")
        del buf[:2]
        upstream.sendall(b"\r\n")
        _add_sent(2)

    if not saw_final_chunk:
        raise OSError("incomplete chunked request body")
    return bytes_forwarded


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
        max_conn = max(4, config.gateway.max_connections)
        self.conn_sem = threading.BoundedSemaphore(max_conn)
        self._thread_sem = threading.BoundedSemaphore(max(16, max_conn + 8))
        self.rate_limiter = AuthRateLimiter(max_failures=15, window_sec=60.0, block_sec=60.0)
        self._node_req_lock = threading.Lock()
        self._node_req_times: dict[str, collections.deque[float]] = {}
        self._active_conns_lock = threading.Lock()
        self._active_node_sockets: dict[str, set[socket.socket]] = {}
        bind_host = normalize_host(str(addr[0])) or "0.0.0.0"
        if ":" in bind_host:
            self.address_family = socket.AF_INET6
        super().__init__((bind_host, addr[1]), _NetworkGuardHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._thread_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._thread_sem.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._thread_sem.release()

    def register_node_sockets(self, node_id: str, *socks: socket.socket) -> None:
        with self._active_conns_lock:
            bucket = self._active_node_sockets.setdefault(node_id, set())
            for s in socks:
                bucket.add(s)

    def unregister_node_sockets(self, node_id: str, *socks: socket.socket) -> None:
        with self._active_conns_lock:
            bucket = self._active_node_sockets.get(node_id)
            if not bucket:
                return
            for s in socks:
                bucket.discard(s)
            if not bucket:
                self._active_node_sockets.pop(node_id, None)

    def disconnect_node(self, node_id: str) -> int:
        """Immediately sever all active proxy/CONNECT tunnels belonging to `node_id` without cross-thread close FD races."""
        with self._active_conns_lock:
            socks = list(self._active_node_sockets.pop(node_id, set()))
        closed = 0
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
                closed += 1
            except OSError:
                pass
        return closed

    def check_node_rate_limit(self, node_id: str) -> tuple[bool, int]:
        """Enforce per-worker sliding-window requests/minute quota (`0` = unlimited)."""
        limit = int(self.cluster_config.gateway.max_requests_per_min_per_node)
        if limit <= 0:
            return True, 0
        now = time.monotonic()
        cutoff = now - 60.0
        with self._node_req_lock:
            dq = self._node_req_times.setdefault(node_id, collections.deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit:
                return False, len(dq)
            dq.append(now)
            return True, len(dq)

    def authenticate_worker(self, headers: dict[str, str], client_ip: str) -> tuple[str | None, str]:
        blocked, retry = self.rate_limiter.is_blocked(client_ip)
        if blocked:
            return None, f"rate limited ({retry}s)"
        creds = _parse_basic_proxy_auth(headers)
        if creds is None:
            self.rate_limiter.record_failure(client_ip)
            return None, "missing Proxy-Authorization"
        node_id, password = creds
        nodes_snapshot = list(self.cluster_config.nodes)
        node = next((n for n in nodes_snapshot if n.id == node_id), None)
        if node is None and "%" in node_id:
            unquoted_id = urllib.parse.unquote(node_id)
            node = next((n for n in nodes_snapshot if n.id == unquoted_id), None)
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
        with self._active_conns_lock:
            all_socks = [s for bucket in self._active_node_sockets.values() for s in bucket]
            self._active_node_sockets.clear()
        for s in all_socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().shutdown()


class _NetworkGuardHandler(socketserver.BaseRequestHandler):
    server: NetworkGuardServer

    def handle(self) -> None:
        conn: socket.socket = self.request
        client_ip = normalize_host(str(self.client_address[0]))
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
        req_parts = lines[0].split(" ")
        if len(req_parts) != 3 or not all(req_parts):
            _send_proxy_error(conn, 400, "Bad Request", "malformed HTTP proxy request")
            return
        method, target, version = req_parts
        if any(c in "\r\n\t\x00" for c in (method + target + version)) or version not in {"HTTP/1.0", "HTTP/1.1"}:
            _send_proxy_error(conn, 400, "Bad Request", "unsupported or malformed HTTP version")
            return
        method_u = method.upper()
        if not _HTTP_TOKEN_RE.fullmatch(method_u):
            _send_proxy_error(conn, 400, "Bad Request", "invalid HTTP method")
            return
        header_pairs: list[tuple[str, str]] = []
        headers_lower: dict[str, str] = {}
        for hline in lines[1:]:
            if not hline:
                continue
            if "\r" in hline or "\n" in hline or ":" not in hline:
                _send_proxy_error(conn, 400, "Bad Request", "malformed HTTP header line")
                return
            raw_k, raw_v = hline.split(":", 1)
            # RFC 9112 §5.1: reject whitespace before colon or non-token header names (smuggling defense)
            if not raw_k or not _HTTP_TOKEN_RE.fullmatch(raw_k):
                _send_proxy_error(conn, 400, "Bad Request", "invalid HTTP header name")
                return
            v_clean = raw_v.strip()
            if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in v_clean):
                _send_proxy_error(conn, 400, "Bad Request", "invalid control character in HTTP header value")
                return
            header_pairs.append((raw_k, v_clean))
            headers_lower[raw_k.lower()] = v_clean

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

        # 1b. Per-worker Quarantine check (instant 1-click isolation from Master UI!)
        if node_id in gw.quarantined_nodes:
            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=target[:120],
                port=0,
                action="quarantined",
                reason="node quarantined by Master",
            )
            _send_proxy_error(conn, 403, "Forbidden", f"node '{node_id}' is quarantined by Master")
            return

        # 1c. Per-worker Request Rate Quota (prevents runaway/compromised phone flooding Master)
        under_quota, rpm_cur = self.server.check_node_rate_limit(node_id)
        if not under_quota:
            self.server.audit_log.record(
                node_id=node_id,
                client_ip=client_ip,
                method=method_u,
                host=target[:120],
                port=0,
                action="rate_limited",
                reason=f"rate quota exceeded ({rpm_cur}/{gw.max_requests_per_min_per_node} req/min)",
            )
            _send_proxy_error(
                conn,
                429,
                "Too Many Requests",
                f"per-worker quota exceeded ({gw.max_requests_per_min_per_node} req/min)",
            )
            return

        # 2. Extract destination host & port
        if method_u == "CONNECT":
            if not _is_safe_ascii_host(target):
                _send_proxy_error(conn, 400, "Bad Request", "invalid CONNECT target")
                return
            if target.startswith("["):
                close_idx = target.find("]")
                if close_idx == -1:
                    _send_proxy_error(conn, 400, "Bad Request", "malformed bracketed IPv6 CONNECT target")
                    return
                dest_host = target[1:close_idx]
                rest = target[close_idx + 1 :]
                if not rest:
                    dest_port = 443
                elif rest.startswith(":") and _ASCII_PORT_RE.fullmatch(rest[1:]):
                    dest_port = int(rest[1:])
                else:
                    _send_proxy_error(conn, 400, "Bad Request", "invalid CONNECT port")
                    return
            elif target.count(":") > 1:
                _send_proxy_error(conn, 400, "Bad Request", "IPv6 CONNECT target must be bracketed")
                return
            elif ":" in target:
                h_part, p_str = target.rsplit(":", 1)
                if not _ASCII_PORT_RE.fullmatch(p_str):
                    _send_proxy_error(conn, 400, "Bad Request", "invalid CONNECT port")
                    return
                dest_host = h_part
                dest_port = int(p_str)
            else:
                dest_host = target
                dest_port = 443
            if not dest_host or "[" in dest_host or "]" in dest_host or not (1 <= dest_port <= 65535):
                _send_proxy_error(conn, 400, "Bad Request", "invalid CONNECT host or port")
                return
            forward_path = ""
        else:
            if "\\" in target:
                _send_proxy_error(conn, 400, "Bad Request", "invalid backslash in proxy URL")
                return
            try:
                parsed = urllib.parse.urlsplit(target)
                dest_port = 80 if parsed.port is None else parsed.port
            except ValueError:
                _send_proxy_error(conn, 400, "Bad Request", "malformed proxy target URL")
                return
            if parsed.scheme.lower() not in {"http"} or not parsed.hostname:
                _send_proxy_error(conn, 400, "Bad Request", "only HTTP URLs or HTTPS CONNECT supported")
                return
            if parsed.username is not None or parsed.password is not None:
                _send_proxy_error(conn, 400, "Bad Request", "userinfo in proxy target URL is not allowed")
                return
            dest_host = parsed.hostname
            if not _is_safe_ascii_host(dest_host):
                _send_proxy_error(conn, 400, "Bad Request", "invalid non-ASCII characters in target host")
                return
            if not (1 <= dest_port <= 65535):
                _send_proxy_error(conn, 400, "Bad Request", "invalid URL port")
                return
            forward_path = parsed.path or "/"
            if parsed.query:
                forward_path = f"{forward_path}?{parsed.query}"
            if not forward_path.startswith("/") or any(ord(c) < 32 or c == "\x7f" for c in forward_path):
                _send_proxy_error(conn, 400, "Bad Request", "invalid request path")
                return

        # 2b. Validate Host consistency (host + explicit port) & HTTP request framing BEFORE touching DNS/upstream
        host_values = [v for k, v in header_pairs if k.lower() == "host"]
        if len(host_values) > 1:
            _send_proxy_error(conn, 400, "Bad Request", "duplicate Host headers rejected")
            return
        if host_values:
            parsed_hdr = _parse_host_header(host_values[0])
            norm_dest = normalize_host(dest_host).lower().rstrip(".")
            if (
                parsed_hdr is None
                or parsed_hdr[0] != norm_dest
                or (parsed_hdr[1] is not None and parsed_hdr[1] != dest_port)
            ):
                bad_hdr = parsed_hdr[0] if parsed_hdr is not None else "?"
                self.server.audit_log.record(
                    node_id=node_id,
                    client_ip=client_ip,
                    method=method_u,
                    host=dest_host,
                    port=dest_port,
                    action="block",
                    reason=f"Host header mismatch ({bad_hdr} != {norm_dest}:{dest_port})",
                )
                _send_proxy_error(conn, 400, "Bad Request", "Host header does not match target URL/port")
                return

        is_chunked = False
        content_len = 0
        if method_u != "CONNECT":
            cl_values = [v.strip() for k, v in header_pairs if k.lower() == "content-length"]
            te_values = [v.strip() for k, v in header_pairs if k.lower() == "transfer-encoding"]
            if te_values and cl_values:
                _send_proxy_error(conn, 400, "Bad Request", "conflicting Transfer-Encoding and Content-Length")
                return
            if len(te_values) > 1:
                _send_proxy_error(conn, 400, "Bad Request", "multiple Transfer-Encoding headers not supported")
                return
            if te_values:
                if version == "HTTP/1.0":
                    _send_proxy_error(conn, 400, "Bad Request", "Transfer-Encoding is not allowed in HTTP/1.0")
                    return
                if te_values[0].lower() != "chunked":
                    _send_proxy_error(conn, 501, "Not Implemented", "only Transfer-Encoding: chunked is supported")
                    return
                is_chunked = True
            if cl_values:
                if len(cl_values) > 1:
                    _send_proxy_error(conn, 400, "Bad Request", "duplicate Content-Length headers rejected")
                    return
                if not _ASCII_UINT_RE.fullmatch(cl_values[0]):
                    _send_proxy_error(conn, 400, "Bad Request", "invalid Content-Length header")
                    return
                content_len = int(cl_values[0])
            if content_len > MAX_HTTP_BODY_BYTES:
                _send_proxy_error(conn, 413, "Payload Too Large", "request body exceeds limit")
                return

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
        # 4b. Also enforce `blocked_domains` against resolved IPs (defeats octal/hex/decimal/mapped/NAT64 IP & DNS indirection)
        if gw.blocked_domains:
            for _fam, sa in candidates:
                resolved_ip = normalize_host(str(sa[0]))
                ip_cands = [resolved_ip]
                try:
                    r_addr = ipaddress.ip_address(resolved_ip)
                    if isinstance(r_addr, ipaddress.IPv6Address):
                        if r_addr.ipv4_mapped is not None:
                            ip_cands.append(str(r_addr.ipv4_mapped))
                        if r_addr in _NAT64_WELL_KNOWN_NET:
                            ip_cands.append(str(ipaddress.IPv4Address(int(r_addr) & 0xFFFFFFFF)))
                except ValueError:
                    pass
                for cand_ip in ip_cands:
                    for pat in gw.blocked_domains:
                        if domain_matches(cand_ip, pat):
                            blk_reason = f"resolved IP {cand_ip} matched blocked rule '{pat}'"
                            self.server.audit_log.record(
                                node_id=node_id,
                                client_ip=client_ip,
                                method=method_u,
                                host=dest_host,
                                port=dest_port,
                                action="block",
                                reason=blk_reason,
                            )
                            _send_proxy_error(conn, 403, "Forbidden", blk_reason)
                            return

        upstream: socket.socket | None = None
        bytes_in = 0
        bytes_out = 0
        response_started = False
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

            self.server.register_node_sockets(node_id, conn, upstream)
            if node_id in self.server.cluster_config.gateway.quarantined_nodes:
                _send_proxy_error(conn, 403, "Forbidden", f"node '{node_id}' is quarantined by Master")
                return
            conn.settimeout(gw.idle_timeout_sec)
            upstream.settimeout(gw.idle_timeout_sec)
            if method_u == "CONNECT":
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                response_started = True
                if leftover:
                    upstream.sendall(leftover)
                    bytes_out += len(leftover)
                r_in, r_out = _relay_bidirectional(
                    conn,
                    upstream,
                    idle_timeout=gw.idle_timeout_sec,
                    stop_event=self.server.stop_event,
                    abort_check=lambda: node_id in self.server.cluster_config.gateway.quarantined_nodes,
                )
                bytes_in += r_in
                bytes_out += r_out
            else:
                # Strip Proxy-* / hop-by-hop headers so worker credentials NEVER leak upstream,
                # while NEVER letting malicious `Connection: Content-Length/Host/Transfer-Encoding` strip framing!
                conn_tokens = {
                    tok.strip().lower()
                    for k, v in header_pairs
                    if k.lower() == "connection"
                    for tok in v.split(",")
                    if tok.strip()
                }
                hop_headers = (
                    {
                        "connection",
                        "keep-alive",
                        "te",
                        "trailers",
                        "upgrade",
                        "expect",
                    }
                    | conn_tokens
                ) - _PROTECTED_END_TO_END_HEADERS
                out_headers = [
                    f"{k}: {v}"
                    for k, v in header_pairs
                    if not k.lower().startswith("proxy-") and k.lower() not in hop_headers
                ]
                if "host" not in headers_lower:
                    host_hdr = (
                        format_host_for_url(dest_host)
                        if dest_port == 80
                        else format_host_port(dest_host, dest_port)
                    )
                    out_headers.append(f"Host: {host_hdr}")
                out_headers.append("Connection: close")
                req_head = (
                    f"{method_u} {forward_path} {version}\r\n"
                    + "\r\n".join(out_headers)
                    + "\r\n\r\n"
                ).encode("iso-8859-1", errors="replace")

                upstream.sendall(req_head)
                bytes_out += len(req_head)

                if version == "HTTP/1.1" and "100-continue" in headers_lower.get("expect", "").lower():
                    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

                if is_chunked:
                    chunk_sent = [0]
                    try:
                        _relay_chunked_request_body(
                            conn,
                            upstream,
                            leftover,
                            idle_timeout=gw.idle_timeout_sec,
                            stop_event=self.server.stop_event,
                            abort_check=lambda: node_id in self.server.cluster_config.gateway.quarantined_nodes,
                            sent_counter=chunk_sent,
                        )
                        bytes_out += chunk_sent[0]
                    except ValueError as exc:
                        bytes_out += chunk_sent[0]
                        self.server.audit_log.record(
                            node_id=node_id,
                            client_ip=client_ip,
                            method=method_u,
                            host=dest_host,
                            port=dest_port,
                            action="block",
                            reason=f"chunked request error: {exc}",
                            bytes_in=bytes_in,
                            bytes_out=bytes_out,
                        )
                        code = 413 if "limit" in str(exc) else 400
                        _send_proxy_error(conn, code, "Bad Request" if code == 400 else "Payload Too Large", str(exc))
                        return
                elif content_len > 0:
                    initial_body = leftover[:content_len]
                    if initial_body:
                        upstream.sendall(initial_body)
                        bytes_out += len(initial_body)
                    remaining = max(0, content_len - len(initial_body))
                    conn.settimeout(gw.idle_timeout_sec)
                    while remaining > 0 and not self.server.stop_event.is_set():
                        if node_id in self.server.cluster_config.gateway.quarantined_nodes:
                            raise OSError("node quarantined during upload")
                        chunk = conn.recv(min(RELAY_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise OSError("truncated request body")
                        upstream.sendall(chunk)
                        bytes_out += len(chunk)
                        remaining -= len(chunk)

                # Relay upstream HTTP response cleanly (sanitizes hop-by-hop headers, forces Connection: close, respects HEAD/204/304/CL/chunked)
                r_in, response_started = _relay_http_response(
                    conn,
                    upstream,
                    method_u=method_u,
                    req_version=version,
                    idle_timeout=gw.idle_timeout_sec,
                    stop_event=self.server.stop_event,
                    abort_check=lambda: node_id in self.server.cluster_config.gateway.quarantined_nodes,
                )
                bytes_in += r_in

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
                action="allow" if response_started else "block",
                reason=f"relay closed: {exc}" if response_started else f"upstream connect/relay error: {exc}",
                bytes_in=bytes_in,
                bytes_out=bytes_out,
            )
            if not response_started:
                _send_proxy_error(conn, 502, "Bad Gateway", str(exc))
        finally:
            if upstream is not None:
                self.server.unregister_node_sockets(node_id, conn, upstream)
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
        self._lifecycle_lock = threading.RLock()
        self._server: NetworkGuardServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_host: str = ""
        self._bound_max_conn: int = 0
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
        with self._lifecycle_lock:
            with self._lock:
                if self._server is not None:
                    return True, f"already running on port {self._server.server_address[1]}"
            gw = self.config.gateway
            try:
                srv = NetworkGuardServer((gw.bind_host, gw.port), self.config, self.audit_log)
            except OSError as exc:
                with self._lock:
                    self._last_error = str(exc)
                return False, f"could not bind {gw.bind_host}:{gw.port}: {exc}"
            th = threading.Thread(
                target=srv.serve_forever,
                kwargs={"poll_interval": 0.25},
                name="network-guard-gateway",
                daemon=True,
            )
            th.start()
            with self._lock:
                self._server = srv
                self._thread = th
                self._bound_host = gw.bind_host
                self._bound_max_conn = gw.max_connections
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

    def disconnect_node(self, node_id: str) -> int:
        """Sever any active proxy/CONNECT tunnels for a newly quarantined or removed worker."""
        with self._lock:
            srv = self._server
        if srv is not None:
            return srv.disconnect_node(node_id)
        return 0

    def stop(self) -> None:
        with self._lifecycle_lock:
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
        with self._lifecycle_lock:
            gw = self.config.gateway
            if not gw.enabled:
                self.stop()
                return True, "disabled"
            with self._lock:
                needs_rebind = (
                    self._server is not None
                    and (
                        (self._server.server_address[1] != gw.port and gw.port != 0)
                        or self._bound_host != gw.bind_host
                        or self._bound_max_conn != gw.max_connections
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
        with self._lock:
            last_err = self._last_error
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
            "quarantined_nodes": list(gw.quarantined_nodes),
            "max_requests_per_min_per_node": gw.max_requests_per_min_per_node,
            "last_error": last_err,
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
