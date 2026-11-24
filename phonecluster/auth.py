"""Shared-secret HMAC request signing, replay protection, bearer auth, and brute-force rate limiting."""

from __future__ import annotations

import collections
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from typing import Any, Mapping

HMAC_AUTH_SCHEME = "PC-HMAC-SHA256"
_NONCE_RE = re.compile(r"^[A-Fa-f0-9]{16,64}$")
_SIG_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_ASCII_UINT_RE = re.compile(r"^[0-9]{1,10}$")
_ASCII_TS_RE = re.compile(r"^[0-9]{1,12}$")
_ASCII_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_SINGLE_LABEL_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MULTI_LABEL_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_NAT64_WELL_KNOWN_NET = ipaddress.IPv6Network("64:ff9b::/96")
_SIIT_TRANSLATED_NET = ipaddress.IPv6Network("::ffff:0:0:0/96")
_IPV4_THIS_NET = ipaddress.IPv4Network("0.0.0.0/8")
_IPV4_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")
_LOCAL_HOST_SUFFIXES = (
    ".local",
    ".lan",
    ".home",
    ".home.arpa",
    ".internal",
    ".cluster",
    ".localhost",
    ".ts.net",
)


def is_allowed_http_host(
    headers: Mapping[str, str],
    extra_allowed_hosts: set[str] | frozenset[str] | None = None,
) -> bool:
    """Validate HTTP `Host:` header(s) to defeat DNS rebinding & duplicate-Host smuggling.

    Allows missing `Host` (HTTP/1.0), any IPv4/IPv6 literal, `localhost`, single-label
    LAN hostnames, standard local/Tailscale suffixes (`.local`, `.lan`, `.home`,
    `.home.arpa`, `.internal`, `.cluster`, `.localhost`, `.ts.net`), this host's own
    hostname, configured cluster node hosts, and `PHONECLUSTER_ALLOWED_HOSTS`.
    Rejects duplicate `Host` headers, malformed host/port syntax, and arbitrary public
    multi-label internet domains (e.g. `evil.com`, `192.168.1.201.nip.io`).
    """
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        host_vals = [str(v).strip() for v in (get_all("Host") or [])]
    else:
        host_vals = [str(v).strip() for k, v in headers.items() if k.lower() == "host"]

    if not host_vals:
        return True
    if len(host_vals) > 1:
        return False

    raw = host_vals[0]
    if not raw or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "@/\\?#;'\"" for c in raw):
        return False

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return False
        host_part = raw[1:end].strip()
        rest = raw[end + 1 :]
        if rest:
            if not rest.startswith(":") or not _ASCII_PORT_RE.fullmatch(rest[1:]):
                return False
            p_num = int(rest[1:])
            if not (1 <= p_num <= 65535):
                return False
        if "%" in host_part:
            return False
        try:
            ipaddress.IPv6Address(host_part)
            return True
        except ValueError:
            return False
    elif raw.count(":") > 1:
        # Unbracketed IPv6 in Host header is invalid per RFC 9110 §7.2
        return False
    elif ":" in raw:
        host_part, p_str = raw.rsplit(":", 1)
        if not host_part or not _ASCII_PORT_RE.fullmatch(p_str):
            return False
        p_num = int(p_str)
        if not (1 <= p_num <= 65535):
            return False
    else:
        host_part = raw

    h = host_part.strip().lower().rstrip(".")
    if not h or "%" in h:
        return False

    # 1. Any IPv4 literal (browsers never perform DNS rebinding against IP literals)
    try:
        ipaddress.IPv4Address(h)
        return True
    except ValueError:
        pass

    # 2. Localhost, single-label LAN hostnames (e.g. `raspberrypi`), or private/mDNS/Tailscale suffixes
    if h == "localhost":
        return True
    if _MULTI_LABEL_HOST_RE.fullmatch(h) and h.endswith(_LOCAL_HOST_SUFFIXES):
        return True
    if "." not in h and _SINGLE_LABEL_HOST_RE.fullmatch(h):
        return True

    # 3. Local machine hostname, configured cluster node hostnames, or explicit env allowlist
    allowed_set: set[str] = set()
    try:
        local_hn = socket.gethostname().strip().lower().rstrip(".")
        if local_hn:
            allowed_set.add(local_hn)
    except OSError:
        pass
    if extra_allowed_hosts:
        for item in extra_allowed_hosts:
            clean_item = str(item or "").strip().strip("[]").lower().rstrip(".")
            if clean_item:
                allowed_set.add(clean_item)
    env_hosts = os.environ.get("PHONECLUSTER_ALLOWED_HOSTS", "")
    if env_hosts:
        for item in env_hosts.split(","):
            clean_item = item.strip().strip("[]").lower().rstrip(".")
            if clean_item:
                allowed_set.add(clean_item)
    return h in allowed_set


def parse_strict_content_length(
    headers: Mapping[str, str], max_bytes: int
) -> tuple[int | None, int, str]:
    """Strictly parse RFC 9110 Content-Length and reject Transfer-Encoding / smuggling forms.

    Returns `(length, http_status, error_msg)`. On success `length` is an `int >= 0`
    and `error_msg` is `""`. Rejects Python `int()` edge forms like `1_0`, `+5`, and
    Unicode digits, as well as duplicate/conflicting `Content-Length` headers and
    unsupported `Transfer-Encoding` on JSON API endpoints.
    """
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        te_vals = [str(v).strip() for v in (get_all("Transfer-Encoding") or []) if str(v).strip()]
        cl_vals = [str(v).strip() for v in (get_all("Content-Length") or [])]
    else:
        te_vals = [str(v).strip() for k, v in headers.items() if k.lower() == "transfer-encoding" and str(v).strip()]
        cl_vals = [str(v).strip() for k, v in headers.items() if k.lower() == "content-length"]

    if te_vals:
        return None, int(HTTPStatus.NOT_IMPLEMENTED), "Transfer-Encoding is not supported on this endpoint"
    if not cl_vals:
        return 0, int(HTTPStatus.OK), ""
    if len(cl_vals) > 1:
        return None, int(HTTPStatus.BAD_REQUEST), "duplicate Content-Length headers rejected"
    raw = cl_vals[0]
    if not _ASCII_UINT_RE.fullmatch(raw):
        return None, int(HTTPStatus.BAD_REQUEST), "invalid Content-Length header"
    length = int(raw)
    if length > max_bytes:
        return None, int(HTTPStatus.REQUEST_ENTITY_TOO_LARGE), f"payload exceeds {max_bytes} bytes"
    return length, int(HTTPStatus.OK), ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse all HTTP redirects for Master<->Worker and Pairing calls (blocks SSRF via compromised workers)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _sanitize_json_value(obj: Any) -> Any:
    """Iteratively replace non-finite floats (NaN/Infinity) with None for RFC 8259 JSON compliance."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if not isinstance(obj, (dict, list, tuple)):
        return obj
    root: Any = {} if isinstance(obj, dict) else []
    stack: list[tuple[Any, Any]] = [(obj, root)]
    while stack:
        src, dst = stack.pop()
        if isinstance(src, dict):
            for k, v in src.items():
                if isinstance(v, float):
                    dst[k] = v if math.isfinite(v) else None
                elif isinstance(v, dict):
                    child_d: dict[Any, Any] = {}
                    dst[k] = child_d
                    stack.append((v, child_d))
                elif isinstance(v, (list, tuple)):
                    child_l: list[Any] = []
                    dst[k] = child_l
                    stack.append((v, child_l))
                else:
                    dst[k] = v
        else:
            for v in src:
                if isinstance(v, float):
                    dst.append(v if math.isfinite(v) else None)
                elif isinstance(v, dict):
                    child_d = {}
                    dst.append(child_d)
                    stack.append((v, child_d))
                elif isinstance(v, (list, tuple)):
                    child_l = []
                    dst.append(child_l)
                    stack.append((v, child_l))
                else:
                    dst.append(v)
    return root


def safe_json_dumps(obj: Any) -> str:
    """Serialize `obj` as strict RFC 8259 JSON (guarantees zero bare `NaN`/`Infinity` tokens)."""
    try:
        return json.dumps(obj, allow_nan=False)
    except ValueError:
        return json.dumps(_sanitize_json_value(obj), allow_nan=False)


def _embedded_ipv4s(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Return any embedded IPv4 addresses carried inside mapped/NAT64/SIIT/6to4/Teredo IPv6 addresses."""
    out: list[ipaddress.IPv4Address] = []
    if isinstance(addr, ipaddress.IPv4Address):
        return [addr]
    if addr.ipv4_mapped is not None:
        out.append(addr.ipv4_mapped)
    if addr.sixtofour is not None:
        out.append(addr.sixtofour)
    if addr.teredo is not None:
        out.extend(addr.teredo)
    if addr in _NAT64_WELL_KNOWN_NET or addr in _SIIT_TRANSLATED_NET:
        out.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    return out


def _is_webhook_ip_disallowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IP (or mapped/NAT64/SIIT/6to4/Teredo IPv4) is link-local/metadata, 0/8, site-local, or multicast."""
    if isinstance(addr, ipaddress.IPv6Address):
        if getattr(addr, "is_site_local", False):
            return True
        for v4 in _embedded_ipv4s(addr):
            if _is_webhook_ip_disallowed(v4):
                return True
    elif addr in _IPV4_THIS_NET:
        return True
    return bool(addr.is_link_local or addr.is_unspecified or addr.is_multicast)


def _is_non_public_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if `addr` (or embedded IPv4) is loopback, private LAN, CGNAT, link-local, or non-global."""
    if _is_webhook_ip_disallowed(addr):
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        for v4 in _embedded_ipv4s(addr):
            if _is_non_public_ip(v4):
                return True
        return bool(addr.is_loopback or addr.is_private or addr.is_reserved or not addr.is_global)
    return bool(
        addr.is_loopback
        or addr.is_private
        or addr.is_reserved
        or addr in _IPV4_CGNAT_NET
        or not addr.is_global
    )


def is_webhook_target_unsafe(url: str) -> bool:
    """Block direct webhook SSRF to non-HTTP(S), link-local/cloud metadata (169.254/16, fe80::/10), 0/8, unspecified, or multicast IPs.

    Legitimate local LAN/loopback Home Assistant / Node-RED webhooks (192.168.x.x, 127.0.0.1)
    and public services (e.g. ntfy.sh) remain allowed.
    """
    clean = str(url or "").strip()
    if not clean or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in clean):
        return True
    try:
        parsed = urllib.parse.urlsplit(clean)
        raw_port = parsed.port
    except ValueError:
        return True
    if raw_port is not None and not (1 <= raw_port <= 65535):
        return True
    port = raw_port if raw_port is not None else (443 if parsed.scheme.lower() == "https" else 80)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return True
    host = parsed.hostname.strip().strip("[]").lower()
    if not host or "%" in host:
        return True
    # Check IP literal directly first (strip trailing dot to catch e.g. 169.254.169.254.)
    host_nodot = host.rstrip(".")
    if not host_nodot:
        return True
    try:
        lit = ipaddress.ip_address(host_nodot)
        return _is_webhook_ip_disallowed(lit)
    except ValueError:
        pass
    # Best-effort DNS check for hostnames resolving to link-local / cloud metadata / unspecified / multicast
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for _fam, _st, _pr, _cn, sa in infos:
        ip_raw = str(sa[0])
        if "%" in ip_raw:
            return True
        try:
            addr = ipaddress.ip_address(ip_raw)
        except ValueError:
            return True
        if _is_webhook_ip_disallowed(addr):
            return True
    return False


def _is_webhook_redirect_target_unsafe(orig_url: str, new_url: str) -> bool:
    """Block webhook redirects to non-HTTP(S), link-local/metadata, public->private/LAN, or remote->loopback SSRF."""
    try:
        parsed_new = urllib.parse.urlsplit(new_url)
        raw_new_port = parsed_new.port
    except ValueError:
        return True
    if raw_new_port is not None and not (1 <= raw_new_port <= 65535):
        return True
    new_port = raw_new_port if raw_new_port is not None else (443 if parsed_new.scheme.lower() == "https" else 80)
    if parsed_new.scheme.lower() not in {"http", "https"} or not parsed_new.hostname:
        return True
    new_host = parsed_new.hostname.strip().strip("[]").lower()
    if not new_host or "%" in new_host:
        return True
    try:
        parsed_orig = urllib.parse.urlsplit(orig_url)
        orig_host = (parsed_orig.hostname or "").strip().strip("[]").lower()
        orig_port = parsed_orig.port or (443 if parsed_orig.scheme.lower() == "https" else 80)
    except ValueError:
        return True

    def _is_loopback_addr(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if isinstance(a, ipaddress.IPv6Address):
            for v4 in _embedded_ipv4s(a):
                if v4.is_loopback or v4.is_unspecified or v4 in _IPV4_THIS_NET:
                    return True
        return bool(a.is_loopback or a.is_unspecified or (isinstance(a, ipaddress.IPv4Address) and a in _IPV4_THIS_NET))

    def _classify_origin(h: str, p: int) -> tuple[bool, bool]:
        """Return `(orig_is_loopback, orig_is_private_or_local)`."""
        nodot = h.rstrip(".")
        if nodot == "localhost":
            return True, True
        try:
            a = ipaddress.ip_address(nodot)
            return _is_loopback_addr(a), _is_non_public_ip(a)
        except ValueError:
            pass
        if nodot.endswith(_LOCAL_HOST_SUFFIXES) or "." not in nodot:
            return False, True
        try:
            orig_infos = socket.getaddrinfo(h, p, type=socket.SOCK_STREAM)
            orig_addrs = [ipaddress.ip_address(str(sa[0])) for *_r, sa in orig_infos if "%" not in str(sa[0])]
            if orig_addrs and all(_is_non_public_ip(a) for a in orig_addrs):
                return all(_is_loopback_addr(a) for a in orig_addrs), True
        except (OSError, ValueError):
            pass
        return False, False

    orig_is_loopback, orig_is_private = _classify_origin(orig_host, orig_port)
    if new_host.rstrip(".") == "localhost" and not orig_is_loopback:
        return True
    new_nodot = new_host.rstrip(".")
    try:
        lit_new = ipaddress.ip_address(new_nodot)
        if _is_webhook_ip_disallowed(lit_new):
            return True
        if _is_loopback_addr(lit_new) and not orig_is_loopback:
            return True
        if _is_non_public_ip(lit_new) and not orig_is_private:
            return True
        return False
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(new_host, new_port, type=socket.SOCK_STREAM)
    except OSError:
        return True
    if not infos:
        return True
    for _fam, _st, _pr, _cn, sa in infos:
        ip_raw = str(sa[0])
        if "%" in ip_raw:
            return True
        try:
            addr = ipaddress.ip_address(ip_raw)
        except ValueError:
            return True
        if _is_webhook_ip_disallowed(addr):
            return True
        if _is_loopback_addr(addr) and not orig_is_loopback:
            return True
        if _is_non_public_ip(addr) and not orig_is_private:
            return True
    return False


def _connect_validated_webhook_socket(
    host: str, port: int, timeout: Any, source_address: Any = None
) -> socket.socket:
    """Resolve DNS ONCE, validate every IP against webhook SSRF rules, and connect directly (blocks DNS-rebinding TOCTOU)."""
    clean_host = str(host or "").strip().strip("[]").lower()
    if not clean_host or "%" in clean_host or not (1 <= int(port) <= 65535):
        raise OSError(f"Refused unsafe webhook target {host!r}:{port}")
    try:
        infos = socket.getaddrinfo(clean_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"Webhook DNS resolution failed for {clean_host!r}: {exc}") from exc
    if not infos:
        raise OSError(f"No addresses resolved for webhook target {clean_host!r}")
    for _fam, _st, _pr, _cn, sa in infos:
        ip_raw = str(sa[0])
        if "%" in ip_raw:
            raise OSError(f"Refused webhook IP with zone identifier: {ip_raw}")
        try:
            addr = ipaddress.ip_address(ip_raw)
        except ValueError as exc:
            raise OSError(f"Invalid resolved webhook IP {ip_raw!r}") from exc
        if _is_webhook_ip_disallowed(addr):
            raise OSError(f"Blocked unsafe webhook destination IP {ip_raw}")
    last_exc: OSError | None = None
    for fam, socktype, proto, _cn, sa in infos:
        s: socket.socket | None = None
        try:
            s = socket.socket(fam, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:  # type: ignore[attr-defined]
                s.settimeout(timeout)
            if source_address:
                s.bind(source_address)
            s.connect(sa)
            return s
        except OSError as exc:
            last_exc = exc
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    raise last_exc or OSError(f"Unable to connect to webhook target {clean_host}:{port}")


class _SafeWebhookHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection subclass that connects only to DNS-validated, SSRF-safe IPs (single-resolve)."""

    def connect(self) -> None:
        self.sock = _connect_validated_webhook_socket(
            self.host, self.port, self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _SafeWebhookHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection subclass that connects only to DNS-validated IPs while preserving TLS SNI."""

    def connect(self) -> None:
        raw_sock = _connect_validated_webhook_socket(
            self.host, self.port, self.timeout, self.source_address
        )
        try:
            if self._tunnel_host:
                self.sock = raw_sock
                self._tunnel()
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host.strip("[]")
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=server_hostname)
        except BaseException:
            try:
                raw_sock.close()
            except OSError:
                pass
            self.sock = None
            raise


class _SafeWebhookHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: Any) -> Any:
        return self.do_open(_SafeWebhookHTTPConnection, req)


class _SafeWebhookHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: Any) -> Any:
        return self.do_open(_SafeWebhookHTTPSConnection, req, context=self._context)


class _HttpOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow safe HTTP(S) redirects for webhooks while blocking file://, metadata, public->LAN, and remote->loopback SSRF."""

    max_redirections = 5

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        if _is_webhook_redirect_target_unsafe(req.full_url, newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_direct_opener() -> urllib.request.OpenerDirector:
    """Return a direct LAN opener that ignores host `HTTP_PROXY` env vars and refuses HTTP redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())


def build_webhook_opener() -> urllib.request.OpenerDirector:
    """Return an opener for user webhooks with single-resolve SSRF blocking and strict redirect guards."""
    return urllib.request.build_opener(
        _SafeWebhookHTTPHandler(),
        _SafeWebhookHTTPSHandler(),
        _HttpOnlyRedirectHandler(),
    )


def read_json_object_bounded(resp: Any, max_bytes: int) -> dict[str, Any]:
    """Read an HTTP JSON response with a strict RAM cap and verify it is a JSON object (`dict`)."""
    raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"response exceeds {max_bytes} byte safety limit")
    try:
        parsed = json.loads(raw.decode("utf-8"), parse_constant=lambda _c: None)
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeded") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"expected JSON object, got {type(parsed).__name__}")
    return parsed


def _get_auth_header(headers: Mapping[str, str]) -> str | None:
    for key, val in headers.items():
        if key.lower() == "authorization":
            return val
    return None


def extract_auth_scheme(headers: Mapping[str, str]) -> str:
    """Return the normalized HTTP Authorization scheme (e.g. 'pc-hmac-sha256', 'bearer', or '')."""
    auth_val = _get_auth_header(headers)
    if not auth_val:
        return ""
    parts = auth_val.strip().split(None, 1)
    return parts[0].lower() if parts else ""


def build_auth_headers(token: str) -> dict[str, str]:
    """Return HTTP headers containing the cluster bearer token."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _canonical_signing_input(
    method: str, path: str, ts: str, nonce: str, body: bytes
) -> bytes:
    clean_path = path.split("?", 1)[0] or "/"
    body_hash = hashlib.sha256(body).hexdigest()
    return f"PC-V1|{method.upper()}|{clean_path}|{ts}|{nonce}|{body_hash}".encode("utf-8")


def build_signed_auth_headers(
    token: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    ts: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Return replay-resistant HMAC-SHA256 Authorization headers without putting the raw token on the wire."""
    ts_str = str(int(time.time()) if ts is None else int(ts))
    nonce_str = nonce if nonce is not None else secrets.token_hex(12)
    msg = _canonical_signing_input(method, path, ts_str, nonce_str, body)
    sig = hmac.new(token.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return {
        "Authorization": f"{HMAC_AUTH_SCHEME} ts={ts_str},nonce={nonce_str},sig={sig}",
        "Content-Type": "application/json",
    }


def parse_hmac_auth_header(headers: Mapping[str, str]) -> tuple[int, str, str] | None:
    """Parse `Authorization: PC-HMAC-SHA256 ts=<int>,nonce=<hex>,sig=<hex64>` safely."""
    auth_val = _get_auth_header(headers)
    if not auth_val:
        return None
    parts = auth_val.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != HMAC_AUTH_SCHEME.lower():
        return None
    kv: dict[str, str] = {}
    for piece in parts[1].split(","):
        if "=" not in piece:
            return None
        k, v = piece.split("=", 1)
        kv[k.strip().lower()] = v.strip()
    if set(kv.keys()) != {"ts", "nonce", "sig"}:
        return None
    if not _ASCII_TS_RE.fullmatch(kv["ts"]):
        return None
    ts = int(kv["ts"])
    nonce = kv["nonce"]
    sig = kv["sig"].lower()
    if not _NONCE_RE.fullmatch(nonce) or not _SIG_RE.fullmatch(sig):
        return None
    return ts, nonce, sig


class ReplayCache:
    """Thread-safe bounded single-use nonce cache preventing captured-request replay attacks."""

    def __init__(self, ttl_sec: float = 150.0, max_entries: int = 4096) -> None:
        self.ttl_sec = max(10.0, float(ttl_sec))
        self.max_entries = max(64, int(max_entries))
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str) -> bool:
        """Atomically record `nonce` and return True if fresh, False if already replayed."""
        now = time.monotonic()
        with self._lock:
            if len(self._seen) >= self.max_entries:
                expired = [k for k, exp in self._seen.items() if exp <= now]
                for k in expired:
                    self._seen.pop(k, None)
                if len(self._seen) >= self.max_entries:
                    # Drop oldest quarter if flooded within window
                    oldest = sorted(self._seen.items(), key=lambda kv: kv[1])[: self.max_entries // 4]
                    for k, _ in oldest:
                        self._seen.pop(k, None)
            exp = self._seen.get(nonce)
            if exp is not None and exp > now:
                return False
            self._seen[nonce] = now + self.ttl_sec
            return True


def verify_hmac_request(
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    expected_token: str,
    replay_cache: ReplayCache | None = None,
    max_skew_sec: float = 60.0,
) -> tuple[bool, str]:
    """Verify an HMAC-SHA256 signed request (timestamp freshness, body integrity, and single-use nonce)."""
    if not expected_token:
        return False, "missing expected token"
    parsed = parse_hmac_auth_header(headers)
    if parsed is None:
        return False, "malformed HMAC authorization header"
    ts, nonce, provided_sig = parsed
    now = time.time()
    if abs(now - ts) > max_skew_sec:
        return False, "expired or future-dated request timestamp"
    msg = _canonical_signing_input(method, path, str(ts), nonce, body)
    expected_sig = hmac.new(expected_token.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        return False, "invalid HMAC request signature"
    if replay_cache is not None and not replay_cache.check_and_record(nonce):
        return False, "replayed request nonce rejected"
    return True, "ok"


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Extract a Bearer token from HTTP request headers (case-insensitive)."""
    auth_val = _get_auth_header(headers)
    if not auth_val:
        return None
    parts = auth_val.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def verify_token(headers: Mapping[str, str], expected_token: str) -> bool:
    """Verify the request's Bearer token in constant time."""
    provided = extract_bearer_token(headers)
    if not provided or not expected_token:
        return False
    return hmac.compare_digest(provided, expected_token)


class AuthRateLimiter:
    """Thread-safe per-IP sliding-window rate limiter against token brute-forcing."""

    def __init__(
        self,
        max_failures: int = 10,
        window_sec: float = 60.0,
        block_sec: float = 60.0,
    ) -> None:
        self.max_failures = max(1, max_failures)
        self.window_sec = max(1.0, window_sec)
        self.block_sec = max(1.0, block_sec)
        self._lock = threading.Lock()
        self._failures: dict[str, collections.deque[float]] = {}
        self._blocked_until: dict[str, float] = {}

    @staticmethod
    def _norm_ip(client_ip: str) -> str:
        raw = str(client_ip or "").strip().strip("[]")
        if "%" in raw:
            raw = raw.split("%", 1)[0]
        try:
            a = ipaddress.ip_address(raw)
            if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
                return str(a.ipv4_mapped)
            return str(a)
        except ValueError:
            return raw.lower()

    def is_blocked(self, client_ip: str) -> tuple[bool, int]:
        """Return `(blocked, retry_after_sec)` for `client_ip`."""
        key = self._norm_ip(client_ip)
        now = time.monotonic()
        with self._lock:
            until = self._blocked_until.get(key, 0.0)
            if until > now:
                return True, max(1, int(until - now))
            if until:
                self._blocked_until.pop(key, None)
        return False, 0

    def _prune_locked(self, now: float) -> None:
        """Bound in-memory IP tracking tables on long-running low-RAM controllers."""
        if len(self._failures) > 512:
            cutoff = now - self.window_sec
            stale = [ip for ip, dq in self._failures.items() if not dq or dq[-1] < cutoff]
            for ip in stale:
                self._failures.pop(ip, None)
            if len(self._failures) > 2048:
                # Hard cap against spoofed/distinct-IP memory floods within one window
                oldest = sorted(
                    self._failures.items(),
                    key=lambda kv: kv[1][-1] if kv[1] else 0.0,
                )[: len(self._failures) - 1024]
                for ip, _ in oldest:
                    self._failures.pop(ip, None)
        if len(self._blocked_until) > 512:
            expired = [ip for ip, until in self._blocked_until.items() if until <= now]
            for ip in expired:
                self._blocked_until.pop(ip, None)
            if len(self._blocked_until) > 2048:
                earliest = sorted(self._blocked_until.items(), key=lambda kv: kv[1])[
                    : len(self._blocked_until) - 1024
                ]
                for ip, _ in earliest:
                    self._blocked_until.pop(ip, None)

    def record_failure(self, client_ip: str) -> bool:
        """Record one failed auth attempt; returns True if the IP is now blocked."""
        key = self._norm_ip(client_ip)
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            self._prune_locked(now)
            dq = self._failures.setdefault(key, collections.deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(now)
            if len(dq) >= self.max_failures:
                self._blocked_until[key] = now + self.block_sec
                dq.clear()
                return True
        return False

    def record_success(self, client_ip: str) -> None:
        """Clear prior failures for `client_ip` after a valid authenticated request."""
        key = self._norm_ip(client_ip)
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)
