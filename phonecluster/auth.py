"""Shared-secret HMAC request signing, replay protection, bearer auth, and brute-force rate limiting."""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import re
import secrets
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


class _HttpOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only http:// or https:// redirects for user-configured outbound webhooks (blocks file:///ftp://)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_direct_opener() -> urllib.request.OpenerDirector:
    """Return a direct LAN opener that ignores host `HTTP_PROXY` env vars and refuses HTTP redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())


def build_webhook_opener() -> urllib.request.OpenerDirector:
    """Return an opener for user webhooks that blocks non-HTTP(S) redirect schemes."""
    return urllib.request.build_opener(_HttpOnlyRedirectHandler())


def read_json_object_bounded(resp: Any, max_bytes: int) -> dict[str, Any]:
    """Read an HTTP JSON response with a strict RAM cap and verify it is a JSON object (`dict`)."""
    raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"response exceeds {max_bytes} byte safety limit")
    parsed = json.loads(raw.decode("utf-8"))
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

    def is_blocked(self, client_ip: str) -> tuple[bool, int]:
        """Return `(blocked, retry_after_sec)` for `client_ip`."""
        now = time.monotonic()
        with self._lock:
            until = self._blocked_until.get(client_ip, 0.0)
            if until > now:
                return True, max(1, int(until - now))
            if until:
                self._blocked_until.pop(client_ip, None)
        return False, 0

    def _prune_locked(self, now: float) -> None:
        """Bound in-memory IP tracking tables on long-running low-RAM controllers."""
        if len(self._failures) > 512:
            cutoff = now - self.window_sec
            stale = [ip for ip, dq in self._failures.items() if not dq or dq[-1] < cutoff]
            for ip in stale:
                self._failures.pop(ip, None)
        if len(self._blocked_until) > 512:
            expired = [ip for ip, until in self._blocked_until.items() if until <= now]
            for ip in expired:
                self._blocked_until.pop(ip, None)

    def record_failure(self, client_ip: str) -> bool:
        """Record one failed auth attempt; returns True if the IP is now blocked."""
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            self._prune_locked(now)
            dq = self._failures.setdefault(client_ip, collections.deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            dq.append(now)
            if len(dq) >= self.max_failures:
                self._blocked_until[client_ip] = now + self.block_sec
                dq.clear()
                return True
        return False

    def record_success(self, client_ip: str) -> None:
        """Clear prior failures for `client_ip` after a valid authenticated request."""
        with self._lock:
            self._failures.pop(client_ip, None)
            self._blocked_until.pop(client_ip, None)
