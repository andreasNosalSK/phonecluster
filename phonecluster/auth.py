"""Shared-secret bearer token authentication and brute-force rate limiting."""

from __future__ import annotations

import collections
import hmac
import threading
import time
from typing import Mapping


def build_auth_headers(token: str) -> dict[str, str]:
    """Return HTTP headers containing the cluster bearer token."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Extract a Bearer token from HTTP request headers (case-insensitive)."""
    auth_val = None
    for key, val in headers.items():
        if key.lower() == "authorization":
            auth_val = val
            break
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
