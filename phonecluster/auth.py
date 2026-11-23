"""Shared-secret bearer token authentication helpers."""

from __future__ import annotations

import hmac
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
