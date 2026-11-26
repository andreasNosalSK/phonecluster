"""Security-first zero-config phone pairing over Wi-Fi/LAN.

Cryptographic & security guarantees (100% Python 3 stdlib, zero pip dependencies):
1. Pairing is CLOSED by default and the cluster is silent on UDP outside an
   explicit, short-lived Pairing Window (default 120 seconds, single-use).
2. Ephemeral 2048-bit Diffie-Hellman (RFC 3526 MODP Group 14) with strict
   prime-order subgroup validation prevents passive Wi-Fi eavesdroppers from
   decrypting tokens OR offline brute-forcing the 6-digit PIN.
3. PBKDF2-HMAC-SHA256 (100,000 iterations) derives independent authentication,
   encryption, and MAC keys bound to `(PIN, DH shared secret, salt, session_id)`.
4. Mutual HMAC challenge-response proves BOTH sides know the PIN — defeating
   strangers trying to join AND rogue fake Masters trying to hijack new phones.
5. Online guessing is capped at 5 attempts with 1s backoff, after which the
   pairing session self-destructs.
6. Every paired phone receives its OWN unique 256-bit least-privilege `node_token`
   encrypted via HMAC-SHA256 CTR + HMAC-SHA256 (Encrypt-then-MAC). Workers never
   receive the Master admin token or other workers' tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import math
import os
import re
import secrets
import selectors
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .auth import (
    AuthRateLimiter,
    build_direct_opener,
    is_allowed_http_host,
    parse_strict_content_length,
    read_json_object_bounded,
    safe_json_dumps,
)
from .config import (
    DEFAULT_SSH_PORT,
    DEFAULT_WORKER_PORT,
    ClusterConfig,
    ConfigConflictError,
    NetworkHardeningConfig,
    NodeConfig,
    SafetyConfig,
    config_revision,
    format_host_port,
    generate_auth_token,
    is_loopback_or_unspecified_host,
    normalize_host,
    save_config,
    validate_host,
    validate_node_id,
    validate_pool_name,
    validate_ssh_user,
)
from .discovery import DISCOVERY_PORT, _candidate_broadcast_addresses, detect_local_ip
from .telemetry import (
    detect_capabilities,
    detect_node_tier,
    detect_os_environment,
    read_memory_info,
)

LOG = logging.getLogger("phonecluster.pairing")

_DIRECT_OPENER = build_direct_opener()
_MAX_PAIR_RESP_BYTES = 128 * 1024

PAIR_SEARCH_TYPE = "phonecluster_pair_search_v1"
PAIR_BEACON_TYPE = "phonecluster_pair_beacon_v1"
DEFAULT_PAIR_PORT = 8767
PBKDF2_ITERATIONS = 100_000

# RFC 3526 Section 3 — 2048-bit MODP Group (Group 14), safe prime P = 2Q + 1
_MODP_2048_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(_MODP_2048_P_HEX, 16)
DH_Q = (DH_P - 1) // 2
DH_G = 2


# ---------------------------------------------------------------------------
# Pure-stdlib cryptographic primitives (DH + PBKDF2 + Encrypt-then-MAC)
# ---------------------------------------------------------------------------

def normalize_pin(pin: str) -> str:
    """Strip spaces/dashes from a human-typed 6-digit PIN."""
    return re.sub(r"[\s-]+", "", str(pin or "")).strip()


def format_pin(pin: str) -> str:
    """Format a 6-digit PIN as `123-456` for easy reading."""
    clean = normalize_pin(pin)
    return f"{clean[:3]}-{clean[3:]}" if len(clean) == 6 else clean


def generate_dh_keypair() -> tuple[int, int]:
    """Generate a 256-bit ephemeral exponent and 2048-bit DH public value."""
    priv = secrets.randbits(256) | (1 << 255)
    pub = pow(DH_G, priv, DH_P)
    return priv, pub


def validate_dh_public(peer_pub: int) -> bool:
    """Strictly verify peer DH public key lies in the prime-order Q subgroup."""
    if not (2 <= peer_pub <= DH_P - 2):
        return False
    return pow(peer_pub, DH_Q, DH_P) == 1


def compute_shared_secret(priv: int, peer_pub: int) -> bytes:
    """Validate peer public key and compute 256-byte big-endian DH shared secret."""
    if not validate_dh_public(peer_pub):
        raise ValueError("Invalid Diffie-Hellman public key (failed subgroup check).")
    shared = pow(peer_pub, priv, DH_P)
    if shared <= 1:
        raise ValueError("Degenerate Diffie-Hellman shared secret.")
    return shared.to_bytes(256, "big")


def fingerprint_public_key(pub: int) -> str:
    """Short human-verifiable visual fingerprint (e.g. `A4F2-91C8`) for the session."""
    digest = hashlib.sha256(pub.to_bytes(256, "big")).hexdigest().upper()
    return f"{digest[:4]}-{digest[4:8]}"


def derive_pairing_keys(
    pin: str,
    shared_secret: bytes,
    salt_hex: str,
    session_id: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes, bytes]:
    """Derive independent `(k_auth, k_enc, k_mac)` 256-bit keys via PBKDF2-HMAC-SHA256."""
    clean_pin = normalize_pin(pin)
    ikm = clean_pin.encode("utf-8") + b"|" + shared_secret
    salt = bytes.fromhex(salt_hex) + b"|phonecluster-pair-v1|" + session_id.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", ikm, salt, iterations=iterations, dklen=96)
    return dk[0:32], dk[32:64], dk[64:96]


def compute_proof(k_auth: bytes, role_label: str, session_id: str, pub_a_hex: str, pub_b_hex: str, meta_json: str) -> str:
    """Compute mutual authentication proof bound to both DH keys and client metadata."""
    msg = f"{role_label}|{session_id}|{pub_a_hex}|{pub_b_hex}|{meta_json}".encode("utf-8")
    return hmac.new(k_auth, msg, hashlib.sha256).hexdigest()


def _ctr_keystream(k_enc: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(k_enc, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_bundle(k_enc: bytes, k_mac: bytes, plaintext_obj: dict[str, Any], aad: str) -> dict[str, str]:
    """Encrypt a JSON dictionary with HMAC-SHA256 CTR + HMAC-SHA256 (Encrypt-then-MAC)."""
    plaintext = json.dumps(plaintext_obj, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(16)
    stream = _ctr_keystream(k_enc, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(k_mac, aad.encode("utf-8") + b"|" + nonce + ciphertext, hashlib.sha256).hexdigest()
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": tag,
    }


def decrypt_bundle(k_enc: bytes, k_mac: bytes, envelope: dict[str, str], aad: str) -> dict[str, Any]:
    """Verify MAC in constant time first, then decrypt the JSON enrollment bundle."""
    try:
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        tag = str(envelope["tag"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError(f"Malformed encrypted envelope: {exc}") from exc

    expected_tag = hmac.new(
        k_mac, aad.encode("utf-8") + b"|" + nonce + ciphertext, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC verification failed (wrong PIN or tampered data).")

    stream = _ctr_keystream(k_enc, nonce, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
    parsed = json.loads(plaintext.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decrypted bundle is not a JSON object.")
    return parsed


# ---------------------------------------------------------------------------
# On-Demand Temporary UDP Pairing Beacon (Active ONLY during Pairing Window)
# ---------------------------------------------------------------------------

class PairingBeaconResponder(threading.Thread):
    """Temporary UDP responder active ONLY while the Master's pairing window is open."""

    def __init__(
        self,
        cluster_name: str,
        pair_port: int,
        session_id: str,
        fingerprint: str,
        expires_at: float,
        listen_host: str = "0.0.0.0",
        discovery_port: int = DISCOVERY_PORT,
    ) -> None:
        super().__init__(name="pairing-beacon", daemon=True)
        self.cluster_name = cluster_name
        self.pair_port = pair_port
        self.session_id = session_id
        self.fingerprint = fingerprint
        self.expires_at = expires_at
        self.listen_host = listen_host
        self.discovery_port = discovery_port
        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self.bound_port: int = discovery_port

    def bind(self) -> bool:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        # On Linux/Android, binding a unicast LAN IP drops IPv4 broadcasts; bind 0.0.0.0 unless loopback.
        lh = normalize_host(self.listen_host)
        if lh and ":" not in lh and lh.startswith("127."):
            bind_addr = lh
        elif lh and (lh.lower().rstrip(".") == "localhost" or lh == "::1"):
            bind_addr = "127.0.0.1"
        else:
            bind_addr = "0.0.0.0"
        try:
            sock.bind((bind_addr, self.discovery_port))
            sock.settimeout(0.4)
            self._sock = sock
            self.bound_port = sock.getsockname()[1]
            return True
        except OSError as exc:
            LOG.warning("Pairing UDP beacon could not bind port %d: %s", self.discovery_port, exc)
            sock.close()
            return False

    def stop(self) -> None:
        self._stop_event.set()
        if not self.is_alive() and self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def run(self) -> None:
        if self._sock is None and not self.bind():
            return
        sock = self._sock
        assert sock is not None
        LOG.info("Temporary pairing beacon active on UDP %s:%d", self.listen_host, self.bound_port)
        reply_window_start = time.monotonic()
        replies_in_window = 0
        try:
            while not self._stop_event.is_set() and time.monotonic() < self.expires_at:
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if self._stop_event.is_set():
                    break
                if not addr or addr[1] <= 0:
                    continue
                now_m = time.monotonic()
                if now_m - reply_window_start >= 1.0:
                    reply_window_start = now_m
                    replies_in_window = 0
                if replies_in_window >= 20:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(msg, dict) and msg.get("type") == PAIR_SEARCH_TYPE:
                    rem = max(0, int(self.expires_at - time.monotonic()))
                    if rem <= 0:
                        break
                    reply = {
                        "type": PAIR_BEACON_TYPE,
                        "cluster_name": self.cluster_name,
                        "pair_port": self.pair_port,
                        "session_id": self.session_id,
                        "fingerprint": self.fingerprint,
                        "expires_in_sec": rem,
                    }
                    try:
                        sock.sendto(json.dumps(reply).encode("utf-8"), addr)
                        replies_in_window += 1
                    except OSError:
                        pass
        finally:
            self._stop_event.set()
            try:
                sock.close()
            except OSError:
                pass
            if self._sock is sock:
                self._sock = None


def _parse_udp_int(val: Any) -> int | None:
    """Safely parse a finite integer from an untrusted UDP JSON packet (rejects None/bool/inf/NaN)."""
    if val is None or isinstance(val, bool):
        return None
    try:
        if isinstance(val, float) and (not math.isfinite(val) or not val.is_integer()):
            return None
        return int(val)
    except (TypeError, ValueError, OverflowError):
        return None


def discover_pairing_masters(
    timeout_sec: float = 2.5,
    discovery_port: int = DISCOVERY_PORT,
    targets: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Auto-search the local Wi-Fi/LAN for Master phones with an open Pairing Window."""
    probe = json.dumps({"type": PAIR_SEARCH_TYPE, "ts": int(time.time())}).encode("utf-8")
    local_ip = detect_local_ip()
    dests = targets if targets is not None else _candidate_broadcast_addresses(local_ip)

    def _open_probe_sock() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setblocking(False)
            return s
        except OSError:
            s.close()
            raise

    socks: list[socket.socket] = []
    sel = selectors.DefaultSelector()
    found: dict[tuple[str, int], dict[str, Any]] = {}
    per_ip_count: dict[str, int] = {}
    try:
        def _add_and_probe() -> None:
            s = _open_probe_sock()
            socks.append(s)
            sel.register(s, selectors.EVENT_READ)
            for dest in dests:
                try:
                    s.sendto(probe, (dest, discovery_port))
                except OSError:
                    pass

        # Use multiple distinct ephemeral source ports to defeat Linux SO_REUSEPORT hash-pinning
        # when DiscoveryResponder and PairingBeaconResponder share UDP 8766 on Master.
        for _ in range(4):
            try:
                _add_and_probe()
            except OSError:
                if not socks:
                    raise
                break

        started = time.monotonic()
        deadline = started + max(0.2, timeout_sec)
        resent = False
        while time.monotonic() < deadline:
            if not resent and timeout_sec >= 0.8 and (time.monotonic() - started) >= (timeout_sec * 0.45):
                for _ in range(2):
                    try:
                        _add_and_probe()
                    except OSError:
                        break
                resent = True
            rem_t = max(0.02, min(0.25, deadline - time.monotonic()))
            try:
                events = sel.select(timeout=rem_t)
            except (OSError, ValueError):
                break
            for key, _mask in events:
                rs: socket.socket = key.fileobj  # type: ignore[assignment]
                try:
                    data, addr = rs.recvfrom(4096)
                except OSError:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(msg, dict) or msg.get("type") != PAIR_BEACON_TYPE:
                    continue
                pair_port = _parse_udp_int(msg.get("pair_port", DEFAULT_PAIR_PORT))
                expires_raw = _parse_udp_int(msg.get("expires_in_sec", 0))
                if pair_port is None or expires_raw is None or not (1 <= pair_port <= 65535):
                    continue
                expires_in_sec = max(0, min(86400, expires_raw))
                host_ip = str(addr[0])
                key_pair = (host_ip, pair_port)
                if key_pair not in found and len(found) < 64 and per_ip_count.get(host_ip, 0) < 4:
                    per_ip_count[host_ip] = per_ip_count.get(host_ip, 0) + 1
                    raw_cn = msg.get("cluster_name")
                    raw_sid = msg.get("session_id")
                    raw_fp = msg.get("fingerprint")
                    found[key_pair] = {
                        "host": host_ip,
                        "pair_port": pair_port,
                        "cluster_name": re.sub(r"[\x00-\x1f\x7f]", "", raw_cn if isinstance(raw_cn, str) else "phonecluster")[:64],
                        "session_id": re.sub(r"[\x00-\x1f\x7f]", "", raw_sid if isinstance(raw_sid, str) else "")[:64],
                        "fingerprint": re.sub(r"[\x00-\x1f\x7f]", "", raw_fp if isinstance(raw_fp, str) else "")[:64],
                        "expires_in_sec": expires_in_sec,
                    }
    finally:
        sel.close()
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    return sorted(found.values(), key=lambda x: (x["host"], x["pair_port"]))


# ---------------------------------------------------------------------------
# Master-Side Pairing Session Manager
# ---------------------------------------------------------------------------

@dataclass
class PairingSession:
    session_id: str
    pin: str
    salt_hex: str
    dh_priv: int
    dh_pub: int
    fingerprint: str
    expires_at: float
    attempts_left: int = 5
    remaining_slots: int = 1
    paired_nodes: list[dict[str, Any]] = field(default_factory=list)
    used_peer_pubs: set[int] = field(default_factory=set)
    used_proofs: set[str] = field(default_factory=set)


def _validate_ssh_pubkey(pubkey: str) -> str | None:
    """Strictly validate a single-line OpenSSH public key (blocks authorized_keys newline/option injection)."""
    raw = str(pubkey or "").strip(" \t")
    if not raw or len(raw) > 4096:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    parts = raw.split()
    if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ssh-rsa"}:
        return None
    try:
        blob = base64.b64decode(parts[1].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return None
    if len(blob) < 16:
        return None
    comment = " ".join(parts[2:])[:128] if len(parts) > 2 else ""
    return f"{parts[0]} {parts[1]} {comment}".strip()


def _read_master_ssh_pubkey() -> str:
    """Optionally read Master's public SSH key (~/.ssh/id_ed25519.pub or id_rsa.pub)."""
    for fname in ("id_ed25519.pub", "id_rsa.pub"):
        p = Path.home() / ".ssh" / fname
        if p.exists():
            try:
                first_line = p.read_text(encoding="utf-8").splitlines()[0]
                valid = _validate_ssh_pubkey(first_line)
                if valid:
                    return valid
            except (OSError, IndexError):
                pass
    return ""


class PairingManager:
    """Thread-safe lifecycle manager for Master's temporary encrypted pairing window."""

    def __init__(
        self,
        config: ClusterConfig,
        config_path: Path | None = None,
        pair_port: int = 8080,
        discovery_port: int = DISCOVERY_PORT,
        listen_host: str = "0.0.0.0",
        fail_delay_sec: float = 1.0,
        enable_beacon: bool = True,
        config_lock: threading.RLock | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.pair_port = pair_port
        self.discovery_port = discovery_port
        self.listen_host = listen_host
        self.fail_delay_sec = fail_delay_sec
        self.enable_beacon = enable_beacon
        self.config_lock = config_lock or threading.RLock()
        self._lock = threading.Lock()
        self._attempt_lock = threading.Lock()  # Strictly serializes PIN attempts against parallel brute-force
        self._dh_rate_limiter = AuthRateLimiter(max_failures=15, window_sec=60.0, block_sec=60.0)
        self._session: PairingSession | None = None
        self._beacon: PairingBeaconResponder | None = None
        self._recent_paired: list[dict[str, Any]] = []

    def _cleanup_expired_locked(self) -> None:
        if self._session is not None:
            if (
                time.monotonic() >= self._session.expires_at
                or self._session.attempts_left <= 0
                or self._session.remaining_slots <= 0
            ):
                self._stop_beacon_locked()
                self._session = None

    def _stop_beacon_locked(self) -> None:
        if self._beacon is not None:
            self._beacon.stop()
            self._beacon = None

    def open_session(
        self,
        ttl_sec: int = 120,
        max_devices: int = 1,
        pair_port: int | None = None,
    ) -> dict[str, Any]:
        """Open a fresh, time-limited pairing window with a random 6-digit PIN."""
        ttl = max(30, min(600, int(ttl_sec)))
        slots = max(1, min(10, int(max_devices)))
        if pair_port is not None:
            self.pair_port = pair_port

        priv, pub = generate_dh_keypair()
        pin = f"{secrets.randbelow(1_000_000):06d}"
        session = PairingSession(
            session_id=secrets.token_hex(8),
            pin=pin,
            salt_hex=secrets.token_hex(16),
            dh_priv=priv,
            dh_pub=pub,
            fingerprint=fingerprint_public_key(pub),
            expires_at=time.monotonic() + ttl,
            attempts_left=5,
            remaining_slots=slots,
        )

        with self._lock:
            old_beacon = self._beacon
            self._stop_beacon_locked()
            self._session = session
        # Wait briefly outside `_lock` for any prior UDP beacon thread to close its socket (avoids EADDRINUSE without SO_REUSEPORT)
        if old_beacon is not None and old_beacon.is_alive():
            old_beacon.join(timeout=0.6)
        if self.enable_beacon:
            with self._lock:
                if self._session is session:
                    beacon = PairingBeaconResponder(
                        cluster_name=self.config.cluster_name,
                        pair_port=self.pair_port,
                        session_id=session.session_id,
                        fingerprint=session.fingerprint,
                        expires_at=session.expires_at,
                        listen_host=self.listen_host,
                        discovery_port=self.discovery_port,
                    )
                    if beacon.bind():
                        beacon.start()
                        self._beacon = beacon

        return self.admin_status()

    def close_session(self) -> dict[str, Any]:
        """Immediately close any active pairing window and silence the UDP beacon."""
        with self._lock:
            self._stop_beacon_locked()
            self._session = None
        return self.admin_status()

    @property
    def beacon_port(self) -> int:
        with self._lock:
            return self._beacon.bound_port if self._beacon else self.discovery_port

    def admin_status(self) -> dict[str, Any]:
        """Status shown to the authenticated Master owner (includes the 6-digit PIN)."""
        with self._lock:
            self._cleanup_expired_locked()
            if self._session is None:
                return {
                    "active": False,
                    "recent_paired": list(self._recent_paired[-10:]),
                }
            s = self._session
            return {
                "active": True,
                "session_id": s.session_id,
                "pin": format_pin(s.pin),
                "fingerprint": s.fingerprint,
                "expires_in_sec": max(0, int(s.expires_at - time.monotonic())),
                "attempts_left": s.attempts_left,
                "remaining_slots": s.remaining_slots,
                "pair_port": self.pair_port,
                "paired_in_session": list(s.paired_nodes),
                "recent_paired": list(self._recent_paired[-10:]),
            }

    def public_hello(self) -> tuple[int, dict[str, Any]]:
        """Public DH hello returned ONLY while a pairing window is open (never exposes PIN)."""
        with self._lock:
            self._cleanup_expired_locked()
            if self._session is None:
                return HTTPStatus.FORBIDDEN, {
                    "error": "Pairing window is closed. Open pairing on the Master phone first."
                }
            s = self._session
            return HTTPStatus.OK, {
                "cluster_name": self.config.cluster_name,
                "session_id": s.session_id,
                "dh_pub": format(s.dh_pub, "x"),
                "salt": s.salt_hex,
                "fingerprint": s.fingerprint,
                "expires_in_sec": max(0, int(s.expires_at - time.monotonic())),
            }

    def complete_pairing(
        self, client_ip: str, body: dict[str, Any], local_ip: str = ""
    ) -> tuple[int, dict[str, Any]]:
        """Verify DH + PIN proof, mint a unique per-node token, and return encrypted bundle."""
        client_ip = normalize_host(client_ip)
        local_ip = normalize_host(local_ip)
        blocked, retry_after = self._dh_rate_limiter.is_blocked(client_ip)
        if blocked:
            return HTTPStatus.TOO_MANY_REQUESTS, {
                "error": f"Too many failed pairing requests; retry in {retry_after}s",
                "retry_after_sec": retry_after,
            }
        peer_pub_hex = str(body.get("dh_pub") or "").strip().lower()
        client_proof = str(body.get("client_proof") or "").strip().lower()
        metadata = body.get("metadata")
        if not peer_pub_hex or not client_proof or not isinstance(metadata, dict):
            self._dh_rate_limiter.record_failure(client_ip)
            return HTTPStatus.BAD_REQUEST, {"error": "Missing dh_pub, client_proof, or metadata."}
        if len(peer_pub_hex) > 600 or len(client_proof) > 128:
            self._dh_rate_limiter.record_failure(client_ip)
            return HTTPStatus.BAD_REQUEST, {"error": "Oversized dh_pub or client_proof."}

        # Snapshot immutable session DH parameters and compute shared secret OUTSIDE `_attempt_lock`
        # so unauthenticated bad-DH requests cannot stall legitimate pairing completions.
        with self._lock:
            self._cleanup_expired_locked()
            if self._session is None:
                return HTTPStatus.FORBIDDEN, {"error": "Pairing window is closed or expired."}
            s0 = self._session
            session_id = s0.session_id
            pin = s0.pin
            salt_hex = s0.salt_hex
            dh_priv = s0.dh_priv
            dh_pub_hex = format(s0.dh_pub, "x")

        req_sid = str(body.get("session_id") or "").strip()
        if req_sid != session_id:
            self._dh_rate_limiter.record_failure(client_ip)
            return HTTPStatus.BAD_REQUEST, {"error": "session_id mismatch (pairing window rotated)."}

        try:
            meta_canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except ValueError as exc:
            self._dh_rate_limiter.record_failure(client_ip)
            return HTTPStatus.BAD_REQUEST, {"error": f"Invalid pairing metadata JSON values: {exc}"}

        try:
            peer_pub = int(peer_pub_hex, 16)
            shared_secret = compute_shared_secret(dh_priv, peer_pub)
        except ValueError as exc:
            self._dh_rate_limiter.record_failure(client_ip)
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}

        # Strictly serialize PIN attempts so parallel sockets can NEVER exceed 5 guesses!
        with self._attempt_lock:
            with self._lock:
                self._cleanup_expired_locked()
                if self._session is None or self._session.session_id != session_id:
                    return HTTPStatus.FORBIDDEN, {"error": "Pairing window is closed or expired."}
                if peer_pub in self._session.used_peer_pubs or client_proof in self._session.used_proofs:
                    return HTTPStatus.FORBIDDEN, {"error": "Replayed pairing proof rejected."}

            k_auth, k_enc, k_mac = derive_pairing_keys(pin, shared_secret, salt_hex, session_id)
            expected_client_proof = compute_proof(
                k_auth, "client", session_id, dh_pub_hex, peer_pub_hex, meta_canonical
            )

            if not hmac.compare_digest(client_proof, expected_client_proof):
                with self._lock:
                    if self._session is not None and self._session.session_id == session_id:
                        self._session.attempts_left -= 1
                        left = max(0, self._session.attempts_left)
                        if left == 0:
                            LOG.warning("Pairing session %s locked out after 5 failed PIN attempts.", session_id)
                            self._stop_beacon_locked()
                            self._session = None
                    else:
                        left = 0
                if self.fail_delay_sec > 0:
                    time.sleep(self.fail_delay_sec)
                return HTTPStatus.FORBIDDEN, {
                    "error": "Invalid pairing PIN." if left > 0 else "Too many wrong PINs — pairing window closed.",
                    "attempts_left": left,
                }

        # Proof verified! Validate metadata cleanly (rejecting bool/inf/NaN) and mint a unique least-privilege node_token.
        worker_port = _parse_udp_int(metadata.get("worker_port", DEFAULT_WORKER_PORT))
        ssh_port = _parse_udp_int(metadata.get("ssh_port", DEFAULT_SSH_PORT))
        cores_raw = _parse_udp_int(metadata.get("cpu_cores", 4))
        mem_raw = _parse_udp_int(metadata.get("mem_total_mb", 0))
        mc_raw = _parse_udp_int(metadata.get("max_concurrency", 2))
        raw_tier = _parse_udp_int(metadata.get("tier", 0))
        if None in (worker_port, ssh_port, cores_raw, mem_raw, mc_raw, raw_tier):
            return HTTPStatus.BAD_REQUEST, {"error": "Invalid numeric pairing metadata."}
        assert worker_port is not None and ssh_port is not None and cores_raw is not None
        assert mem_raw is not None and mc_raw is not None and raw_tier is not None
        cores = max(1, min(1024, cores_raw))
        mem_mb = max(0, min(16 * 1024 * 1024, mem_raw))
        max_conc = max(1, min(32, mc_raw))
        if not (0 <= worker_port <= 65535 and 1 <= ssh_port <= 65535):
            return HTTPStatus.BAD_REQUEST, {"error": "worker_port must be 0..65535 and ssh_port must be 1..65535."}
        try:
            ssh_user = validate_ssh_user(str(metadata.get("ssh_user") or "")[:64])
            node_pool = validate_pool_name(str(metadata.get("pool") or "auto"))
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, {"error": str(exc)}
        os_env = re.sub(r"[^A-Za-z0-9._-]", "", str(metadata.get("os_env") or "unknown"))[:32] or "unknown"
        node_tier = raw_tier if raw_tier in {0, 1, 2, 3} else 0
        node_token = generate_auth_token()

        with self._lock, self.config_lock:
            self._cleanup_expired_locked()
            if self._session is None or self._session.session_id != session_id:
                return HTTPStatus.FORBIDDEN, {"error": "Pairing session closed before completion."}
            if peer_pub in self._session.used_peer_pubs or client_proof in self._session.used_proofs:
                return HTTPStatus.FORBIDDEN, {"error": "Replayed pairing proof rejected."}

            # If this exact worker IP was previously paired, rotate its token & refresh metadata (with rollback if disk save fails)
            existing = next(
                (n for n in self.config.nodes if normalize_host(n.host) == client_ip and n.role != "master"),
                None,
            )
            prev_snapshot: tuple[Any, ...] | None = None
            appended_new = False
            if existing is not None:
                prev_snapshot = (
                    existing.host,
                    existing.worker_port,
                    existing.ssh_port,
                    existing.ssh_user,
                    existing.max_concurrency,
                    existing.tier,
                    existing.pool,
                    existing.auth_token,
                    existing.notes,
                )
                existing.host = client_ip
                existing.worker_port = worker_port
                existing.ssh_port = ssh_port
                existing.ssh_user = ssh_user or existing.ssh_user
                existing.max_concurrency = max_conc
                existing.tier = node_tier
                existing.pool = node_pool
                existing.auth_token = node_token
                existing.notes = f"Re-paired ({os_env}, T{node_tier or '?'} {node_pool}, {cores}c, {mem_mb} MB RAM)"
                assigned_node = existing
            else:
                existing_ids = {n.id for n in self.config.nodes}
                idx = len(self.config.nodes)
                while f"node{idx}" in existing_ids:
                    idx += 1
                assigned_node = NodeConfig(
                    id=f"node{idx}",
                    host=client_ip,
                    role="worker",
                    worker_port=worker_port,
                    ssh_port=ssh_port,
                    ssh_user=ssh_user,
                    max_concurrency=max_conc,
                    weight=1.0,
                    tier=node_tier,
                    pool=node_pool,
                    tags=["worker", "paired", f"tier{node_tier}" if node_tier else "auto"],
                    notes=f"Securely paired ({os_env}, T{node_tier or '?'} {node_pool}, {cores}c, {mem_mb} MB RAM)",
                    auth_token=node_token,
                )
                self.config.nodes.append(assigned_node)
                appended_new = True

            if self.config_path is not None:
                try:
                    save_config(self.config, self.config_path)
                except Exception as exc:
                    if existing is not None and prev_snapshot is not None:
                        (
                            existing.host,
                            existing.worker_port,
                            existing.ssh_port,
                            existing.ssh_user,
                            existing.max_concurrency,
                            existing.tier,
                            existing.pool,
                            existing.auth_token,
                            existing.notes,
                        ) = prev_snapshot
                    elif appended_new:
                        self.config.nodes.pop()
                    LOG.error("Failed to save cluster config during pairing: %s", exc)
                    if isinstance(exc, ConfigConflictError):
                        return HTTPStatus.CONFLICT, {"error": f"{exc} Restart pairing on the Master."}
                    return HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Failed to persist cluster config: {exc}"}

            self._session.used_peer_pubs.add(peer_pub)
            self._session.used_proofs.add(client_proof)

            master_node = next((n for n in self.config.nodes if n.role == "master"), self.config.nodes[0])
            effective_master_host = normalize_host(master_node.host)
            if is_loopback_or_unspecified_host(effective_master_host) and not is_loopback_or_unspecified_host(client_ip):
                if local_ip and not is_loopback_or_unspecified_host(local_ip):
                    effective_master_host = local_ip
                else:
                    detected = normalize_host(detect_local_ip())
                    if detected and not is_loopback_or_unspecified_host(detected):
                        effective_master_host = detected
            allowed_master_set = {normalize_host(ip) for ip in self.config.network.allowed_master_ips if ip}
            for cand_ip in (effective_master_host, local_ip, normalize_host(master_node.host)):
                if cand_ip and (not is_loopback_or_unspecified_host(cand_ip) or is_loopback_or_unspecified_host(client_ip)):
                    allowed_master_set.add(cand_ip)
            bundle = {
                "cluster_name": self.config.cluster_name,
                "node_id": assigned_node.id,
                "node_host": client_ip,
                "node_token": node_token,
                "worker_port": worker_port,
                "ssh_port": ssh_port,
                "ssh_user": ssh_user,
                "max_concurrency": max_conc,
                "master_host": effective_master_host,
                "safety": {
                    "max_temp_c": self.config.safety.max_temp_c,
                    "resume_temp_c": self.config.safety.resume_temp_c,
                    "min_free_ram_mb": self.config.safety.min_free_ram_mb,
                    "battery_low_pct": self.config.safety.battery_low_pct,
                    "battery_high_pct": self.config.safety.battery_high_pct,
                    "battery_poll_sec": self.config.safety.battery_poll_sec,
                    "webhook_cooldown_sec": self.config.safety.webhook_cooldown_sec,
                    "battery_webhook_url": self.config.safety.battery_webhook_url,
                },
                "network": {
                    "enforce_worker_source_ip": self.config.network.enforce_worker_source_ip,
                    "require_signed_requests": self.config.network.require_signed_requests,
                    "allowed_master_ips": sorted(allowed_master_set),
                },
                "master_ssh_pubkey": _read_master_ssh_pubkey(),
            }

            server_proof = compute_proof(
                k_auth, "server", session_id, dh_pub_hex, peer_pub_hex, meta_canonical
            )
            aad = f"{session_id}|{assigned_node.id}|{dh_pub_hex[:16]}|{peer_pub_hex[:16]}"
            encrypted = encrypt_bundle(k_enc, k_mac, bundle, aad=aad)

            paired_rec = {
                "id": assigned_node.id,
                "host": client_ip,
                "os_env": os_env,
                "paired_at": int(time.time()),
            }
            self._session.paired_nodes.append(paired_rec)
            self._recent_paired.append(paired_rec)
            if len(self._recent_paired) > 50:
                self._recent_paired = self._recent_paired[-50:]
            self._session.remaining_slots -= 1
            if self._session.remaining_slots <= 0:
                self._stop_beacon_locked()
                self._session = None

        LOG.info("Securely paired '%s' (%s) with unique per-node token.", assigned_node.id, client_ip)
        return HTTPStatus.OK, {
            "session_id": session_id,
            "node_id": assigned_node.id,
            "server_proof": server_proof,
            "encrypted_bundle": encrypted,
        }


# ---------------------------------------------------------------------------
# Standalone Temporary Pairing Server (`pc pair` in terminal)
# ---------------------------------------------------------------------------

class StandalonePairingServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], manager: PairingManager) -> None:
        self.manager = manager
        self._conn_sem = threading.BoundedSemaphore(32)
        self._active_lock = threading.Lock()
        self._active_cond = threading.Condition(self._active_lock)
        self._active_requests = 0
        self.rate_limiter = AuthRateLimiter(max_failures=15, window_sec=60.0, block_sec=60.0)
        bind_host = normalize_host(str(addr[0])) or "0.0.0.0"
        if ":" in bind_host:
            self.address_family = socket.AF_INET6
        super().__init__((bind_host, addr[1]), StandalonePairingHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._conn_sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._active_cond:
            self._active_requests += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._active_cond:
                self._active_requests -= 1
                if self._active_requests <= 0:
                    self._active_cond.notify_all()
            self._conn_sem.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_cond:
                self._active_requests -= 1
                if self._active_requests <= 0:
                    self._active_cond.notify_all()
            self._conn_sem.release()

    def wait_active_requests(self, timeout: float = 5.0) -> None:
        """Wait for any in-flight pairing HTTP responses to flush before process exit."""
        deadline = time.monotonic() + max(0.1, float(timeout))
        with self._active_cond:
            while self._active_requests > 0:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                self._active_cond.wait(timeout=rem)


class StandalonePairingHandler(BaseHTTPRequestHandler):
    server: StandalonePairingServer
    timeout = 15.0

    def version_string(self) -> str:
        return "PhoneCluster"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        msg = re.sub(r"[\x00-\x1f\x7f]", "?", format % args)
        LOG.info("pair %s - %s", self.address_string(), msg)

    def _allowed_hosts(self) -> set[str]:
        with self.server.manager.config_lock:
            return {n.host for n in self.server.manager.config.nodes if n.host}

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        raw = safe_json_dumps(data).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        if not is_allowed_http_host(self.headers, extra_allowed_hosts=self._allowed_hosts()):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: invalid or untrusted Host header (DNS rebinding guard)"},
            )
            return
        if self.path.split("?", 1)[0] == "/api/pair/hello":
            status, data = self.server.manager.public_hello()
            self._send_json(status, data)
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not is_allowed_http_host(self.headers, extra_allowed_hosts=self._allowed_hosts()):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden: invalid or untrusted Host header (DNS rebinding guard)"},
            )
            return
        if self.path.split("?", 1)[0] != "/api/pair/complete":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        origin = self.headers.get("Origin", "").strip()
        referer = self.headers.get("Referer", "").strip()
        sec_fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if origin or referer or sec_fetch_site == "cross-site":
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "browser cross-origin pairing POST rejected"})
            return
        norm_ip = normalize_host(str(self.client_address[0]))
        blocked, retry_after = self.server.rate_limiter.is_blocked(norm_ip)
        if blocked:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": f"too many failed pairing requests; retry in {retry_after}s", "retry_after_sec": retry_after},
            )
            return
        length, err_status, err_msg = parse_strict_content_length(self.headers, 64 * 1024)
        if length is None:
            self._send_json(err_status, {"error": err_msg})
            return
        try:
            if length > 0:
                # Enforce a strict 10s total body-read deadline to block Slowloris slot exhaustion
                deadline = time.monotonic() + 10.0
                chunks = bytearray()
                while len(chunks) < length:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        raise TimeoutError("request body read timed out")
                    self.connection.settimeout(rem)
                    piece = self.rfile.read1(min(4096, length - len(chunks))) if hasattr(self.rfile, "read1") else self.rfile.read(length - len(chunks))
                    if not piece:
                        break
                    chunks.extend(piece)
                raw_bytes = bytes(chunks)
                if len(raw_bytes) != length:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "truncated request body"})
                    return

                def _reject_nonfinite(tok: str) -> Any:
                    raise ValueError(f"non-finite JSON constant '{tok}' not allowed")

                body = json.loads(raw_bytes.decode("utf-8"), parse_constant=_reject_nonfinite)
            else:
                body = {}
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, OSError) as exc:
            self.server.rate_limiter.record_failure(norm_ip)
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
            return
        try:
            local_ip = str(self.connection.getsockname()[0])
        except OSError:
            local_ip = ""
        status, data = self.server.manager.complete_pairing(
            self.client_address[0], body, local_ip=local_ip
        )
        if status == HTTPStatus.OK:
            self.server.rate_limiter.record_success(norm_ip)
        else:
            self.server.rate_limiter.record_failure(norm_ip)
        self._send_json(status, data)


def run_cli_pairing_host(
    config: ClusterConfig,
    config_path: Path,
    port: int = DEFAULT_PAIR_PORT,
    ttl_sec: int = 120,
    max_devices: int = 1,
) -> int:
    """Open a temporary standalone pairing server on Master for `pc pair`."""
    manager = PairingManager(
        config=config,
        config_path=config_path,
        pair_port=port,
    )
    server = StandalonePairingServer(("0.0.0.0", port), manager)
    actual_port = server.server_address[1]
    info = manager.open_session(ttl_sec=ttl_sec, max_devices=max_devices, pair_port=actual_port)
    lan_ip = detect_local_ip()

    print("=" * 60)
    print("  PhoneCluster Secure Pairing Window OPEN")
    print("=" * 60)
    print(f"  Cluster     : {config.cluster_name}")
    print(f"  Master IP   : {lan_ip}:{actual_port}")
    print(f"  Fingerprint : {info['fingerprint']}")
    print(f"  6-Digit PIN : >>>  {info['pin']}  <<<")
    print(f"  Valid for   : {info['expires_in_sec']}s  |  Devices allowed: {info['remaining_slots']}  |  Max wrong PINs: 5")
    print("=" * 60)
    print("\nOn your NEW phone, run:")
    print("  pc join")
    print(f"  (or if Wi-Fi blocks broadcast: pc join --master {lan_ip}:{actual_port})")
    print("\nWaiting for new phone to pair... (Ctrl+C to cancel)\n")

    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
    t.start()
    seen_count = 0
    try:
        while True:
            st = manager.admin_status()
            paired_now = st.get("recent_paired", [])
            while seen_count < len(paired_now):
                rec = paired_now[seen_count]
                print(f"  [OK] Securely paired '{rec['id']}' ({rec['host']}, {rec['os_env']}) with unique token!")
                seen_count += 1
            if not st["active"]:
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\nPairing cancelled by user.")
    finally:
        manager.close_session()
        server.shutdown()
        server.wait_active_requests(timeout=5.0)
        server.server_close()

    if seen_count > 0:
        print(f"\nPairing window closed cleanly. {seen_count} phone(s) added to {config_path}.")
        return 0
    print("\nPairing window expired with no new phone paired.")
    return 1


# ---------------------------------------------------------------------------
# New Worker Phone Client (`pc join`)
# ---------------------------------------------------------------------------

def _http_json(url: str, method: str = "GET", body: dict[str, Any] | None = None, timeout: float = 10.0) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _DIRECT_OPENER.open(req, timeout=timeout) as resp:
            return resp.status, read_json_object_bounded(resp, _MAX_PAIR_RESP_BYTES)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(16384).decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException):
            raw = ""
        finally:
            try:
                exc.close()
            except OSError:
                pass
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                parsed = {"error": raw[:200]}
        except json.JSONDecodeError:
            parsed = {"error": raw[:200]}
        return exc.code, parsed
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        raise RuntimeError(f"Could not reach Master pairing endpoint {url}: {exc}") from exc


def _install_ssh_pubkey(pubkey: str) -> bool:
    """Safely append Master's validated single-line SSH public key to ~/.ssh/authorized_keys."""
    clean = _validate_ssh_pubkey(pubkey)
    if not clean:
        return False
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ssh_dir, 0o700)
    except OSError:
        pass
    auth_keys = ssh_dir / "authorized_keys"
    existing = auth_keys.read_text(encoding="utf-8", errors="ignore") if auth_keys.exists() else ""
    if clean in existing.splitlines():
        return True
    fd = os.open(auth_keys, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(clean + "\n")
    try:
        os.chmod(auth_keys, 0o600)
    except OSError:
        pass
    return True


def join_cluster_via_pairing(
    master_host: str,
    pair_port: int,
    pin: str,
    config_out: Path,
    worker_port: int = DEFAULT_WORKER_PORT,
    ssh_port: int | None = None,
    ssh_user: str = "",
    max_concurrency: int = 2,
    trust_ssh_key: bool = False,
    tier: int = 0,
    pool: str = "auto",
    expected_fingerprint: str = "",
) -> dict[str, Any]:
    """Perform authenticated DH pairing with Master and save a scoped worker config."""
    previous_revision = config_revision(config_out)
    clean_master = normalize_host(master_host)
    base_url = f"http://{format_host_port(clean_master, pair_port)}"
    status, hello = _http_json(f"{base_url}/api/pair/hello", method="GET")
    if status != HTTPStatus.OK:
        raise RuntimeError(hello.get("error", f"Master refused pairing hello (HTTP {status})"))

    session_id = str(hello.get("session_id") or "").strip()
    pub_a_hex = str(hello.get("dh_pub") or "").strip().lower()
    salt_hex = str(hello.get("salt") or "").strip().lower()
    if (
        not session_id
        or len(session_id) > 64
        or not pub_a_hex
        or len(pub_a_hex) > 600
        or not re.fullmatch(r"[0-9a-f]+", pub_a_hex)
        or not re.fullmatch(r"(?:[0-9a-f]{2}){8,64}", salt_hex)
    ):
        raise RuntimeError("Malformed pairing hello from Master (invalid session_id, dh_pub, or salt).")
    pub_a = int(pub_a_hex, 16)
    actual_fp = fingerprint_public_key(pub_a)
    hello_fp = str(hello.get("fingerprint") or "").strip().upper()
    if hello_fp and not hmac.compare_digest(hello_fp, actual_fp):
        raise RuntimeError(
            f"Master hello fingerprint mismatch ({hello_fp} != {actual_fp}) — possible spoofed Master!"
        )
    exp_fp = str(expected_fingerprint or "").strip().upper()
    if exp_fp and not hmac.compare_digest(exp_fp, actual_fp):
        raise RuntimeError(
            f"Master DH key fingerprint mismatch (expected {exp_fp}, got {actual_fp}) — aborting before sending PIN proof!"
        )

    priv_b, pub_b = generate_dh_keypair()
    pub_b_hex = format(pub_b, "x")
    shared_secret = compute_shared_secret(priv_b, pub_a)
    k_auth, k_enc, k_mac = derive_pairing_keys(pin, shared_secret, salt_hex, session_id)

    os_env = detect_os_environment()
    caps = detect_capabilities()
    det_tier, det_pool = detect_node_tier(os_env, caps["tools"])
    eff_tier = tier if tier in {1, 2, 3} else det_tier
    eff_pool = (
        pool.strip().lower()
        if pool and pool.strip().lower() != "auto"
        else ({1: "compute", 2: "services", 3: "docker"}.get(eff_tier, det_pool))
    )
    actual_ssh_port = ssh_port if ssh_port is not None else (8022 if os_env == "termux" else 22)
    try:
        actual_user = validate_ssh_user(ssh_user or os.environ.get("USER", ""))
    except ValueError:
        actual_user = ""
    mem = read_memory_info()
    metadata = {
        "worker_port": worker_port,
        "ssh_port": actual_ssh_port,
        "ssh_user": actual_user,
        "os_env": os_env,
        "tier": eff_tier,
        "pool": eff_pool,
        "cpu_cores": os.cpu_count() or 1,
        "mem_total_mb": mem["total_mb"],
        "max_concurrency": max_concurrency,
    }
    meta_canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    client_proof = compute_proof(k_auth, "client", session_id, pub_a_hex, pub_b_hex, meta_canonical)

    c_status, reply = _http_json(
        f"{base_url}/api/pair/complete",
        method="POST",
        body={
            "session_id": session_id,
            "dh_pub": pub_b_hex,
            "client_proof": client_proof,
            "metadata": metadata,
        },
    )
    if c_status != HTTPStatus.OK:
        raise RuntimeError(reply.get("error", f"Pairing rejected (HTTP {c_status})"))

    # CRITICAL: Verify Master's proof BEFORE trusting or saving anything!
    expected_server_proof = compute_proof(
        k_auth, "server", session_id, pub_a_hex, pub_b_hex, meta_canonical
    )
    if not hmac.compare_digest(str(reply.get("server_proof", "")).lower(), expected_server_proof):
        raise RuntimeError("Master authentication proof failed! Possible rogue/spoofed Master — aborting.")

    raw_node_id = str(reply.get("node_id") or "").strip()
    enc_bundle = reply.get("encrypted_bundle")
    if not raw_node_id or not isinstance(enc_bundle, dict):
        raise RuntimeError("Malformed pairing completion reply from Master.")
    node_id = validate_node_id(raw_node_id)
    aad = f"{session_id}|{node_id}|{pub_a_hex[:16]}|{pub_b_hex[:16]}"
    bundle = decrypt_bundle(k_enc, k_mac, enc_bundle, aad=aad)

    # Write LEAST-PRIVILEGE worker config containing ONLY this worker's own unique token!
    worker_token = str(bundle.get("node_token") or "").strip()
    if not worker_token:
        raise RuntimeError("Master pairing bundle missing node_token.")
    assigned_host = validate_host(str(bundle.get("node_host") or detect_local_ip()))
    raw_net_obj = bundle.get("network")
    raw_net = dict(raw_net_obj) if isinstance(raw_net_obj, dict) else {}
    raw_mips = raw_net.get("allowed_master_ips")
    master_ips = [str(x).strip() for x in raw_mips if x is not None and str(x).strip()] if isinstance(raw_mips, list) else []
    for m_ip in (normalize_host(str(bundle.get("master_host") or "")), clean_master):
        if m_ip and m_ip not in master_ips:
            master_ips.append(m_ip)
    raw_net["allowed_master_ips"] = master_ips
    raw_safety_obj = bundle.get("safety")
    worker_cfg = ClusterConfig(
        cluster_name=str(bundle.get("cluster_name") or "phonecluster"),
        auth_token=worker_token,
        safety=SafetyConfig.from_dict(raw_safety_obj if isinstance(raw_safety_obj, dict) else {}),
        network=NetworkHardeningConfig.from_dict(raw_net),
        nodes=[
            NodeConfig(
                id=node_id,
                host=assigned_host,
                role="worker",
                worker_port=worker_port,
                ssh_port=actual_ssh_port,
                ssh_user=actual_user,
                max_concurrency=max(1, min(32, int(bundle.get("max_concurrency", max_concurrency) or max_concurrency))),
                tier=eff_tier,
                pool=eff_pool,
                tags=["worker", "paired"],
                notes=f"Paired to Master {bundle.get('master_host', master_host)}",
                auth_token=worker_token,
            )
        ],
    )
    save_config(worker_cfg, config_out, expected_revision=previous_revision)

    ssh_trusted = False
    if trust_ssh_key and bundle.get("master_ssh_pubkey"):
        ssh_trusted = _install_ssh_pubkey(str(bundle["master_ssh_pubkey"]))

    return {
        "cluster_name": worker_cfg.cluster_name,
        "node_id": node_id,
        "node_host": worker_cfg.nodes[0].host,
        "tier": eff_tier,
        "pool": eff_pool,
        "master_host": str(bundle.get("master_host", master_host)),
        "config_path": str(config_out),
        "ssh_key_trusted": ssh_trusted,
    }
