# PhoneCluster Security Architecture & Threat Model

PhoneCluster is built with **security first**: adding a new phone on your Wi-Fi takes ~15 seconds without typing IP addresses, while ensuring strangers on the same network cannot discover your cluster, sneak in as rogue workers, sniff secrets, or take over your phones.

---

## 1. Stealth-by-Default LAN Posture

- **Workers are completely silent on UDP by default.** Running phones do **not** advertise their hostname, SSH username, OS, or specs on UDP port `8766` unless you explicitly pass `--discover`.
- **Pairing is CLOSED by default.** Both `/api/pair/hello` and `/api/pair/complete` reject all requests (`HTTP 403`) outside an explicit, short-lived Pairing Window opened by the authenticated Master owner (`pc pair` or Web UI → Tab 5).
- **On-demand temporary beacon:** Only while a 2-minute Pairing Window is open does the Master answer UDP `8766` pairing searches (`phonecluster_pair_search_v1`) with non-sensitive info (`cluster_name`, `pair_port`, `session_id`, visual `fingerprint`, seconds remaining). The instant a phone finishes pairing (or the timer expires), the beacon stops and the cluster goes completely silent again.

---

## 2. How Secure One-Tap Pairing Works (`pc pair` + `pc join`)

Every pairing handshake uses pure Python 3 standard-library cryptography (zero pip dependencies):

1. **Ephemeral 2048-bit Diffie-Hellman (RFC 3526 MODP Group 14):**
   - Both Master and new phone generate fresh ephemeral 256-bit private exponents (`a`, `b`) and exchange 2048-bit public values (`A`, `B`).
   - Both sides strictly validate the peer's public key lies in the prime-order `Q = (P-1)/2` subgroup (`pow(pub, Q, P) == 1`), preventing small-subgroup attacks.
   - **Why this matters:** A passive Wi-Fi sniffer sees `A`, `B`, and ciphertext, but cannot compute the shared secret `S = g^(ab) mod P` — so they **cannot decrypt the enrollment bundle AND cannot offline brute-force the 6-digit PIN**.
2. **Key Derivation (PBKDF2-HMAC-SHA256, 100,000 iterations):**
   - Derives three independent 256-bit keys `(k_auth, k_enc, k_mac)` bound to `(6-digit PIN, DH shared secret S, random 128-bit salt, session_id)`.
3. **Mutual Authentication (Anti-Stranger & Anti-Spoofed-Master):**
   - The new phone displays the Master's 8-hex visual fingerprint (`A4F2-91C8`) so you can confirm you're talking to your own Master phone.
   - The new phone sends `client_proof = HMAC-SHA256(k_auth, "client"|session_id|A|B|metadata)`.
   - Wrong PIN attempts incur a `1s` delay and decrement a strict **5-attempt counter** — after 5 wrong guesses, the pairing session self-destructs immediately.
   - The Master returns `server_proof = HMAC-SHA256(k_auth, "server"|session_id|A|B|metadata)`. The new phone **verifies `server_proof` BEFORE writing any config or SSH key**, blocking fake/rogue Master spoofing.
4. **Encrypted Token Delivery (Encrypt-then-MAC):**
   - The onboarding bundle is encrypted using `HMAC-SHA256` counter-mode (`k_enc`) and authenticated with `HMAC-SHA256` (`k_mac`) over `(AAD || nonce || ciphertext)`. Decryption verifies the MAC in constant time before decrypting.

---

## 3. Least-Privilege Per-Node Token Isolation

- Every newly paired worker receives its **own unique 256-bit `node_token`** (`NodeConfig.auth_token`).
- Worker phones **never** receive the Master's admin `auth_token` or any other worker's token!
- Both `pc join` and `pc sync` write a **worker-scoped `config/cluster.json`** (`0600` permissions, atomic `os.replace()`) containing only that worker's own token.
- If a worker phone is ever lost, stolen, or retired:
  - It **cannot** control the Master dashboard, Terminal Control, or other workers.
  - Clicking **Remove** in the Web UI immediately cuts it off with zero impact on the rest of your cluster.

---

## 4. Brute-Force Rate Limiting & Shared Wi-Fi Lockdown

- **Brute-Force Protection (`AuthRateLimiter`):** Both the Master Dashboard and every Worker daemon track failed Bearer auth attempts per client IP (`10` failures per `60s` → `HTTP 429 Too Many Requests` for `60s`).
- **Strict Read-Auth Lockdown (for shared/dorm/campus Wi-Fi):**
  - By default on a private home LAN, read-only status/telemetry can be viewed in the browser while running commands, terminal, batch jobs, pairing, and settings require unlocking with your Master `auth_token`.
  - If you are on a **shared or untrusted Wi-Fi**, start the dashboard with:
    ```bash
    pc dashboard --require-auth
    ```
    (or set `"dashboard_require_auth": true` in `config/cluster.json`). Every `/api/*` endpoint — including `/api/live`, `/api/status`, `/api/jobs`, and `/api/doctor` — will then require your Master `auth_token`.
- **Over the Internet / Untrusted Networks:** Never port-forward HTTP `8080` or `8765` to the public internet. Use **Tailscale** or **WireGuard** (encrypted WireGuard mesh) for remote access!

---

## 5. Optional Master Network Guard (Air-Gapping Older Unrooted Phones from WAN)

By default, all phones sit on your home Wi-Fi as LAN peers (`gateway.enabled = false`). However, older unrooted Android phones often stop receiving OS security patches — and **PhoneCluster workers do not need direct internet (WAN) access during normal operation**.

### Recommended Air-Gapped Worker Topology
1. **On your home router:** Assign static DHCP leases to all phones, then **block outbound & inbound WAN (internet)** for your older worker phones (via Router Firewall / Parental Controls / VLAN), while keeping **LAN traffic open** so workers talk freely to Master and Cross-Tier Service Mesh peers.
2. **On your Master (updated modern phone OR Raspberry Pi Zero 2 W):** Enable **Network Guard** in **Web UI → Tab 5 → 4. Optional Network Guard** (or `pc gateway --enable`).
   - Master runs a lightweight, zero-dependency, **authenticated HTTP/HTTPS (`CONNECT`) Allowlist Proxy** (default port `8888`).
   - Every worker job automatically receives `HTTP_PROXY` / `HTTPS_PROXY` (authenticated with a **separate derived per-node HMAC proxy secret** — never exposing `/exec` or admin tokens) plus `NO_PROXY` excluding `localhost`, `.cluster`, and every LAN phone IP so cross-tier MQTT / Home Assistant / AdGuard traffic stays direct on LAN.
   - **Three policy modes:**
     - `allowlist` *(Recommended · Default-Deny)* — only explicitly approved domains (e.g., GitHub, Termux/Debian repos, PyPI, HuggingFace) and ports (`80, 443`) are allowed.
     - `monitor` — logs every domain contacted by each worker so you can audit before locking down.
     - `block_all` — strict air-gap blocking all outbound WAN even through the proxy.
   - **SSRF / LAN Pivot Guard (`block_private_ips: true`):** Resolves DNS once and rejects private, loopback, link-local, and multicast IPs so a compromised old phone cannot use Master as a pivot into your router or localhost.
   - **Router Verification:** Click **Verify Router WAN Block on Workers** (or `pc gateway --check-isolation`) to confirm your router firewall genuinely blocks direct WAN on every worker.
   - **100% Optional:** Leave `gateway.enabled = false` (default) to keep zero extra ports open and zero proxy env vars injected.

### Updated Master Phone vs. Raspberry Pi / Pi Zero 2 W as Master
| Choice | Best When | Pros & Cons |
| :--- | :--- | :--- |
| **Updated Modern Android Phone as Master** *(€0 extra)* | You already have one newer phone receiving security updates (or rooted Debian 13). | Zero extra hardware, runs Dashboard + Scheduler + Network Guard unrooted on Termux; cannot run port-53 AdGuard Home or kernel `nftables` without root (router handles WAN blocking instead). |
| **Raspberry Pi Zero 2 W (~€15) / Pi 4 as Master** | **All** of your phones are old/unpatched, OR you want a zero-battery-swelling 24/7 controller with AdGuard DNS. | Runs updated 64-bit Debian 13 natively, **no Li-Po battery risk**, ~1–2 W, runs PhoneCluster Master + Network Guard + **Native AdGuard Home (single ~12 MB Go binary — NO Docker required!)** + hardened `nftables` firewall! |

### One-Command Raspberry Pi / Pi Zero 2 W Master + Native AdGuard Setup
```bash
sudo bash scripts/setup_pi_master.sh --with-adguard --with-firewall --enable-gateway
```

---

## 6. Master & Worker Deep Network Hardening (`Tab 5: Network & Pi Guard`)

- **Worker Master-IP Source Allowlist (`network.enforce_worker_source_ip`):** When enabled (1-click in Tab 5 or `pc net-audit --profile lockdown`), worker daemons reject HTTP `:8765` connections from ANY IP except your Master (`HTTP 403 Forbidden`) before reading the body. Both `pc pair` and `pc sync` automatically propagate your Master's IP into each worker's scoped `cluster.json`.
- **Per-Worker Instant Quarantine & Rate Quotas:** Click **Quarantine** on any worker in Tab 5 (`POST /api/gateway/quarantine`) to immediately block 100% of its outbound proxy traffic (`HTTP 403`), and cap proxy traffic per phone (`max_requests_per_min_per_node`, default `120 req/min` → `HTTP 429`) so a runaway device cannot flood a Pi Zero 2 W Master.
- **Listening-Port Attack Surface Audit (`/proc/net/tcp`):** Every online phone reports externally bound listening TCP ports; `pc net-audit` and Tab 5 highlight unexpected ports and compute a 0–100 Hardening Score.
- **Browser CSRF & Security Headers:** Both Master Dashboard and Workers return `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on `/api/*`. Cross-origin browser `POST` requests whose `Origin` mismatches `Host` are rejected (`HTTP 403`).
- **3 One-Click Security Profiles (`Tab 5` or `pc net-audit --profile ...`):** `standard` (default direct LAN), `airgap_workers` (allowlist proxy + SSRF guard + rate quota), and `lockdown` (air-gap `block_all` + Dashboard read-auth lock + Worker Master-IP allowlist).
