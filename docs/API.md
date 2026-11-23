# REST & Discovery API Reference

All HTTP payloads are UTF-8 JSON. Mutating and worker endpoints require:
```http
Authorization: Bearer <auth_token>
```

---

## 1. Worker Agent API (Default Port `8765`)

### `GET /health` *(Auth required)*
Returns live node telemetry, thermal/RAM readiness, active jobs, and detected local services.
```json
{
  "node_id": "node1",
  "role": "worker",
  "os_env": "termux",
  "cpu_cores": 8,
  "load_1m": 0.42,
  "mem_total_mb": 3512,
  "mem_available_mb": 1920,
  "battery_pct": 54,
  "temp_c": 34.5,
  "battery_status": "DISCHARGING",
  "overheated": false,
  "ready_for_jobs": true,
  "not_ready_reasons": [],
  "active_jobs": 0,
  "max_concurrency": 2,
  "tools": {"python3": true, "distccd": true},
  "services": {"sshd_8022": true, "distccd_3632": true, "llama_rpc_50052": false}
}
```

### `GET /jobs` *(Auth required)*
Returns `{"active": [...], "recent": [...]}` for jobs on this phone.

### `POST /exec` *(Auth required)*
Executes a shell command or staged inline script inside a new process group (`start_new_session=True`).

- **Shell command payload:**
  ```json
  { "command": "uname -a", "timeout_sec": 120 }
  ```
- **Inline script payload (automatically written to a temporary file, executed, and deleted):**
  ```json
  {
    "script_content": "import sys; print(sys.argv[1])",
    "script_name": "task.py",
    "interpreter": "python3",
    "args": ["hello"],
    "timeout_sec": 120
  }
  ```
- **Responses:**
  - `200 OK`: `{"job_id", "node_id", "returncode", "timed_out", "cancelled", "duration_sec", "stdout", "stderr"}`
  - `503 Service Unavailable`: Node is overheated, low on RAM, or at `max_concurrency` (signals Master to re-route the job).

### `POST /cancel` *(Auth required)*
Terminates a running job's entire process group (`SIGTERM` → `SIGKILL`):
```json
{ "job_id": "map-0004" }
```

---

## 2. Master Web Control Center API (Default Port `8080`)

| Endpoint | Auth | Purpose |
| :--- | :--- | :--- |
| `GET /` | None | Accessible btop-inspired HTML/CSS/JS Control Center + Web Terminal |
| `GET /api/live` | None | Single-request combined `summary`, `jobs`, and `history` (sparklines) payload |
| `GET /api/metrics` | None | Time-series ring buffer (last 60 samples) for cluster & per-node CPU/RAM/Temp/Net |
| `GET /api/status` | None | Unified cluster summary + per-node health + non-secret safety thresholds |
| `GET /api/jobs` | None | Live active & recent jobs across every configured phone |
| `GET /api/doctor` | None* | Live local + remote diagnostic & battery safety audit |
| `GET /api/workloads` | None* | Live `distcc_hosts`, `llama_rpc`, `mpi_hostfile`, Home Assistant URLs, Docker nodes, plus `services_info` |
| `GET /api/services` | None* | Live cross-tier Service Mesh (`pools`, `services`, `env` vars, and `.cluster` `dns_hosts`) |
| `GET /api/gateway/status` | None* | Optional Master Network Guard status, policy config, stats, presets, and recent audit events |
| `GET /api/network/audit` | None* | Full Master/Worker network hardening audit, Raspberry Pi & AdGuard detection, open ports, and firewall/AdGuard guides |
| `GET /api/discover` | None* | Runs a 2-second UDP LAN scan and returns discovered phones |
| `GET /api/auth/verify` | Bearer | Validates an `auth_token` before unlocking UI controls |
| `GET /api/settings` | Bearer | Returns full safety settings including `battery_webhook_url` |
| `POST /api/exec` | Bearer | Run a single command (`target`: `auto` default, `tier:1\|2\|3`, `pool:<name>`, `best`, `all`, or `node_id`) |
| `POST /api/terminal/exec` | Bearer | Run an interactive Web Terminal command with smart auto-routing & persistent `cwd` (`cd` support) |
| `POST /api/map` | Bearer | Run a parallel batch of shell commands or inline script + args (supports `target` & `workload_hint`) |
| `POST /api/pipeline` | Bearer | Execute a multi-step cross-tier pipeline chaining outputs (`PHONECLUSTER_PREV_STDOUT` & `PHONECLUSTER_STEP_{N}_STDOUT`) across Tier 1/2/3 |
| `POST /api/services/custom` | Bearer | Register a custom service (`name`, `url`) in the Cross-Tier Service Mesh and save atomically |
| `POST /api/services/custom/remove` | Bearer | Remove a custom service from the Service Mesh |
| `POST /api/services/probe` | Bearer | Measure TCP reachability & latency to a registered Service Mesh endpoint |
| `POST /api/gateway/settings` | Bearer | Enable/disable Master Network Guard, change policy (`allowlist`/`monitor`/`block_all`), edit domains/ports |
| `POST /api/gateway/allow-domain` | Bearer | One-click approve a blocked domain into the Network Guard allowlist |
| `POST /api/gateway/quarantine` | Bearer | Instantly quarantine or unblock a worker phone on the Master Network Guard proxy |
| `POST /api/gateway/logs/clear` | Bearer | Clear Network Guard traffic audit counters and log ring buffer |
| `POST /api/gateway/check-isolation` | Bearer | Probe workers directly (bypassing proxy) to verify router WAN firewall blocking |
| `POST /api/network/profile` | Bearer | Apply a 1-click security profile (`standard`, `airgap_workers`, or `lockdown`) |
| `POST /api/network/hardening` | Bearer | Configure `dashboard_require_auth`, `enforce_worker_source_ip`, `lan_subnet`, and `adguard_url` |
| `POST /api/jobs/cancel` | Bearer | Cancel a running job on a specific `node_id` |
| `POST /api/workloads/action` | Bearer | Start/stop `distcc` or `llama-rpc` across all ready phones |
| `POST /api/nodes/add` | Bearer | Add a discovered or manual worker phone (with optional `tier` & `pool`) into `config/cluster.json` |
| `POST /api/nodes/update` | Bearer | Update a phone's `tier` (`0..3`), `pool`, `max_concurrency`, `weight`, or `notes` in `config/cluster.json` |
| `POST /api/nodes/remove` | Bearer | Remove a worker phone from `config/cluster.json` (Master protected) |
| `GET /api/pair/hello` | Open Window | Public DH hello (`dh_pub`, `salt`, `session_id`, `fingerprint`) ONLY while a pairing window is open (`403` when closed) |
| `POST /api/pair/complete` | Open Window | Completes 2048-bit DH + PIN mutual-proof handshake and returns Encrypt-then-MAC enrollment bundle (5-attempt lockout) |
| `GET /api/pair/status` | Bearer | Returns active pairing window PIN, fingerprint, countdown, attempts left, and recently paired nodes |
| `POST /api/pair/open` | Bearer | Opens a temporary pairing window (`ttl_sec`, `max_devices`) and starts the temporary UDP `8766` pairing beacon |
| `POST /api/pair/close` | Bearer | Immediately closes any active pairing window and stops the UDP beacon |
| `POST /api/settings` | Bearer | Update thermal & 24/7 battery safety settings and save atomically |
| `POST /api/settings/test-webhook` | Bearer | Send a test JSON POST to the configured battery/smart-plug webhook URL |

---

## 3. Zero-Config UDP LAN Discovery (Port `8766`)

- **Probe (Master broadcasts to `<subnet>.255:8766` and `255.255.255.255:8766`):**
  ```json
  { "type": "phonecluster_discover_v1", "ts": 1795450000 }
  ```
- **Reply (Each running worker unicasts back to probe sender):**
  ```json
  {
    "type": "phonecluster_announce_v1",
    "node_id": "node1",
    "role": "worker",
    "worker_port": 8765,
    "ssh_port": 8022,
    "ssh_user": "u0_a250",
    "os_env": "termux",
    "cpu_cores": 8,
    "mem_total_mb": 3512
  }
  ```
- **Security:** `auth_token` is never sent over UDP.
