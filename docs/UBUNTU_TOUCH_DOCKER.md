# Ubuntu Touch + Snap Docker Clustering Guide (Tier 3)

PhoneCluster natively supports uniting **two (or more) Ubuntu Touch (UBports) phones** running **Docker via Snap** into one unified Tier 3 container cluster — safely respecting Ubuntu Touch's read-only rootfs, Snap home confinement, and `repowerd` power management.

---

## Why Ubuntu Touch + Snap Docker Needs Special Handling

Ubuntu Touch differs from standard desktop Linux in four important ways that PhoneCluster handles automatically:

1. **Read-Only Root Filesystem (`/`)**: You don't need `apt` or `/etc` edits. PhoneCluster runs cleanly out of `/home/phablet/phonecluster` using **`systemd --user`** services (`~/.config/systemd/user/`) and user lingering (`loginctl enable-linger phablet`).
2. **Snap Docker Binary & PATH**: Snap installs Docker at `/snap/bin/docker`, which is often missing from non-login SSH shells and `systemd --user` services. PhoneCluster automatically appends `/snap/bin` to `PATH` for capability detection, every worker `/exec` job, `pc` wrappers, and `03_sync_cluster.sh`.
3. **Snap Confinement & Socket Group**:
   - The `docker` snap must connect `docker:home` and your `phablet` user must belong to the `docker` group to access `/var/run/docker.sock`.
   - **Important bind-mount rule:** Snap Docker can only bind-mount host volumes located inside **`$HOME`** (PhoneCluster creates `~/phonecluster/docker-data` and exports `$PHONECLUSTER_DOCKER_DATA_DIR` to every job). Do **not** bind-mount `/tmp` or `/opt`.
4. **Screen-Off Deep Sleep (`repowerd`)**: Ubuntu Touch suspends the CPU shortly after the screen turns off. PhoneCluster's worker daemon automatically holds a keep-awake lock (`repowerd-cli active` / `powerd-cli active`) while running and releases it cleanly on exit.

---

## Quickstart for Two Ubuntu Touch Phones

### Step 1: Install Snap Docker on Both Phones

On **both** Ubuntu Touch phones (in Terminal or over SSH as `phablet`):

```bash
sudo snap install docker
```

### Step 2: Install & Configure PhoneCluster on Phone #1 (Master)

```bash
curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash -s -- --master --node-id ut-master
```

Or if you already cloned the repo:

```bash
bash scripts/06_ubuntu_touch_node_setup.sh --master --node-id ut-master
```

What this does automatically (safe on read-only rootfs):
- Enables SSH (`port 22`, user `phablet`) and sets `0700`/`0600` permissions on `~/.ssh`.
- Connects `sudo snap connect docker:home`, adds `phablet` to the `docker` group, fixes root-owned `~/.docker` if present, restarts Snap Docker, and creates `~/phonecluster/docker-data`.
- Installs `~/.local/bin/pc` and persistent `systemd --user` services (`phonecluster-worker.service` + `phonecluster-dashboard.service`) with lingering enabled.

> **Important:** After being added to the `docker` group for the first time, log out & back in (or reboot / restart `systemctl --user restart phonecluster-worker.service`) so the worker process inherits the `docker` group!

The installer can run the wizard before enabling the boot services. If you used the setup script directly, create the config with the same Master node ID and start both services.

```bash
pc wizard --master-id ut-master
systemctl --user start phonecluster-worker.service phonecluster-dashboard.service
pc doctor
```

### Step 3: Pair Phone #2 (Worker) Securely

1. On **Phone #2**, install PhoneCluster:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash -s -- --worker --node-id ut-worker1
   ```
2. On **Phone #1 (Master)**, open a 2-minute encrypted pairing window:
   ```bash
   pc pair
   ```
   *(Or open the Web Dashboard at `http://<phone1-ip>:8080` → Tab 6 → Open Pairing Window.)*
3. On **Phone #2**, run:
   ```bash
   pc join
   ```
   Enter the 6-digit PIN. Phone #2 automatically receives its unique per-node token, saves its `systemd --user` service, and comes online in Tier 3 (`docker` pool)!

---

## Managing Containers Across Both Ubuntu Touch Phones

### 1. Direct Cross-Phone Container Scheduling (Works on ALL Halium Kernels!)

PhoneCluster automatically routes Docker commands to Tier 3 (`docker` pool) and sets `$PHONECLUSTER_DOCKER_DATA_DIR` (`~/phonecluster/docker-data`):

```bash
# Inspect Docker version, Snap confinement, Swarm state & containers across BOTH phones
pc docker status

# Run `docker ps` across all Tier 3 phones
pc docker ps --target all

# Deploy a container to whichever phone is coolest / least busy (Snap-safe volume path!)
pc run --target tier:3 'docker run -d --restart unless-stopped -p 8088:80 -v "$PHONECLUSTER_DOCKER_DATA_DIR/web:/usr/share/nginx/html" nginx:alpine'

# Run parallel container tasks across BOTH phones simultaneously
pc map --target tier:3 --repeat 4 'docker run --rm alpine uname -a'
```

You can also manage containers from the **Web Control Center** (`pc dashboard` → **Tab 4: Workloads & Service Mesh** → **Check Docker Containers** / **Init 2-Phone Docker Swarm**).

### 2. Optional: Unite Both Phones in a Docker Swarm

If your Ubuntu Touch phones' kernels support VXLAN and netfilter modules, you can initialize a two-phone Docker Swarm. The workers need the manager's reachable Docker address. The result counts worker IDs confirmed by the selected manager and flags memberships it cannot verify.

```bash
pc docker swarm-init
```

If using a firewall (`ufw` / `nftables`), `pc net-audit --ufw` / `pc net-audit --firewall` automatically includes the LAN-only Docker Swarm ports (`2377/tcp`, `7946/tcp+udp`, `4789/udp`) whenever Tier 3 / Ubuntu Touch nodes are present.

> **Halium Kernel Note:** Some Ubuntu Touch Halium kernels omit `CONFIG_VXLAN` or certain netfilter modules required for Docker Swarm overlay networks. If `docker swarm join` fails on your device kernel, **you don't need Swarm** — PhoneCluster's built-in Tier 3 scheduler (`pc run --target tier:3`, `pc map`, `pc pipeline`, and automatic `PHONECLUSTER_*` service mesh) already clusters containers across both phones over standard LAN TCP/HTTP!

### 3. Using Master Network Guard with Snap & Docker

If you enable optional Master Network Guard (`Tab 5`), apply both the **Docker Hub & GHCR** (`docker`) and **Ubuntu Touch / Snap Store** (`snap`) allowlist presets so container image pulls and Snap refreshes continue smoothly while blocking unauthorized WAN traffic.

---

## Troubleshooting & 24/7 Safety

- Run **`pc doctor`** on each phone to verify SSH (`:22`), `systemd --user` auto-start, `repowerd-cli` wake-lock, `/snap/bin/docker` socket access, and `~/.docker` ownership.
- **24/7 Battery Protection:** Stand both phones vertically with airflow gaps and set `safety.battery_webhook_url` to cycle a Wi-Fi smart plug between `45%` and `60%`. Thermal throttling automatically pauses new jobs at `40 °C` and resumes at `37 °C`.
