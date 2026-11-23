# Upgrading to Native Debian 13 ARM64 & Docker (Tier 2 & Tier 3)

PhoneCluster works immediately on unrooted Termux (Tier 1), and automatically adapts without code changes when you upgrade to native **Debian 13 (Trixie) ARM64**.

---

## Why Not `proot-distro` or QEMU VMs on 4 GB Phones?

- **`proot-distro`** intercepts every Linux syscall via `ptrace()`, cutting I/O-heavy performance by ~44% and blocking native Docker and `/proc/net` discovery.
- **No-root QEMU VM apps** (like Podroid/Linxr) require capping guest VM RAM to ≤50% of host RAM (≤2 GB total on a 4 GB phone for the entire OS + containers).
- **Bare-metal Linux replacements** (postmarketOS/Nura, Ubuntu Touch) have poor or archived driver support on MediaTek handsets (e.g. Redmi Note 9/9T/10 5G).

Keeping Android's kernel as a stable hardware driver layer and running a **native ARM64 Debian 13 chroot** (Tier 2) gives you full glibc Linux speed with zero `ptrace()` overhead.

---

## Tier 2: Rooted Native Debian 13 ARM64 Chroot (Recommended Sweet Spot)

### What You Gain Over Termux
- Full standard **Debian 13 (Trixie)** `apt` repository & prebuilt glibc Python wheels
- **Home Assistant Core** (Python venv) + native **Mosquitto MQTT** + **Zigbee2MQTT**
- **HashiCorp Nomad (`raw_exec`)** and **Slurm + OpenMPI** HPC queues
- **AdGuard Home / Pi-hole** on privileged port `53` + **Tailscale / WireGuard** VPN gateway
- Mandatory **24/7 kernel battery protection** via [`vr-25/acc`](https://github.com/vr-25/acc)

### Step 1: Pre-Flight Check & Root Prerequisites
1. Unlock the bootloader (backup `boot`, `preloader`, and `EFS/persist` first).
2. Root with **Magisk** by patching your exact stock `boot.img` (skip official KernelSU on pre-GKI Linux 4.14 kernels).
3. **Install battery protection first:** Flash the `vr-25/acc` Magisk module, test with `acc -t`, and lock a safe 24/7 charge profile:
   ```bash
   su -c "acc -s pc=60 rc=55 mcv=3900 mcc=500"
   ```
   *(On Xiaomi PMICs, never disable ACC's `shutdown_capacity` protection; rebooting into Fastboot and back resets a stuck PMIC.)*
4. Run our dry-run check first:
   ```bash
   bash scripts/04_debian13_chroot_setup.sh --check-only
   ```

### Step 2: Bootstrap Native Debian 13 ARM64
```bash
su -mm -c "bash scripts/04_debian13_chroot_setup.sh"
```

Enter Debian 13:
```bash
su -mm -c /data/local/linux/enter_debian13.sh
```

Inside Debian 13, install standard packages and launch PhoneCluster:
```bash
apt update && apt install -y \
  openssh-server python3 python3-venv git tmux htop \
  clang cmake distcc openmpi-bin

# Configure SSH (port 22 or 8022) and run PhoneCluster identically:
python3 ~/phonecluster/phonecluster_cli.py worker --node-id node0
```
PhoneCluster automatically detects `debian-13` and reads battery level & temperature directly from `/sys/class/power_supply/*`!

### Step 3: Home Assistant & Smart-Home Radios on Tier 2
- **Avoid USB Zigbee dongles directly on phones** (stock MediaTek kernels often omit `cp210x`/`cdc_acm` drivers and occupy the phone's single USB-C charging port).
- Instead, plug a networked Ethernet/PoE Zigbee coordinator (such as **SMLIGHT SLZB-06 / SLZB-06M**) into your router/switch and connect Home Assistant / Zigbee2MQTT over LAN TCP (`tcp://<ip>:6638`).
- Host Home Assistant on your **UFS 2.2 Master phone** (`node0`), never on slower eMMC storage.

### Step 4: Exposing Port 53 / VPN (Punching Through Android `netd`)
If you run **AdGuard Home** or **WireGuard/Tailscale** on a rooted worker phone, Android's `netd` blocks inbound LAN traffic to privileged ports until you add three boot rules:
```bash
sysctl -w net.ipv4.ip_forward=1
iptables -A INPUT -i wlan0 -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i wlan0 -p tcp --dport 53 -j ACCEPT
# Plus `ip rule` priority entries (e.g. 21000/21001) routing wg0/tailscale0 subnets to `main`.
```

---

## Tier 3: Custom Kernel + Droidspaces (Native Docker & Home Assistant Container)

Stock Android 4.14 kernels omit Linux container namespaces and cgroups. Attempt Tier 3 **only** if you specifically need **native Docker Engine**, **Home Assistant Container**, or a **K3s** lab:

1. Cross-compile your phone's Linux 4.14 kernel with container defconfig flags enabled:
   `CONFIG_NAMESPACES`, `CONFIG_PID_NS`, `CONFIG_IPC_NS`, `CONFIG_NET_NS`, `CONFIG_CGROUPS`, `CONFIG_MEMCG`, `CONFIG_VETH`, `CONFIG_BRIDGE`, `CONFIG_OVERLAY_FS`, `CONFIG_DEVTMPFS`, `CONFIG_ANDROID_PARANOID_NETWORK=n`.
2. Patch `net/netfilter/xt_qtaguid.c` if present to prevent container-launch kernel freezes.
3. Install **Droidspaces** using **sparse `ext4` loopback rootfs images** (Android's `f2fs` `/data` breaks OverlayFS in plain directories) running **Debian 12/13** or **Alpine Linux (OpenRC)**.
   - *Compatibility note:* Avoid rolling distros (Arch/Fedora) on 4.14 kernels because `systemd >= v258` dropped fallback support for kernels older than 5.4.
4. Set `"iptables": false` in Docker's `/etc/docker/daemon.json` so Docker uses `docker-proxy` without corrupting Android's `netd` rules.
