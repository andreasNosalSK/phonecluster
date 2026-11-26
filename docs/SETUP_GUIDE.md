# Complete Setup Guide (Android 7+ — No Root Required)

This guide takes you from spare Android phones to a working cluster in **~15 minutes** at **€0 upfront** over your existing 5 GHz Wi-Fi.

---

## 1. Install the 3 Core Android Apps (From the EXACT Same Source)

On **every** phone, install these three free apps from **F-Droid** (recommended) or all three from **GitHub Releases**:

1. **Termux** — native ARM64 Linux shell & package manager
2. **Termux:Boot** — launches your cluster daemon automatically on reboot
3. **Termux:API** — reads battery level & temperature without root

> **Critical rule:** Never install Termux from Google Play, and never mix F-Droid with GitHub/Play builds — signature mismatches silently break `Termux:API` and `Termux:Boot`.

After installing on each phone:
- Open **Termux:Boot** once manually (registers its Android boot receiver).
- Go to **Settings → Apps → Battery Optimization** and set **Unrestricted** for **Termux**, **Termux:Boot**, and **Termux:API**.
- On **Xiaomi / MIUI**: search Settings for **Background autostart** and enable it for **Termux** and **Termux:Boot**.

---

## 2. One-Click ADB Fleet Prep (From Your PC)

Enable **Developer Options → USB Debugging** on each phone, connect them to your PC (one by one or all at once via USB hub), and run:

```bash
./scripts/setup_all_via_adb.sh
```

What this script automates for you:
- Reads each phone's model, codename, Android version, RAM, and Wi-Fi IP.
- Automatically ranks your best **Master phone (`node0`)** — preferring higher RAM and faster UFS flash over slower eMMC devices (like Redmi Note 9 `merlin`).
- Applies the **Phantom Process Killer** fix:
  - **Android 7–11:** not affected.
  - **Android 12:** runs `set_sync_disabled_for_tests persistent` first, then `max_phantom_processes 2147483647`.
  - **Android 13:** sets `settings_enable_monitor_phantom_procs false`.
  - **Android 14+:** reminds you to enable *Developer Options → Disable child process restrictions*.
- Whitelists Termux apps from Android Doze (`dumpsys deviceidle whitelist`).
- Bonus: if you place the 3 F-Droid `.apk` files in an `./apks/` folder before running, it installs them automatically onto every connected phone!
- Generates `config/cluster.json` with a fresh random `auth_token`.

**Reboot each phone** after running the script so the Phantom Process Killer setting takes effect, and reserve their Wi-Fi IPs as **static DHCP leases** in your router.

---

## 3. One-Line Termux Install on Each Phone

Open Termux on each phone and run:

```bash
curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash
```

The installer:
- Clones (or updates) PhoneCluster into `~/phonecluster`.
- Installs `openssh`, `termux-api`, `python`, `jq`, `tmux`, `git` (pass `--with-compute` for `clang`, `cmake`, `distcc`, `openmpi`, `htop`).
- Creates global `phonecluster` and short `pc` commands in PATH.
- Starts `sshd` on port `8022` and sets up `~/.termux/boot/00-start-cluster.sh` (with `termux-wake-lock`).
- Offers to run `pc wizard` on your Master phone.

---

## 4. Sync & Verify Your Cluster

Copy your generated `config/cluster.json` to the Master phone or run `pc wizard` there to discover workers. Preview the first worker, then deploy to that worker from the Master.

```bash
# Use the worker ID shown by pc status
pc sync --node-id node1 --dry-run
pc sync --node-id node1 --setup-keys

# Run automated diagnostics
pc doctor

# Check unified "one PC" resources (add --watch for live refresh)
pc status --watch

# Print your auth_token to unlock controls in the browser
pc token

# Start the accessible Web Control Center
pc dashboard
```

The preview lists the selected endpoints and planned restart. Sync stages and verifies the received code archive before extracting it. Verify the canary's health and run a small job before syncing more workers. Repeat `--node-id` to select several nodes or use `--skip-node` with the local controller ID for a fleet sync.

Open `http://<master-phone-ip>:8080` in any browser on your Wi-Fi! Paste your token from `pc token` into the top bar and click **Unlock** (check **Remember** if you're on your own personal device).

---

## 5. Adding Another Phone Anytime (15 Seconds — Secure Auto-Search!)

PhoneCluster stays **completely silent on Wi-Fi** by default so strangers cannot discover or join your cluster. To add another Android phone safely:

1. **On your Master phone:** Open a temporary 2-minute Pairing Window:
   - In the Web Control Center → **5. Phones, Safety & Doctor** → click **Open Pairing Window (2 min)**, OR run `pc pair` in terminal.
   - Note the **6-digit PIN** (e.g. `482-917`) and **Master Fingerprint** (`A4F2-91C8`).
2. **On the new phone (Termux):** Run the one-line installer (or `pc join` if already installed):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/andreasNosalSK/phonecluster/main/install.sh | bash
   ```
   Choose **2) Worker phone** → accept **Auto-search Wi-Fi for your Master phone** → verify the fingerprint → type the **6-digit PIN**.
3. **Done!** Under the hood, PhoneCluster runs a 2048-bit Diffie-Hellman encrypted exchange, verifies mutual PIN proofs, mints a **unique least-privilege token** just for that phone, saves its `0600` config, sets up Termux:Boot, starts the worker daemon, and immediately closes the pairing window!

*(If your router blocks Wi-Fi broadcast or you're pairing over Tailscale, run `pc join --master <master-ip>:8080` or `:8767` instead.)*

---

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Background jobs die with `[Process completed (signal 9)]` | Android 12+ Phantom Process Killer | Re-run `./scripts/01_adb_prep.sh` and **reboot** the phone. |
| `termux-battery-status` hangs or times out | Termux and Termux:API installed from different stores, or Battery Optimization enabled | Uninstall both and reinstall all 3 apps from F-Droid; set Battery Optimization to Unrestricted. |
| `pc discover` finds 0 phones | Router AP/Client Isolation enabled, or worker daemons not running | Disable AP Isolation in router Wi-Fi settings, or enter static phone IPs manually in `pc wizard`. |
| Phone shows `PAUSED (overheated)` | Temperature reached `40.0 °C` | Stand phones vertically with air gaps. Running jobs continue. The worker accepts new jobs again at `37.0 °C`. |
| `HTTP 401 unauthorized` | The worker's local credential differs from its entry on the Master. | Run `pc sync` on the Master. If it reports shared or missing credentials, follow the [credential migration steps](SECURITY.md#migrating-a-cluster-that-used-shared-credentials). |
