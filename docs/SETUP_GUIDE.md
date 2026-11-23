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

## 3. One-Command Termux Install on Each Phone

Open Termux on each phone and run:

```bash
pkg install -y git
git clone https://github.com/<your-user>/phonecluster.git ~/phonecluster
bash ~/phonecluster/install.sh
```

The installer:
- Installs `openssh`, `termux-api`, `python`, `jq`, `tmux`, `git` (add `--with-compute` for `clang`, `cmake`, `distcc`, `openmpi`, `htop`).
- Creates global `phonecluster` and short `pc` commands in PATH.
- Starts `sshd` on port `8022` and sets up `~/.termux/boot/00-start-cluster.sh` (with `termux-wake-lock`).
- Offers to run `pc wizard` on your Master phone.

---

## 4. Sync & Verify Your Cluster

Copy your generated `config/cluster.json` to your Master phone (or run `pc wizard` on the Master phone to auto-discover workers over Wi-Fi), then run from the Master phone:

```bash
# Push SSH keys + sync PhoneCluster code & config to all phones + start workers
~/phonecluster/scripts/03_sync_cluster.sh --setup-keys

# Run automated diagnostics
pc doctor

# Check unified "one PC" resources
pc status

# Start the accessible Web Control Center
pc dashboard
```

Open `http://<master-phone-ip>:8080` in any browser on your Wi-Fi! To unlock command execution in the Web UI, paste your `auth_token` from `config/cluster.json` into the top bar and click **Unlock**.

---

## 5. Adding Another Phone Later (Wi-Fi Auto-Discovery)

1. Install Termux + `install.sh` on the new phone (choose **Worker**).
2. Open the **Web Control Center → 4. Add Phone & Doctor** tab and click **Scan Wi-Fi Now** (or run `pc discover` in terminal).
3. Click **+ Add to Cluster**, then run `~/phonecluster/scripts/03_sync_cluster.sh --setup-keys` to push the shared `auth_token` and start its worker.

---

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Background jobs die with `[Process completed (signal 9)]` | Android 12+ Phantom Process Killer | Re-run `./scripts/01_adb_prep.sh` and **reboot** the phone. |
| `termux-battery-status` hangs or times out | Termux and Termux:API installed from different stores, or Battery Optimization enabled | Uninstall both and reinstall all 3 apps from F-Droid; set Battery Optimization to Unrestricted. |
| `pc discover` finds 0 phones | Router AP/Client Isolation enabled, or worker daemons not running | Disable AP Isolation in router Wi-Fi settings, or enter static phone IPs manually in `pc wizard`. |
| Phone shows `PAUSED (overheated)` | Battery reached `40.0 °C` | Stand phones vertically with air gaps (never stacked flat). Jobs auto-resume once temp drops to `37.0 °C`. |
| `HTTP 401 unauthorized` | Worker has a different `auth_token` than Master | Re-run `./scripts/03_sync_cluster.sh` so all nodes share the exact same `config/cluster.json`. |
