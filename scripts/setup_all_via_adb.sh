#!/usr/bin/env bash
# setup_all_via_adb.sh — One-click PC-side USB Fleet Provisioner for Android phones.
#
# Plug in one or more Android phones (with USB Debugging enabled), then run this script:
#   1. Audits every connected phone (model, codename, Android version, RAM, Wi-Fi IP)
#   2. Ranks and picks the best Master phone (highest RAM + UFS storage over eMMC)
#   3. Applies the Android 12/13 Phantom Process Killer fix automatically
#   4. Whitelists Termux / Termux:Boot / Termux:API from Android Doze battery saver
#   5. Optionally installs APKs from ./apks/*.apk if present
#   6. Generates a ready-to-use config/cluster.json with all discovered Wi-Fi IPs!
set -euo pipefail

CONFIG_OUT="config/cluster.json"
APKS_DIR="apks"
FORCE_OVERWRITE=0

usage() {
  cat <<'EOF'
Usage: ./scripts/setup_all_via_adb.sh [--force] [config-output-path]

Options:
  -f, --force   Overwrite existing cluster config file if present
  -h, --help    Show this help
EOF
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--force) FORCE_OVERWRITE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done ;;
    -*) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
if [[ "${#POSITIONAL[@]}" -ge 1 ]]; then
  CONFIG_OUT="${POSITIONAL[0]}"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_REVISION="$(PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" python3 -m phonecluster.config_transfer "${CONFIG_OUT}")"
if [[ -n "${CONFIG_REVISION}" && "${FORCE_OVERWRITE}" -eq 0 ]]; then
  echo "Error: Config already exists at '${CONFIG_OUT}' (refusing to overwrite existing cluster tokens)." >&2
  echo "Pass --force to overwrite or specify a different output path." >&2
  exit 1
fi

if ! command -v adb >/dev/null 2>&1; then
  echo "Error: 'adb' not found. Install android-tools / platform-tools on your PC first." >&2
  exit 1
fi

SERIALS=()
while IFS= read -r _ser; do
  [[ -n "${_ser}" ]] && SERIALS+=("${_ser}")
done < <(adb devices | awk 'NR>1 && $2=="device" {print $1}')
if [[ "${#SERIALS[@]}" -eq 0 ]]; then
  echo "No authorized Android devices found via ADB." >&2
  echo "Enable Developer Options -> USB Debugging on each phone, connect USB, and accept the RSA prompt." >&2
  exit 1
fi

echo "============================================================"
echo "  PhoneCluster Multi-Phone ADB Fleet Provisioner"
echo "============================================================"
echo "Detected ${#SERIALS[@]} connected Android device(s)."
echo

TMP_TSV="$(mktemp)"
trap 'rm -f "${TMP_TSV}"' EXIT

for SER in "${SERIALS[@]}"; do
  MODEL="$(adb -s "${SER}" shell getprop ro.product.model | tr -d '\r\n\t')"
  DEVICE="$(adb -s "${SER}" shell getprop ro.product.device | tr -d '\r\n\t')"
  VER="$(adb -s "${SER}" shell getprop ro.build.version.release | tr -d '\r\n\t')"
  MEM_KB="$(adb -s "${SER}" shell cat /proc/meminfo 2>/dev/null | awk '/MemTotal/{print $2; exit}' | tr -d '\r\n\t ' || true)"
  [[ "${MEM_KB}" =~ ^[0-9]+$ ]] || MEM_KB=0
  MEM_MB="$(( MEM_KB / 1024 ))"
  WIFI_IP="$(adb -s "${SER}" shell ip -4 addr show wlan0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 | tr -d '\r\n\t ' || true)"

  echo ">>> Device ${SER}: ${MODEL} (${DEVICE}) | Android ${VER} | ${MEM_MB} MB RAM | Wi-Fi IP: ${WIFI_IP:-NOT CONNECTED}"

  # Optional APK install from ./apks/ (put F-Droid Termux, Termux:Boot, Termux:API APKs there)
  if [[ -d "${APKS_DIR}" ]]; then
    shopt -s nullglob
    for APK in "${APKS_DIR}"/*.apk; do
      echo "    Installing $(basename "${APK}")..."
      adb -s "${SER}" install -r "${APK}" >/dev/null || echo "    Warning: Failed to install ${APK}"
    done
    shopt -u nullglob
  fi

  # Check Termux apps (inspect stdout instead of exit code — Android 7-9 ADB protocol v1 always returns 0!)
  MISSING_APPS=()
  for PKG in com.termux com.termux.boot com.termux.api; do
    PKG_PATH="$(adb -s "${SER}" shell pm path "${PKG}" 2>/dev/null | tr -d '\r\n' || true)"
    if [[ -z "${PKG_PATH}" ]]; then
      MISSING_APPS+=("${PKG}")
    else
      # Best-effort Doze whitelist (works on most unrooted Android builds)
      adb -s "${SER}" shell "dumpsys deviceidle whitelist +${PKG}" >/dev/null 2>&1 || true
    fi
  done
  if [[ "${#MISSING_APPS[@]}" -gt 0 ]]; then
    echo "    [!] Missing apps (install ALL from F-Droid or GitHub — never Google Play): ${MISSING_APPS[*]}"
  else
    echo "    [OK] Termux + Termux:Boot + Termux:API installed (Doze whitelisted)."
  fi

  # Apply Phantom Process Killer fix based on Android version
  MAJOR="${VER%%.*}"
  if [[ "${MAJOR}" =~ ^[0-9]+$ ]]; then
    if (( MAJOR == 12 )); then
      if adb -s "${SER}" shell "/system/bin/device_config set_sync_disabled_for_tests persistent" >/dev/null 2>&1 \
        && adb -s "${SER}" shell "/system/bin/device_config put activity_manager max_phantom_processes 2147483647" >/dev/null 2>&1; then
        echo "    [OK] Applied Android 12 Phantom Process Killer fix (reboot phone to finalize)."
      else
        echo "    [!] Warning: Could not apply Android 12 Phantom Process Killer fix (on MIUI, enable 'USB debugging (Security settings)')."
      fi
    elif (( MAJOR == 13 )); then
      if adb -s "${SER}" shell "settings put global settings_enable_monitor_phantom_procs false" >/dev/null 2>&1; then
        echo "    [OK] Applied Android 13 Phantom Process Killer fix (reboot phone to finalize)."
      else
        echo "    [!] Warning: Could not apply Android 13 Phantom Process Killer fix (on MIUI, enable 'USB debugging (Security settings)')."
      fi
    elif (( MAJOR >= 14 )); then
      echo "    [!] Android ${VER}: Enable Developer Options -> 'Disable child process restrictions', then reboot."
    else
      echo "    [OK] Android ${VER}: Not affected by Phantom Process Killer."
    fi
  fi

  # Score candidate for Master role (higher RAM + bonus for non-eMMC UFS devices)
  IS_EMMC=0
  [[ "${DEVICE}" == "merlin"* ]] && IS_EMMC=1
  SCORE="$(( MEM_MB - IS_EMMC * 1000 ))"
  printf "%d\t%s\t%s\t%s\t%d\t%s\n" "${SCORE}" "${SER}" "${DEVICE}" "${MODEL}" "${MEM_MB}" "${WIFI_IP}" >> "${TMP_TSV}"
  echo
done

# Generate config/cluster.json automatically using detected Wi-Fi IPs ranked by Master score
python3 - "${TMP_TSV}" "${CONFIG_OUT}" "${REPO_ROOT}" "${CONFIG_REVISION}" <<'PY'
import json, secrets, sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from phonecluster.config import ClusterConfig, replace_config_file

rows = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    score, ser, dev, model, mem_mb, ip = line.split("\t")
    rows.append((int(score), ser, dev, model, int(mem_mb), ip.strip()))

rows.sort(key=lambda r: r[0], reverse=True)

nodes = []
for idx, (score, ser, dev, model, mem_mb, ip) in enumerate(rows):
    role = "master" if idx == 0 else "worker"
    host = ip if ip else f"192.168.1.{201 + idx}"
    is_emmc = dev.startswith("merlin")
    weight = 1.2 if role == "master" else (0.8 if is_emmc else 1.0)
    node_entry = {
        "id": f"node{idx}",
        "host": host,
        "role": role,
        "worker_port": 8765,
        "ssh_port": 8022,
        "ssh_user": "",
        "max_concurrency": 2,
        "weight": weight,
        "tags": [role, "emmc" if is_emmc else "ufs"],
        "notes": f"{model} ({dev}, {mem_mb} MB RAM, serial {ser})",
    }
    if role == "worker":
        node_entry["auth_token"] = secrets.token_urlsafe(32)
    nodes.append(node_entry)

cfg = {
    "cluster_name": "phone-cluster",
    "auth_token": secrets.token_urlsafe(32),
    "default_job_timeout_sec": 600,
    "health_timeout_sec": 3.0,
    "dashboard_port": 8080,
    "safety": {
        "max_temp_c": 40.0,
        "resume_temp_c": 37.0,
        "min_free_ram_mb": 256,
        "battery_low_pct": 45,
        "battery_high_pct": 60,
        "battery_poll_sec": 60,
        "webhook_cooldown_sec": 900,
        "battery_webhook_url": "",
    },
    "nodes": nodes,
}

out = Path(sys.argv[2])
ClusterConfig.from_dict(cfg)
payload = (json.dumps(cfg, indent=2) + "\n").encode("utf-8")
replace_config_file(out, payload, expected_revision=sys.argv[4])

print("=== Auto-Generated Cluster Plan ===")
for n in nodes:
    print(f"  {n['id']:6s} ({n['role']:6s}) -> {n['host']:15s} | {n['notes']}")
print(f"\nSaved config to: {out}")
PY

echo
echo "Next steps:"
echo "  1. Reserve those Wi-Fi IPs as static DHCP leases in your router."
echo "  2. Reboot each phone (so the Phantom Process Killer fix activates) and open Termux:Boot once."
echo "  3. Inside Termux on each phone, run: bash install.sh"
echo "  4. On your Master phone (node0), run: pc dashboard  (open http://<master-ip>:8080)"
