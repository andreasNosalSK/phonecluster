#!/usr/bin/env bash
# 01_adb_prep.sh — Run from your PC with a phone connected via USB or Wireless ADB.
# Performs hardware audit (codename, RAM, Android version) and disables Android's
# Phantom Process Killer on Android 12/13 (per instruction.txt).
set -euo pipefail

SERIAL_ARGS=()
APPLY_FIX=1

usage() {
  cat <<'EOF'
Usage: ./scripts/01_adb_prep.sh [-s <adb-serial>] [--audit-only]

Options:
  -s <serial>    Target a specific ADB device serial (see `adb devices`)
  --audit-only   Only print hardware specs; do not modify phantom process settings
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s)
      [[ $# -ge 2 ]] || { echo "Error: -s requires an ADB device serial" >&2; usage; exit 2; }
      SERIAL_ARGS=(-s "$2"); shift 2 ;;
    --audit-only) APPLY_FIX=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if ! command -v adb >/dev/null 2>&1; then
  echo "Error: 'adb' not found in PATH. Install android-tools / platform-tools first." >&2
  exit 1
fi

adb "${SERIAL_ARGS[@]}" get-state >/dev/null

DEVICE="$(adb "${SERIAL_ARGS[@]}" shell getprop ro.product.device | tr -d '\r')"
MODEL="$(adb "${SERIAL_ARGS[@]}" shell getprop ro.product.model | tr -d '\r')"
ANDROID_VER="$(adb "${SERIAL_ARGS[@]}" shell getprop ro.build.version.release | tr -d '\r')"
SDK_INT="$(adb "${SERIAL_ARGS[@]}" shell getprop ro.build.version.sdk | tr -d '\r')"
MIUI_VER="$(adb "${SERIAL_ARGS[@]}" shell getprop ro.miui.ui.version.name | tr -d '\r' || true)"
MEM_INFO="$(adb "${SERIAL_ARGS[@]}" shell "head -n 3 /proc/meminfo" | tr -d '\r')"

echo "=== Android Phone Hardware Audit ==="
echo "Model          : ${MODEL}"
echo "Codename       : ${DEVICE}"
echo "Android / SDK  : ${ANDROID_VER} (API ${SDK_INT})"
[[ -n "${MIUI_VER}" ]] && echo "MIUI Version   : ${MIUI_VER}"
echo "--- Memory ---"
echo "${MEM_INFO}"
echo "===================================="
echo "Tip: Pick the phone with the highest RAM and UFS storage (e.g., cannong/cannon/camellian, NOT eMMC merlin) as Master (node0)."
echo

if [[ "${APPLY_FIX}" -eq 0 ]]; then
  exit 0
fi

MAJOR_VER="${ANDROID_VER%%.*}"
if [[ ! "${MAJOR_VER}" =~ ^[0-9]+$ ]]; then
  echo "Warning: Could not parse Android major version '${ANDROID_VER}'. Skipping automatic fix." >&2
  exit 0
fi

if (( MAJOR_VER <= 11 )); then
  echo "Android ${ANDROID_VER}: Phantom Process Killer not present — no ADB fix required."
elif (( MAJOR_VER == 12 )); then
  echo "Applying Android 12 Phantom Process Killer fix..."
  # set_sync_disabled_for_tests persistent MUST run first so Play Services does not revert it
  adb "${SERIAL_ARGS[@]}" shell "/system/bin/device_config set_sync_disabled_for_tests persistent"
  adb "${SERIAL_ARGS[@]}" shell "/system/bin/device_config put activity_manager max_phantom_processes 2147483647"
  echo "Done. Reboot the phone and verify with:"
  echo "  adb shell \"/system/bin/device_config get activity_manager max_phantom_processes\""
elif (( MAJOR_VER == 13 )); then
  echo "Applying Android 13 Phantom Process Killer fix..."
  adb "${SERIAL_ARGS[@]}" shell "settings put global settings_enable_monitor_phantom_procs false"
  echo "Done. Reboot the phone for the setting to take effect."
else
  echo "Android ${ANDROID_VER} (14+): Open Settings -> Developer Options -> enable 'Disable child process restrictions', then reboot."
fi

cat <<'EOF'

Manual Android Settings Checklist (do once on each phone):
  1. Install Termux, Termux:Boot, and Termux:API from the EXACT SAME source (F-Droid or GitHub Releases — NEVER Google Play).
  2. Open Termux:Boot once manually so Android registers its boot receiver.
  3. Settings -> Apps -> Battery Optimization -> Unrestricted for Termux, Termux:Boot, and Termux:API.
  4. On Xiaomi/MIUI: enable "Background autostart" for Termux and Termux:Boot.
  5. Assign a static DHCP IP in your router for this phone's Wi-Fi MAC address.
EOF
