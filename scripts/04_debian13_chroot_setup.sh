#!/usr/bin/env bash
# 04_debian13_chroot_setup.sh — Tier 2 Upgrade Path (Rooted Phone -> Native Debian 13 ARM64 chroot).
#
# Why Debian 13 chroot instead of Termux proot-distro?
#   - Full standard glibc Debian 13 (Trixie) ARM64 (`apt`, Python wheels, Home Assistant Core venv,
#     Nomad, Slurm, distcc, OpenMPI, AdGuard Home on port 53, Tailscale/WireGuard)
#   - Native Linux syscall speed (no ptrace() overhead)
#   - Runs on the stock Android 4.14 kernel (NO custom kernel compilation needed)
#
# Note on Native Docker / Home Assistant Container:
#   - Stock Android 4.14 MediaTek kernels omit Linux namespaces/cgroups/OverlayFS required by Docker.
#   - For native Docker, upgrade to Tier 3 (custom-compiled 4.14 kernel + Droidspaces using sparse
#     ext4 rootfs images with Debian 13 or Alpine OpenRC — see README.md).
set -euo pipefail

CHROOT_DIR="/data/local/linux/debian13"
CHECK_ONLY=0
ROOTFS_URL=""

usage() {
  cat <<'EOF'
Usage: su -mm -c "bash scripts/04_debian13_chroot_setup.sh [options]"

Options:
  --check-only        Check root, kernel, ACC battery limiter, and Docker/namespace support without modifying anything
  --dir <path>        Chroot destination directory (default: /data/local/linux/debian13)
  --rootfs-url <url>  Direct URL to a Debian 13 (trixie) arm64 rootfs.tar.xz tarball
                      (if omitted, fetches latest index from images.linuxcontainers.org)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --dir)
      [[ $# -ge 2 ]] || { echo "Error: --dir requires a path" >&2; usage; exit 2; }
      CHROOT_DIR="$2"; shift 2 ;;
    --rootfs-url)
      [[ $# -ge 2 ]] || { echo "Error: --rootfs-url requires an https:// URL" >&2; usage; exit 2; }
      ROOTFS_URL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${CHROOT_DIR}" || "${CHROOT_DIR}" == "/" || "${CHROOT_DIR}" != /* || "${CHROOT_DIR}" == *$'\n'* || "${CHROOT_DIR}" == *'"'* || "${CHROOT_DIR}" == *'$'* || "${CHROOT_DIR}" == *'`'* || "${CHROOT_DIR}" == *'\'* ]]; then
  echo "Error: Invalid --dir '${CHROOT_DIR}' (must be a safe absolute path and not '/')." >&2
  exit 2
fi

if [[ -n "${ROOTFS_URL}" && ! "${ROOTFS_URL}" =~ ^https?:// ]]; then
  echo "Error: --rootfs-url must start with https:// or http://" >&2
  exit 2
fi

echo "=== Debian 13 (Trixie) ARM64 Chroot Pre-Flight Check ==="
echo "Kernel  : $(uname -a)"
echo "Arch    : $(uname -m)"
echo "UID     : $(id -u)"

if command -v acc >/dev/null 2>&1; then
  echo "ACC     : INSTALLED (recommended 24/7 limit: acc -s pc=60 rc=55 mcv=3900 mcc=500)"
else
  echo "ACC     : NOT FOUND — WARNING: Install vr-25/acc Magisk module before running rooted 24/7!"
fi

if [[ -f /proc/config.gz ]]; then
  echo -n "Namespaces (Docker Tier 3 check): "
  KCFG="$(zcat /proc/config.gz 2>/dev/null || true)"
  if [[ "${KCFG}" == *"CONFIG_PID_NS=y"* && "${KCFG}" == *"CONFIG_NET_NS=y"* ]]; then
    echo "ENABLED (kernel supports Droidspaces/Docker!)"
  else
    echo "DISABLED (stock kernel — Tier 2 Debian 13 chroot works great; Docker requires Tier 3 custom kernel)"
  fi
fi

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: Root access is required for native chroot. Run inside: su -mm" >&2
  exit 1
fi

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "Error: Expected aarch64 (ARM64) device, found '$(uname -m)'." >&2
  exit 1
fi

mkdir -p "${CHROOT_DIR}" /data/local/linux

if [[ ! -d "${CHROOT_DIR}/etc" ]]; then
  if [[ -z "${ROOTFS_URL}" ]]; then
    echo "Resolving latest Debian 13 (trixie) arm64 rootfs from images.linuxcontainers.org..."
    BASE_URL="https://images.linuxcontainers.org/images/debian/trixie/arm64/default/"
    LATEST_DIR="$(curl -fsSL "${BASE_URL}" | grep -oE '[0-9]{8}_[0-9]{2}:[0-9]{2}/' | sort | tail -n 1 || true)"
    if [[ -z "${LATEST_DIR}" ]]; then
      echo "Error: Could not auto-detect latest Debian 13 rootfs. Pass --rootfs-url manually." >&2
      exit 1
    fi
    ROOTFS_URL="${BASE_URL}${LATEST_DIR}rootfs.tar.xz"
  fi
  echo "Downloading ${ROOTFS_URL}..."
  TMP_TAR="/data/local/linux/debian13-rootfs.tar.xz.tmp.$$"
  trap 'rm -f "${TMP_TAR}"' EXIT
  curl -fsSL -- "${ROOTFS_URL}" -o "${TMP_TAR}"
  echo "Extracting Debian 13 rootfs into ${CHROOT_DIR}..."
  tar --numeric-owner -xJf "${TMP_TAR}" -C "${CHROOT_DIR}"
  rm -f "${TMP_TAR}"
  trap - EXIT
fi

# Basic DNS & Android group compatibility inside Debian chroot (unlink symlinked resolv.conf first!)
rm -f "${CHROOT_DIR}/etc/resolv.conf"
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > "${CHROOT_DIR}/etc/resolv.conf"
grep -q "^aid_inet:" "${CHROOT_DIR}/etc/group" || echo "aid_inet:x:3003:root" >> "${CHROOT_DIR}/etc/group"
grep -q "^aid_net_raw:" "${CHROOT_DIR}/etc/group" || echo "aid_net_raw:x:3004:root" >> "${CHROOT_DIR}/etc/group"

# Create mount + enter helper scripts
cat > /data/local/linux/mount_debian13.sh <<EOF
#!/system/bin/sh
set -e
CHROOT="${CHROOT_DIR}"
mkdir -p "\${CHROOT}/dev/pts" "\${CHROOT}/dev/shm" "\${CHROOT}/proc" "\${CHROOT}/sys"
mountpoint -q "\${CHROOT}/proc"    || mount -t proc proc "\${CHROOT}/proc"
mountpoint -q "\${CHROOT}/sys"     || mount -t sysfs sysfs "\${CHROOT}/sys"
mountpoint -q "\${CHROOT}/dev"     || mount -o bind /dev "\${CHROOT}/dev"
mountpoint -q "\${CHROOT}/dev/pts" || mount -t devpts devpts "\${CHROOT}/dev/pts"
mountpoint -q "\${CHROOT}/dev/shm" || mount -t tmpfs -o size=256M tmpfs "\${CHROOT}/dev/shm"
EOF
chmod +x /data/local/linux/mount_debian13.sh

cat > /data/local/linux/enter_debian13.sh <<EOF
#!/system/bin/sh
set -e
/data/local/linux/mount_debian13.sh
exec chroot "${CHROOT_DIR}" /usr/bin/env -i \\
  HOME=/root \\
  TERM="\${TERM:-xterm-256color}" \\
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
  /bin/bash --login "\$@"
EOF
chmod +x /data/local/linux/enter_debian13.sh

echo
echo "=== Debian 13 ARM64 Chroot Installed ==="
echo "Enter Debian 13 with:"
echo "  su -mm -c /data/local/linux/enter_debian13.sh"
echo
echo "Inside Debian 13, install standard cluster & app packages:"
echo "  apt update && apt install -y openssh-server python3 python3-venv git tmux htop clang cmake distcc openmpi-bin"
echo "  # PhoneCluster auto-detects Debian 13 and reads /sys/class/power_supply/* directly!"
echo "  # Remember to configure SSH on port 22 or 8022 and apply ACC battery limits on Android:"
echo "  #   acc -s pc=60 rc=55 mcv=3900 mcc=500"
