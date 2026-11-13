#!/usr/bin/env bash
# Read-only inventory for the CentOS 10 competition database host.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${1:-/var/tmp/chomper-inventory-${STAMP}.txt}"
umask 077

{
  echo "=== CHOMPER HOST INVENTORY ==="
  date --iso-8601=seconds
  echo
  echo "=== OS ==="
  cat /etc/os-release 2>/dev/null || true
  echo
  echo "=== HOST / NETWORK ==="
  hostnamectl 2>/dev/null || hostname
  ip -brief address 2>/dev/null || true
  ip route 2>/dev/null || true
  echo
  echo "=== LISTENING SOCKETS ==="
  ss -tulpn 2>&1 || true
  echo
  echo "=== RUNNING SERVICES ==="
  systemctl --type=service --state=running --no-pager 2>&1 || true
  echo
  echo "=== DATABASE-RELATED PACKAGES ==="
  rpm -qa 2>/dev/null | grep -Ei 'mariadb|mysql|postgres|mongodb|redis' || true
  echo
  echo "=== DATABASE-RELATED UNIT FILES ==="
  systemctl list-unit-files --type=service --no-pager 2>/dev/null |
    grep -Ei 'mariadb|mysql|postgres|mongo|redis' || true
  echo
  echo "=== FIREWALL ==="
  firewall-cmd --state 2>&1 || true
  firewall-cmd --get-active-zones 2>&1 || true
  firewall-cmd --list-all-zones 2>&1 || true
  echo
  echo "=== SELINUX ==="
  getenforce 2>&1 || true
  sestatus 2>&1 || true
  echo
  echo "=== LOCAL ACCOUNTS (name:uid:gid:home:shell) ==="
  awk -F: '{print $1 ":" $3 ":" $4 ":" $6 ":" $7}' /etc/passwd
  echo
  echo "=== PRIVILEGED GROUPS ==="
  getent group wheel 2>&1 || true
  getent group sudo 2>&1 || true
  echo
  echo "=== ENABLED TIMERS ==="
  systemctl list-timers --all --no-pager 2>&1 || true
  echo
  echo "=== CRON LOCATIONS (names and metadata only) ==="
  find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly \
    -maxdepth 1 -type f -printf '%p | %u:%g | %m\n' 2>/dev/null || true
  echo
  echo "=== END ==="
} | tee "$OUT"

chmod 600 "$OUT"
echo
echo "Inventory saved to: $OUT"
echo "Review before making changes. This script does not modify host configuration."
