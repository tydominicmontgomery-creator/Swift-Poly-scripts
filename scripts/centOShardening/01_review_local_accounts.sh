#!/usr/bin/env bash
# Reports local human-style accounts and privileged groups; makes no account changes.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

AUTHORIZED=("root" "user" "spikeweed")
OUT="${1:-/var/tmp/chomper-account-review-$(date +%Y%m%d-%H%M%S).txt}"
umask 077

{
  echo "=== AUTHORIZED LINUX ACCOUNTS FROM THE COMPETITION BRIEF ==="
  printf '%s\n' "${AUTHORIZED[@]}"
  echo
  echo "=== LOCAL ACCOUNTS WITH UID >= 1000, PLUS ROOT ==="
  awk -F: '($3 >= 1000 && $3 < 60000) || $1 == "root" {
    printf "user=%s uid=%s gid=%s home=%s shell=%s\n",$1,$3,$4,$6,$7
  }' /etc/passwd
  echo
  echo "=== WHEEL GROUP ==="
  getent group wheel || true
  echo
  echo "=== SUDO GROUP (IF PRESENT) ==="
  getent group sudo || true
  echo
  echo "=== SUDOERS FILE METADATA ==="
  stat -c '%A %U:%G %n' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
  find /etc/sudoers.d -maxdepth 1 -type f -printf '%M %u:%g %p\n' 2>/dev/null || true
  echo
  echo "=== REVIEW NOTES ==="
  echo "Do not delete accounts solely because they are absent from the competition user list."
  echo "Investigate service identities (for example mysql or postgres), ownership, processes,"
  echo "scheduled jobs, SSH keys, and application dependencies before changing an account."
} | tee "$OUT"

chmod 600 "$OUT"
echo
echo "Review saved to: $OUT"
echo "No accounts, groups, passwords, or sudo rules were changed."
