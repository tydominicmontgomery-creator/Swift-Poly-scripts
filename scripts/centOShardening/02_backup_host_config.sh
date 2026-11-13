#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root."; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
DEST="/root/chomper-recovery-$STAMP"
install -d -m 0700 "$DEST"
for p in /etc/ssh /etc/firewalld /etc/selinux /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/login.defs /etc/security; do
  [[ -e "$p" ]] || continue
  mkdir -p "$DEST$(dirname "$p")"
  cp -a "$p" "$DEST$p"
done
echo "Host config backup: $DEST"
echo "This does not back up database contents. Use a vendor-supported logical/physical DB backup."
