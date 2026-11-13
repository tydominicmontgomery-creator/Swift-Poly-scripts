#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
ROOT=/root/chomper-hardening/backups
DEST="$ROOT/$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$DEST"
exec > >(tee -a "$DEST/backup.log") 2>&1
{
 date -Is; cat /etc/os-release; ip -brief address; ip route; ss -tulpn
 systemctl --type=service --state=running --no-pager
 firewall-cmd --get-active-zones 2>&1 || true; getenforce 2>&1 || true
} > "$DEST/baseline.txt"
for p in /etc/ssh /etc/firewalld /etc/selinux /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/login.defs /etc/security /etc/sysctl.conf /etc/sysctl.d /etc/NetworkManager/system-connections; do
 [[ -e "$p" ]] || continue
 mkdir -p "$DEST$(dirname "$p")"; cp -a "$p" "$DEST$p"; echo "[OK] saved $p"
done
chmod -R go-rwx "$DEST"
install -d -m 0700 /root/chomper-hardening
printf '%s\n' "$DEST" > /root/chomper-hardening/LAST_BACKUP
chmod 0600 /root/chomper-hardening/LAST_BACKUP
echo "[DONE] Backup: $DEST"
echo "[NOTE] Host config only; not a database data backup. Never commit backups to GitHub."
