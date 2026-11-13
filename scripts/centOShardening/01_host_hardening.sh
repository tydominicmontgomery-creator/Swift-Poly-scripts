#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
STATE=/var/lib/chomper-hardening; LOGDIR=/var/log/chomper-hardening
install -d -m 0700 "$STATE" "$LOGDIR"
STAMP=$(date +%Y%m%d-%H%M%S); REPORT="$LOGDIR/host-$STAMP.log"
exec > >(tee -a "$REPORT") 2>&1
BACKUP=$(cat /root/chomper-hardening/LAST_BACKUP 2>/dev/null || true)
[[ -d "$BACKUP" ]] || { echo "[ERROR] Run 00_backup.sh first."; exit 1; }
AUTH=(root user spikeweed)
allowed(){ local x; for x in "${AUTH[@]}"; do [[ "$1" == "$x" ]] && return 0; done; return 1; }
ask(){ local a; read -r -p "$1 [y/N]: " a; [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]; }
echo "=== CHOMPER HOST HARDENING $(date -Is) ==="
echo "Report: $REPORT | Backup: $BACKUP"
cat /etc/os-release; hostnamectl 2>/dev/null || hostname; ip -brief address
echo "[CHECK] sudoers syntax"; visudo -c || echo "[FAIL] sudoers syntax check failed; investigate."
echo "[CHECK] UID 0 accounts"; awk -F: '$3==0{print $1}' /etc/passwd
echo "[CHECK] wheel: $(getent group wheel || true)"
echo "[CHECK] sudo: $(getent group sudo || true)"
echo "[AUDIT] Login-capable local accounts not in authorized list:"
while IFS=: read -r n _ uid _ _ home shell; do
 [[ "$uid" =~ ^[0-9]+$ ]] || continue; ((uid>=1000 && uid<60000)) || continue
 [[ "$shell" =~ (nologin|false)$ ]] && continue; allowed "$n" && continue
 echo "[FINDING][REVIEW] $n uid=$uid home=$home shell=$shell"
 echo "Check service ownership, cron, SSH keys and application dependencies before disabling."
 if ask "Lock password and set shell to /sbin/nologin for $n?"; then
   usermod -L "$n"; usermod -s /sbin/nologin "$n"; echo "[FIXED] $n locked; data/home retained."
 else echo "[SKIPPED] $n unchanged."; fi
done < /etc/passwd
echo "[AUDIT] Unlisted wheel members:"
members=$(getent group wheel | awk -F: '{print $4}' | tr ',' '\n' || true)
while IFS= read -r n; do
 [[ -n "$n" ]] || continue; allowed "$n" && continue
 echo "[FINDING][REVIEW] wheel member $n"
 if ask "Remove $n from wheel?"; then gpasswd -d "$n" wheel; echo "[FIXED] removed $n"; fi
done <<< "$members"
echo "[CHECK] SSH daemon"
if command -v sshd >/dev/null; then
 unit=""; for u in sshd.service ssh.service; do systemctl is-active --quiet "$u" && unit="$u" && break; done
 if [[ -n "$unit" ]]; then
  drop=/etc/ssh/sshd_config.d/00-chomper-baseline.conf
  install -d -m 0755 /etc/ssh/sshd_config.d
  if [[ ! -e "$drop" ]]; then
   cat > "$drop" <<'EOF'
# Chomper baseline
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
EOF
   chmod 0644 "$drop"
   if sshd -t; then systemctl reload "$unit"; echo "[FIXED] SSH baseline installed and validated."
   else rm -f "$drop"; echo "[FAIL] sshd -t failed; removed new drop-in."; fi
  else echo "[INFO] Existing drop-in preserved; validating."; sshd -t && echo "[PASS] sshd config valid" || true; fi
 else echo "[INFO] No active SSH unit."; fi
else echo "[INFO] sshd not installed."; fi
echo "[INFO] Root SSH, password auth, port, and allow-users policy unchanged."
fixmode(){ [[ -e "$1" ]] || return; cur=$(stat -c %a "$1"); if [[ "$cur" != "$2" ]]; then
 echo "[FINDING] $1 mode=$cur expected=$2"; if ask "Set mode $2 on $1?"; then chmod "$2" "$1"; echo "[FIXED] $1"; fi
 else echo "[PASS] $1 mode=$2"; fi; }
fixmode /etc/passwd 644; fixmode /etc/group 644; fixmode /etc/shadow 000; fixmode /etc/gshadow 000
chown root:root /etc/shadow /etc/gshadow 2>/dev/null || true
echo "[CHECK] SELinux: $(getenforce 2>/dev/null || echo unavailable)"
echo "[INFO] SELinux mode is not changed automatically; inspect AVCs and labels before remediation."
echo "[CHECK] Updates (preview only)"
if command -v dnf >/dev/null; then dnf check-update || rc=$?; rc=${rc:-0}; [[ $rc == 100 ]] && echo "[FINDING] Updates available; review dnf upgrade --assumeno."; dnf upgrade --assumeno || true; fi
echo "[CHECK] Running services"; systemctl --type=service --state=running --no-pager
echo "[CHECK] Listeners"; ss -tulpn
echo "[CHECK] Timers"; systemctl list-timers --all --no-pager
echo "[DONE] Host pass complete. Report: $REPORT"
