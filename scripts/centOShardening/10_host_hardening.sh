#!/usr/bin/env bash
# Interactive host hardening for Chomper (CentOS Stream 10 expected).
# Makes changes only after presenting the plan and obtaining explicit confirmation.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }

AUTHORIZED=(root user spikeweed)
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/chomper-hardening-$STAMP"
install -d -m 0700 "$BACKUP"
exec > >(tee -a "$BACKUP/host-hardening.log") 2>&1

confirm() {
  local prompt="$1" answer
  read -r -p "$prompt [y/N]: " answer
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}
is_authorized() {
  local u="$1" a
  for a in "${AUTHORIZED[@]}"; do [[ "$u" == "$a" ]] && return 0; done
  return 1
}

echo "=== CHOMPER HOST HARDENING ==="
cat /etc/os-release
if ! grep -qE 'CentOS Stream 10|CentOS Linux 10|VERSION_ID="?10' /etc/os-release; then
  echo "WARNING: this host does not clearly identify as CentOS 10. Review before proceeding."
  confirm "Continue anyway?" || exit 1
fi
echo "Expected Team 15 host IP (verify, do not assume): 172.16.15.53"
ip -brief address
echo "Authorized human Linux accounts from the briefing: root, user, spikeweed."
echo "A restricted backup/log directory was created: $BACKUP"

# Preserve relevant configs before modifications.
for f in /etc/ssh/sshd_config /etc/sudoers /etc/login.defs /etc/security/pwquality.conf; do
  [[ -f "$f" ]] && cp -a "$f" "$BACKUP/"
done
[[ -d /etc/ssh/sshd_config.d ]] && cp -a /etc/ssh/sshd_config.d "$BACKUP/"
[[ -d /etc/sudoers.d ]] && cp -a /etc/sudoers.d "$BACKUP/"

echo
echo "=== 1. Validate privilege configuration ==="
if command -v visudo >/dev/null; then
  visudo -c || { echo "sudoers validation failed; stopping before edits."; exit 1; }
fi
echo "UID-0 accounts:"
awk -F: '$3==0 {print $1}' /etc/passwd
echo "wheel group:"
getent group wheel || true
echo "sudo group:"
getent group sudo || true

echo
echo "=== 2. Review and optionally disable unapproved human login accounts ==="
while IFS=: read -r name _ uid _ _ home shell; do
  [[ "$uid" =~ ^[0-9]+$ ]] || continue
  (( uid >= 1000 && uid < 60000 )) || continue
  is_authorized "$name" && continue
  [[ "$shell" =~ (nologin|false)$ ]] && continue
  echo "Unlisted login-capable account: $name (UID=$uid home=$home shell=$shell)"
  echo "This is NOT proof of compromise. Check ownership, services, cron, SSH keys, and tasks first."
  if confirm "Lock password and disable interactive shell for $name?"; then
    usermod -L "$name"
    usermod -s /sbin/nologin "$name"
    echo "Disabled interactive login for $name. Home/data were not deleted."
  fi
done < /etc/passwd

echo
echo "=== 3. Review unapproved wheel members ==="
wheel_members="$(getent group wheel | awk -F: '{print $4}' | tr ',' '\n' || true)"
while IFS= read -r member; do
  [[ -n "$member" ]] || continue
  is_authorized "$member" && continue
  echo "Unlisted wheel member: $member"
  if confirm "Remove $member from wheel?"; then
    gpasswd -d "$member" wheel || true
  fi
done <<< "$wheel_members"

echo
echo "=== 4. Apply conservative SSH daemon settings ==="
if command -v sshd >/dev/null && systemctl is-active --quiet sshd.service; then
  DROPIN_DIR=/etc/ssh/sshd_config.d
  DROPIN="$DROPIN_DIR/00-chomper-baseline.conf"
  install -d -m 0755 "$DROPIN_DIR"
  [[ -e "$DROPIN" ]] && cp -a "$DROPIN" "$BACKUP/00-chomper-baseline.conf.previous"
  cat > "$BACKUP/00-chomper-baseline.conf.new" <<'EOF'
# Chomper baseline: safe protocol hygiene; access method and root policy unchanged.
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
EOF
  echo "Proposed drop-in:"
  cat "$BACKUP/00-chomper-baseline.conf.new"
  echo "Root SSH login and password/key authentication are intentionally not changed."
  if confirm "Install this SSH drop-in and reload sshd? Keep a second session/console open."; then
    install -m 0644 -o root -g root "$BACKUP/00-chomper-baseline.conf.new" "$DROPIN"
    if sshd -t; then
      systemctl reload sshd.service
      echo "sshd config validated and reloaded. Test a NEW SSH login before closing this session."
    else
      echo "sshd -t failed; restoring previous drop-in."
      if [[ -e "$BACKUP/00-chomper-baseline.conf.previous" ]]; then
        cp -a "$BACKUP/00-chomper-baseline.conf.previous" "$DROPIN"
      else
        rm -f "$DROPIN"
      fi
      exit 1
    fi
  fi
else
  echo "Active sshd.service not found; SSH step skipped. Inspect service name manually."
fi

echo
echo "=== 5. File permission checks / repairs ==="
for spec in "/etc/passwd:0644" "/etc/group:0644" "/etc/shadow:0000" "/etc/gshadow:0000"; do
  file="${spec%%:*}"; mode="${spec##*:}"
  [[ -e "$file" ]] || continue
  current="$(stat -c %a "$file")"
  echo "$file current mode=$current target=$mode"
  if [[ "$current" != "$mode" ]] && confirm "Set $file mode to $mode?"; then
    chmod "$mode" "$file"
  fi
done
[[ -e /etc/shadow ]] && chown root:root /etc/shadow
[[ -e /etc/gshadow ]] && chown root:root /etc/gshadow

echo
echo "=== 6. SELinux status ==="
getenforce || true
if command -v sestatus >/dev/null; then sestatus | head -n 12; fi
echo "This script does not disable SELinux or change policy automatically."

echo
echo "=== 7. Service and persistence review ==="
systemctl --type=service --state=running --no-pager
systemctl list-timers --all --no-pager
echo "No unknown service, timer, cron job, package, or file is automatically removed."
echo
echo "Host hardening pass complete. Backups/log: $BACKUP"
echo "Validate authorized SSH access, sudo, and the scoring service."
