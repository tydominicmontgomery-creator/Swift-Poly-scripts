#!/usr/bin/env bash
# Applies a conservative SSH server hardening drop-in.
# Preserves authentication mode, root-login policy, port, users, and forwarding settings.
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo/root: sudo $0" >&2
  exit 1
fi

SSHD="$(command -v sshd || true)"
[[ -n "$SSHD" ]] || { echo "sshd executable not found. Is OpenSSH server installed?" >&2; exit 1; }

if [[ -f /etc/ssh/sshd_config ]]; then
  MAIN_CONFIG="/etc/ssh/sshd_config"
else
  echo "/etc/ssh/sshd_config not found." >&2
  exit 1
fi

DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN="$DROPIN_DIR/00-chomper-hardening.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/chomper-ssh-backups/$STAMP"
install -d -m 0700 "$BACKUP_DIR"

echo "=== Current effective SSH settings ==="
"$SSHD" -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|logingracetime|x11forwarding|allowtcpforwarding|allowagentforwarding) ' || true
echo
echo "=== Proposed conservative settings ==="
cat <<'SETTINGS'
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
SETTINGS
echo
echo "This script intentionally does NOT change:"
echo "- PasswordAuthentication or KbdInteractiveAuthentication"
echo "- PermitRootLogin"
echo "- SSH port, AllowUsers/AllowGroups, authorized keys"
echo "- TCP/agent forwarding"
echo
echo "These are left unchanged to avoid breaking required access or competition workflows."

read -r -p "Create a backup, install the drop-in, validate sshd, and reload SSH? Type APPLY: " CONFIRM
[[ "$CONFIRM" == "APPLY" ]] || { echo "Cancelled."; exit 0; }

cp -a "$MAIN_CONFIG" "$BACKUP_DIR/sshd_config"
if [[ -d "$DROPIN_DIR" ]]; then
  cp -a "$DROPIN_DIR" "$BACKUP_DIR/sshd_config.d"
fi
if [[ -e "$DROPIN" ]]; then
  cp -a "$DROPIN" "$BACKUP_DIR/00-chomper-hardening.conf.previous"
fi

install -d -m 0755 "$DROPIN_DIR"
TMP="$(mktemp "$DROPIN_DIR/.00-chomper-hardening.XXXXXX")"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

cat > "$TMP" <<'SETTINGS'
# Managed by chomper-centos-hardening/scripts/07_ssh_hardening.sh
# Conservative settings; authentication and access policy remain unchanged.
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
SETTINGS
chmod 0644 "$TMP"
chown root:root "$TMP"
mv -f "$TMP" "$DROPIN"
trap - EXIT

if ! "$SSHD" -t; then
  echo "sshd configuration validation failed. Restoring previous drop-in state." >&2
  if [[ -f "$BACKUP_DIR/00-chomper-hardening.conf.previous" ]]; then
    cp -a "$BACKUP_DIR/00-chomper-hardening.conf.previous" "$DROPIN"
  else
    rm -f "$DROPIN"
  fi
  exit 1
fi

# Identify the active unit without assuming the distro unit name.
UNIT=""
for candidate in sshd.service ssh.service; do
  if systemctl is-active --quiet "$candidate"; then
    UNIT="$candidate"
    break
  fi
done

if [[ -z "$UNIT" ]]; then
  echo "No active SSH server unit (sshd.service/ssh.service) found." >&2
  echo "Configuration validated, but service was not reloaded. Inspect manually." >&2
  exit 1
fi

if ! systemctl reload "$UNIT"; then
  echo "SSH reload failed. Review: $BACKUP_DIR" >&2
  echo "Do not close existing administrative sessions." >&2
  exit 1
fi

echo
echo "SSH configuration validated and $UNIT reloaded."
echo "Backup location: $BACKUP_DIR"
echo
echo "Verify by opening a NEW SSH session before closing this one:"
echo "  ssh -p <verified-port> <authorized-user>@<chomper-address>"
echo "Then check effective settings with: sshd -T"
echo "If access fails, retain the console session and restore the backed-up configuration."
