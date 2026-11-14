#!/usr/bin/env bash
# Defensive Socat bind-shell hunt for the authorized Chomper host.
# Detection is read-only; process/service remediation requires confirmation.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0"; exit 1; }

LOGDIR=/var/log/chomper-hardening
STATE=/var/lib/chomper-hardening
install -d -o root -g root -m 0700 "$LOGDIR" "$STATE"
STAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$LOGDIR/socat-hunt-$STAMP.log"
EVIDENCE="$STATE/socat-evidence-$STAMP"
install -d -o root -g root -m 0700 "$EVIDENCE"
exec > >(tee -a "$REPORT") 2>&1

ask() { local a; read -r -p "$1 [y/N]: " a; [[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]; }
section() { printf '\n===== %s =====\n' "$1"; }

echo "[INFO] Socat hunt: $(date -Is)"
echo "[INFO] Host: $(hostname -f 2>/dev/null || hostname)"
echo "[INFO] Report: $REPORT"
echo "[INFO] Evidence: $EVIDENCE"
echo "[SCOPE] This script examines this host only."

section "1. Socat processes"
mapfile -t PIDS < <(pgrep -x socat 2>/dev/null || true)
if ((${#PIDS[@]} == 0)); then
  echo "[PASS] No process named socat is running."
else
  printf '%s\n' "${PIDS[@]}" > "$EVIDENCE/pids.txt"
  for pid in "${PIDS[@]}"; do
    [[ -r "/proc/$pid/cmdline" ]] || continue
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
    owner=$(getent passwd "$uid" | cut -d: -f1 || true)
    printf 'PID=%s USER=%s UID=%s EXE=%s\nCMD=%s\n' "$pid" "${owner:-unknown}" "$uid" "$exe" "$cmd" \
      | tee "$EVIDENCE/process-$pid.txt"
    cat "/proc/$pid/cgroup" >> "$EVIDENCE/process-$pid.txt" 2>/dev/null || true
    if [[ "$cmd" =~ (EXEC|SYSTEM):.*(/bin/)?(ba)?sh ]]; then
      echo "[HIGH] Socat process command line appears to launch a shell (PID $pid)."
    else
      echo "[REVIEW] Socat process found; confirm whether it is authorized."
    fi
  done
fi

section "2. TCP listeners"
ss -ltnp > "$EVIDENCE/listeners.txt" 2>&1 || true
cat "$EVIDENCE/listeners.txt"
if grep -qi socat "$EVIDENCE/listeners.txt"; then
  echo "[HIGH] A TCP listener is associated with Socat."
else
  echo "[INFO] No Socat-associated listener was identified by ss."
fi
echo "[REVIEW] Check wildcard binds (0.0.0.0 or [::]) and match listener PIDs to process records."

section "3. Systemd persistence"
: > "$EVIDENCE/systemd-matches.txt"
for root in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system; do
  [[ -d "$root" ]] || continue
  while IFS= read -r -d '' file; do
    if grep -IqE '(^|[/[:space:]])socat([[:space:]]|$)' "$file"; then
      echo "$file" | tee -a "$EVIDENCE/systemd-matches.txt"
      grep -nEi 'socat|ExecStart|User=' "$file" || true
    fi
  done < <(find "$root" -type f \( -name '*.service' -o -name '*.socket' -o -name '*.timer' \) -print0 2>/dev/null)
done
[[ -s "$EVIDENCE/systemd-matches.txt" ]] || echo "[PASS] No Socat command found in standard systemd unit files."

section "4. Cron and startup persistence"
: > "$EVIDENCE/persistence-matches.txt"
for target in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/rc.local /etc/profile /etc/bashrc /etc/profile.d; do
  [[ -e "$target" ]] || continue
  grep -RInI -E 'socat|TCP-LISTEN|EXEC:/(bin/)?(ba)?sh' "$target" 2>/dev/null \
    | tee -a "$EVIDENCE/persistence-matches.txt" || true
done
[[ -s "$EVIDENCE/persistence-matches.txt" ]] || echo "[PASS] No matching strings found in scanned cron/startup locations."
echo "[NOTE] Matches require review; they are not proof of maliciousness."

section "5. Process-to-service mapping"
for pid in "${PIDS[@]}"; do
  [[ -d "/proc/$pid" ]] || continue
  echo "--- PID $pid cgroup ---"
  cat "/proc/$pid/cgroup" 2>/dev/null || true
  systemctl status "$pid" --no-pager 2>&1 | head -n 16 || true
done

section "6. Interactive remediation"
if ((${#PIDS[@]})); then
  for pid in "${PIDS[@]}"; do
    [[ -d "/proc/$pid" ]] || continue
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    echo "[FINDING] PID $pid: $cmd"
    if ask "Send SIGTERM to Socat PID $pid?"; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 2
      if kill -0 "$pid" 2>/dev/null; then
        echo "[WARN] PID $pid is still running."
        if ask "Escalate to SIGKILL?"; then kill -KILL "$pid" 2>/dev/null || true; fi
      fi
      if kill -0 "$pid" 2>/dev/null; then echo "[FAIL] PID $pid remains."; else echo "[FIXED] PID $pid stopped."; fi
    else
      echo "[SKIPPED] PID $pid left running."
    fi
  done
else
  echo "[INFO] No Socat process to stop."
fi

if [[ -s "$EVIDENCE/systemd-matches.txt" ]]; then
  while IFS= read -r file; do
    [[ -f "$file" ]] || continue
    unit=$(basename "$file")
    echo "[FINDING] Unit references Socat: $file"
    systemctl is-enabled "$unit" 2>/dev/null || true
    systemctl is-active "$unit" 2>/dev/null || true
    if ask "Disable and stop $unit?"; then
      cp -a "$file" "$EVIDENCE/$unit.backup"
      systemctl disable --now "$unit" || echo "[WARN] Could not fully disable/stop $unit."
      echo "[INFO] Unit file retained for forensic review."
    fi
  done < "$EVIDENCE/systemd-matches.txt"
fi

if [[ -s "$EVIDENCE/persistence-matches.txt" ]]; then
  echo "[REVIEW REQUIRED] Cron/startup matches were not edited automatically."
  echo "Inspect $EVIDENCE/persistence-matches.txt and remove only confirmed malicious entries."
fi

section "7. Verification"
pgrep -a -x socat || echo "[PASS] No Socat process currently running."
ss -ltnp | grep -i socat || echo "[PASS] No Socat-associated listener currently shown."
echo "[DONE] Hunt complete."
echo "[REPORT] $REPORT"
echo "[EVIDENCE] $EVIDENCE"
echo "[NOTE] This script does not scan, connect to, or modify other teams."
