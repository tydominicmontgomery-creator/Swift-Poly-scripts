#!/usr/bin/env bash
# Interactive firewalld tightening for Chomper. Prompts for unknown client networks.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo/root."; exit 1; }
command -v firewall-cmd >/dev/null || { echo "firewalld is not installed."; exit 1; }
firewall-cmd --state >/dev/null || { echo "firewalld is not running. No automatic enable/restart."; exit 1; }

read -r -p "Enter the ACTIVE firewalld zone shown by firewall-cmd --get-active-zones: " ZONE
ACTIVE="$(firewall-cmd --get-active-zones)"
grep -Fxq "$ZONE" <<< "$ACTIVE" || { echo "That zone is not active. Active zones:"; echo "$ACTIVE"; exit 1; }

echo "Team 15 Chomper address expected from packet: 172.16.15.53"
ip -brief address
echo "This address is NOT the scoring-client source network."
read -r -p "SSH administrator source CIDR (e.g. team management subnet): " SSH_CIDR
read -r -p "Database scoring-client source CIDR (ask Green Team if unknown): " DB_CIDR
valid_cidr() { python3 - "$1" <<'PY'
import ipaddress,sys
try: ipaddress.ip_network(sys.argv[1], strict=False); sys.exit(0)
except ValueError: sys.exit(1)
PY
}
valid_cidr "$SSH_CIDR" || { echo "Invalid SSH CIDR."; exit 2; }
valid_cidr "$DB_CIDR" || { echo "Invalid DB CIDR."; exit 2; }

echo "Detecting DB listener candidates from process ownership:"
mapfile -t CANDIDATES < <(ss -H -ltnp 2>/dev/null | awk '
  /(mysqld|mariadbd|postgres|mongod|redis-server|cockroach|influxd|couchdb|sqlservr)/ {
    endpoint=$4; sub(/^.*:/,"",endpoint); if (endpoint ~ /^[0-9]+$/) print endpoint
  }' | sort -nu)
if ((${#CANDIDATES[@]}==1)); then
  DB_PORT="${CANDIDATES[0]}"
  echo "Candidate database port: $DB_PORT"
  read -r -p "Type the port to confirm this is the SCORED database listener: " CONFIRM_PORT
  [[ "$CONFIRM_PORT" == "$DB_PORT" ]] || { echo "Cancelled; rerun with verified listener details."; exit 1; }
elif ((${#CANDIDATES[@]}>1)); then
  printf 'Candidate ports: %s\n' "${CANDIDATES[*]}"
  read -r -p "Enter the verified scored database TCP port: " DB_PORT
else
  echo "Automatic DB listener detection failed."
  read -r -p "Enter the verified scored database TCP port: " DB_PORT
fi
[[ "$DB_PORT" =~ ^[0-9]+$ ]] && ((10#$DB_PORT>=1 && 10#$DB_PORT<=65535)) || { echo "Invalid DB port."; exit 2; }
read -r -p "SSH port [22]: " SSH_PORT
SSH_PORT="${SSH_PORT:-22}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && ((10#$SSH_PORT>=1 && 10#$SSH_PORT<=65535)) || { echo "Invalid SSH port."; exit 2; }

SSH_RULE="rule family=\"ipv4\" source address=\"$SSH_CIDR\" port port=\"$SSH_PORT\" protocol=\"tcp\" accept"
DB_RULE="rule family=\"ipv4\" source address=\"$DB_CIDR\" port port=\"$DB_PORT\" protocol=\"tcp\" accept"

echo
echo "Current runtime zone:"
firewall-cmd --zone="$ZONE" --list-all
echo "Current permanent zone:"
firewall-cmd --permanent --zone="$ZONE" --list-all
echo "Rules to add:"
printf '%s\n%s\n' "$SSH_RULE" "$DB_RULE"
echo "This script will NOT remove broad rules automatically."
read -r -p "Type APPLY to add both rules at runtime and permanently: " APPLY
[[ "$APPLY" == "APPLY" ]] || { echo "No firewall changes made."; exit 0; }

added_runtime=(); added_permanent=()
rollback() {
  for r in "${added_runtime[@]}"; do firewall-cmd --zone="$ZONE" --remove-rich-rule="$r" || true; done
  for r in "${added_permanent[@]}"; do firewall-cmd --permanent --zone="$ZONE" --remove-rich-rule="$r" || true; done
}
for RULE in "$SSH_RULE" "$DB_RULE"; do
  if ! firewall-cmd --zone="$ZONE" --query-rich-rule="$RULE" >/dev/null; then
    firewall-cmd --zone="$ZONE" --add-rich-rule="$RULE"
    added_runtime+=("$RULE")
  fi
  if ! firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$RULE" >/dev/null; then
    if firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$RULE"; then
      added_permanent+=("$RULE")
    else
      echo "Permanent add failed; rolling back rules added by this run."
      rollback; exit 1
    fi
  fi
done
echo "Added/reconciled narrow rules. Test NEW SSH and remote DB connections, then scoring."
echo "If all clients are confirmed, inspect existing broad service/port allowances manually."
echo "IPv6 was not changed; inspect it separately if the host has active IPv6 listeners."
