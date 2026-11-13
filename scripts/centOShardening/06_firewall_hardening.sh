#!/usr/bin/env bash
# Adds explicit source-restricted firewalld rules for SSH and the scored database.
# Database listener detection is advisory and always requires human confirmation.
# Dry-run by default. Does not remove existing rules or change zone defaults.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  sudo ./06_firewall_hardening.sh \
    --zone ACTIVE_ZONE \
    --ssh-source ADMIN_CIDR --ssh-port SSH_PORT \
    --db-source DB_CLIENT_CIDR [--db-port DB_PORT] [--apply]

If --db-port is omitted, the script searches listening TCP sockets owned by
recognizable database processes, displays the candidate port(s), and asks you
to select/confirm one. Detection is advisory: verify it is the scored database.

Example (PLACEHOLDERS ONLY; verify all values first):
  sudo ./06_firewall_hardening.sh \
    --zone public \
    --ssh-source 172.16.15.0/24 --ssh-port 22 \
    --db-source 172.16.15.0/24

Manual database-port override:
  ... --db-source 172.16.15.0/24 --db-port 3306

Add --apply to request changes. The script will ask you to type APPLY.

This script ADDS narrow IPv4 TCP allow rules only. It does not:
- remove existing broad service/port allowances;
- set a default-deny target or change the active zone;
- alter IPv6 rules;
- change database bind/listen settings;
- enable or restart firewalld;
- prove that the supplied CIDRs include every legitimate client.
USAGE
}

ZONE=""
SSH_SOURCE=""
SSH_PORT=""
DB_SOURCE=""
DB_PORT=""
APPLY=0

while (($#)); do
  case "$1" in
    --zone) ZONE="${2:?Missing zone}"; shift 2 ;;
    --ssh-source) SSH_SOURCE="${2:?Missing SSH source CIDR}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:?Missing SSH port}"; shift 2 ;;
    --db-source) DB_SOURCE="${2:?Missing database source CIDR}"; shift 2 ;;
    --db-port) DB_PORT="${2:?Missing database port}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run with sudo/root." >&2; exit 1; }
for value in "$ZONE" "$SSH_SOURCE" "$SSH_PORT" "$DB_SOURCE"; do
  [[ -n "$value" ]] || { usage >&2; exit 2; }
done

valid_cidr() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]
}
valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}
valid_cidr "$SSH_SOURCE" || { echo "Invalid SSH IPv4 CIDR." >&2; exit 2; }
valid_cidr "$DB_SOURCE" || { echo "Invalid database IPv4 CIDR." >&2; exit 2; }
valid_port "$SSH_PORT" || { echo "Invalid SSH port." >&2; exit 2; }

if [[ -z "$DB_PORT" ]]; then
  command -v ss >/dev/null || { echo "'ss' is required for port discovery; provide --db-port manually." >&2; exit 1; }
  echo "Searching listening TCP sockets for recognizable database processes..."
  mapfile -t DB_CANDIDATES < <(
    ss -H -ltnp 2>/dev/null |
      awk 'BEGIN { IGNORECASE=1 }
        /(mysqld|mariadbd|postgres|mongod|redis-server|cockroach|influxd|couchdb|sqlservr)/ {
          endpoint=$4
          sub(/^.*:/, "", endpoint)
          if (endpoint ~ /^[0-9]+$/) print endpoint
        }' |
      sort -nu
  )

  if ((${#DB_CANDIDATES[@]} == 0)); then
    echo "No database listener could be identified automatically." >&2
    echo "Run scripts/04_database_service_check.sh and identify the scored DB port." >&2
    echo "Then rerun this script with --db-port DB_PORT." >&2
    exit 1
  elif ((${#DB_CANDIDATES[@]} == 1)); then
    DB_PORT="${DB_CANDIDATES[0]}"
    echo "Detected candidate database TCP port: $DB_PORT"
    read -r -p "Confirm this is the scored database port. Type $DB_PORT to continue: " CONFIRM_PORT
    [[ "$CONFIRM_PORT" == "$DB_PORT" ]] || { echo "Cancelled. Supply the verified port with --db-port."; exit 1; }
  else
    echo "Multiple candidate database TCP ports were detected:"
    for i in "${!DB_CANDIDATES[@]}"; do
      printf '  %d) %s\n' "$((i + 1))" "${DB_CANDIDATES[$i]}"
    done
    read -r -p "Enter the number for the scored database listener: " CHOICE
    [[ "$CHOICE" =~ ^[0-9]+$ ]] || { echo "Invalid selection." >&2; exit 2; }
    ((CHOICE >= 1 && CHOICE <= ${#DB_CANDIDATES[@]})) || { echo "Selection out of range." >&2; exit 2; }
    DB_PORT="${DB_CANDIDATES[$((CHOICE - 1))]}"
    read -r -p "Confirm scored database port $DB_PORT. Type $DB_PORT to continue: " CONFIRM_PORT
    [[ "$CONFIRM_PORT" == "$DB_PORT" ]] || { echo "Cancelled."; exit 1; }
  fi
fi

valid_port "$DB_PORT" || { echo "Invalid database port." >&2; exit 2; }

command -v firewall-cmd >/dev/null || { echo "firewall-cmd not found." >&2; exit 1; }
firewall-cmd --state >/dev/null || { echo "firewalld is not running; no changes made." >&2; exit 1; }

ACTIVE_ZONES="$(firewall-cmd --get-active-zones)"
grep -Fxq "$ZONE" <<<"$ACTIVE_ZONES" || {
  echo "Zone '$ZONE' is not active. Active zones:" >&2
  printf '%s\n' "$ACTIVE_ZONES" >&2
  exit 1
}

SSH_RULE="rule family=\"ipv4\" source address=\"$SSH_SOURCE\" port port=\"$SSH_PORT\" protocol=\"tcp\" accept"
DB_RULE="rule family=\"ipv4\" source address=\"$DB_SOURCE\" port port=\"$DB_PORT\" protocol=\"tcp\" accept"

echo
echo "Selected active zone: $ZONE"
echo "SSH source / port: $SSH_SOURCE / $SSH_PORT"
echo "Database source / port: $DB_SOURCE / $DB_PORT"
echo "Proposed SSH rule: $SSH_RULE"
echo "Proposed DB rule:  $DB_RULE"
echo
echo "Current zone configuration:"
firewall-cmd --zone="$ZONE" --list-all
echo
echo "Dry-run mode: no changes have been made."

if ((APPLY == 0)); then
  echo "Review the source networks and ports. Re-run with --apply when verified."
  exit 0
fi

echo
echo "WARNING: Incorrect source CIDRs can interrupt administration or scoring."
read -r -p "Confirm console/second-session access and verified client networks. Type APPLY: " CONFIRM
[[ "$CONFIRM" == "APPLY" ]] || { echo "Cancelled."; exit 0; }

added_runtime=()
added_permanent=()
rollback_runtime() {
  local rule
  for rule in "${added_runtime[@]}"; do
    firewall-cmd --zone="$ZONE" --remove-rich-rule="$rule" || true
  done
}
rollback_permanent() {
  local rule
  for rule in "${added_permanent[@]}"; do
    firewall-cmd --permanent --zone="$ZONE" --remove-rich-rule="$rule" || true
  done
}

for rule in "$SSH_RULE" "$DB_RULE"; do
  if ! firewall-cmd --zone="$ZONE" --query-rich-rule="$rule" >/dev/null; then
    firewall-cmd --zone="$ZONE" --add-rich-rule="$rule"
    added_runtime+=("$rule")
  fi
  if ! firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$rule" >/dev/null; then
    if firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$rule"; then
      added_permanent+=("$rule")
    else
      echo "Permanent rule addition failed; rolling back rules added by this run." >&2
      rollback_runtime
      rollback_permanent
      exit 1
    fi
  fi
done

echo
echo "Rules are present in runtime and permanent configuration."
echo "Verify from a NEW SSH session and from a permitted database client."
echo "Check the scoring engine before considering removal of broader rules."
echo "No existing rules were removed."
