#!/usr/bin/env bash
# Adds a narrowly scoped firewalld rich rule. It never removes existing rules.
# Runtime + permanent changes occur only with --apply and explicit parameters.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  sudo ./03_allow_database_client.sh --source CLIENT_CIDR --port DB_PORT --zone ACTIVE_ZONE [--apply]

Example (replace all values with verified competition facts):
  sudo ./03_allow_database_client.sh --source 172.16.20.0/24 --port 5432 --zone public
  sudo ./03_allow_database_client.sh --source 172.16.20.0/24 --port 5432 --zone public --apply

Without --apply, the script prints the proposed rule only.
The source network, database port, and active zone must be confirmed first.
This script adds an allow rule; it does NOT remove broad/pre-existing allows or create a default-deny policy.
USAGE
}

SOURCE=""
PORT=""
ZONE=""
APPLY=0

while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?Missing CIDR}"; shift 2 ;;
    --port) PORT="${2:?Missing port}"; shift 2 ;;
    --zone) ZONE="${2:?Missing zone}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root via sudo." >&2
  exit 1
fi
if [[ -z "$SOURCE" || -z "$PORT" || -z "$ZONE" ]]; then
  usage >&2
  exit 2
fi
if [[ ! "$SOURCE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
  echo "Source must be an IPv4 CIDR, e.g. 172.16.20.0/24." >&2
  exit 2
fi
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  echo "Port must be an integer from 1 to 65535." >&2
  exit 2
fi
command -v firewall-cmd >/dev/null || { echo "firewall-cmd not found." >&2; exit 1; }
firewall-cmd --state >/dev/null || { echo "firewalld is not running; no changes made." >&2; exit 1; }

ACTIVE_ZONES="$(firewall-cmd --get-active-zones)"
if ! grep -Fxq "$ZONE" <<<"$ACTIVE_ZONES"; then
  echo "Zone '$ZONE' is not listed as active. Active zones:" >&2
  printf '%s\n' "$ACTIVE_ZONES" >&2
  exit 1
fi

RULE="rule family=\"ipv4\" source address=\"$SOURCE\" port port=\"$PORT\" protocol=\"tcp\" accept"
echo "Proposed firewalld rule:"
echo "$RULE"
echo "Zone: $ZONE"
echo
echo "Current zone rules:"
firewall-cmd --zone="$ZONE" --list-all

if ((APPLY == 0)); then
  echo
  echo "Dry run only. Re-run with --apply after confirming source, port, zone, and scoring connectivity."
  exit 0
fi

read -r -p "Type APPLY to add this rule at runtime and permanently: " CONFIRM
[[ "$CONFIRM" == "APPLY" ]] || { echo "Cancelled."; exit 0; }

if firewall-cmd --zone="$ZONE" --query-rich-rule="$RULE" >/dev/null; then
  echo "Rule already exists at runtime; no duplicate added."
else
  firewall-cmd --zone="$ZONE" --add-rich-rule="$RULE"
fi

if ! firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$RULE" >/dev/null; then
  if ! firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$RULE"; then
    echo "Permanent add failed. Removing the runtime rule added by this run." >&2
    firewall-cmd --zone="$ZONE" --remove-rich-rule="$RULE" || true
    exit 1
  fi
fi

echo
echo "Rule status (runtime):"
firewall-cmd --zone="$ZONE" --query-rich-rule="$RULE"
echo "Rule status (permanent):"
firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$RULE"
echo
echo "Now test the database from an intended client and check the scoring engine."
echo "Existing broad allows remain in place; review and remove them manually only after validation."
