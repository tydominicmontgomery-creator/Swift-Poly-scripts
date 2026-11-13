#!/usr/bin/env bash
# Engine-aware database security assistant. Makes only confirmed, reversible edits.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/chomper-db-hardening-$STAMP"
install -d -m 0700 "$BACKUP"
echo "Restricted backup directory: $BACKUP"

echo "=== Detect database engine ==="
rpm -qa | grep -Ei 'mariadb|mysql|postgres' || true
systemctl --type=service --state=running --no-pager | grep -Ei 'mariadb|mysql|postgres' || true
ss -ltnp
echo
ENGINE=""
if command -v mariadb >/dev/null || command -v mysql >/dev/null; then
  if systemctl is-active --quiet mariadb.service || systemctl is-active --quiet mysqld.service; then ENGINE="mysql"; fi
fi
if command -v psql >/dev/null && systemctl is-active --quiet postgresql.service; then
  [[ -z "$ENGINE" ]] || { echo "Multiple active DB engines detected. Stop and investigate manually."; exit 1; }
  ENGINE="postgres"
fi
[[ -n "$ENGINE" ]] || {
  echo "No supported active MariaDB/MySQL or PostgreSQL service detected."
  echo "MongoDB/Redis/containerized/other deployments require a separately reviewed engine-specific workflow."
  exit 1
}
echo "Detected engine family: $ENGINE"
echo "This script does not assume that a Linux account is the scored database account."

if [[ "$ENGINE" == mysql ]]; then
  CLIENT="$(command -v mariadb || command -v mysql)"
  UNIT="mariadb.service"; systemctl is-active --quiet "$UNIT" || UNIT="mysqld.service"
  echo "Attempting local administrative inspection using sudo $CLIENT (socket authentication)."
  if ! "$CLIENT" -NBe "SELECT VERSION();" > "$BACKUP/version.txt" 2>"$BACKUP/client-error.txt"; then
    echo "Could not authenticate through local socket as root."
    cat "$BACKUP/client-error.txt"
    echo "Do not place passwords in command-line arguments. Establish a permitted local admin session, then rerun."
    exit 1
  fi
  "$CLIENT" -e "SELECT VERSION(); SHOW VARIABLES LIKE 'port'; SHOW VARIABLES LIKE 'bind_address'; SHOW VARIABLES LIKE 'require_secure_transport'; SELECT User,Host,plugin FROM mysql.user ORDER BY User,Host;" | tee "$BACKUP/inspection.txt"
  echo "Current grants for each account will be saved after you select an account."
  read -r -p "Scored DB username (exact, not Linux user): " DBUSER
  read -r -p "Scored DB account host pattern (exact Host column value): " DBHOST
  read -r -p "Scored database/schema name: " DBNAME
  [[ -n "$DBUSER" && -n "$DBHOST" && -n "$DBNAME" ]] || { echo "All fields required."; exit 2; }
  if [[ "$DBUSER$DBHOST" == *"'"* || "$DBUSER$DBHOST" == *$'\\n'* || "$DBNAME" == *'`'* || "$DBNAME" == *$'\\n'* ]]; then
    echo "Quotes, newlines, and backticks are not accepted by this helper; administer unusual identifiers manually."
    exit 2
  fi
  "$CLIENT" -e "SHOW GRANTS FOR '${DBUSER//\'/\'\'}'@'${DBHOST//\'/\'\'}';" | tee "$BACKUP/scored-account-grants.txt"
  echo
  echo "Review these grants and identify the minimum needed by the exact scored query."
  echo "The packet does not specify the expected SQL operation, so the script will not guess or revoke grants."
  echo "Choose a privilege set only after checking the scorer's required transaction:"
  echo "  1) SELECT only"
  echo "  2) SELECT, INSERT"
  echo "  3) SELECT, INSERT, UPDATE"
  echo "  4) SELECT, INSERT, UPDATE, DELETE"
  echo "  5) Do not modify grants; inspection only"
  echo "  6) Replace direct account grants with the selected schema-level set (disruptive; review roles separately)"
  read -r -p "Selection: " choice
  case "$choice" in
    1) PRIVS="SELECT";;
    2) PRIVS="SELECT, INSERT";;
    3) PRIVS="SELECT, INSERT, UPDATE";;
    4) PRIVS="SELECT, INSERT, UPDATE, DELETE";;
    5) PRIVS="";;
    6) PRIVS="REPLACE";;
    *) echo "Invalid selection."; exit 2;;
  esac
  if [[ "$PRIVS" == REPLACE ]]; then
    echo "Choose the minimum direct privileges for the scored transaction:"
    echo "  1) SELECT"
    echo "  2) SELECT, INSERT"
    echo "  3) SELECT, INSERT, UPDATE"
    echo "  4) SELECT, INSERT, UPDATE, DELETE"
    read -r -p "Privilege set: " set_choice
    case "$set_choice" in
      1) PRIVS="SELECT";;
      2) PRIVS="SELECT, INSERT";;
      3) PRIVS="SELECT, INSERT, UPDATE";;
      4) PRIVS="SELECT, INSERT, UPDATE, DELETE";;
      *) echo "Invalid selection."; exit 2;;
    esac
    ACCOUNT="'$DBUSER'@'$DBHOST'"
    echo "This will REVOKE ALL direct privileges and GRANT OPTION from $ACCOUNT, then grant $PRIVS on the selected schema."
    echo "Role memberships may still confer additional privileges and must be reviewed separately."
    read -r -p "Type REVOKE-AND-REGRANT to proceed: " ok
    if [[ "$ok" == "REVOKE-AND-REGRANT" ]]; then
      "$CLIENT" -e "REVOKE ALL PRIVILEGES, GRANT OPTION FROM $ACCOUNT;"
      "$CLIENT" -e "GRANT $PRIVS ON \`$DBNAME\`.* TO $ACCOUNT;"
      "$CLIENT" -e "SHOW GRANTS FOR $ACCOUNT;" | tee "$BACKUP/grants-after.txt"
    fi
  elif [[ -n "$PRIVS" ]]; then
    ACCOUNT="'$DBUSER'@'$DBHOST'"
    echo "Planned additive schema-level grant: $PRIVS ON \`$DBNAME\`.* TO $ACCOUNT"
    echo "This does NOT remove pre-existing global privileges or GRANT OPTION."
    read -r -p "Apply this additional grant? Type APPLY: " ok
    if [[ "$ok" == APPLY ]]; then
      "$CLIENT" -e "GRANT $PRIVS ON \`$DBNAME\`.* TO $ACCOUNT;"
      "$CLIENT" -e "SHOW GRANTS FOR $ACCOUNT;" | tee "$BACKUP/grants-after.txt"
    fi
  fi
  echo "Inspect bind/port/TLS variables above. No bind, TLS, password, or authentication-plugin settings were changed."
else
  echo "Attempting local PostgreSQL inspection through the postgres OS account."
  if ! runuser -u postgres -- psql -XAtqc "SELECT version();" > "$BACKUP/version.txt" 2>"$BACKUP/client-error.txt"; then
    cat "$BACKUP/client-error.txt"
    echo "Could not use local peer/admin access. No database changes made."
    exit 1
  fi
  runuser -u postgres -- psql -X -c "SHOW config_file; SHOW hba_file; SHOW listen_addresses; SHOW port; SHOW password_encryption; SELECT rolname,rolsuper,rolcreaterole,rolcreatedb,rolcanlogin FROM pg_roles ORDER BY rolname;" | tee "$BACKUP/inspection.txt"
  HBA="$(runuser -u postgres -- psql -XAtqc 'SHOW hba_file')"
  CONF="$(runuser -u postgres -- psql -XAtqc 'SHOW config_file')"
  cp -a "$HBA" "$BACKUP/pg_hba.conf"
  cp -a "$CONF" "$BACKUP/postgresql.conf"
  echo
  echo "Current HBA entries:"
  grep -nEv '^[[:space:]]*(#|$)' "$HBA" || true
  echo "The guide requires reviewing first-match HBA behavior and replacing unsafe remote trust only after verifying the scored client."
  read -r -p "Scored database name: " DBNAME
  read -r -p "Scored PostgreSQL role: " DBUSER
  read -r -p "Scoring-client source CIDR: " CIDR
  [[ -n "$DBNAME" && -n "$DBUSER" && -n "$CIDR" ]] || { echo "All fields required."; exit 2; }
  python3 - "$CIDR" <<'PY' || { echo "Invalid CIDR"; exit 2; }
import ipaddress,sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
  if grep -nEi '^[[:space:]]*host[[:space:]].*[[:space:]]trust([[:space:]]|$)' "$HBA"; then
    echo "WARNING: an earlier remote host trust rule may match first. Appending a secure rule would not override it."
    echo "No HBA change made. Review and reorder existing HBA rules manually."
    exit 1
  fi
  echo "A narrow rule would be: hostssl $DBNAME $DBUSER $CIDR scram-sha-256"
  echo "Before adding it, confirm server TLS, client TLS verification, SCRAM-compatible client, and role password hash."
  read -r -p "Have you verified all four requirements and want to append this rule? Type APPEND: " ok
  if [[ "$ok" == APPEND ]]; then
    printf '\n# Added by Chomper hardening %s after operator verification\nhostssl %s %s %s scram-sha-256\n' "$STAMP" "$DBNAME" "$DBUSER" "$CIDR" >> "$HBA"
    chown postgres:postgres "$HBA"
    if runuser -u postgres -- psql -XAtqc "SELECT * FROM pg_hba_file_rules WHERE error IS NOT NULL;" | grep -q .; then
      echo "HBA parse errors detected. Restoring backup."
      cp -a "$BACKUP/pg_hba.conf" "$HBA"; exit 1
    fi
    runuser -u postgres -- psql -XAtqc "SELECT pg_reload_conf();"
    echo "HBA rule appended and reload requested. Verify logs and test a NEW remote scored-role connection."
  fi
  echo "No PostgreSQL role privileges, passwords, listen_addresses, TLS settings, or earlier HBA rules were changed."
fi

echo
echo "Database inspection/hardening pass complete. Restricted backup: $BACKUP"
echo "Run the exact competition query remotely and check scoring before considering further restrictions."
