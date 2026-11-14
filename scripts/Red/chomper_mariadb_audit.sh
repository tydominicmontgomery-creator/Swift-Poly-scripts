#!/usr/bin/env bash
# chomper_mariadb_audit.sh
# Read-only local MariaDB security inventory for an authorized server.
# Does not brute-force credentials, exploit services, change settings, or scan peers.

set -u
umask 077

OUT_DIR="${OUT_DIR:-/var/log/chomper-mariadb-audit}"
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="${OUT_DIR}/mariadb-audit-${STAMP}.txt"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
touch "$REPORT"
chmod 600 "$REPORT"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
section() { log ""; log "===== $* ====="; }

DBCLI=""
if command -v mariadb >/dev/null 2>&1; then
  DBCLI="$(command -v mariadb)"
elif command -v mysql >/dev/null 2>&1; then
  DBCLI="$(command -v mysql)"
fi

run_sql() {
  local label="$1"
  local sql="$2"
  section "$label"
  if [[ -z "$DBCLI" ]]; then
    log "MariaDB/MySQL client not installed; SQL checks skipped."
    return
  fi
  # Prefer local socket authentication via sudo/root. Never place passwords in argv.
  if "$DBCLI" --protocol=socket --batch --raw --skip-column-names \
      -e "$sql" >>"$REPORT" 2>&1; then
    :
  else
    log "Query unavailable or access denied; review locally with an authorized DBA account."
  fi
}

section "Host"
log "Timestamp: $(date --iso-8601=seconds)"
log "Hostname: $(hostname -f 2>/dev/null || hostname)"
log "OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
log "Kernel: $(uname -r)"
log "Report: $REPORT"

section "Packages and service"
if command -v rpm >/dev/null 2>&1; then
  rpm -qa | grep -Ei '^(MariaDB|mariadb|mysql)' | sort >>"$REPORT" || true
elif command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null |
    grep -Ei 'mariadb|mysql' | sort >>"$REPORT" || true
fi

for svc in mariadb mysql; do
  if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service"; then
    log "--- ${svc}.service ---"
    systemctl is-enabled "${svc}.service" 2>&1 | tee -a "$REPORT" || true
    systemctl is-active "${svc}.service" 2>&1 | tee -a "$REPORT" || true
    systemctl status "${svc}.service" --no-pager -l 2>&1 |
      sed -n '1,18p' | tee -a "$REPORT" || true
  fi
done

section "Listening sockets"
ss -lntp 2>&1 | grep -E '(:3306[[:space:]]|:33060[[:space:]]|mariadbd|mysqld)' |
  tee -a "$REPORT" || log "No obvious MariaDB TCP listener found."
log "Review all listeners separately if MariaDB uses a nonstandard port."

section "Configuration file locations"
for f in /etc/my.cnf /etc/mysql/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf; do
  [[ -f "$f" ]] || continue
  log "--- $f ---"
  # Print security-relevant directives only; avoid dumping credentials from config files.
  grep -Ein '^[[:space:]]*(bind-address|skip-networking|skip_name_resolve|local_infile|secure_file_priv|symbolic-links|skip-symbolic-links|ssl|require_secure_transport|user)[[:space:]]*=' "$f" |
    sed -E 's/(password|passwd|secret)[[:space:]]*=.*/\1=[REDACTED]/I' |
    tee -a "$REPORT" || true
done

run_sql "Server version and security variables" "
SELECT CONCAT('version=', VERSION());
SHOW GLOBAL VARIABLES WHERE Variable_name IN
('bind_address','port','skip_networking','skip_name_resolve','local_infile',
 'secure_file_priv','symbolic_links','have_ssl','require_secure_transport',
 'tls_version','log_error','general_log','general_log_file','slow_query_log',
 'slow_query_log_file','secure_auth');
"

run_sql "Account inventory (no password hashes)" "
SELECT CONCAT('account=', User, '@', Host, '; plugin=', COALESCE(plugin,'(default)'))
FROM mysql.user ORDER BY User, Host;
"

run_sql "Potentially risky account patterns" "
SELECT CONCAT('anonymous_account=', Host)
FROM mysql.user WHERE User='';
SELECT CONCAT('root_account_host=', Host)
FROM mysql.user WHERE User='root';
"

run_sql "Accounts with broad/global privileges" "
SELECT CONCAT('global_privilege_account=', GRANTEE, '; privilege=', PRIVILEGE_TYPE,
              '; grantable=', IS_GRANTABLE)
FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE IN
('ALL PRIVILEGES','FILE','SUPER','SHUTDOWN','PROCESS','CREATE USER','GRANT OPTION')
ORDER BY GRANTEE, PRIVILEGE_TYPE;
"

run_sql "Database inventory (names only)" "
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;
"

section "Firewall context"
if command -v firewall-cmd >/dev/null 2>&1; then
  log "firewalld state: $(firewall-cmd --state 2>&1)"
  firewall-cmd --get-active-zones 2>&1 | tee -a "$REPORT" || true
  firewall-cmd --list-all-zones 2>&1 |
    grep -E '^(public|trusted|internal|external|work|home|dmz|  interfaces:|  sources:|  services:|  ports:|  rich rules:)' |
    tee -a "$REPORT" || true
elif command -v nft >/dev/null 2>&1; then
  nft list ruleset 2>&1 | tee -a "$REPORT" || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -S 2>&1 | tee -a "$REPORT" || true
else
  log "No supported firewall inspection command found."
fi

section "SELinux"
if command -v getenforce >/dev/null 2>&1; then
  getenforce 2>&1 | tee -a "$REPORT"
else
  log "SELinux tools not installed."
fi

section "Review notes"
log "- This is a read-only inventory; it does not prove exploitability."
log "- Do not test credentials against other teams or reuse findings outside approved scope."
log "- Verify each finding against the competition scoring requirements before changing settings."
log "- Preserve scoring-client and application-server access when tightening DB network rules."
log "- Do not publish this report without reviewing it for internal host/account details."

echo
echo "Audit complete: $REPORT"
echo "Report permissions: 600 (root only)"
