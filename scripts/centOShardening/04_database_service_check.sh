#!/usr/bin/env bash
# Discovers likely database engines and checks service/listener/SELinux status.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

echo "=== OS RELEASE ==="
cat /etc/os-release
echo
echo "=== DATABASE-RELATED INSTALLED PACKAGES ==="
rpm -qa | grep -Ei 'mariadb|mysql|postgres|mongodb|redis' || true
echo
echo "=== DATABASE-RELATED SERVICES ==="
systemctl list-unit-files --type=service --no-pager |
  grep -Ei 'mariadb|mysql|postgres|mongo|redis' || true
echo
echo "=== ACTIVE DATABASE-RELATED SERVICES ==="
for unit in mariadb.service mysqld.service postgresql.service mongod.service redis.service; do
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "$unit"; then
    systemctl --no-pager --full status "$unit" || true
  fi
done
echo
echo "=== TCP/UDP LISTENERS ==="
ss -tulpn
echo
echo "=== SELINUX MODE ==="
getenforce
echo
echo "=== RECENT SELINUX DENIALS (IF AUDIT TOOLS ARE AVAILABLE) ==="
if command -v ausearch >/dev/null; then
  ausearch -m AVC,USER_AVC -ts recent 2>/dev/null || true
else
  echo "ausearch not installed; inspect audit logs using approved system tools."
fi
echo
echo "Discovery only. Identify the actual engine, version, unit, port, config paths, and scored transaction."
