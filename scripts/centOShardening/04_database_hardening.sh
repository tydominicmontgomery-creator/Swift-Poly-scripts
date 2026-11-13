#!/usr/bin/env bash
# Discovery only. Engine-specific remediation intentionally deferred.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
echo "=== Chomper database discovery ==="
cat /etc/os-release
rpm -qa | grep -Ei 'mariadb|mysql|postgres|mongodb|redis' || true
systemctl --type=service --state=running --no-pager | grep -Ei 'mariadb|mysql|postgres|mongo|redis' || true
ss -ltnp
echo "[STOP] No DB configuration or account changes made."
echo "Before building DB hardening, identify engine/version, scored DB/user/host, exact expected query,"
echo "required read/write privileges, TLS/auth requirements, scoring CIDR and application-server CIDR."
