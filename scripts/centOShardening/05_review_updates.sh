#!/usr/bin/env bash
# Reviews available updates without installing them or restarting services.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

echo "=== DNF VERSION / REPOSITORIES ==="
dnf --version
dnf repolist --enabled
echo
echo "=== AVAILABLE UPDATE CHECK ==="
set +e
dnf check-update
RC=$?
set -e
if [[ $RC -eq 100 ]]; then
  echo "Updates are available. Review the proposed transaction below."
elif [[ $RC -eq 0 ]]; then
  echo "No updates reported."
else
  echo "dnf check-update returned exit code $RC; investigate repository/network errors."
fi
echo
echo "=== TRANSACTION PREVIEW (NO INSTALL) ==="
dnf upgrade --assumeno || true
echo
echo "No packages were installed. Schedule targeted updates only after reviewing downtime and recovery."
