#!/usr/bin/env bash
# Creates a restricted backup of selected host and database configuration.
# This is NOT a database data backup and does not replace an engine-native backup.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="${1:-/root/chomper-config-backups}"
umask 077
install -d -m 0700 "$DEST"

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

mkdir -p "$TMP/etc"
for path in \
  /etc/os-release /etc/passwd /etc/group /etc/shadow /etc/gshadow \
  /etc/sudoers /etc/sudoers.d /etc/ssh \
  /etc/firewalld /etc/selinux \
  /etc/my.cnf /etc/my.cnf.d /etc/mysql \
  /etc/postgresql /var/lib/pgsql/data/postgresql.conf \
  /var/lib/pgsql/data/pg_hba.conf
do
  if [[ -e "$path" ]]; then
    mkdir -p "$TMP$(dirname "$path")"
    cp -a "$path" "$TMP$path"
  fi
done

{
  date --iso-8601=seconds
  echo "Host: $(hostname -f 2>/dev/null || hostname)"
  echo "Note: selected configuration only; database data files are not included."
} > "$TMP/BACKUP-METADATA.txt"

ARCHIVE="$DEST/chomper-config-${STAMP}.tar.gz"
tar -czf "$ARCHIVE" -C "$TMP" .
chmod 600 "$ARCHIVE"
echo "Configuration backup created: $ARCHIVE"
echo "Contains sensitive account and service configuration. Keep it off GitHub."
