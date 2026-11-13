# Chomper — CentOS 10 Database Hardening

Bash hardening and validation scripts for the **CentOS 10 (`chomper`) database host** used in the 2026 Purple vs. Purple competition.

The goal is to reduce unnecessary host and database exposure while keeping the scored database operation available.

> **Important:** These scripts are intentionally conservative. They inspect first and avoid guessing the database engine, database port, scoring-client network, or firewall zone. Read each script before running it. Test in a practice VM first.

## Competition-specific requirements

From the competition briefing and defense preparation guide:

- Host: `chomper.misty.view`
- Listed addresses: `192.168.1.53` and team-facing `172.16.XX.53` (confirm the actual event-day address).
- OS: CentOS 10; verify `/etc/os-release` because the guide identifies this as CentOS Stream 10.
- Scored service: **Database**.
- Authorized Linux users listed in the packet: `user`, `spikeweed`, and `root`.
- The database engine, version, schema, scored database account, port, client source network, and exact scoring query are not specified in the packet. Discover these on the live host before applying engine-specific settings.
- Database users are distinct from Linux users. Preserve required service identities such as `mysql` or `postgres`.

## Repository layout

```text
chomper-centos-hardening/
├── README.md
└── scripts/
    ├── 00_inventory.sh
    ├── 01_review_local_accounts.sh
    ├── 02_backup_host_config.sh
    ├── 03_allow_database_client.sh
    ├── 04_database_service_check.sh
    └── 05_review_updates.sh
```

## Script descriptions

| Script | Purpose | Makes changes? |
|---|---|---|
| `00_inventory.sh` | Collects OS, network, listening sockets, running services, database package clues, firewall zones/rules, SELinux state, local accounts, privileged groups, timers, and cron-file metadata. Saves a restricted report. | No |
| `01_review_local_accounts.sh` | Compares local human-style accounts with the competition's authorized Linux account list and reports wheel/sudo group membership. It does not assume every unlisted account is malicious. | No |
| `02_backup_host_config.sh` | Creates a root-only archive of selected account, SSH, firewall, SELinux, and likely database configuration files. It does not copy live database data files. | Creates a local backup |
| `03_allow_database_client.sh` | Shows or adds a firewalld IPv4 rich rule allowing one verified client CIDR to reach one verified TCP database port in one active zone. It does not remove broad rules or set a default-deny policy. | Only with `--apply` and interactive confirmation |
| `04_database_service_check.sh` | Reports likely database packages/services, service status, listening sockets, SELinux mode, and recent AVC denials when `ausearch` is available. | No |
| `05_review_updates.sh` | Checks enabled DNF repositories and previews an upgrade transaction. Does not install updates. | No |

## Recommended first-run order

Run these from a root shell or with `sudo`. Keep a console or a second verified administrative session open.

```bash
chmod +x scripts/*.sh

sudo ./scripts/00_inventory.sh
sudo ./scripts/04_database_service_check.sh
sudo ./scripts/01_review_local_accounts.sh
sudo ./scripts/02_backup_host_config.sh
sudo ./scripts/05_review_updates.sh
```

Review the reports before making changes. Protect the generated reports and backups: they may reveal host configuration, usernames, network layout, and secrets-related paths. **Do not commit them to GitHub.**

## Firewall script

First identify all legitimate database clients, the actual database port, and the active firewalld zone. The competition guide warns that a localhost-only bind can break a remotely scored database, and that a narrow allow rule does not override an existing broad allow.

Dry run:

```bash
sudo ./scripts/03_allow_database_client.sh \
  --source VERIFIED_CLIENT_CIDR \
  --port VERIFIED_DB_PORT \
  --zone VERIFIED_ACTIVE_ZONE
```

Apply only after verifying those values and confirming that all required clients are included:

```bash
sudo ./scripts/03_allow_database_client.sh \
  --source VERIFIED_CLIENT_CIDR \
  --port VERIFIED_DB_PORT \
  --zone VERIFIED_ACTIVE_ZONE \
  --apply
```

The script adds the rule to runtime and permanent firewalld configuration after an interactive `APPLY` confirmation. It does **not** remove existing service/port allowances, alter IPv6 policy, change the database bind address, or close management access. Review those separately and test from an allowed client before removing any superseded rule.

## Database-specific hardening is deliberately separate

Do not apply MariaDB/MySQL settings to PostgreSQL or vice versa. The preparation guide requires identifying the actual engine and mapping the scored transaction first.

### If MariaDB/MySQL is installed

Before changing anything, inspect the installed version, account/host pairs, grants, bind address, port, TLS settings, and active sessions using the engine's authorized local administrative client. Reduce privileges only after confirming the exact scored query and application dependencies. Do not blindly run a secure-installation wizard.

### If PostgreSQL is installed

Locate the active `config_file` and `hba_file` from the running cluster. Review `listen_addresses`, port, roles, and the complete ordered `pg_hba.conf` rules. The first matching HBA rule wins. Preserve a verified local administrative path and test the remote scored role after any change.

### If another engine is installed

Do not use either branch above. Identify its supported authentication, privilege, network binding, TLS, logging, and backup controls first.

## Competition-safe operating procedure

1. Record the baseline and current score.
2. Keep a working console or second administrative session.
3. Back up only the configuration you intend to edit.
4. Make one small change at a time.
5. Validate syntax and service health.
6. Test a new connection from the actual intended client using the scored identity and authentication method.
7. Run the expected query against the required schema, then check the scoring engine.
8. Keep the change only if the service still works; otherwise restore the last known-good configuration.

### Password changes and scoring

Do not place passwords in scripts, command-line arguments, GitHub, or shared notes. The competition packet says that when a **scored service user** password is changed, a Password Change Request (PCR) must also be submitted so the scoring engine knows the new credential. A PCR does not itself change the account password. Update any application or service that consumes the credential, then verify the score.

### Flags and destructive actions

Never edit, delete, move, hash, or change permissions/ownership on competition flags. Do not run blanket cleanup commands, mass account deletion, or broad recursive permission changes. Do not touch the router or take/revert VM snapshots without Green Team approval.

## Requirements and compatibility

- Written for Bash on a CentOS Stream 10-style system.
- Uses common system administration tools such as `rpm`, `systemctl`, `ss`, `firewall-cmd`, `getenforce`, `dnf`, and (optionally) `ausearch`.
- Scripts should be reviewed against the actual competition image before use.
- These scripts have not been executed against the competition VM.
- The firewall helper handles IPv4 only; confirm and separately protect IPv6 if it is enabled.
- This repository does not include database-native data backups, password rotation, automatic account deletion, automatic package installation, or automatic database configuration edits.

## GitHub hygiene

Commit the scripts and this README only. Do not commit:
- inventory/account-review output;
- configuration backup archives;
- database dumps;
- credentials, password hashes, private keys, TLS private keys, or connection strings;
- competition flags or flag hashes.

## Source documents

Prepared from the supplied competition materials:

- *PvP 2026 Defense Preparation Guide*, especially pages 2–10 and 24–28.
- *Intro to PvP*, especially pages 16–21 (script preparation, Linux scripting, firewalls, and password changes).
- *PvP (2026) Briefing Packet*, especially pages 3–9 and 14 (scope, scoring, PCRs, flags, and CentOS host requirements).

The competition documents provide the host/service requirements; actual engine settings and network values must be discovered on the running host.
