# Chomper CentOS 10 Database-Server Hardening

Competition-focused Bash scripts for the CentOS 10 database host (`chomper.misty.view`). The scripts are designed to be reviewed and run individually, with conservative defaults and explicit confirmation before configuration changes.

> **Important:** These scripts were syntax-checked, but they have not been executed against the live competition VM. Run the read-only checks first and verify every environment-specific value with the competition instructions / Green Team. Do not assume the database engine, port, scoring-client network, or management network.

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
    ├── 05_review_updates.sh
    ├── 06_firewall_hardening.sh
    └── 07_ssh_hardening.sh
```

## Competition-specific facts and cautions

- The supplied competition material identifies Chomper as CentOS 10 and the scored service as **Database**.
- The competition brief lists the authorized Linux accounts as `root`, `user`, and `spikeweed`. Database/service identities (such as `mysql` or `postgres`) are not interchangeable with these login accounts and must not be removed merely because they are not on the human-login list.
- Team 15's expected team-facing address is `172.16.15.53`, based on the stated addressing pattern. Verify the actual address on event day; do not hardcode it into these scripts.
- The database engine, version, scored database port, database client source CIDR, SSH administrator source CIDR, active firewalld zone, schema, and scoring transaction are not specified here. Discover and verify them on the host / with the competition staff.
- The competition guide warns that the database may need to accept remote scoring connections. Do not change its bind/listen address to localhost-only without confirming that remote scoring does not require access.
- Keep SELinux enforcing where the service works. Do not disable SELinux as a generic troubleshooting step.
- Do not alter competition flags or their permissions/ownership. Do not touch the router or other teams' systems. Follow the competition's Green Team / reset rules.

## Runbook: recommended execution order

Run these steps from a root shell or prefix each command with `sudo`. Keep a second working administrative session or console open before any network or SSH change. The runbook intentionally separates discovery from changes.

### Phase 1 — Establish a baseline (read-only)

1. **Inventory the host and network.**
   ```bash
   sudo ./scripts/00_inventory.sh
   ```
   Review the generated `/var/tmp/chomper-inventory-*.txt`. Record hostname, addresses, routes, listening sockets, running services, active firewalld zones, SELinux mode, accounts, and scheduled tasks. Protect the report; it may contain sensitive operational details.

2. **Review local accounts and privileged groups.**
   ```bash
   sudo ./scripts/01_review_local_accounts.sh
   ```
   Compare the human login accounts with the competition-authorized list. Investigate unexpected accounts, `wheel` membership, sudoers files, SSH keys, service dependencies, and scheduled tasks before making any account changes. This script does not delete or modify accounts.

3. **Identify the actual database engine, service, listener, and SELinux status.**
   ```bash
   sudo ./scripts/04_database_service_check.sh
   ```
   Cross-check this output against the inventory. Record the actual engine/version, systemd unit, listening TCP port, configuration paths, and any relevant SELinux denials. If the database is not listening, investigate service health before changing the firewall.

4. **Review pending operating-system updates.**
   ```bash
   sudo ./scripts/05_review_updates.sh
   ```
   This checks repositories and previews an upgrade transaction without installing packages. Do not blindly update during a scoring window; review compatibility, downtime, restart requirements, and competition guidance first.

### Phase 2 — Create a recovery point

5. **Back up selected host configuration.**
   ```bash
   sudo ./scripts/02_backup_host_config.sh
   ```
   The archive is written under `/root/chomper-config-backups/` with restrictive permissions. It includes selected account, SSH, firewall, SELinux, and likely database configuration files when present. It is **not** a database-native backup and does not include database data files. Keep it off GitHub.

   If you plan to change database data or engine configuration, arrange and verify an engine-appropriate backup separately, following the database vendor's supported procedure.

### Phase 3 — Apply only verified network hardening

6. **Determine the exact network values before invoking the firewall script.**

   You must verify:
   - the active firewalld zone from `firewall-cmd --get-active-zones`;
   - the SSH administrator/client source CIDR and current SSH port;
   - the database scoring-client source CIDR;
   - that the detected database listener is the **scored** database listener.

   Do not assume that Team 15's host address (`172.16.15.53`) is the source address of the scoring client. Ask the competition staff or use the supplied network documentation to identify the correct client CIDR. A host address and a client source network are different things.

7. **Preview the proposed SSH and database allow rules.**

   The script now tries to identify listening TCP ports owned by recognizable database processes (for example, `mysqld`, `mariadbd`, `postgres`, `mongod`, or `redis-server`). It displays candidate ports and asks you to select/confirm one. This is only a convenience: process-based detection may miss a database, identify an unrelated instance, or find multiple listeners. Verify the chosen port against the actual service and scoring requirements.

   Example using placeholders:
   ```bash
   sudo ./scripts/06_firewall_hardening.sh \
     --zone public \
     --ssh-source <VERIFIED_ADMIN_CIDR> --ssh-port <VERIFIED_SSH_PORT> \
     --db-source <VERIFIED_DB_CLIENT_CIDR>
   ```

   If auto-detection cannot identify the listener, or you prefer to specify it yourself, provide the verified database port:
   ```bash
   sudo ./scripts/06_firewall_hardening.sh \
     --zone public \
     --ssh-source <VERIFIED_ADMIN_CIDR> --ssh-port <VERIFIED_SSH_PORT> \
     --db-source <VERIFIED_DB_CLIENT_CIDR> --db-port <VERIFIED_DB_PORT>
   ```

   The above commands are examples only. Replace every placeholder with verified values. Do not include angle brackets literally.

8. **Apply the firewall rules only after reviewing the dry run.**

   Repeat the selected command with `--apply` appended. The script asks for the word `APPLY`. It adds source-restricted IPv4 TCP rich rules to both runtime and permanent firewalld configuration. It does not remove existing broad allowances, change zone defaults, configure IPv6, or modify database bind settings.

   Immediately test:
   - a **new** SSH connection from the authorized administrator network;
   - a database connection and the expected scoring transaction from an intended client;
   - the competition scoring engine.

   Do not remove an existing broad rule until you have confirmed that the narrow rules cover every required legitimate client and scoring still works. Review IPv6 separately if it is enabled.

   `03_allow_database_client.sh` is an alternative database-only rule helper. Use it only if you intentionally want to add just the database rule rather than the combined SSH + database rules in step 8:
   ```bash
   sudo ./scripts/03_allow_database_client.sh \
     --source <VERIFIED_DB_CLIENT_CIDR> --port <VERIFIED_DB_PORT> --zone <ACTIVE_ZONE>
   ```
   Add `--apply` only after reviewing its dry run. Do not run both firewall scripts with overlapping rules unless you have a specific reason; duplicate rules are unnecessary.

### Phase 4 — SSH hardening and post-change validation

9. **Apply conservative SSH settings only after confirming alternate access.**
   ```bash
   sudo ./scripts/07_ssh_hardening.sh
   ```
   Read the script's summary, then type `APPLY` only if you have a working console or second admin session and have verified an authorized non-root administrator can log in and use sudo. The script backs up the SSH configuration, installs a drop-in, validates it with `sshd -t`, and reloads the active SSH service.

   It sets:
   - `PermitEmptyPasswords no`
   - `MaxAuthTries 4`
   - `LoginGraceTime 60`
   - `X11Forwarding no`

   It intentionally does **not** set `PermitRootLogin no`, disable password authentication, change the SSH port, restrict allowed users/groups, or change forwarding policies. Those changes can lock out administrators or disrupt competition workflows and should be considered separately only after access requirements are confirmed.

   Open a new SSH session and verify it works before closing the original session.

10. **Re-run the read-only checks and validate scoring.**
    ```bash
    sudo ./scripts/00_inventory.sh
    sudo ./scripts/01_review_local_accounts.sh
    sudo ./scripts/04_database_service_check.sh
    ```
    Compare with the baseline. Confirm expected services remain active, required listeners are reachable, SELinux remains in the intended mode, authorized users retain required access, and the scoring engine awards points.

## Script reference

| Script | Purpose | Changes the host? |
|---|---|---|
| `00_inventory.sh` | Captures OS, network, listeners, services, firewall, SELinux, account, and timer/cron inventory. | No |
| `01_review_local_accounts.sh` | Reports human-style local accounts, authorized competition login names, and privileged-group/sudoers information. | No |
| `02_backup_host_config.sh` | Archives selected host and service configuration files with restrictive permissions. | Creates a backup archive only |
| `03_allow_database_client.sh` | Adds one source-restricted IPv4 TCP database allow rule to a verified active zone. Dry-run unless `--apply` is supplied. | Yes, with `--apply` |
| `04_database_service_check.sh` | Checks likely database packages, services, TCP/UDP listeners, SELinux mode, and recent AVC denials. | No |
| `05_review_updates.sh` | Checks enabled DNF repositories and previews available upgrades without installing them. | No |
| `06_firewall_hardening.sh` | Adds source-restricted IPv4 TCP rules for SSH administration and the database scoring client. Detects candidate DB ports when `--db-port` is omitted, then requires selection/confirmation. Dry-run unless `--apply` is supplied. | Yes, with `--apply` |
| `07_ssh_hardening.sh` | Backs up SSH config, installs conservative SSH hardening drop-in, validates config, and reloads SSH after confirmation. | Yes, after confirmation |

## General operating rules

- Run one change at a time. Record the baseline and the exact command used.
- Keep a second admin session or console open during SSH/firewall changes.
- Review each script before execution. Do not pipe scripts directly from the internet into a root shell.
- Do not guess network ranges, ports, database engines, or service names.
- Test the service from the same kind of remote client used by the scoring system.
- If a change harms access or scoring, use the console / approved recovery method and the saved backup. Do not improvise broad firewall or SELinux changes.
- Competition materials describe a 30-minute grace period and require changes to stay within your own environment. Follow current event staff instructions; do not scan other teams, alter the router, or reset/revert systems without authorization.
- If changing a scored user's password, follow the competition's Password Change Request (PCR) process and update dependent consumers. A PCR submission alone does not change the password.

## Important limitations

- `06_firewall_hardening.sh` detects candidate database ports from process names in listening TCP socket output. Detection is not proof that the listener is the scored database. It requires the operator to confirm the detected port.
- Both firewall scripts add IPv4 allow rules only. They do not remove existing broad allows, create a default-deny policy, or manage IPv6.
- The SSH script does not disable root SSH login. Do not add `PermitRootLogin no` until an authorized non-root administrator has verified SSH and sudo access and the competition's access requirements are understood.
- No script automatically deletes users, rotates passwords, installs updates, changes database authentication/bind settings, modifies SELinux policy, or backs up database contents.

## GitHub hygiene

Commit the scripts and this README only. Do not commit:
- inventory/account-review output;
- configuration backup archives;
- database dumps;
- credentials, password hashes, private keys, TLS private keys, or connection strings;
- competition flags or flag hashes.

## Source documents

Prepared from the supplied competition materials:
- *PvP 2026 Defense Preparation Guide*
- *Intro to PvP*
- *PvP (2026) Briefing Packet*

The competition documents provide host/service and operational requirements; actual engine settings and network values must be discovered and verified on the running host.
