# Chomper (Team 15) CentOS 10 hardening toolkit

This version contains scripts that make real system changes after interactive discovery and explicit confirmation. They are intended for the authorized Chomper host only.

## Ground truth from competition documents

- Host: `chomper.misty.view`
- Internal address: `192.168.1.53`
- Team-facing pattern: `172.16.XX.53`; for Team 15, expected `172.16.15.53`. Verify on the actual VM.
- Authorized Linux accounts: `user`, `spikeweed`, `root`
- Scored service: Database
- Database engine, version, scored database account, account host/role, database/schema, required query, TLS requirements, and scoring-client source CIDR are not supplied. Scripts discover what they can and prompt for the rest.
- Database Linux service accounts such as `mysql` and `postgres` are not human login accounts and must be preserved.
- Router is out of scope. Do not touch other teams during the 30-minute grace period. Do not alter flags or their ownership/permissions. Do not snapshot/revert without Green Team approval.

## Runbook

Run from the repository root. Use a console or retain a second proven admin session before SSH/firewall changes. Execute one script at a time and monitor the scoring engine after each phase.

### 1. Back up current host configuration

```bash
sudo ./scripts/02_backup_host_config.sh
```

Creates a root-only backup of host configuration. It is not a database data backup.

### 2. Apply host-level hardening

```bash
sudo ./scripts/10_host_hardening.sh
```

Actions:
- checks CentOS identity, privilege configuration, local UID-0 accounts, wheel/sudo membership;
- enumerates login-capable local human-style accounts not on the authorized list (`root`, `user`, `spikeweed`) and prompts individually to lock password + set shell to `/sbin/nologin`;
- prompts before removing unlisted users from `wheel`;
- offers a conservative SSH drop-in (`PermitEmptyPasswords no`, `MaxAuthTries 4`, `LoginGraceTime 60`, `X11Forwarding no`), validates with `sshd -t`, then reloads sshd;
- checks and offers repairs for standard passwd/group/shadow/gshadow file modes;
- reports SELinux, running services and timers.

It does not delete accounts or home directories, kill sessions, remove packages, delete unknown services/tasks, disable root SSH, disable password authentication, or turn SELinux off. Unknown accounts are not automatically presumed malicious.

### 3. Tighten firewall access for SSH and the database

```bash
sudo ./scripts/11_firewall_hardening.sh
```

The script:
- asks for the active zone and verifies it;
- displays the host addresses; Team 15's expected host IP is `172.16.15.53`, but it does not assume this is a client source;
- prompts for the SSH administrator CIDR and database scoring-client CIDR;
- detects candidate DB TCP listeners from owning process names; if detection is ambiguous or unavailable, prompts for the scored DB port;
- asks for SSH port (default 22);
- shows current runtime and permanent zone policy;
- after the operator types `APPLY`, adds source-restricted IPv4 TCP rules for SSH and DB at runtime and permanently.

It does not remove existing broad rules, change default zone targets, enable firewalld, alter database bind addresses, or modify IPv6. This is deliberate: the guide says add required management/database access first, then test, and only then remove superseded broad rules. If broad rules remain, the new narrow allow does not constrain them. Review and remove only rules you have proven unnecessary, then test allowed AND denied access. Keep IPv6 in scope if enabled.

**Important:** Team host address `172.16.15.53` is not necessarily the scoring client's source address. If you do not know the scorer CIDR, ask Green Team; do not guess.

### 4. Harden the actual database engine

```bash
sudo ./scripts/12_database_hardening.sh
```

Detects active MariaDB/MySQL or PostgreSQL and takes an engine-specific path.

MariaDB/MySQL:
- attempts local socket administrative access without putting a password in command arguments;
- records engine version, port, bind address, TLS transport setting, database accounts and grants;
- prompts for the exact scored database account (`User` + `Host`) and schema;
- presents a small privilege menu and can add schema-level privileges after confirmation.

The script intentionally does not automatically revoke grants: the packet does not tell us whether the scored query reads, writes, updates, deletes, executes routines, or requires another operation. It does not remove global privileges, GRANT OPTION, accounts, anonymous users, or test databases. Review the saved grant output before changing privileges.

PostgreSQL:
- uses local `postgres` peer access to record version, config paths, HBA path, listen address, port, password encryption, and role privilege flags;
- backs up active `postgresql.conf` and `pg_hba.conf`;
- displays active HBA rules and prompts for scored DB, role and source CIDR;
- only offers to append a narrow `hostssl ... scram-sha-256` rule after the operator confirms server TLS, client TLS verification, SCRAM-compatible client and role password hash;
- checks for earlier broad remote `trust` rules (and stops if found), validates HBA parse errors, and reloads only after successful validation.

The script does not change PostgreSQL role privileges, passwords, listen addresses, or existing HBA rules. It cannot safely infer TLS compatibility from the competition packet.

Other engines, multiple active engines, containers, or failed local admin authentication stop safely and require a separate engine-specific procedure. Do not run a generic secure-install wizard blindly.

### 5. Validate the scored transaction

Use the actual scorer client and credentials. Verify:
- new SSH login from the authorized management path;
- remote database login using the scored identity and authentication method;
- the exact expected query and schema operations;
- expected operations succeed and unneeded administrative operations fail;
- service logs and scoring engine show healthy results.

A successful TCP connection or `SELECT 1` is not proof that the competition's real transaction works. For scored-user password changes, submit the required Password Change Request (PCR) and update dependent consumers. A PCR submission alone does not change the host/database password.

## Script inventory

| Script | Function | Changes |
|---|---|---|
| `02_backup_host_config.sh` | Restricted host configuration backup | Creates backup only |
| `10_host_hardening.sh` | Account review/interactive containment, sudo/wheel review, SSH baseline, file mode checks | Yes, per prompt |
| `11_firewall_hardening.sh` | Discover listener, prompt client CIDRs/ports, add source-restricted rules | Yes, after `APPLY` |
| `12_database_hardening.sh` | Engine-specific database inspection and carefully gated privilege/HBA changes | Yes, after explicit confirmation |

## Safety / limitations

- These scripts have not been run against the live competition VM. Review them before execution and test in a practice clone where possible.
- Do not run all scripts blindly in one shell command. Run each phase, validate, and then proceed.
- `user`, `spikeweed`, and `root` are the only authorized human Linux accounts listed for Chomper. Preserve service identities and investigate before disabling an unlisted account.
- The database engine and scorer's exact transaction are unknown. Least privilege is transaction-specific; never revoke access until the expected SQL operation and dependencies are known.
- Firewall source CIDRs must be verified from event network documentation/Green Team. Team 15's host IP does not determine the scoring-client CIDR.
- `02_backup_host_config.sh` and the database script's backups do not replace a database-native consistent backup. Use the engine's supported backup method if changing data or major engine configuration.
- No script changes competition flags, touches the router, scans other teams, or changes snapshots.
- Backups and logs may contain sensitive information. Keep them root-only and never commit them to GitHub.

## Source basis

Prepared from the supplied *PvP 2026 Defense Preparation Guide* (especially pp. 8–9 and 24–28), *PvP (2026) Briefing Packet* (pp. 3–9 and 14), and *Intro to PvP* (pp. 16–21). Those documents do not specify the scored database credentials/schema/query or client CIDR; the scripts prompt rather than invent them.
