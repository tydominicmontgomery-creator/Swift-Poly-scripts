# Chomper Team 15 — CentOS 10 Hardening Toolkit

## Competition facts
- Host: `chomper.misty.view`
- Internal address: `192.168.1.53`
- Team-facing pattern: `172.16.XX.53`; Team 15 expected address `172.16.15.53` (verify on host).
- Authorized Linux users: `user`, `spikeweed`, `root`
- Scored service: Database
- Engine, version, scored account/schema/query, TLS requirements and scoring-client CIDR are not supplied in the briefing.
- An external HTTP/application server may connect to Chomper's DB; include its verified source address in the DB allowlist.
- Do not touch the router, other teams during the grace period, competition flags, or snapshots without Green Team approval.

## Backup and report paths
- Backups: `/root/chomper-hardening/backups/YYYYMMDD-HHMMSS/`
- Last backup pointer: `/root/chomper-hardening/LAST_BACKUP`
- Reports: `/var/log/chomper-hardening/`
- Firewall state created by this toolkit: `/var/lib/chomper-hardening/`

Backups may contain password hashes, private keys, and secrets. Never commit them to GitHub. Host configuration backups are not database data backups.

## Runbook — run one script at a time

Keep a second working SSH session or console open before network/SSH changes. Review each report and check scoring before proceeding.

### 1. Backup

```bash
sudo ./scripts/00_backup.sh
```

Creates a root-only backup of selected configuration plus a baseline of addresses, routes, listeners, services, firewall zones and SELinux mode.

### 2. Host hardening

```bash
sudo ./scripts/01_host_hardening.sh
```

Verbose audit/remediation/verification:
- checks OS identity, UID-0 accounts, sudoers syntax and privileged groups;
- reports login-capable accounts outside `root`, `user`, `spikeweed`; prompts before locking them and setting `/sbin/nologin` (does not delete home/data);
- prompts before removing unlisted wheel members;
- installs a conservative SSH drop-in (`PermitEmptyPasswords no`, `MaxAuthTries 4`, `LoginGraceTime 60`, `X11Forwarding no`) only if absent, validates with `sshd -t`, reloads active SSH;
- checks standard passwd/group/shadow/gshadow modes and offers repairs;
- reports SELinux, updates, running services, listeners and timers.

It does not delete users, disable root SSH/password authentication, disable SELinux, remove packages, or delete unknown services/tasks. Unknown items require review, not blind deletion.

### 3. Initial firewall reachability

```bash
sudo ./scripts/02_firewall_initial.sh
```

Finds active firewalld zone (prompts only if multiple), detects TCP listeners for SSH, common DB processes and common HTTP servers, and adds temporary broad IPv4/IPv6 rules after `OPEN`. If no DB listener is detected, it prompts for the verified DB port or allows skipping. It does not assume port 3306. It does not enable firewalld if stopped.

**This phase deliberately opens detected ports to all sources temporarily. Run step 4 promptly after obtaining source CIDRs.** HTTP is opened only if a web server is listening on Chomper. If the HTTP application is on another machine and connects to Chomper's DB, allow that app server as a DB source in step 4.

### 4. Firewall lockdown

```bash
sudo ./scripts/03_firewall_lockdown.sh
```

Prompts for verified source CIDRs by service:
- SSH: administrator network.
- DB: scoring-client network AND any remote app/web server that connects to the DB. Multiple CIDRs can be comma-separated. Supply IPv4 and/or IPv6 networks as applicable; a family with no matching CIDR is deliberately left broad and retained in the state file for a later lockdown run.
- HTTP: legitimate HTTP client networks, if detected.

It adds scoped rules first, then removes only the exact broad rules recorded as created by step 3. It does not remove unrelated firewall rules. Blank source leaves that service broad and reports it. Do not guess CIDRs: `172.16.15.53` is Chomper's expected host IP, not necessarily the scoring client's source.

After lockdown, test a new SSH session, exact scored DB transaction, dependent HTTP application, and denied access from an unauthorized source. Existing broad firewalld service/port allows may still expose the same port; inspect runtime and permanent zone policy and remove only verified unnecessary rules.

### 5. Database-specific hardening — deferred

```bash
sudo ./scripts/04_database_hardening.sh
```

Discovery-only. No database changes. Once engine/version and scored transaction are known, build an engine-specific script. Do not run generic secure-installation wizards or revoke grants blindly.

## Script reference

| Script | Purpose | Changes |
|---|---|---|
| `00_backup.sh` | Central root-only configuration backup | Backup only |
| `01_host_hardening.sh` | Verbose host audit and interactive remediation | Yes, confirmed fixes |
| `02_firewall_initial.sh` | Detect zone/listeners; temporary broad rules | Yes, after `OPEN` |
| `03_firewall_lockdown.sh` | Restrict toolkit-created broad rules to verified sources | Yes, after `LOCKDOWN` |
| `04_database_hardening.sh` | DB discovery pending engine identification | No |

## Limitations
- All scripts pass `bash -n`, but have not been tested on the live competition VM.
- Initial firewall rules are intentionally broad and temporary.
- Listener detection relies on process names; containers/proxies/unusual engines may require manual port input.
- Firewalld rules do not change database bind addresses, DB authentication/TLS, or SELinux labels.
- The host script does not prove malware; unknown services/accounts are findings for investigation.
- DNF updates are previewed, not installed.
- Scored-user password changes require the competition PCR process and dependent-client updates.
- Never change `/root/flag.txt`, `/user/flag.txt`, their permissions/ownership, or other competition flags.
- Never commit backups, reports, credentials, password hashes, private keys, database dumps, or competition secrets.

## Source basis
Based on supplied *PvP 2026 Defense Preparation Guide* (Linux baseline and Chomper database sections, pp. 9 and 24–28), *PvP (2026) Briefing Packet* (scope and Chomper details, pp. 3–9 and 14), and *Intro to PvP* (scripting/firewalls/backups/password changes, pp. 16–21). The supplied materials do not specify DB engine/query or scoring-client CIDR; the toolkit defers or prompts rather than inventing them.
