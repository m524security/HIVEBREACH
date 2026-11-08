---
skill: state-verification-and-compliance-deep-aggressive
mitre_attack_id: T1082
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [system-discovery, compliance-check, configuration-drift, change-detection, state-verification, osquery, ansible, integrity-verification, idempotent-recheck]
---

# Deep Aggressive Mode Playbook: state-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for system state verification, baseline enforcement, and drift detection. Every assertion is verified by two independent methods and re-checked for idempotent reproducibility.

## Phase 1 — Pre-Exploitation Baseline Snapshot

Reference: skills/dfir/skill-playbook.md, skills/dfir/incident-triage.md

1. Receive checkpoint request specifying target(s), timing (pre/post), and scope (system, user, service, registry, file, network).
2. Establish access to target via existing session handle (Ansible WinRM, PowerShell PSRemoting, SSH).
3. Capture baseline state snapshot with all relevant categories:
   - System: OS version, kernel, hostname, domain, architecture, uptime, patches
   - Users: Local users, domain users (if joined), groups, privileges, SIDs, last logon
   - Processes: Running processes with PID, user, CPU/memory, parent process, executable path
   - Services: Installed services, status, start type, account, binary path
   - Registry (Windows): Selected keys (Run, RunOnce, services, security policies)
   - Network: Interfaces, IPs, listening ports, active connections, DNS configuration, ARP table
   - Filesystem: Selected directory listings, file attributes, hashes, ACLs
   - Scheduled Tasks: Cron jobs (Linux), scheduled tasks (Windows), trigger/action details
4. Capture volatile data first (processes, sockets, sessions), then persistent data (files, registry).

## Phase 2 — osquery State Collection

1. Run declarative SQL queries via osqueryi for portable evidence:
   ```bash
   osqueryi --json "SELECT pid, name, path, uid, parent FROM processes;"
   osqueryi --json "SELECT pid, name, port, address, protocol FROM listening_ports;"
   osqueryi --json "SELECT username, uid, directory, shell FROM users;"
   osqueryi --json "SELECT name, command, path FROM crontab;"
   osqueryi --json "SELECT name, path, args, source FROM startup_items;"
   osqueryi --json "SELECT path, md5, sha256 FROM file WHERE path LIKE '/etc/%';"
   ```
2. For scheduled continuous baseline drift, configure osqueryd scheduled queries writing to a results log.
3. For Windows hosts, run osquery via `osqueryi --json` over the PowerShell remoting channel and cross-check against Get-CimInstance output.

## Phase 3 — Ansible State Verification

1. Use ad-hoc modules for single checks:
   - `ansible win -m win_shell -a "Get-LocalUser" -i inventory.yml`
   - `ansible linux -m shell -a "cat /etc/passwd" -i inventory.yml`
   - `ansible all -m setup -i inventory.yml` (comprehensive fact gathering)
2. Write a state verification playbook that asserts desired state without modifying the target:
   ```yaml
   - hosts: all
     tasks:
       - name: assert expected user exists
         ansible.builtin.command: getent passwd backdoor
         register: out
         failed_when: out.rc != 0
       - name: assert no unexpected listening ports
         ansible.builtin.command: ss -tlnp
         register: ports
         changed_when: false
   ```
3. Run in check mode to prove idempotency: `ansible-playbook verify-state.yml --check`.
4. Re-run twice and confirm identical output (idempotent re-check methodology).

## Phase 4 — Configuration Baseline Checks

1. Compare captured state against CIS benchmark and STIG baselines:
   - Windows password policy: `net accounts`, `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
   - Audit policy: `auditpol /get /category:*`
   - Service configurations: allowed services, disabled legacy protocols
   - Linux: `/etc/ssh/sshd_config` PermitRootLogin, /etc/pam.d password policies, file permissions
2. Score each control: compliant, non-compliant, not-applicable.
3. Record remediation suggestions for non-compliant findings.
4. Annotate each control with the framework control ID (CIS section, STIG rule).

## Phase 5 — Drift Detection

1. If a pre-exploitation snapshot exists, compute delta by comparing each category:
   ```python
   import json
   pre = json.load(open("pre.json")); post = json.load(open("post.json"))
   added = set(post["users"]) - set(pre["users"])
   removed = set(pre["users"]) - set(post["users"])
   modified = {k for k in pre["users"] & post["users"] if pre["users"][k] != post["users"][k]}
   ```
2. Flag changes: added, removed, modified entries with before/after values.
3. Classify drift as expected (documented change) or suspicious (exploitation artifact, compromise).
4. Cross-reference suspicious drift against threat-intel persistence indicators (skills/threat-intel/skill-playbook.md): scheduled tasks, autoruns, new services, unexpected user accounts.
5. Map each suspicious drift to the ATT&CK technique it enables (T1547 persistence, T1543 create/modify system process).

## Phase 6 — Integrity Verification

1. File integrity via two independent methods:
   - `sha256sum /path/to/bin`
   - `Get-FileHash /path/to/bin -Algorithm SHA256` (Windows) or `certutil -hashfile`
   - osquery: `osqueryi --json "SELECT path, sha256 FROM file WHERE path='/path/to/bin';"`
2. Package integrity:
   - `rpm -V package`, `dpkg --verify package`
   - `sigcheck.exe -a file.exe` against published hashes
3. Hosts/DNS integrity: compare `/etc/hosts`, DNS resolver config, hosts file against baseline.
4. Only accept an integrity verdict when both methods agree.

## Phase 7 — Exploitation Claim Verification

Verify exploitation claims by independently checking specific assertions:
- "User created" -> Check /etc/passwd, `getent passwd`, Get-LocalUser, and osquery users table
- "Service installed" -> Check systemctl status, Get-Service, and osquery services table
- "Registry key added" -> Test-Path registry path plus `reg query`
- "File created" -> Test-Path file with hash verification (Get-FileHash + certutil)
- "Listener opened" -> `ss -tlnp`, `netstat -ano`, and osquery listening_ports
1. Score verification confidence based on evidence strength (direct >= indirect >= inferred).
2. Idempotent re-check: repeat the assertion with a different tool; confidence is reduced if methods disagree.

## Phase 8 — Output and Handoff

1. Serialize snapshot as structured JSON with timestamps per metric.
2. Output structured state report with full snapshot, delta, and verification results.
3. Send pre/post state deltas to analyzer-agent for attack chain enrichment.
4. Send compliance deviation scores to risk-agent.
5. Send exploitation verification results (confirmed/denied claims) to validator-agent.
6. Log all state capture, delta computation, and verification actions to audit-agent.

## Verification

1. Each state assertion is verified via two different methods: direct check (native OS command) and alternative method (different tool/API), e.g., user existence via net user and Get-LocalUser and osquery users table.
2. File integrity verified via Get-FileHash and certutil -hashfile and osquery file table.
3. Idempotent re-check: the same assertion re-run with a different tool produces the same result.
4. Confidence reduced if methods disagree; never report unverified assertions as confirmed.
5. Drift classified as expected or suspicious before reporting.
6. No sensitive data exposed in state reports (passwords, keys masked).

## Skill Library References
- skills/threat-intel/skill-playbook.md
- skills/dfir/skill-playbook.md
- skills/dfir/incident-triage.md
