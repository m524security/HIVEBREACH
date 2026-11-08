---
skill: password-recovery-deep-aggressive
mitre_attack_id: T1110
owasp_mapping: [A02, A04, A07]
difficulty: advanced
mode: deep-aggressive
tags: [hash-identification, rule-based-attacks, mask-attacks, combinator, hybrid-attacks, dictionary-attacks, prince, markov-chains, wordlist-generation, cracking-optimization]
---

# Deep Aggressive Mode Playbook: password-credential-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for password recovery and credential analysis. Offline cracking runs the full attack ladder with GPU optimization and target-specific wordlists. Online attacks are strictly RoE-gated with lockout discipline. Every hash is identified before a mode is chosen.

## Phase 1 — Pre-Flight Authorization Check

Reference: skills/network-security/service-enumeration.md

1. **Verify RoE** — Confirm that credential testing is explicitly authorized in the Rules of Engagement. If not authorized, halt and request additional authorization.
2. **Document Authorization** — Record the exact scope, services, and accounts authorized for credential testing. Include the time window and lockout policy.
3. **Confirm compute posture** — Check GPU availability: `hashcat --benchmark -m 1000`, `nvidia-smi` / `rocminfo`, and OpenCL device list `hashcat -I`.
4. **Inventory resources** — Wordlists (rockyou, SecLists, crackstation), rulesets (best64, rockyou-30000, OneRuleToRuleThemAll), and mask sets.
5. **Set session management** — Designate `--potfile-path` and restore points for resumability.

## Phase 2 — Hash Identification

1. Identify every hash format precisely before choosing a mode:
   - `hashid '31d6cfe0d16ae931b73c59d7e0c089c0'`
   - `hashcat --identify hash.txt`
   - Manual structure review: NTLM = 32 hex, LM = 32 hex split, bcrypt = `$2a$`/`$2b$`, PBKDF2 = `$pbkdf2-sha512$`, Kerberos = `$krb5tgs$`.
2. Map to hashcat mode:
   - NTLM `-m 1000`, LM `-m 3000`, Net-NTLMv1 `-m 5500`, Net-NTLMv2 `-m 5600`
   - Kerberos TGS-REP `-m 13100`, Kerberos AS-REP `-m 18200`
   - bcrypt `-m 3200`, sha512crypt `-m 1800`, sha256crypt `-m 7400`
   - PBKDF2-HMAC-SHA512 `-m 7100`, WPA/WPA2 `-m 22000`, TrueCrypt `-m 6211`
   - PKZIP `-m 17225`, RAR5 `-m 13000`, 7-Zip `-m 11600`, KeePass `-m 13400`
   - ASP.NET Identity `-m 17300`, Argon2 `-m 25600`
3. Cross-check with john where ambiguous: `john --list=formats | grep -i ntlm`.
4. Split hashes into per-mode files to maximize GPU efficiency and avoid failed-marker warnings.

## Phase 3 — Wordlist & Rule Preparation

1. **Target-specific wordlist generation (OSINT)**:
   - `cewl -d 3 -m 6 -w cewl_words.txt https://target.com`
   - `cewl -d 5 -m 4 --with-numbers --email -w intranet_words.txt https://intranet.target.com`
   - Add company names, founding years, product names, city names, and joint ventures to a seed list.
2. **Crunch mask generation**:
   - `crunch 8 10 "Company2023!@#%" -o masks.txt`
   - Company + year + special patterns: `crunch 10 14 Company?d?d?d! -o company_masks.txt`
3. **PRINCE generation**:
   - `pp64 --pw-min=8 --pw-max=20 --elem-cnt-min=2 seed_words.txt > prince_words.txt`
4. **Merge and prioritize**:
   - `cat cewl_words.txt crunch_words.txt prince_words.txt | sort -u > target_words.txt`
   - Run `target_words.txt` FIRST — organizational patterns crack the majority of accounts.
5. Select rulesets: best64.rule (fast), rockyou-30000.rule (deep), OneRuleToRuleThemAll.rule (exhaustive).

## Phase 4 — Attack Ladder (Offline, parallel escalation)

Reference: skills/network-security/protocol-exploitation.md (credential reuse after recovery)

1. **Dictionary attack** (baseline):
   - `hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -O -w 3 --potfile-path creds.pot`
2. **Rule-based attacks**:
   - `hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O`
   - `hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule -O`
   - `hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule -O`
3. **Target-specific wordlist attack** (high priority):
   - `hashcat -m 1000 hashes.txt target_words.txt -O -w 3`
4. **Combinator attack** (two lists merged):
   - `combinator.bin list_a.txt list_b.txt | hashcat -m 1000 hashes.txt -O`
   - `hashcat -m 1000 hashes.txt -a 1 words.txt words.txt`
5. **Mask attacks**:
   - `hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?l?l?l?d?d?d?s'`
   - `hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?d?d?d?d?d?d'`
   - Company masks: `hashcat -m 1000 hashes.txt -a 3 'Company?d?d?d!s'`
   - Use maskprocessor for offline generation then hashcat -a 0.
6. **Hybrid attacks**:
   - Wordlist + mask: `hashcat -m 1000 hashes.txt -a 6 rockyou.txt '?d?d?d?s'`
   - Mask + wordlist: `hashcat -m 1000 hashes.txt -a 7 '?u?l?l?l' rockyou.txt`
7. **PRINCE (association) attack**:
   - `hashcat -m 1000 hashes.txt prince_words.txt -a 9 --loopback`
8. **Markov-chain attacks** (john):
   - `john --wordlist=rockyou.txt --rules=Markov --markov hc-max=32 hash.txt`
   - `john --incremental hash.txt`
9. **GPU optimization for all attacks**:
   - `-O` (optimized kernels), `-w 3` (high workload), `--opencl-device-types 1` (GPU only), `--force` only if required
   - Split slow/fast hashes across devices; run slow hashes (bcrypt) on CPU with john `--fork=N`.
10. **Session management**:
   - `hashcat -m 1000 hashes.txt ... --potfile-path creds.pot`
   - Resume: `hashcat --restore --session ntlm_crack`
   - Check progress: `hashcat --potfile-path creds.pot --show -m 1000 hashes.txt`

## Phase 5 — Slow Hash Prioritization

1. bcrypt/PBKDF2/sha512crypt: wordlist + rules first, mask only on target-specific guesses:
   - `hashcat -m 3200 bcrypt.txt target_words.txt -r best64.rule -O`
   - `john --format=bcrypt --wordlist=target_words.txt --rules=all bcrypt.txt`
   - `john --format=pbkdf2-sha512 --wordlist=rockyou.txt pbkdf2.txt`
2. Encrypted document/container hashes (PKZIP, RAR5, KeePass, 7-Zip):
   - Identify with hashid; run target_words.txt before rockyou.
3. Never waste GPU time on unbounded masks for slow hashes — always prioritize target-specific material and rules.

## Phase 6 — Cracking Statistics & Strength Analysis

1. Extract cracked passwords: `hashcat --potfile-path creds.pot --show -m 1000 hashes.txt > cracked.txt`.
2. Statistical analysis: `pipal cracked.txt` for distribution, frequency, and pattern reporting.
3. Compute strength distribution (weak/medium/strong), identify reused patterns and shared prefixes.
4. Map cracked passwords to original sources for credential reuse assessment (hash_source field).

## Phase 7 — Online Credential Testing (Authorized Only)

Reference: skills/network-security/protocol-exploitation.md (weak credential paths)

1. **Password Spraying** — Use `hydra -L users.txt -p <common_password> <service>://<target>` for single-password spraying across many usernames. Use randomized delays (5-30 seconds between attempts).
2. **Targeted Brute-Force** — Use `hydra -l <user> -P wordlist.txt <service>://<target>` for single-user brute-force. Respect lockout thresholds.
3. **Credential Stuffing** — Test compromised credentials against the target's login endpoint. Note success rates.
4. **CrackMapExec** — Use `crackmapexec <protocol> <target> -u <user> -p <password>` for Windows domain credential testing:
   - SMB authentication testing
   - WMI authentication testing
   - WinRM authentication testing
   - LDAP authentication testing
   - MSSQL authentication testing
5. **Medusa** — `medusa -h <target> -U users.txt -P pass.txt -M ssh -t 4` for parallel protocol testing.
6. **Lockout discipline** — Determine threshold first (observe event 4740 or service response); stay under 75%; log every attempt.

## Phase 8 — MFA Assessment

1. Identify MFA implementation type (TOTP, SMS, push notification, hardware token).
2. Test MFA bypass techniques: session prediction, backup code enumeration, OAuth token reuse.
3. Assess MFA enrollment and recovery process for weaknesses.
4. Document whether bypass applies to real accounts or only test accounts.

## Phase 9 — Reporting & Credential Routing

1. List all successfully cracked credentials with instructions for verified access.
2. Provide password policy analysis with recommendations.
3. Calculate password strength distribution and identify patterns (pipal output).
4. Document all unsuccessful attempts, hash rates, and lockout events.
5. Route cracked credentials to vault-agent (AES-256-GCM encrypted) and to requesting agents.
6. Hand hash files with format annotations to audit-agent for chain-of-custody.

## Verification

1. Every cracked hash confirmed via potfile match (`hashcat --show`) — never assume.
2. Hash identification cross-checked by at least two methods (hashid + manual structure).
3. Attack metrics recorded per stage: hashes/sec, elapsed, cracked count.
4. Online attempts counted against lockout threshold; zero lockouts caused.
5. Cracked credentials verified by live authentication where authorized (crackmapexec/ssh).
6. Credentials handled via vault-agent only; no plaintext in logs or reports.

## Skill Library References
- skills/network-security/service-enumeration.md
- skills/network-security/protocol-exploitation.md
- skills/threat-intel/skill-playbook.md
