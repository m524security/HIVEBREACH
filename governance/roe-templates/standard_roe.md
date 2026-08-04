# Standard Rules of Engagement

> **Template version:** 2.0.0
> **ECC Pattern:** `governance/roe-templates/standard_roe.md`

---

## 1. Engagement Header

| Field | Value |
|-------|-------|
| **Engagement ID** | `ROE-{YYYY}-{NNNN}` |
| **Client** | `[Client Name]` |
| **Date Range** | `[Start Date]` — `[End Date]` |
| **Authorized Scope** | `[CIDR ranges / Domains / IPs]` |
| **Engagement Type** | `[External / Internal / Web App / Red Team / Purple Team]` |

---

## 2. Authorization Signatures

**Client Representative:**

- Name: `___________________________`
- Title: `___________________________`
- Signature: `___________________________`
- Date: `___________________________`

**Testing Lead (HiveBreach):**

- Name: `___________________________`
- Title: `___________________________`
- Signature: `___________________________`
- Date: `___________________________`

**Authorizing Executive:**

- Name: `___________________________`
- Title: `___________________________`
- Signature: `___________________________`
- Date: `___________________________`

---

## 3. Allowed Techniques (MITRE ATT&CK Mapped)

The following techniques are **authorised** for this engagement:

| Tactic | Technique ID | Technique Name | Restrictions |
|--------|-------------|----------------|-------------|
| Reconnaissance | T1595 | Active Scanning | Port scan rate ≤ 1000 pkts/sec |
| Reconnaissance | T1046 | Network Service Discovery | In-scope targets only |
| Resource Development | T1587 | Develop Capabilities | No 0-day development |
| Initial Access | T1190 | Exploit Public-Facing Application | CVSS ≥ 9.0 requires go/no-go |
| Execution | T1059 | Command and Scripting Interpreter | Log all commands executed |
| Persistence | T1098 | Account Manipulation | Test accounts only |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Document all escalation paths |
| Defense Evasion | T1070 | Indicator Removal on Host | Whitelisted tools only |
| Credential Access | T1003 | OS Credential Dumping | Offline cracking only; no plaintext capture |
| Discovery | T1082 | System Information Discovery | No exfiltration of PII |
| Lateral Movement | T1021 | Remote Services | In-scope subnet only |
| Collection | T1005 | Data from Local System | Mock data only; no real PII |
| Command and Control | T1071 | Application Layer Protocol | C2 IPs pre-approved |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Mock data only; < 1 MB |
| Impact | T1499 | Endpoint Denial of Service | Not authorised without explicit approval |

---

## 4. Prohibited Actions

The following are **strictly prohibited**:

- Social engineering of client employees without explicit written authorisation
- Denial of Service attacks exceeding agreed rate limits
- Modification or deletion of production data
- Exfiltration of Personally Identifiable Information (PII)
- Installation of persistent backdoors without documented approval
- Lateral movement beyond the authorised scope boundary
- Use of exploits known to cause service instability without a rollback plan
- Physical security testing without prior coordination
- Testing during blackout windows (see Section 6)
- Encryption of client data (e.g., ransomware simulation)

---

## 5. Allowed Tools

- **Reconnaissance:** nmap, masscan, rustscan, naabu, dnsrecon, subfinder, amass
- **Discovery:** ffuf, gobuster, httpx, katana
- **Vulnerability Scanning:** nuclei, nikto
- **Exploitation:** Metasploit (whitelisted modules only), sqlmap, custom PoC scripts
- **Credential Testing:** hydra, john, hashcat
- **Lateral Movement:** chisel, sshuttle, ligolo
- **Analysis:** jq, nuclei, custom analyzers

Tools not on this list must be **pre-approved** by the client and testing lead.

---

## 6. Time Window Restrictions

| Day | Window (UTC) | Notes |
|-----|-------------|-------|
| Monday—Thursday | 08:00 — 18:00 | Standard testing window |
| Friday | 08:00 — 14:00 | Reduced window |
| Saturday | **No testing** | Blackout |
| Sunday | **No testing** | Blackout |

**Emergency testing outside windows** requires verbal approval from the client POC and written confirmation within 2 hours.

**Client-declared blackout periods:**

- `[Blackout Period 1]`: `[Date Range]`
- `[Blackout Period 2]`: `[Date Range]`

---

## 7. Data Handling Rules

| Data Category | Handling Rule |
|---------------|--------------|
| Credentials (hashed) | Store encrypted; destroy within 30 days post-engagement |
| Credentials (plaintext — accidental capture) | Immediately report; delete upon confirmation |
| PII | Do not intentionally collect; destroy accidental captures immediately |
| Findings evidence | Encrypt at rest (AES-256-GCM); retain per client retention policy |
| Logs | Immutable audit trail via HMAC-SHA256 chain; retain 90 days |
| Screenshots | Store in project directory; strip metadata before delivery |

**Data classification per engagement:**

- All data collected in this engagement is **CLIENT CONFIDENTIAL**
- Shared only on a need-to-know basis within the HiveBreach testing team
- Delivered to client via encrypted channel

---

## 8. Communication Protocol

### Channel

- Primary: `[Signal / Slack / Email]`
- Emergency: `[Phone / SMS]`
- Escalation: `[Client POC]` → `[Testing Lead]` → `[HiveBreach Manager]`

### Reporting Cadence

- **Daily standup:** 09:00 UTC — status, blockers, findings review
- **Critical finding:** Immediate notification; within 1 hour written summary
- **Weekly summary:** Every Friday — full findings, progress, risk update
- **Final report:** Within 5 business days of engagement end

### Message Format

All operational messages must include:

- `[ENGAGEMENT_ID]` — Subject prefix
- `[AGENT_ID]` — Reporting agent
- `[TIMESTAMP]` — UTC timestamp
- `[ACTION]` — Description of action taken

---

## 9. Emergency Stop / Abort Procedure

### Criteria for Abort

- Unplanned service degradation or outage
- Discovery of PII exposure beyond scope
- Unauthorised access to production systems
- Client requests halt (any reason)

### Abort Steps

1. **Stop all active testing** immediately across all agents.
2. **Notify** the testing lead and client POC via primary communication channel.
3. **Capture** volatile state (sessions, active connections, in-flight requests).
4. **Revert** any changes where possible (roll back exploits, terminate tunnels).
5. **Document** the incident timeline and submit within 2 hours.
6. **Stand by** for client direction before resuming.

### Kill Switch

The client POC can trigger an abort by sending the codeword **`REDSTOP`** via any verified communication channel. All agents must cease testing within 60 seconds.

---

## 10. Post-Engagement Cleanup Requirements

| Action | Owner | Deadline |
|--------|-------|----------|
| Remove all testing tools from client systems | Testing Lead | End of engagement + 1 day |
| Terminate all reverse shells, tunnels, listeners | Testing Lead | End of engagement |
| Delete cached credentials from testing infrastructure | All agents | End of engagement + 1 day |
| Rotate any credentials created during testing | Client | End of engagement + 3 days |
| Archive audit logs (immutable, encrypted) | Audit Agent | End of engagement + 5 days |
| Deliver final report | Report Agent | End of engagement + 5 days |
| Destroy temporary test accounts | Testing Lead | End of engagement + 3 days |
| Purge PII from all systems and backups | All agents | Immediate upon discovery |

**Certification of Cleanup:**

> I, `___________________________`, confirm that all testing artefacts have been removed from client systems and that the engagement area has been restored to its pre-engagement state.

Signature: `___________________________` Date: `___________________________`

---

## 11. Scope Exclusions

The following are **explicitly out of scope**:

- `[System / Network / Application 1]`
- `[System / Network / Application 2]`
- `[System / Network / Application 3]`

---

## 12. Amendments

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0.0 | `[Date]` | `[Author]` | Initial ROE |
| 2.0.0 | `[Date]` | `[Author]` | ECC pattern alignment; added MITRE mapping |
