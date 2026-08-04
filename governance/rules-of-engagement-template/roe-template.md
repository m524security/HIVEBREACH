# Rules of Engagement (ROE) Document Template

**HiveBreach — Authorised Security Testing**

| Field | Value |
|---|---|
| Engagement ID | `ROE-YYYYMMDD-XXX` |
| Client | [Client Name] |
| Authorised Tester(s) | [HiveBreach Agent Team] |
| Issue Date | YYYY-MM-DD |
| Expiry Date | YYYY-MM-DD |
| Classification | CONFIDENTIAL |

---

## 1. Authorisation Statement

This document constitutes the **Rules of Engagement** (ROE) for the authorised security testing engagement described herein. Any testing activities conducted outside the scope, window, or constraints defined below are **unauthorised** and must cease immediately.

**By signing below, the Client confirms authorisation for HiveBreach to conduct the activities described in this document, subject to the limitations and conditions herein.**

---

## 2. Scope of Testing

### 2.1 In-Scope Targets

| Category | Targets |
|---|---|
| Domains | `*.target.com`, `target.io`, `app.target.com` |
| IP Ranges | `10.10.10.0/24`, `192.168.1.0/24` |
| Cloud Accounts | AWS account `123456789012`, Azure tenant `target.onmicrosoft.com` |
| Repositories | `github.com/target/webapp`, `github.com/target/mobile` |
| APIs | `api.target.com/*`, `graphql.target.com/graphql` |
| Mobile Apps | `com.target.app` (Android), `com.target.ios` (iOS) |
| External Footprint | All public-facing subdomains and services owned by target.com |

### 2.2 Out-of-Scope Targets

| Category | Targets | Rationale |
|---|---|---|
| Production DB clusters | `db.target.com:3306`, `db.target.com:5432` | Read-only by agreement |
| Payment processor | `payments.target.com` | Third-party managed (Stripe) |
| HR systems | `hr.target.com` | Contains PII, excluded |
| [Third-party SaaS] | `target.slack.com`, `target.atlassian.net` | Not owned by client |
| End-user workstations | `DESKTOP-*`, `LAPTOP-*` | End-user impact avoidance |
| [Specific critical infra] | `core-router.target.com` | Network stability |

### 2.3 Target Validation (Scope Enforcement)

All targets must be validated against this scope document before any testing action:

1. **Domain check** — Is `*.target.com` in the in-scope list?
2. **IP check** — Is the IP within a listed CIDR?
3. **Cloud check** — Is the account/resource tagged as authorised?
4. **Exclusion check** — Is the target on the out-of-scope list?

If any check fails → **DO NOT TEST**. Log the target as a scope boundary exception and alert the operator.

---

## 3. Testing Window

| Parameter | Value |
|---|---|
| Start Date/Time | `YYYY-MM-DD HH:MM UTC` |
| End Date/Time | `YYYY-MM-DD HH:MM UTC` |
| Active testing hours | `09:00 – 18:00 UTC` (Mon–Fri) |
| Blackout periods | `YYYY-MM-DD` (change freeze), `YYYY-MM-DD` (client audit) |
| Extension process | Written request 48h before expiry; max 2 extensions |

### Time Zone Notes
- All times in UTC unless otherwise agreed
- Client on-call engineer must be available during active hours
- If impact is detected outside active hours → emergency stop applies

---

## 4. Rate Limits & Throttling

### 4.1 Network Scanning

| Tool | Max Rate | Notes |
|---|---|---|
| nmap | 500 pkts/sec | `--max-rate 500` |
| masscan | 1,000 pkts/sec | External; 10,000 pkts/sec for internal ranges |
| ffuf / gobuster | 50 req/sec | Web directory fuzzing |
| Hydra / Medusa | 5 attempts/min per account | Credential testing — sandbox only |

### 4.2 Web Application Testing

| Action | Limit | Notes |
|---|---|---|
| Concurrent requests | 10 threads | Per tool instance |
| Login attempts | 5 per user per minute | Excludes sandbox tests |
| Large payloads | < 10 MB | For file upload testing |
| Bypass attempts | 100 req/min | WAF rule testing |

### 4.3 API Testing

| Action | Limit | Notes |
|---|---|---|
| GraphQL batched queries | 100 aliases per request | Avoid query cost DoS |
| Pagination busting | 1,000 records per endpoint | Sufficient for PoC |
| Fuzzing | 50 req/min | Per endpoint |

### 4.4 Automatic Stop Conditions

Testing **must stop immediately** if any of the following exceeds thresholds:

| Metric | Threshold | Action |
|---|---|---|
| CPU on target host | > 90% for > 30s | Pause all scanning |
| Network latency increase | > 500ms from baseline | Pause scanning |
| Error rate increase | > 10% 5xx responses | Pause, investigate |
| Service crash / unavailability | Any occurrence | Emergency stop, notify client |

---

## 5. Credential Testing Rules

### 5.1 General Policy

**All credential testing is restricted to sandbox environments by default.**

| Environment | Credential Testing Allowed? | Notes |
|---|---|---|
| Production systems | NO | Never test credentials against production |
| Staging / UAT | NO | Unless explicitly authorised in writing |
| Dedicated test tenant | YES | Client-provisioned |
| Sandbox / isolated | YES | Full credential testing permitted |
| Shadow IT discovery | Review only | Passive — no login attempts |

### 5.2 Password Spraying

- Allowed in **sandbox only**
- Max 5 passwords per user over a 24-hour window
- Must use accounts provisioned for testing (not real users)
- Lockout policy must be documented before testing

### 5.3 Credential Dumping / Extraction

- **Never** dump LSASS/credentials from production systems
- Credential extraction on sandbox systems only
- Extracted credentials must be encrypted at rest (AES-256-GCM)
- Plaintext credentials must never be stored in logs or reports
- All test credentials must be rotated after engagement

### 5.4 Token Handling

- API tokens discovered during testing → immediate revocation and rotation
- Session tokens must not be used for lateral movement without explicit authorisation
- OAuth refresh tokens must be discarded after PoC capture

---

## 6. Wireless Testing

### 6.1 Separate Authorisation Required

Wireless testing is **NOT** authorised by this document unless explicitly checked below:

```
☐ Wireless testing IS authorised under this ROE (additional terms apply)
☑ Wireless testing is NOT authorised (must obtain separate authorisation)
```

### 6.2 Wireless Testing Terms (if authorised)

| Parameter | Value |
|---|---|
| SSID(s) in scope | `[SSID-1]`, `[SSID-2]` |
| Physical locations | `[Building A, Floor 3]`, `[Building B, Lobby]` |
| Testing hours | `22:00 – 06:00` (after business hours) |
| Deauth frames | ⛔ Prohibited |
| Evil twin / rogue AP | ⛔ Prohibited |
| Handshake capture | ✅ Allowed (target SSIDs only) |
| WPA cracking | ✅ Allowed (offline, sandbox only) |
| WPS testing | ✅ Allowed |

---

## 7. Data Handling & Retention

### 7.1 Classification of Findings

| Classification | Definition | Storage | Examples |
|---|---|---|---|
| Critical | Immediate threat to confidentiality, integrity, or availability | Encrypted, air-gapped | Plaintext credentials, RCE PoC, PII dumps |
| High | Significant security gap | Encrypted, access-controlled | SQLi with data extraction, lateral movement paths |
| Medium | Notable finding | Encrypted, project-only | Missing headers, verbose error messages |
| Low | Informational | Standard project storage | Software version disclosure, missing CSP |
| Internal | Operational data related to testing | Standard storage | Scan logs, configuration files |

### 7.2 Data Lifecycle

| Phase | Action | Timeline |
|---|---|---|
| Collection | Encrypt at rest (AES-256-GCM) | Immediate |
| Storage | HiveBreach vault (AES-256 encrypted), access logged | During engagement |
| Analysis | Accessed only by authorised agents | During engagement |
| Delivery | Report delivered via encrypted channel | At engagement end |
| Retention | Client data retained per agreement | 90 days post-engagement |
| Destruction | Cryptographic erase + overwrite | After retention period |

### 7.3 Prohibited Data Storage

The following data must **never** be stored outside the encrypted vault:

- Plaintext passwords or credential hashes
- PII (personally identifiable information) beyond scope of engagement
- Credit card numbers or financial data
- Health records (HIPAA protected)
- Full database dumps (sample only for PoC)

### 7.4 Breach Notification

If test data is suspected to be exposed or compromised:

1. **Immediately** halt all testing
2. Notify client security contact within 1 hour
3. Preserve all logs for forensic analysis
4. Rotate all vault keys and access tokens
5. Conduct joint incident review with client

---

## 8. Emergency Contact & Kill-Switch

### 8.1 Contacts

| Role | Name | Phone | Email | Availability |
|---|---|---|---|---|
| Client Primary | [Name] | [+1-555-0100] | [email@target.com] | 24/7 |
| Client Escalation | [Name] | [+1-555-0101] | [escalation@target.com] | 24/7 |
| HiveBreach Lead | [Name] | [+1-555-0200] | [lead@hivebreach.io] | 24/7 |
| HiveBreach SOC | [Name] | [+1-555-0201] | [soc@hivebreach.io] | 24/7 |

### 8.2 Kill-Switch Activation

A kill-switch may be activated by any of the following parties:

1. **Client** — Any client representative listed above
2. **HiveBreach Lead** — Engagement lead or SOC analyst
3. **Automated** — System detects threshold breach (Section 4.4)

### 8.3 Kill-Switch Procedure

```
KILL-SWITCH TRIGGERED
    │
    ▼
┌─────────────────────────────────────────────┐
│ IMMEDIATE ACTIONS (within 60 seconds)        │
│                                              │
│ 1. Halt all active testing processes         │
│ 2. Terminate all agent actions in progress   │
│ 3. Revoke all temporary access tokens        │
│ 4. Snapshot current state for audit          │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│ CONTAINMENT (within 5 minutes)               │
│                                              │
│ 1. Rotate API keys and credentials used      │
│ 2. Close all tunnel/proxy connections        │
│ 3. Disconnect from target network            │
│ 4. Notify client security contact            │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│ RESUMPTION (requires ALL of):               │
│                                              │
│ 1. Root cause identified and documented      │
│ 2. Client confirms it is safe to resume      │
│ 3. New ROE addendum signed (if required)     │
│ 4. HiveBreach lead authorises resumption     │
└─────────────────────────────────────────────┘
```

### 8.4 Emergency Stop Word

Plain-text keyword that halts all automated agents immediately:

```
KILLSWITCH_2026
```

This stop word must be recognised by all scheduler-agent message processing.

---

## 9. Reporting Requirements

### 9.1 Deliverables

| Deliverable | Due | Format |
|---|---|---|
| Preliminary Findings | Within 48h of discovery | Secure PDF |
| Draft Report | 5 business days post-engagement | Secure PDF |
| Final Report | 10 business days post-engagement | Secure PDF + raw data |
| Evidence Package | 10 business days post-engagement | Encrypted archive |

### 9.2 Report Contents

- Executive summary (non-technical audience)
- Methodology overview
- Findings by severity (Critical → Low)
- Detailed findings with reproduction steps
- Evidence (truncated for sensitive data)
- Remediation guidance with priority
- Appendices: tools used, IOCs, timeline

---

## 10. Legal & Compliance

### 10.1 Governing Law

This engagement is governed by the laws of [Jurisdiction]. The Client and HiveBreach agree to resolve disputes through binding arbitration per [Clause].

### 10.2 Confidentiality

All findings, data, and methodology are confidential between HiveBreach and the Client. Neither party shall disclose engagement details without written consent, except as required by law.

### 10.3 Limitation of Liability

Testing is performed on an "as-is" basis. HiveBreach shall not be liable for indirect damages arising from security testing, except in cases of gross negligence.

### 10.4 Destruction of Data

Upon engagement closure, all client data will be securely erased within 90 days unless a longer retention period is contractually agreed.

---

## 11. Signatures

| Party | Name | Title | Signature | Date |
|---|---|---|---|---|
| Client | | | | |
| HiveBreach | | | | |

---

## 12. Document History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | YYYY-MM-DD | HiveBreach | Initial version |
| 1.1 | YYYY-MM-DD | HiveBreach | [Amendments] |

---

*This ROE is a living document. Any amendment requires written agreement from both parties.*
