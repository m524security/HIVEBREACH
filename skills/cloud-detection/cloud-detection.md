# Cloud-Based Detection & Findings — Skill Playbook

**Mitre ATT&CK ID:** T1592 (Gather Victim Host Information) / T1535 (Unused/Unsupported Cloud Regions)
**OWASP Mapping:** A05:2021 – Security Misconfiguration
**Severity:** Low → Critical (varies)
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: cloud-detection-v1
category: cloud-detection
author: HiveBreach
mitre_attack_id: T1592
owasp_mapping:
  - A05:2021-SecurityMisconfiguration
  - A01:2021-BrokenAccessControl
tags:
  - cloud
  - aws
  - azure
  - gcp
  - serverless
  - s3
  - bucket
  - k8s
  - terraform
  - T1592
  - T1535
  - T1110
  - T1546
  - T1190
environments:
  - cloud
  - aws
  - azure
  - gcp
  - kubernetes
verification_required: sandbox
```

---

## 1. Cloud Asset Detection (External)

### 1.1 Cloud IP Range Mapping

| Provider | Range Data | Tool |
|---|---|---|
| AWS | https://ip-ranges.amazonaws.com/ip-ranges.json | `awsipranges` |
| Azure | https://www.microsoft.com/en-us/download/details.aspx?id=56519 | `az` |
| GCP | https://cloud.google.com/compute/docs/ip-addresses/reserved-static-external-ip-addresses | `gcloud` |

```bash
# Check if target IP belongs to a cloud provider
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.ip_prefix|contains("10.0.")) | .ip_prefix' > aws-cidrs.txt

# Enrich with whois
whois <target-ip> | grep -iE "NetName|CIDR|OrgName"
```

### 1.2 Cloud Fingerprinting

| Indicator | Provider |
|---|---|
| `us-east-1`, `amazonaws.com` hostnames | AWS |
| `azurewebsites.net`, `cloudapp.net`, `core.windows.net` | Azure |
| `appspot.com`, `googleusercontent.com`, `cloudfunctions.net` | GCP |
| `b-cdn.net`, `fastly.net`, `cloudfront.net` (CDN) | CDN / Edge |

```bash
# Resolve and inspect
dig +short <target>.amazonaws.com
curl -s https://<target> | grep -iE "server:|x-amz|azure|google"
# Enumerate bucket endpoints
curl -s https://<target>.s3.amazonaws.com/
```

---

## 2. Cloud Storage Misconfiguration (S3 / Azure Blob / GCS)

### 2.1 S3 Bucket Enumeration

```bash
# Bucket name guess + check (from DNS, CNAME, JS, git history)
curl -s https://<bucket>.s3.amazonaws.com/            # list if public
aws s3 ls s3://<bucket> --no-sign-request             # anonymous
aws s3 ls s3://<bucket> --profile <test-creds>        # with creds

# Enumerate common prefixes
for name in dev prod backup logs www assets media static; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://$name.s3.amazonaws.com/)
  echo "$name -> $code"
done

# Bucket takeover (subdomain taken over - T1584)
# If bucket returns 404 NoSuchBucket but DNS points to it -> takeover possible
```

**Findings:** Public-read bucket (High), public-write (Critical), missing server-side encryption, versioning disabled, cross-account access.

### 2.2 Azure Blob & GCS

```bash
# Azure
curl -s "https://<account>.blob.core.windows.net/?comp=list&restype=container"
# GCS
curl -s https://storage.googleapis.com/<bucket>
gsutil ls gs://<bucket>   # with creds
```

---

## 3. Cloud IAM & Identity Detection

### 3.1 Enumerating Access

```bash
# AWS - with obtained creds (authorized)
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam get-account-authorization-details --output json | jq -r '.UserDetailList[].UserName'

# Check for exposed access keys in code/git (see secrets-scanning skill)
# Git dorking for keys
git clone <target-repo> && grep -rEi "AKIA|ASIA" .

# Azure - with token
az account list --output table
az role assignment list --all

# GCP
gcloud auth list
gcloud projects list
gcloud iam service-accounts list
```

### 3.2 Privesc Paths (summary — see cloud-identity skill)

| Weakness | Escalation |
|---|---|
| `iam:CreatePolicyVersion` | Set admin policy on self |
| `iam:AttachRolePolicy` | Attach admin policy to own role |
| `iam:PassRole` + `ec2:RunInstances` | Launch instance with privileged role |
| `sts:AssumeRole` wide open | Assume any role |
| Lambda with `iam:PutRolePolicy` | Privilege on execution role |

---

## 4. Cloud Compute & Serverless Detection

### 4.1 Compute

```bash
# EC2 / VM
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,ImageId,PublicIpAddress]'
# Unattached public IPs / EIP
aws ec2 describe-addresses

# Metadata service (SSRF chain — inside the instance)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # EC2 (IMDSv1)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"  # EC2 role creds
# IMDSv2 requires token:
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Azure IMDS
curl -s "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" -H "Metadata: true"
# Azure managed identity token
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"

# GCP metadata (only on GCE)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Findings:** IMDSv1 enabled (High — SSRF→creds), SSRF to metadata with usable role creds (Critical), managed identity token leakage (Critical).

### 4.2 Serverless

```bash
# Lambda
aws lambda list-functions --output json | jq -r '.Functions[].FunctionName'
aws lambda get-function --function-name <name> --query 'Configuration.Environment'  # env vars (may leak secrets)
# Exposed function URL
curl -s https://<lambda-url>.lambda-url.<region>.on.aws/

# Azure Function
curl -s https://<func>.azurewebsites.net/api/<fn>
# GCP Cloud Function
curl -s https://<region>-<project>.cloudfunctions.net/<fn>
```

**Findings:** Lambda env var secrets, exposed function URLs without auth, permissive execution roles, insecure API gateway routing.

---

## 5. Cloud Networking Detection

```bash
# Security groups / NSG review
aws ec2 describe-security-groups --output json | jq -r '.SecurityGroups[].IpPermissions[]?.IpRanges[].CidrIp'
# Look for 0.0.0.0/0 exposure
# Load balancers
aws elbv2 describe-load-balancers --output json
# CloudFront distributions with weak origin
aws cloudfront list-distributions
```

**Findings:** 0.0.0.0/0 on SSH/RDP/DB (Critical), unrestricted egress, exposed ELB, misconfigured WAF.

---

## 6. Cloud Detection Automation

```bash
# Prowler - comprehensive AWS/Azure/GCP audit (authorized, read-only by default)
prowler aws -M csv -o prowler-out
prowler azure -M csv -o prowler-out
prowler gcp -M csv -o prowler-out

# ScoutSuite - multi-cloud audit
scout aws --profile <test>   # or: scoutsuite

# Pacu - AWS exploitation framework
pacu
# > import_keys <profile>
# > run iam__enum_users_roles_policies_groups
# > run s3__enum_buckets

# CloudSploit
cloudsploit scan --config config.js --json
```

---

## 7. Finding Template (Cloud)

```markdown
## [FINDING_ID] — [TITLE]
Class: [bucket|iam|compute|serverless|network|credential]
Provider: [AWS|Azure|GCP]
Resource: <resource ARN / URL>
Evidence:
  - `<output proving access>`
Reproduction:
  1. `<step>`
Impact:
  - `<what an attacker gains>`
Remediation:
  - `<AWS docs link / config fix>`
Mitre: T###
```

### Example

```markdown
## CLD-001 — Publicly writable S3 bucket
Class: bucket
Provider: AWS
Resource: s3://<company>-backup (us-east-1)
Evidence:
  - aws s3 ls s3://<company>-backup --no-sign-request  ->  SUCCESS (no auth needed)
  - aws s3 cp ./test.txt s3://<company>-backup/ --no-sign-request  ->  upload accepted (write confirmed)
  - Two independent anonymous requests succeeded
Reproduction:
  1. aws s3 ls s3://<company>-backup --no-sign-request
  2. Observe listing of 1,204 files
Impact: Attacker can read/modify/delete company backups; possible crypto-mining or malware hosting
Remediation: Enable Block Public Access; enforce bucket policy; enable versioning + SSE
Confidence: confirmed
```

---

## 8. Verification (Sandbox)

- [ ] Metadata SSRF verified against sandbox instance with IMDS enabled
- [ ] Bucket write test used non-destructive sample file, cleaned up
- [ ] IAM privesc verified with isolated test account only
- [ ] No real production data downloaded (R4 — sample one object only)
- [ ] Access keys never committed (R8)

---

## 9. Rate-Limit & Safe Request Policy

1. Cloud APIs throttle: use `--max-requests`, respect `Throttling`/`429` responses
2. Never enumerate buckets aggressively against production — cap at 200 bucket-name requests/min
3. Metadata SSRF: single request to `/latest/meta-data/iam/security-credentials/` to enumerate role names, then only the relevant role — no full credential dump to logs (R4/R8)
4. Terminate on repeated 403/Throttling (indicates WAF or detection) — switch to passive

---

## 10. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1592 | Gather Victim Host Information | Asset fingerprint |
| T1535 | Unused/Unsupported Cloud Regions | Legacy resource abuse |
| T1190 | Exploit Public-Facing Application | Metadata/SSRF chains |
| T1110 | Brute Force | Cloud console/API auth |
| T1546 | Event Triggered Execution | Lambda/automation abuse |
| T1078 | Valid Accounts | Stolen/lateral cloud creds |
| T1584 | Compromise Infrastructure | Bucket takeover |
| T1552.005 | Cloud Instance Metadata API | IMDS credential theft |

---

## 11. References

- Prowler: https://github.com/prowler-cloud/prowler
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- CloudSploit: https://github.com/aquasecurity/cloudsploit
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- AWS IAM privesc (Rhino): https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation

---

*This playbook is for authorised security testing only. Cloud enumeration and metadata access are high-impact — verify scope per R1, sandbox privesc paths per R5, and never exfiltrate full datasets per R4.*
