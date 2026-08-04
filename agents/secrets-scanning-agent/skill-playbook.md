# Skill Playbook: secrets-scanning-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for secrets and credential leakage discovery. Embeds the technique chains from `skills/api-security/api-key-leaks.md`. Detection is default; credential activation requires explicit authorization.

## Phase 1 — Scope & Credential Surface Mapping

1. **Enumerate Target Surface** — Collect from recon-agent: org/account names, repository lists, container registries, CI/CD hosts, cloud account IDs, subdomains. Record which systems the client owns and authorizes.
2. **Credential Profile Build** — Identify the platforms the organization likely uses (GitHub org, AWS account IDs in DNS/TXT, Slack workspace, Stripe, Google Cloud project names). This drives targeted regex and dorks.
3. **Define Verification Boundaries** — Record the authorized test endpoints (staging) vs. production. Default policy: zero-touch detection only.
4. **Pattern Rule Setup** — Configure gitleaks custom rules (`~/.gitleaks.toml`) with org-specific keywords plus the standard credential formats: `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `sk_live_[a-zA-Z0-9]{24}`, `xox[baprs]-`, `AIza[0-9A-Za-z_-]{35}`, `sk-[a-zA-Z0-9]{20,}`, private key headers.

## Phase 2 — Git History Mining

1. **Clone Deeply** — `git clone --mirror git@github.com:org/repo.git` (mirror pulls all branches, tags, and refs); also fetch reflogs and stash.
2. **Full History Scan** — `gitleaks git --remote-url . --log-opts="--all --reflog" --report-format json --report-path leaks.json`; `trufflehog git git@github.com:org/repo --results-verification --only-verified --since-commit <oldest>`.
3. **Blob Walk** — `git log -p --all | rg -i "AKIA|ghp_|password|secret|token"` for deleted-but-recoverable content; `git fsck --full --lost-found && git show <dangling-blob>`.
4. **Targeted File Scans** — `gitleaks detect --source . --log-opts="--all" --redact=false --path-glob '.env*'`; `git log --all --diff-filter=D -- .env.production --name-only`; `git log -p --all -- .env.production config/credentials.yml.enc`.
5. **Commit Attribution** — For each leak: `git log --format="%H|%an|%ae|%ad" -S "<secret>" --all` to record author, date, and commit of exposure. Verify whether the secret is still live by checking the service (zero-touch where possible, e.g., token type format + expiry fields).
6. **Repository Reflog/Stash** — `git reflog show --all` and `git stash list`; dump and scan.

## Phase 3 — Public Repository & Code Search Dorking

1. **GitHub Code Search (authorized org only)** — Dork queries:
   - `org:acme "password" in:file`
   - `org:acme "aws_secret_access_key" in:file`
   - `org:acme "BEGIN RSA PRIVATE KEY" in:file`
   - `org:acme "sk_live_" in:file`
   - `org:acme "AKIA" in:file extension:env`
   - `org:acme "client_secret" in:file`
   - `org:acme "api_key" extension:json`
   - `org:acme filename:.npmrc` / `filename:.pypirc` / `filename:credentials.json`
   - `org:acme "ghp_" in:file`
2. **Sourcegraph API** — `curl -G 'https://sourcegraph.com/.api/search/stream' --data-urlencode 'q=context:global org:acme AKIA file:env' --data-urlencode 'v=V3'`; iterate with `-i` pattern for file-type-specific scans.
3. **GitLab Search** — if client uses GitLab: `curl -G 'https://gitlab.com/api/v4/search' --data-urlencode 'scope=blobs' --data-urlencode 'search=AKIA' --header 'PRIVATE-TOKEN: <scope-token>'`.
4. **shhgit Continuous Watch** — `shhgit -terms "acme,org.com,AWS" -liveness -webhooks` to catch new leaks.
5. **Gist/Paste Mining** — Search gists and public pastes for org keywords combined with credential formats (only within client scope).

## Phase 4 — Artifact, Config & Container Inspection

1. **CI/CD Config Audit** — Download and scan: `.github/workflows/*.yml`, `.gitlab-ci.yml`, Jenkinsfile, `.circleci/config.yml`, Travis `*.yml`. Look for secrets in env blocks, curl headers, and base64-encoded payloads.
2. **Env & Config Templates** — Scan for `.env`, `.env.production`, `.env.example`, `config/settings.yml`, `appsettings.json`, `web.config`, `application.properties`, `credentials.yml.enc` (if key leaked separately).
3. **Container Image Layers** — `docker pull image:tag && docker save image:tag -o img.tar && tar -xvf img.tar`; for each layer directory run `gitleaks detect --source <layer> -r layer.json`; also `docker history --no-trunc image:tag | rg -i "key|token|password"`.
4. **Package & Binary Mining** — NPM tarballs (`npm pack`), wheels (`pip download`), and compiled binaries; scan with `strings` + ripgrep for `AKIA|ghp_|sk_live_|-----BEGIN`.
5. **Mobile Binaries** — If mobile-app-agent shares APK/IPA, scan resources, strings, and JS bundles: `rg -i "AKIA|sk-|ghp_|api[_-]?key" jadx_out/ res/ assets/`.

## Phase 5 — Network & Cloud Exposed-Surface Probing

1. **Exposed .git** — For each recon subdomain: `curl -sk https://target.tld/.git/config`; if `[core]` returned, dump with `git-dumper` or manually: `curl -sk https://target.tld/.git/HEAD` then walk `.git/objects/`.
2. **Exposed Config Files** — `nuclei -t ~/nuclei-templates/exposures/ -u https://target.tld -severity high,critical`; manual probes: `/.env`, `/.env.production`, `/config.json`, `/debug/verbose`, `/actuator/env`, `/.npmrc`, `/.pypirc`.
3. **Cloud Metadata & Buckets** — Metadata endpoint (authorized infra only): `curl -sk http://169.254.169.254/latest/meta-data/iam/security-credentials/`; bucket checks: `curl -sk https://<org>-assets.s3.amazonaws.com/` and `https://<org>-backup.s3.us-east-1.amazonaws.com/`.
4. **API Documentation Leaks** — Swagger/OpenAPI endpoints often embed example tokens or admin keys: probe `/swagger-ui.html`, `/api-docs`, `/openapi.json`, `/v2/api-docs`.
5. **Source Maps** — `.js.map` files: `curl -sk https://target.tld/assets/app.js.map | jq '.sources'` and grep sources content for secrets and endpoints.

## Phase 6 — Secret Validation & Blast Radius (Authorization-Gated)

1. **Zero-Touch Format Check** — Decode JWT: `jwt_tool <token> -d` and inspect claims (issuer, scope, expiry). Parse AWS keys for region/account hints via AWS docs/`sts get-caller-identity` ONLY on approved staging accounts.
2. **Authorized Validation** — With client approval against staging/test endpoints only:
   - AWS: `aws sts get-caller-identity --profile leaked` to confirm validity and scope (read-only, list-only).
   - GitHub token: `curl -H "Authorization: token ghp_..." https://api.github.com/user` (note repos/orgs exposed).
   - Slack: `curl -H "Authorization: Bearer xoxb-..." https://slack.com/api/auth.test`.
   - Stripe: list-only call to `/v1/balance` with secret key.
   - JWT signing key: `jwt_tool <token> -C -k <leaked-key>`; craft forged token with escalated role claims.
3. **Blast Radius Assessment** — Map each verified secret to reachable endpoints from recon inventory; document scope per policy; estimate affected data/accounts.
4. **Reproduce Independently** — Re-verify with a second tool/approach to eliminate false positives before reporting.

## Phase 7 — Evasion & Deep Aggressive Execution

1. **Stealth Probing** — Space requests across rotating egress (SOCKS via authorized infrastructure), use `nuclei -rate-limit`, and prefer read-only GET endpoints. Never trigger password-reset or alerting flows.
2. **Chain to Real Impact (Authorized Only)** — Combine a leaked JWT signing key with api-testing-agent endpoint findings to forge admin sessions; combine leaked cloud key with exposed bucket from recon to prove data access; combine GitHub PAT with secrets-scanning-agent's own repo inventory to find nested secrets in private repos.
3. **Historical Deep Dive** — Mine PR discussions, commit messages, and issue threads for pasted tokens (`gh` CLI: `gh api repos/org/repo/issues --paginate | rg -i "password|token"`).
4. **Coverage Gate** — Before closing: full mirror history scanned, all branches/reflogs/stash covered, public dork set executed, CI/CD and env templates inspected, container layers scanned, exposed web surfaces probed, every finding triaged to a confidence tier with blast radius.

## Phase 8 — Verification & Evidence

1. **Sandbox Isolation** — All validation on isolated lab/staging; zero production touch without explicit approval.
2. **Reproduction** — High-value findings re-detected with a second independent tool; format re-validated.
3. **Evidence Pack** — For each finding: exact secret (redacted for report), source URL/commit/author/date, repro commands, blast radius, CVSS severity.
4. **Remediation Guidance** — Rotation + revocation, `git-filter-repo --invert-paths --path-glob '*.env' --force`, secret manager adoption, pre-commit hooks (`git-secrets`, `pre-commit gitleaks`).
5. **Cleanup** — Delete downloaded mirrors, image layers, and dumps from attacker-controlled storage after extraction.
6. **Handoff** — Secrets inventory YAML to verification-correlation-agent; encrypted credential bundles to vault-agent; authorization-gated exploitation leads to exploit-poc-agent; supply-chain findings to sca-sbom-agent.
