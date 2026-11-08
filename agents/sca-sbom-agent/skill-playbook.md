# Skill Playbook: sca-sbom-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for software composition analysis and SBOM-driven supply chain risk assessment. Embeds the CVE triage methodology from `skills/cve-staging/cve-analysis.md` and exploitation-intelligence correlation from `skills/threat-intel/skill-playbook.md`. Analysis-only default; exploitation is authorization-gated.

## Phase 1 — Scope & Component Surface Inventory

1. **Collect Inputs** — From config-agent: repository list, container images, binaries, IaC definitions, mobile packages. From recon-agent: deployed runtime versions and which hosts run which images. This maps SBOM components to live attack surface.
2. **Catalog Ecosystems** — Identify package managers in each repo: `package.json` (npm/yarn/pnpm), `requirements.txt`/`pyproject.toml` (pip/poetry), `pom.xml`/`build.gradle` (Maven/Gradle), `go.mod` (Go), `Cargo.toml` (Rust), `Gemfile` (Ruby), `composer.json` (PHP), `packages.lock.json` (NuGet). Lockfiles give exact pinned versions.
3. **Container Baseline** — For each image: base OS (alpine/debian/ubuntu/distroless), language runtimes baked in, and installed OS packages. Record image digests for SBOM diffing later.

## Phase 2 — SBOM Generation

1. **Application-Level SBOM** — `syft scan dir:./app -o cyclonedx-json > app.cdx.json`; repeat with `-o spdx-json > app.spdx.json` for format coverage.
2. **Image-Level SBOM** — `syft scan registry:acme/app:1.2.3 -o cyclonedx-json > image.cdx.json` (pulls metadata only, no runtime install); OCI archive: `syft scan oci-archive:app.tar -o cyclonedx-json`.
3. **Binary-Level SBOM** — `syft scan file:./compiled-binary -o cyclonedx-json`; mark binary-inferred components as `inferred` and cross-check with manifest-derived SBOMs.
4. **Merge & Validate** — `cyclonedx-cli merge --input-files app.cdx.json image.cdx.json --output-file full.cdx.json`; `spdx-tools-java Verify full.spdx.json`; extract purl list: `cyclonedx-cli convert -i full.cdx.json -o json | jq -r '.components[].purl'`.
5. **SBOM Diffing (multi-version)** — When several versions exist: `cyclonedx-cli diff --from v1.cdx.json --to v2.cdx.json` to detect new/removed components and regression risk between releases.

## Phase 3 — Vulnerability Scanning & CVE Correlation (skills/cve-staging/cve-analysis.md)

1. **Comprehensive Scan** — `trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignore-unfixed -f json -o trivy.json ./app`; `grype dir:./app -o json > grype.json`; `osv-scanner scan -r ./app > osv.json`.
2. **Ecosystem Auditors** — `npm audit --json`; `pip-audit -r requirements.txt`; `cargo audit`; `govulncheck ./...` (Go call-site reachability evidence).
3. **CVE Triage per cve-analysis** — For each match: confirm installed version is in affected range; fetch advisory (`curl -s https://nvd.nist.gov/vuln/detail/<CVE>` or GitHub Advisory API); record: root cause, fix version, CVSS, CWE, attack vector.
4. **False Positive Removal** — Suppress findings where vendor marks the version unaffected; flag findings where the vulnerable function is not invoked (`not-reachable`).
5. **OS Package vs App Layer** — Distinguish image base-layer vulns (often shared across images) from app-layer dependency vulns (higher first-party responsibility).

## Phase 4 — Exploitability & Threat-Intel Correlation (skills/threat-intel/skill-playbook.md)

1. **EPSS & Wild Status** — For each candidate: EPSS score from FIRST API; check exploitation-in-the-wild status and public PoC availability (searchsploit, GitHub, metasploit module presence, nuclei template presence).
2. **Ransomware/Tooling Flag** — Flag CVEs integrated into commercial/ransomware tooling as highest urgency: `searchsploit <cve>`; nuclei template grep: `grep -rl "<cve>" ~/nuclei-templates/`.
3. **Reachability Analysis** — Map each vulnerable component to call sites: `govulncheck` for Go; `pip-audit --vulnerability-service osv` for Python; static import graph via `madge --json` (npm) or `jdeps` (Java). Classify `reachable` / `reachable-uncertain` / `not-reachable`.
4. **Chain Assessment** — For reachable criticals, consult web-hunting/api-hunting skill libraries for how the CVE payload is delivered through the app's exposed endpoints; prepare handoff evidence for exploit-poc-agent.

## Phase 5 — Supply Chain Risk & Malicious Package Hunting

1. **Typosquatting Check** — For each first-party-imported package, compare registered name against the org's naming conventions: `curl -s https://registry.npmjs.org/<pkg>` / `https://pypi.org/pypi/<pkg>/json`; flag names one-char-different from popular packages and freshly-created packages with high download counts (suspicious).
2. **Maintenance State** — Record last publish date and latest version vs installed: abandoned/deprecated packages are supply chain risk even without CVEs.
3. **Malicious Indicators** — For high-value packages, review source tarballs for: postinstall scripts (`npm install` / setup.py) that contact external hosts, obfuscated install hooks, and version-squatting releases. Cross-check with OSV.dev malicious package feeds.
4. **License Compliance** — Extract licenses per component (`syft -o cyclonedx-json | jq '.components[].licenses'`); flag copyleft conflicts (GPL/AGPL in proprietary code) and missing licenses; hand off to compliance-audit-agent.
5. **Secret-in-Dependency** — Scan third-party package contents with gitleaks/truffleHog; route finds to secrets-scanning-agent.

## Phase 6 — Evasion & Deep Aggressive Execution

1. **Registry-Only Discovery** — Never install or execute dependency package installers; pull tarballs into isolated scratch space (`pip download --no-deps`, `npm pack`, `mvn dependency:get`) for metadata and static review.
2. **Reachability Proof** — For the highest-severity reachable components, produce a minimal repro in a sandbox: extract the vulnerable function signature and confirm the app calls it (static evidence), then prepare the exploit path for exploit-poc-agent without executing it.
3. **Cross-Agent Chaining** — Combine: reachable vulnerable component + exposed endpoint from recon-agent + auth bypass knowledge from api-testing-agent = realistic full-chain impact narrative for the report.
4. **SBOM-Driven Detection** — Use generated SBOMs to spot discrepancies: components in the SBOM that are not in the codebase (stale/embedded), and runtime packages not in any SBOM (undeclared dependencies — supply chain blind spots).
5. **Coverage Gate** — Before closing: every repo/image/binary has an SBOM, every ecosystem auditor run, trivy+grype+osv cross-scanned, reachability classified per finding, EPSS/wild status recorded, malicious/typosquat hunt complete, licenses extracted, remediation paths drafted.

## Phase 7 — Verification & Evidence

1. **Cross-Scanner Confirmation** — High-severity findings confirmed by at least two independent scanners; version-range matches validated against vendor advisory.
2. **Reachability Evidence** — Include call-site references and import paths, not just CVE matches.
3. **Severity Discipline** — Use CVSS for technical severity; EPSS + wild-exploitation for urgency; reachability for exploitability. A finding's reported severity is `CVSS adjusted by reachability`.
4. **Cleanup** — Remove downloaded package tarballs and scratch SBOMs from attacker-controlled storage.
5. **Handoff** — SBOM files + risk report to verification-correlation-agent and compliance-audit-agent; reachable criticals (authorization-gated) to exploit-poc-agent; dependency secrets to secrets-scanning-agent; supply chain alerts to orchestrator.
