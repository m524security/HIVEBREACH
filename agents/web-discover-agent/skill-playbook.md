---
skill: web-application-discovery-deep-aggressive
mitre_attack_id: T1046
owasp_mapping: [A01, A05, A07]
difficulty: advanced
tags: [directory-brute-force, endpoint-discovery, technology-fingerprinting, web-reconnaissance, vhost-enumeration, parameter-discovery, js-endpoint-extraction, favicon-hashing]
---
## Summary
Deep Aggressive Mode web application discovery to identify live endpoints, hidden directories, API routes, technology stacks, and misconfigurations across target web services. Executes recursive multi-wordlist directory brute-force, virtual host enumeration, parameter fuzzing, JavaScript endpoint extraction, historical archive mining (Wayback/GAU), and favicon-hash asset correlation. Establishes the complete web attack surface for web exploitation.

Skill library references:
- skills/penetration-testing/*.md (SQLi, XSS, SSRF, file-inclusion, file-upload, idor, command-injection and related techniques whose discovery prerequisites this playbook fulfils)

## Phase 0 — Target Consolidation
1. Receive target list (domains:ports) from dns-agent and recon-agent
2. Merge and deduplicate: `cat targets.txt | sort -u`
3. Probe every port for live web services: `httpx -l targets.txt -ports 80,443,8080,8000,8443,8888,3000,5000 -status-code -title -o live_webs.txt`
4. Record scope exclusions and WAF awareness from scope-agent

## Phase 1 — Technology Fingerprinting
```bash
httpx -l live_webs.txt -tech-detect -web-server -status-code -title -content-length -follow-redirects -location -cname -o tech_scan.txt
httpx -l live_webs.txt -screenshot -o screenshots/
whatweb -v https://<target>
nmap -p80,443 --script http-server-header,http-title,http-tech-detect,http-methods,http-headers <target>
curl -sI https://<target> | grep -iE 'server|x-powered-by|set-cookie|x-aspnet'
openssl s_client -connect <target>:443 -servername <hostname> </dev/null 2>/dev/null | openssl x509 -text
```
Record server, framework, CMS, CDN, analytics, and cookie names in the tech stack for the endpoint map.

## Phase 2 — Recursive Directory Brute-Force
```bash
# Medium wordlist recursive
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -recursion -recursion-depth 4 -t 50 -fc 403,404,500 -o ffuf_recursive.json
# Large wordlist + extensions (source disclosure)
gobuster dir -u https://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,bak,old,swp,git,sql,config,log -t 50 -o gobuster.txt
# dirsearch recursive with extension set
dirsearch -u https://<target> -e php,html,js,aspx,asp,txt,bak -x 403,404 --threads 50 -r -o dirsearch_report.json
# Backup files / source archives
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt -fc 404,403
ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/Common-PHP-Filenames.txt -fc 404,403
```
Paranoid finds (.git/config, .env, db backups) are confirmed by downloading and parsing the actual file.

## Phase 3 — Virtual Host Enumeration
```bash
# Baseline content length of a non-existent vhost
curl -s https://<target> -H "Host: nonexistent.<domain>" | wc -c
# Fuzz Host header
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -fs <baseline_length> -t 50
gobuster vhost -u https://<target> -w /usr/share/seclists/Discovery/DNS/vhost-subdomains.txt --append-domain -t 50
# Validate found vhosts resolve and serve distinct content
```
Every discovered vhost is cross-checked with dns-agent for resolution and deduplicated against wildcard baselines.

## Phase 4 — Parameter Discovery
```bash
# GET parameter names
ffuf -u https://<target>/<endpoint>?FUZZ=1 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 403,404 -fs <baseline>
# POST parameter names
ffuf -u https://<target>/<endpoint> -X POST -d 'FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 403,404
# Common hidden params (debug, admin, test, source, config)
ffuf -u https://<target>/<endpoint>?FUZZ=1 -w /usr/share/seclists/Discovery/Web-Content/params.txt
# Header-based probes
ffuf -u https://<target>/ -H "X-Forwarded-For: FUZZ" -w xff.txt -fc 403,404
```
Differential analysis of response length/status identifies interesting parameters that change application behavior.

## Phase 5 — JS Endpoint Extraction & Crawling
```bash
# Crawl and extract JS files
katana -u https://<target> -jc -d 5 -silent -o katana_all.txt
grep -E '\.js' katana_all.txt | sort -u > js_files.txt
# Extract endpoints/routes from JS content
cat js_files.txt | while read js; do curl -s $js; done | grep -oE '"(/api/[^"]+|/[a-z0-9_\-/]+\.(php|aspx|jsp|json))"' | tr -d '"' | sort -u > js_endpoints.txt
# Historical content mining
gau <target> --threads 10 > gau_urls.txt
waybackurls <target> | sort -u > wayback_urls.txt
# Filter historical URLs to unique paths
cat gau_urls.txt wayback_urls.txt | grep -oE '^[^?]+' | sort -u > historical_paths.txt
# Re-probe historical endpoints for liveness
cat historical_paths.txt js_endpoints.txt katana_all.txt | sort -u | httpx -status-code -title -tech-detect -o live_endpoints.txt
```
Historical paths that no longer resolve are kept as context for parameter-fuzzing targets.

## Phase 6 — Favicon Hashing & Asset Correlation
```bash
httpx -u https://<target>/favicon.ico -favicon -o favicon_hashes.txt
# Query shodan/fofa/censys by mmh3 favicon hash to find related infrastructure
python3 - <<'EOF'
import mmh3, requests, codecs
r = requests.get("https://<target>/favicon.ico")
h = mmh3.hash(codecs.encode(r.content, "base64"))
print("mmh3 hash:", h)
EOF
```
Hash correlation exposes hidden staging, dev, and production twins of the target application.

## Phase 7 — Screenshot & Response Categorization
```bash
httpx -l live_endpoints.txt -screenshot -o screenshots/
# Group by status and content-length for triage
awk '{print $1}' live_endpoints.txt | while read u; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $u\n" "$u"
done | sort -rn
```
Unique 200/403 responses get screenshots for manual review and comparison against known-good baseline.

## Phase 8 — Preliminary Vulnerability Triage (Nuclei)
```bash
nuclei -l live_webs.txt -severity critical,high,medium -rl 50 -json -o nuclei_quick.json
nuclei -l live_webs.txt -tags exposure,config,backup,admin-login -rl 50 -json -o nuclei_exposure.json
nuclei -l live_webs.txt -tags tech -json -o nuclei_tech.json
```
Findings here are preliminary; vuln-scan-agent performs full verification and false-positive triage.

## Phase 9 — Consolidation, Verification, Handoff
Verification checklist (sandbox):
- [ ] Every reported endpoint has a valid HTTP response (status + content length captured)
- [ ] Screenshots captured for all unique 200/403 responses
- [ ] .git/config and backup-file findings confirmed by downloading the actual file
- [ ] Vhost findings validated against wildcard baseline content length
- [ ] Historical endpoints re-probed for current liveness
- [ ] Parameters that change response differentials documented
- [ ] Output in JSON with source attribution (ffuf/gobuster/katana/gau/wayback)

Handoff:
- Enriched endpoint map (URL, method, status, tech, priority, source) to web-exploit-agent and vuln-scan-agent
- New subdomain/vhost candidates to dns-agent
- Full discovery log to audit-agent

## References
- Skill library: skills/penetration-testing/*.md
- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1595.001: https://attack.mitre.org/techniques/T1595/001/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- ffuf: https://github.com/ffuf/ffuf
- httpx: https://github.com/projectdiscovery/httpx
- katana: https://github.com/projectdiscovery/katana
- gau: https://github.com/lc/gau
- waybackurls: https://github.com/tomnomnom/waybackurls
- nuclei: https://github.com/projectdiscovery/nuclei

Prohibited: state-changing form submission, destructive fuzzing against production data, rate patterns that trigger WAF/IDS beyond authorized ceilings.
