---
skill: dns-enumeration-deep-aggressive
mitre_attack_id: T1590.002
owasp_mapping: []
difficulty: advanced
tags: [dns, subdomain-enumeration, zone-transfer, dns-reconnaissance, osint, wildcard-detection, dnssec, cache-snooping]
---
## Summary
Deep Aggressive Mode DNS enumeration to discover subdomains, DNS records, and exposed infrastructure. Combines passive OSINT collection (certificate transparency, passive DNS, threat-intel feeds) with aggressive active query techniques: multi-wordlist brute-force, permutation sweeps, zone-transfer campaigns, cache snooping, and DNSSEC analysis. Wildcard DNS is actively detected and filtered so reported subdomains are real. All findings are validated against multiple resolvers before handoff.

Skill library references:
- skills/network-security/service-enumeration.md (DNS section)
- skills/threat-intel/skill-playbook.md

## Phase 0 — Scope & Resolver Prep
1. Receive base domains and IP ranges from recon-agent; validate against scope-agent
2. Set up resolver pool: `echo -e "1.1.1.1\n8.8.8.8\n9.9.9.9\n1.0.0.1" > resolvers.txt`
3. Confirm the target domain is registered and resolves (dig +short SOA)
4. Create output structure: `mkdir -p dns/{records,axfr,brute,passive,permutation,validate}`
5. Record ROE authorization ref and rate ceiling for DNS queries

## Phase 1 — Authoritative NS Discovery
```bash
dig +short NS <domain> > dns/records/ns.txt
dig +short SOA <domain>
dig @<ns> <domain> ANY
# Delegation path
dig @8.8.8.8 <domain> +trace
```

## Phase 2 — Zone Transfer Campaign (AXFR)
Attempt against every authoritative name server; a single open server reveals the full zone:
```bash
while read ns; do
  echo "=== AXFR from $ns ==="
  dig @$ns <domain> AXFR | grep -v '^;' >> dns/axfr/zone_$(echo $ns | tr -d '.').txt
done < dns/records/ns.txt
# dnsrecon
dnsrecon -d <domain> -t axfr
# nmap NSE
nmap -p 53 --script dns-zone-transfer --script-args dns.zone=<domain> -iL dns/records/ns.txt
```
A successful AXFR is a Critical/High misconfiguration finding: the entire DNS zone is exposed. Cross-verify returned records against public DNS before reporting.

## Phase 3 — Full Record Enumeration
```bash
for t in A AAAA CNAME MX TXT NS SOA SRV PTR CAA DS; do
  dig @8.8.8.8 <domain> $t +short > dns/records/$t.txt
done
dig @8.8.8.8 <domain> ANY +short >> dns/records/ANY.txt
# Parse MX/TXT/SPF/DMARC/DKIM metadata
dig @8.8.8.8 <domain> TXT +short | grep -iE 'spf|dkim|dmarc'
```
Record SPF/DKIM/DMARC presence and policy strength for risk-agent.

## Phase 4 — Passive Subdomain Discovery
```bash
# subfinder (30+ OSINT sources)
subfinder -d <domain> -all -o dns/passive/subfinder.txt
# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u > dns/passive/crtsh.txt
# amass passive
amass enum -d <domain> -passive -o dns/passive/amass_passive.txt
# DNSDumpster / SecurityTrails harvest (web API)
# Merge + normalize
cat dns/passive/*.txt | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | sort -u > dns/passive/all_passive.txt
```

## Phase 5 — Active Brute-Force (Deep Aggressive)
```bash
# dnsrecon with large wordlist
dnsrecon -d <domain> -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -j dns/brute/dnsrecon.json
# dnsrecon commonspeak2
dnsrecon -d <domain> -t brt -D /usr/share/seclists/Discovery/DNS/commonspeak2-subdomains.txt
# amass active brute with recursive resolution
amass enum -d <domain> -active -brute -min-for-recursive 3 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o dns/brute/amass_brute.txt
# massdns high-throughput brute (rate-limited to avoid blacklist)
massdns -r resolvers.txt -t A -o S -w dns/brute/massdns.txt -s 1000 /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Phase 6 — Permutation & Recursive Enumeration
```bash
# Generate permutations from discovered names
cat dns/passive/all_passive.txt dns/brute/*.txt | sort -u > dns/permutation/names.txt
dnsgen dns/permutation/names.txt > dns/permutation/permutations.txt
massdns -r resolvers.txt -t A -o S -w dns/permutation/resolved.txt -s 1000 dns/permutation/permutations.txt
# Resolve every candidate to IP
while read sub; do ip=$(dig +short $sub A | head -1); [ -n "$ip" ] && echo "$sub $ip"; done < dns/permutation/names.txt > dns/validate/sub_to_ip.txt
```

## Phase 7 — Wildcard Detection & Filtering
```bash
# Non-existent subdomain probe
rand=$(head -c 12 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 12)
dig +short $rand.<domain> A
# If it resolves, wildcard is active: filter all brute-force results
dnsrecon -d <domain> -w -j dns/validate/wildcard.json
# Programmatic filter: drop any subdomain that resolves to the wildcard IP set
grep -v "$(cat dns/validate/wildcard_ips.txt)" dns/validate/sub_to_ip.txt > dns/validate/real_subdomains.txt
```

## Phase 8 — Reverse DNS & Network Mapping
```bash
# Reverse DNS over target ranges
dnsrecon -r <target_cidr> -n 8.8.8.8 -j dns/records/reverse.json
for ip in $(cat scan/hosts.txt); do dig +short -x $ip; done
# Group subdomains by IP to find shared/virtual hosting
awk '{print $2, $1}' dns/validate/sub_to_ip.txt | sort | uniq -c | sort -rn
```

## Phase 9 — Cache Snooping & Resolver Assessment
```bash
# Cache snooping (detects recently-queried domains by clients of a resolver)
dig @<resolver> <domain> A +norecurse +short
# Open resolver / amplification check
dig @<resolver> <domain> ANY +short
nmap -p 53 --script dns-recursion <resolver>
# Amplication factor measurement for risk-agent
```

## Phase 10 — DNSSEC Validation
```bash
dig @<ns> <domain> DNSKEY +short              # key presence
dig @<ns> <domain> DS +short                   # parent delegation (chain of trust)
dig +dnssec @<ns> <domain> A                   # RRSIG attached?
nmap -p 53 --script dns-nsec-enum,dns-nsec3-enum --script-args dns.zone=<domain> <ns>
```
Absence of DNSSEC is a Low/Medium finding; zone enumeration via NSEC is enabled when NSEC (not NSEC3) is used.

## Phase 11 — Consolidation, Validation, Handoff
Verification checklist (sandbox):
- [ ] Every record validated against at least two independent resolvers
- [ ] Zone-transfer results spot-checked against public DNS
- [ ] Wildcard-filtered subdomains re-resolved with A/AAAA
- [ ] No internal DNS leaks in external report without explicit scope
- [ ] Cache-snooping and open-resolver results tagged with resolver identity
- [ ] DNSSEC state (secure/insecure/bogus) recorded per domain
- [ ] Output in JSON with source attribution per record

Handoff:
- Subdomain+IP dataset to web-discover-agent for HTTP probing
- Hostname-to-IP mapping back to recon-agent
- DNS misconfiguration findings (AXFR success, open resolver, DNSSEC absence) to risk-agent
- Full query log to audit-agent

## References
- Skill library: skills/network-security/service-enumeration.md (DNS section), skills/threat-intel/skill-playbook.md
- MITRE ATT&CK T1590.002 (DNS): https://attack.mitre.org/techniques/T1590/002/
- MITRE ATT&CK T1596.001 (Search Open Technical Databases: DNS/Passive DNS): https://attack.mitre.org/techniques/T1596/001/
- MITRE ATT&CK T1584: https://attack.mitre.org/techniques/T1584/
- amass: https://github.com/owasp-amass/amass
- subfinder: https://github.com/projectdiscovery/subfinder
- dnsrecon: https://github.com/darkoperator/dnsrecon
- dnsgen: https://github.com/ProjectAnte/dnsgen
- massdns: https://github.com/blechschmidt/massdns

Prohibited: DNS amplification attacks, flooding resolvers, modifying zone files, enumerating internal DNS namespaces outside explicit scope.
