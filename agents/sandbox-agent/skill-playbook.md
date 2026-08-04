# Skill Playbook: sandbox-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for Docker sandbox lifecycle, snapshot/restore, malware detonation isolation, and evidence collection. Every phase embeds the technique chains from `skills/malware-analysis/dynamic-analysis.md`, `skills/malware-analysis/static-analysis.md`, and `skills/malware-analysis/memory-analysis.md`. Sandbox-only default: malicious payloads execute only inside isolated, instrumented environments.

## Phase 1 — Provisioning and Image Management

1. **Parse Sandbox Spec** — Extract OS/image, tool list, network mode (isolated/restricted/open), resource limits, volumes, env vars, and evidence directives.
2. **Compute Cache Key** — Key = sha256(OS + sorted(tool list)). Check the image cache; on hit, reuse.
3. **Pull or Build** — On miss, pull from registry or build:
   ```bash
   docker pull ubuntu:22.04
   # or
   packer build -var "tools=$(cat tools.json)" analysis.pkr.hcl
   docker-compose -f analysis-stack.yml up -d
   ```
4. **Create Container** — Apply hard limits and isolation:
   ```bash
   docker run -d \
     --name sandbox-<corr_id> \
     --cpus 2 --memory 4g --memory-swap 4g \
     --ulimit nofile=1024:1024 --ulimit nproc=512:512 \
     --network sandbox_isolated \
     --read-only \
     --tmpfs /tmp --tmpfs /data \
     --security-opt=no-new-privileges \
     --cap-drop=ALL \
     -e AGENT_ID=validator-agent -e CORRELATION_ID=<id> \
     analysis-image:latest
   ```
5. **Configure Isolation Network** — Create an isolated bridge with no gateway:
   ```bash
   docker network create --internal sandbox_isolated
   # restricted mode: allow-list egress via firewall rules on the egress node
   ```
6. **Run Health Check** — Verify tools present, connectivity matches spec, limits enforced:
   ```bash
   docker exec sandbox-<corr_id> /opt/healthcheck.sh
   cat /proc/self/cgroup | grep -i mem
   ```
7. **Return Handle** — Emit `{container_id, ip, ports, access_token, health: ready}` to the requesting agent.

## Phase 2 — Exploitation PoC Sandboxing

1. **Provision per Finding** — Each PoC replay gets a fresh container. Never reuse a sandbox across findings.
2. **Pre-Exploit Snapshot** — Before any PoC execution, snapshot the clean state:
   ```bash
   docker commit sandbox-<corr_id> sandbox-snap:pre-<finding_id>
   docker tag sandbox-snap:pre-<finding_id> sandbox-snap:pre-<finding_id>
   ```
3. **Restricted Egress for Callbacks** — For callback-based PoCs, allow egress only to the attacker's handler IP/port via iptables allow-list on the egress node.
4. **Post-Exploit Snapshot** — After PoC completion, snapshot again:
   ```bash
   docker commit sandbox-<corr_id> sandbox-snap:post-<finding_id>
   ```
5. **State Diff Handoff** — Hand the pre/post snapshot pair to validator-agent for state comparison. Confirm restored containers reproduce identical state:
   ```bash
   docker run -d --name sandbox-restore-<id> sandbox-snap:pre-<finding_id>
   docker exec sandbox-restore-<id> ls /data/state.marker
   ```

## Phase 3 — Malware Detonation Stack

1. **Provision Analysis Stack** — Per `skills/malware-analysis/dynamic-analysis.md` section 3.1, spin up the victim container paired with fake-network responders:
   ```bash
   docker-compose -f detonation-stack.yml up -d
   # victim + fakenet + dns-sinkhole + pcap-capture containers
   ```
2. **Start Network Capture** — Before detonation:
   ```bash
   tcpdump -i any -w /evidence/analysis.pcap -n &
   ```
3. **Start Fake Services** — FakeNet-NG / INetSim bound to the sink:
   ```bash
   inetsim --conf /etc/inetsim/inetsim.conf
   python fakenet-ng.py -i eth0
   echo "127.0.0.1 *" > /etc/dnsmasq.d/sinkhole.conf
   ```
4. **Verify Isolation Gate** — Confirm no internet route and DNS sinks:
   ```bash
   ip addr show                 # internal only
   ping -c 1 10.0.2.2           # gateway only
   curl -s --max-time 3 http://internet.simulated   # FakeNet response expected
   ```
5. **Arm Telemetry** — Pre-install per `skills/malware-analysis/static-analysis.md` tooling and start collectors:
   ```bash
   inotifywait -m -r -e create,modify,delete /tmp /var/tmp > /evidence/fs_changes.log &
   # regshot-style registry diff before detonation
   ```
6. **Detonate** — Run the sample inside the victim container with the configured timeout:
   ```bash
   timeout 300 docker exec sandbox-<corr_id> /opt/sample.exe
   # or cuckoo-style submission:
   cuckoo submit --machine win10_x64 --package exe --timeout 300 sample.exe
   ```

## Phase 4 — Post-Detonation Evidence Collection

1. **Capture Process Tree** — Extract parent-child relationships:
   ```bash
   docker exec sandbox-<corr_id> ps -ef --forest > /evidence/process_tree.txt
   ```
2. **Diff File System** — Compare before/after files:
   ```bash
   diff /evidence/fs_before.txt /evidence/fs_after.txt > /evidence/fs_changes.diff
   ```
3. **Diff Registry** — Use regshot-equivalent snapshots:
   ```bash
   regshot_x64.exe -c -L -o before.txt   # pre-detonation
   regshot_x64.exe -c -L -o after.txt    # post-detonation
   ```
4. **Extract Network Indicators** — Per `skills/malware-analysis/dynamic-analysis.md` section 3.3:
   ```bash
   tshark -r /evidence/analysis.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
   tshark -r /evidence/analysis.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
   tshark -r /evidence/analysis.pcap -Y "tcp.flags.syn == 1" -T fields -e ip.dst -e tcp.dstport | sort | uniq -c
   ```
5. **Hash Dropped Files** — Every extracted artifact gets a SHA-256:
   ```bash
   find /evidence/dropped -type f -exec sha256sum {} \; > /evidence/dropped_hashes.txt
   ```
6. **Acquire Memory Dump** — For `skills/malware-analysis/memory-analysis.md`:
   ```bash
   docker exec sandbox-<corr_id> avml /evidence/memory.raw
   # or from the VM layer: vol3 -f memory.raw windows.info
   ```
7. **Classify Behavior** — Map to the behavior classes in `skills/malware-analysis/dynamic-analysis.md` section 3.7 (dropper, loader, infostealer, ransomware, keylogger, RAT/C2, miner).
8. **Bundle Evidence** — Package all artifacts with correlation_id, hashes, and capture metadata. Hand to audit-agent for the evidence chain and to validator-agent for independent review.

## Phase 5 — Evasion Detection and Bypass

1. **Detect Evasion** — Watch for sleep inflation, VM-artifact checks, and environment fingerprinting per `skills/malware-analysis/dynamic-analysis.md` section 2.2.
2. **Extend Timeout** — If a sample sleeps to outlive the analysis window, re-run with a longer window:
   ```bash
   cuckoo submit --timeout 600 --enforce-timeout sample.exe
   ```
3. **Simulate Interaction** — Inject user-like cursor movement and input.
4. **Apply Bypass Profile** — Use ScyllaHide-style hooking or a realistic VM profile, then re-detonate.
5. **Flag Confidence Impact** — Record that evasion influenced the analysis; note the reduced confidence in the evidence bundle.

## Phase 6 — Monitoring, Limits, and Teardown

1. **Health Polling** — Ping health endpoint every 30s. Healthy = operational and within limits.
2. **Resource Thresholds** — CPU >90% for 60s → warn → throttle → terminate. Memory >90% → pressure handling. Disk >90% → clean /tmp.
3. **Isolation Breach** — Any outbound connection from isolated mode → immediate `docker kill`, security incident log, scheduler notification.
4. **Log Collection** — On teardown request, collect:
   ```bash
   docker logs sandbox-<corr_id> > /evidence/container.log
   ```
5. **Teardown** — Stop with 10s grace, force kill if needed, remove container and ephemeral snapshots:
   ```bash
   docker stop -t 10 sandbox-<corr_id> || docker kill sandbox-<corr_id>
   docker rm sandbox-<corr_id>
   docker rmi sandbox-snap:pre-<id> sandbox-snap:post-<id>
   ```
6. **Report Metrics** — Emit uptime, peak CPU/memory/disk, network I/O, snapshot count to scheduler-agent.
7. **Retention** — Purge sandbox data after 24h retention unless marked for retention by audit-agent.

## Quality Gates

- **Gate 1:** Container integrity verified (image digest unchanged) before reporting ready.
- **Gate 2:** Isolation gate verified before any detonation: no internet route, DNS sinks to sinkhole, only fake-network responders reachable.
- **Gate 3:** Pre/post snapshots captured for every exploitation PoC; restore fidelity confirmed.
- **Gate 4:** Every detonation yields the full evidence bundle: process tree, file/registry diffs, pcap, dropped-file hashes, memory dump.
- **Gate 5:** Resource limits and isolation breaches are enforced with warn → throttle → terminate escalation.

## References
- skills/malware-analysis/dynamic-analysis.md
- skills/malware-analysis/static-analysis.md
- skills/malware-analysis/memory-analysis.md
- Docker Documentation: https://docs.docker.com/
- Docker Compose: https://docs.docker.com/compose/
- OWASP Docker Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- NIST SP 800-190 Application Container Security Guide
- Cuckoo Sandbox: https://cuckoosandbox.org/
- CAPE Sandbox: https://github.com/kevoreilly/CAPEv2
