# Skill Playbook: cleanup-teardown-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for verified teardown: pre-destruction state capture, remote-access termination, credential destruction, artifact removal, configuration rollback, and residual verification. Every phase embeds the DFIR discipline from `skills/dfir/skill-playbook.md` and `skills/dfir/incident-triage.md`. Zero residuals is the only acceptable teardown outcome.

## Phase 1 — Pre-Teardown State Capture

1. **Capture Processes** — Enumerate framework-related processes (reverse shells, tunnels, handlers, sandbox runtimes):
   ```bash
   python3 -c "
   import psutil
   for p in psutil.process_iter(['pid','name','cmdline']): print(p.info)
   " > /evidence/pre/processes.txt
   ```
2. **Capture Connections** — Enumerate listening and established sockets:
   ```bash
   ss -tulnp > /evidence/pre/connections.txt
   ```
3. **Capture Files** — Scan artifact paths (tmp, /opt/hivebreach, sandbox data, cracking temp):
   ```bash
   find /tmp /opt/hivebreach /var/tmp -type f 2>/dev/null > /evidence/pre/files.txt
   ```
4. **Capture Credentials** — Request vault-agent secret manifest (active secrets, expirations).
5. **Capture Configs** — Request config-agent config snapshot registry (config_id/version list).
6. **Emit Baseline** — Send the complete pre-teardown state capture to audit-agent as the baseline.

## Phase 2 — Terminate Remote Access

1. **Kill Reverse Shells** — SIGTERM the handler/connection process; SIGKILL after 10s if needed:
   ```bash
   kill -TERM $(pgrep -f 'reverse_shell_handler') ; sleep 10 ; kill -KILL $(pgrep -f 'reverse_shell_handler') 2>/dev/null
   ```
2. **Close Tunnels** — Terminate SSH -L/-R/-D, chisel, socat, and pivot processes and their socket fds.
3. **Stop Callback Handlers** — Close persistent HTTP/WebSocket callback listeners.
4. **Drop Firewall Rules** — Remove allow-list rules opened for callbacks:
   ```bash
   ufw delete allow from <target_ip> to any port <callback_port> proto tcp
   iptables -D INPUT -s <target_ip> -p tcp --dport <callback_port> -j ACCEPT
   ```
5. **Record Kills** — Per process: PID, cmdline, signal, timestamp, exit status.

## Phase 3 — Destroy Credentials

1. **Order Vault Destruction** — Request vault-agent to cryptographically destroy all active secrets (zeroize + unlink).
2. **Collect Confirmations** — Gather secret_id, method, timestamp from vault-agent for the report.
3. **Shred External Files** — Destroy temp credential files outside the vault:
   ```bash
   shred -u -z /tmp/creds/*.hash /tmp/.netrc /opt/hivebreach/tmp/creds.json 2>/dev/null
   ```
4. **Zeroize Env** — Clear env vars still carrying secret values in running shells:
   ```bash
   unset API_KEY; unset VAULT_MASTER
   ```
5. **Log Destruction** — Record every credential destruction with method and timestamp.

## Phase 4 — Remove Local Artifacts

1. **Remove Sandboxes** — Containers and ephemeral snapshots:
   ```bash
   docker rm -f sandbox-<corr_id> 2>/dev/null
   docker rmi sandbox-snap:pre-<id> sandbox-snap:post-<id> 2>/dev/null
   docker network rm sandbox_isolated 2>/dev/null
   ```
2. **Purge Temp and Capture Files** — Remove evidence bundles NOT marked for retention by audit-agent:
   ```bash
   shred -u -z /evidence/post-<id>.pcap /tmp/scan_output/* 2>/dev/null
   rm -rf /opt/hivebreach/tmp /opt/hivebreach/evidence 2>/dev/null
   ```
3. **Remove Config Snapshots** — Purge config-agent distribution cache (except retained version history).
4. **Clean Cracking Intermediates** — Delete hash temp files, wordlist caches, tool output dumps.
5. **Rotate/Shred Logs** — Zero or rotate logs that may carry partial engagement traces.

## Phase 5 — Remove Configuration and Registry

1. **Flush Firewall** — Remove all engagement firewall rules, restore original chain state.
2. **Revert Host Config** — Restore proxy settings, DNS overrides, hosts entries, iptables chains to baseline.
3. **Clean Registry Entries** — Remove any framework-registered launch entries (launchd/reg/rc entries).
4. **Revert Env Overrides** — Restore environment to pre-engagement values.
5. **Remove Key Material** — Clear vault key material from non-persistent storage, retaining only the zeroize record.

## Phase 6 — Verified Teardown Report

1. **Rescan Residuals** — Re-run Phase 1 scans post-teardown:
   ```bash
   python3 -c "
   import psutil
   print([p.info for p in psutil.process_iter(['pid','name','cmdline'])])
   " > /evidence/post/processes.txt
   ss -tulnp > /evidence/post/connections.txt
   find /tmp /opt/hivebreach /var/tmp -type f 2>/dev/null > /evidence/post/files.txt
   ```
2. **Diff Baselines** — Account for every pre-teardown item: terminated, destroyed, or retained (per audit-agent markers):
   ```bash
   diff /evidence/pre/files.txt /evidence/post/files.txt
   ```
3. **Compile Report** — Per-artifact-class summary, destruction methods/timestamps, residual scan result, post-teardown state diff.
4. **Notify Scheduler** — Emit cleanup-complete with residual count (must be zero for engagement-level teardown).

## Quality Gates

- **Gate 1:** Pre-teardown state capture for all five artifact classes reaches audit-agent before any destruction.
- **Gate 2:** Zero remote-access artifacts survive: reverse shells, tunnels, callbacks, and firewall rules all terminated/removed.
- **Gate 3:** Every credential is destroyed (zeroize + unlink confirmed by vault-agent) or shredded; confirmations collected.
- **Gate 4:** Every retained evidence item is covered by an audit-agent retention marker.
- **Gate 5:** Post-teardown residual scan + state diff accounts for 100% of pre-teardown artifacts.
- **Gate 6:** Engagement-level teardown reports zero residuals.

## References
- skills/dfir/skill-playbook.md
- skills/dfir/incident-triage.md
- GNU Coreutils shred: https://www.gnu.org/software/coreutils/manual/html_node/shred-invocation.html
- psutil Documentation: https://psutil.readthedocs.io/
- NIST SP 800-88 Guidelines for Media Sanitization
- SDelete: https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
