# Skill Playbook: vault-agent — DEEP AGGRESSIVE MODE

> **Purpose:** Authoritative deep-aggressive-mode operating procedures for the secrets vault: AES-256-GCM encryption, HKDF per-secret key derivation, lifecycle management, key rotation, and cryptographic destruction. Every phase embeds the credential-intelligence discipline from `skills/threat-intel/skill-playbook.md`. The vault never logs, transmits, or persists plaintext secrets; the master key lives in memory only.

## Phase 1 — Vault Initialization and Key Material

1. **Generate Master Key** — Cryptographically secure 256-bit key, memory-only, never persisted:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   # operator delivers via env var / HSM at startup; never via CLI history or files
   ```
2. **Verify Against KAT Vectors** — Before operational use, validate the AES-256-GCM implementation against NIST known-answer test vectors; decryption of a tampered ciphertext must fail with an authentication error.
3. **Init Storage Backend** — Create the encrypted blob store (file-based or DB) with restrictive permissions:
   ```bash
   mkdir -p /opt/hivebreach/vault/store
   chmod 700 /opt/hivebreach/vault/store
   ```
4. **Set Rotation Schedule** — Default 24h master-key rotation with a 7-day grace window for the old key. Read overrides from config-agent.
5. **Announce Ready** — Emit `{vault_id, status: initialized, storage: backend, rotation: schedule}` to scheduler-agent and audit-agent.

## Phase 2 — Secret Ingestion

1. **Validate Payload** — Required: plaintext, metadata (source, type, target), authorized_consumers, ttl. Reject anything missing fields.
2. **Attach Intel Tags** — Per `skills/threat-intel/skill-playbook.md`, correlate credential material with IOC context: source target, credential type, confidence, TLP-style handling.
3. **Derive Per-Secret Key**:
   ```bash
   python3 -c "
   from cryptography.hazmat.primitives.kdf.hkdf import HKDF
   from cryptography.hazmat.primitives import hashes
   import secrets
   salt = secrets.token_bytes(32)
   key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=b'hivebreach-vault-v1:' + secret_id.encode()).derive(master_key)
   "
   ```
4. **Encrypt AES-256-GCM** — 96-bit random nonce, associated_data = agent_id + secret_id; append 128-bit tag to ciphertext.
5. **Store Blob** — Write the JSON blob (ciphertext, nonce, salt, associated_data_hash, algorithm, timestamps, consumers, metadata) to the store with 0600 perms.
6. **Emit Handle** — Return `secret_id` to the submitting agent; log only the secret_id, never plaintext.
7. **Flag Cracking Candidate** — If credential_type is a hash targetable by hashcat/john, tag it for the cracking workflow; hashes flow out encrypted and are decrypted just-in-time into a 0600 temp file that is shredded after the job.

## Phase 3 — Retrieval and Access Control

1. **Authenticate Request** — Verify agent_id of the requester is in authorized_consumers; else deny and notify audit-agent.
2. **Check Expiry** — `expires_at` passed → return expired error, notify scheduler-agent for renewal or destruction.
3. **Decrypt Just-In-Time**:
   ```bash
   python3 -c "
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   pt = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
   "
   ```
4. **Verify Tag** — Authentication failure → tamper incident logged, secret quarantined, audit-agent notified.
5. **Update Access Metadata** — Increment access_count, set last_accessed.
6. **Transmit Securely** — Deliver plaintext only over the TLS/mutual-auth channel; require the consumer to zeroize after use.
7. **Sweep Expired** — Background sweep every 300s purges expired secrets with cryptographic destruction.

## Phase 4 — Key Rotation

1. **Trigger** — On schedule, or on compromise suspicion, or on cleanup-teardown-agent directive.
2. **Generate New Master Key** — `secrets.token_bytes(32)` in memory.
3. **Re-Encrypt Active Secrets** — For each active secret: decrypt with old key, derive fresh per-secret key, re-encrypt with new master key.
4. **Grace Window** — Retain old master key for 7 days (configurable) to decrypt any missed secrets.
5. **Destroy Old Key** — After the grace window, zeroize the old master key in memory:
   ```bash
   python3 -c "import ctypes; buf=...; ctypes.memset(ctypes.addressof(buf), 0, len(buf))"
   ```
6. **Report** — Notify audit-agent (rotation id, count re-encrypted, grace date) and scheduler-agent.

## Phase 5 — Cryptographic Destruction

1. **On Expiry / Rotation / Directive** — Zeroize then delete each blob:
   ```bash
   python3 -c "
   import os
   with open(path, 'r+b') as f: f.write(b'\x00' * os.path.getsize(path))
   os.unlink(path)
   "
   ```
2. **Shred Intermediates** — Plaintext temp files for cracking workflows are shredded with `shred -u -z` after the job.
3. **Zeroize Memory** — Plaintext byte buffers cleared with `ctypes.memset` after every use.
4. **Confirm** — Emit destruction confirmation `{secret_id, method: zeroize+unlink, timestamp}` to cleanup-teardown-agent and audit-agent.
5. **Engagement Close** — On cleanup-teardown-agent directive, destroy all active secrets, zeroize the master key, and emit a vault teardown confirmation.

## Quality Gates

- **Gate 1:** AES-256-GCM implementation passes NIST KAT vectors and tamper-detection check before operational use.
- **Gate 2:** Zero plaintext secrets in logs, config files, env dumps, or inter-agent messages; only secret_ids appear.
- **Gate 3:** Every retrieval request is authorization-checked and audited (success and denial).
- **Gate 4:** Every secret has a TTL; expired secrets are unrecoverable and cryptographically destroyed.
- **Gate 5:** Every key rotation re-encrypts all active secrets and destroys the old key after the grace window.
- **Gate 6:** Master key exists only in memory; startup without the key blocks all requests.

## References
- skills/threat-intel/skill-playbook.md
- NIST SP 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions (HKDF)
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Python cryptography AEAD: https://cryptography.io/en/latest/hazmat/primitives/aead/
