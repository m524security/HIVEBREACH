import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

SECRETS_VAULT_KEY_ENV = "SECRETS_VAULT_KEY"
SECRETS_RETENTION_HOURS_ENV = "SECRETS_RETENTION_HOURS"
DEFAULT_RETENTION_HOURS = 24

_KEY_BYTE_LENGTH = 32
_NONCE_BYTE_LENGTH = 12


class VaultError(Exception):
    pass


class SecretNotFoundError(VaultError):
    pass


class SecretExpiredError(VaultError):
    pass


class VaultKeyError(VaultError):
    pass


@dataclass
class SecretEntry:
    key_id: str
    ciphertext: bytes
    nonce: bytes
    created_at: float
    expires_at: float
    access_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self, include_value: bool = False) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key_id": self.key_id,
            "created_at": datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(self.expires_at, tz=timezone.utc).isoformat(),
            "access_count": self.access_count,
            "metadata": self.metadata,
        }
        if include_value:
            d["ciphertext"] = base64.b64encode(self.ciphertext).decode()
            d["nonce"] = base64.b64encode(self.nonce).decode()
        return d


class SecretsVault:
    def __init__(
        self,
        vault_key: Optional[str] = None,
        retention_hours: Optional[float] = None,
        key_id: str = "primary",
    ):
        self._lock = RLock()
        self._key_id = key_id
        self._retention_hours = retention_hours or float(
            os.environ.get(SECRETS_RETENTION_HOURS_ENV, str(DEFAULT_RETENTION_HOURS))
        )
        self._vault_key = vault_key or os.environ.get(SECRETS_VAULT_KEY_ENV)
        if not self._vault_key:
            raise VaultKeyError(
                f"No vault key provided. Set {SECRETS_VAULT_KEY_ENV} environment variable "
                f"or pass vault_key to the constructor."
            )
        self._aesgcm: Optional[AESGCM] = None
        self._secrets: Dict[str, SecretEntry] = {}
        self._init_cipher()

    def _init_cipher(self) -> None:
        raw_key = self._vault_key.encode("utf-8")
        if len(raw_key) < 8:
            raise VaultKeyError("Vault key must be at least 8 characters")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_BYTE_LENGTH,
            salt=None,
            info=b"hivebreach-secrets-vault-v1",
        )
        derived_key = hkdf.derive(raw_key)
        self._aesgcm = AESGCM(derived_key)
        logger.debug("Cipher initialized (key_id=%s)", self._key_id)

    def rotate_key(self, new_vault_key: str, new_key_id: str = "rotated") -> int:
        with self._lock:
            old_secrets = list(self._secrets.items())
            self._vault_key = new_vault_key
            self._key_id = new_key_id
            self._init_cipher()
            re_encrypted = 0
            for secret_id, entry in old_secrets:
                try:
                    plaintext_bytes = self._decrypt_entry(entry)
                except (VaultError, InvalidTag):
                    logger.warning("Could not decrypt %s during key rotation; dropping", secret_id)
                    del self._secrets[secret_id]
                    continue
                nonce = os.urandom(_NONCE_BYTE_LENGTH)
                ciphertext = self._aesgcm.encrypt(nonce, plaintext_bytes, None)
                self._secrets[secret_id] = SecretEntry(
                    key_id=self._key_id,
                    ciphertext=ciphertext,
                    nonce=nonce,
                    created_at=entry.created_at,
                    expires_at=entry.expires_at,
                    access_count=entry.access_count,
                    metadata=entry.metadata,
                )
                re_encrypted += 1
            logger.info(
                "Key rotation complete: %d secrets re-encrypted (new_key_id=%s)",
                re_encrypted, new_key_id,
            )
            return re_encrypted

    def store(
        self,
        secret_id: str,
        value: str,
        ttl_hours: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        with self._lock:
            now = time.time()
            ttl = (ttl_hours if ttl_hours is not None else self._retention_hours) * 3600
            nonce = os.urandom(_NONCE_BYTE_LENGTH)
            plaintext_bytes = value.encode("utf-8")
            ciphertext = self._aesgcm.encrypt(nonce, plaintext_bytes, None)
            self._secrets[secret_id] = SecretEntry(
                key_id=self._key_id,
                ciphertext=ciphertext,
                nonce=nonce,
                created_at=now,
                expires_at=now + ttl,
                metadata=metadata or {},
            )
            logger.info(
                "Stored secret '%s' (key_id=%s, expires_at=%s)",
                secret_id, self._key_id,
                datetime.fromtimestamp(now + ttl, tz=timezone.utc).isoformat(),
            )
            _redact_log(secret_id)
            return secret_id

    def retrieve(self, secret_id: str) -> str:
        with self._lock:
            entry = self._secrets.get(secret_id)
            if not entry:
                raise SecretNotFoundError(f"Secret '{secret_id}' not found")
            if entry.is_expired:
                del self._secrets[secret_id]
                raise SecretExpiredError(f"Secret '{secret_id}' has expired")
            plaintext = self._decrypt_entry(entry)
            entry.access_count += 1
            _redact_log(secret_id)
            return plaintext

    def _decrypt_entry(self, entry: SecretEntry) -> str:
        try:
            plaintext_bytes = self._aesgcm.decrypt(entry.nonce, entry.ciphertext, None)
        except InvalidTag as e:
            raise VaultError(f"Decryption failed for key_id={entry.key_id}: {e}") from e
        return plaintext_bytes.decode("utf-8")

    def exists(self, secret_id: str) -> bool:
        with self._lock:
            entry = self._secrets.get(secret_id)
            if not entry:
                return False
            if entry.is_expired:
                del self._secrets[secret_id]
                return False
            return True

    def delete(self, secret_id: str) -> bool:
        with self._lock:
            entry = self._secrets.pop(secret_id, None)
            if entry:
                logger.info("Deleted secret '%s'", secret_id)
                _redact_log(secret_id)
                return True
            return False

    def expire_all(self) -> int:
        with self._lock:
            now = time.time()
            expired = [sid for sid, entry in self._secrets.items() if entry.expires_at <= now]
            for sid in expired:
                del self._secrets[sid]
            if expired:
                logger.info("Expired %d secrets", len(expired))
            return len(expired)

    def purge_all(self) -> int:
        with self._lock:
            count = len(self._secrets)
            self._secrets.clear()
            logger.info("Purged all %d secrets from vault", count)
            return count

    def get_info(self, secret_id: str) -> Dict[str, Any]:
        with self._lock:
            entry = self._secrets.get(secret_id)
            if not entry:
                raise SecretNotFoundError(f"Secret '{secret_id}' not found")
            if entry.is_expired:
                del self._secrets[secret_id]
                raise SecretExpiredError(f"Secret '{secret_id}' has expired")
            return entry.to_dict(include_value=False)

    def list_secrets(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            self.expire_all()
            return {sid: entry.to_dict(include_value=False) for sid, entry in self._secrets.items()}

    def __len__(self) -> int:
        with self._lock:
            self.expire_all()
            return len(self._secrets)

    def __contains__(self, secret_id: str) -> bool:
        return self.exists(secret_id)


def _redact_log(secret_id: str) -> None:
    logger.debug("Accessed secret '%s' (value redacted)", secret_id)
