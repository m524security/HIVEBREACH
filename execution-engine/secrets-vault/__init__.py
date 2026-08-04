"""
HiveBreach Secrets Vault.

AES-256-GCM encrypted secrets store with auto-expiry,
key rotation support, and thread-safe access.
"""

from .vault_manager import SecretsVault, VaultError, SecretNotFoundError

__all__ = [
    "SecretsVault",
    "VaultError",
    "SecretNotFoundError",
]
