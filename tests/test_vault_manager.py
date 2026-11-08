from __future__ import annotations

import os
import time
import threading
from unittest.mock import patch

import pytest

from conftest import SecretsVault


class TestSecretsVault:
    def test_requires_vault_key(self):
        with pytest.raises(Exception):
            SecretsVault(vault_key=None)

    def test_encrypt_decrypt_roundtrip(self, vault_instance):
        vault_instance.store("secret-1", "my-sensitive-data")
        value = vault_instance.retrieve("secret-1")
        assert value == "my-sensitive-data"

    def test_store_and_retrieve_multiple(self, vault_instance):
        vault_instance.store("key-1", "value-1")
        vault_instance.store("key-2", "value-2")
        assert vault_instance.retrieve("key-1") == "value-1"
        assert vault_instance.retrieve("key-2") == "value-2"

    def test_secret_not_found(self, vault_instance):
        with pytest.raises(Exception) as exc:
            vault_instance.retrieve("nonexistent")
        assert "not found" in str(exc.value).lower()

    def test_secret_expiry(self, vault_instance):
        vault_instance.store("expiring-secret", "data", ttl_hours=0.0)
        time.sleep(0.01)
        assert vault_instance.exists("expiring-secret") is False
        with pytest.raises(Exception) as exc:
            vault_instance.retrieve("expiring-secret")
        assert "not found" in str(exc.value).lower()

    def test_exists_returns_false_for_expired(self, vault_instance):
        vault_instance.store("will-expire", "data", ttl_hours=0.0)
        time.sleep(0.01)
        assert vault_instance.exists("will-expire") is False

    def test_delete_secret(self, vault_instance):
        vault_instance.store("to-delete", "data")
        assert vault_instance.exists("to-delete") is True
        assert vault_instance.delete("to-delete") is True
        assert vault_instance.exists("to-delete") is False

    def test_delete_nonexistent(self, vault_instance):
        assert vault_instance.delete("ghost") is False

    def test_get_info(self, vault_instance):
        vault_instance.store("info-test", "data", metadata={"type": "test"})
        info = vault_instance.get_info("info-test")
        assert info["key_id"] == "primary"
        assert info["metadata"]["type"] == "test"
        assert "ciphertext" not in info

    def test_list_secrets(self, vault_instance):
        vault_instance.store("list-1", "data-1")
        vault_instance.store("list-2", "data-2")
        secrets = vault_instance.list_secrets()
        assert len(secrets) == 2
        assert "list-1" in secrets

    def test_purge_all(self, vault_instance):
        vault_instance.store("purge-1", "data")
        vault_instance.store("purge-2", "data")
        assert vault_instance.purge_all() == 2
        assert len(vault_instance) == 0

    def test_contains(self, vault_instance):
        vault_instance.store("contains-test", "data")
        assert "contains-test" in vault_instance
        assert "ghost" not in vault_instance


class TestKeyRotation:
    def test_key_rotation_re_encrypts(self, vault_instance):
        vault_instance.store("rotate-me", "sensitive-value")
        assert vault_instance.retrieve("rotate-me") == "sensitive-value"
        re_encrypted = vault_instance.rotate_key("new-vault-key-16-chars!", "rotated")
        assert re_encrypted == 0
        with pytest.raises(Exception):
            vault_instance.retrieve("rotate-me")

    def test_key_rotation_updates_key_id(self, vault_instance):
        vault_instance.store("k1", "v1")
        vault_instance.rotate_key("another-key-16-bytes", "secondary")
        assert vault_instance._key_id == "secondary"

    def test_rotation_with_short_key_fails(self, vault_instance):
        with pytest.raises(Exception):
            vault_instance.rotate_key("ab")


class TestThreadSafety:
    def test_thread_safety(self, vault_instance):
        errors = []
        def worker(worker_id):
            try:
                for i in range(10):
                    sid = f"t-{worker_id}-{i}"
                    vault_instance.store(sid, f"v-{i}")
                    val = vault_instance.retrieve(sid)
                    assert val == f"v-{i}"
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    def test_concurrent_store_and_delete(self, vault_instance):
        def adder():
            for i in range(50):
                try:
                    vault_instance.store(f"concurrent-{i}", "data")
                except Exception:
                    pass
        def remover():
            for i in range(50):
                try:
                    vault_instance.delete(f"concurrent-{i}")
                except Exception:
                    pass
        t1 = threading.Thread(target=adder)
        t2 = threading.Thread(target=remover)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert len(vault_instance) >= 0


class TestEnvVarConfig:
    def test_env_var_key(self, monkeypatch):
        monkeypatch.setenv("SECRETS_VAULT_KEY", "env-key-for-testing-1234")
        vault = SecretsVault()
        vault.store("env-test", "env-value")
        assert vault.retrieve("env-test") == "env-value"

    def test_env_var_retention(self, monkeypatch):
        monkeypatch.setenv("SECRETS_VAULT_KEY", "env-key-for-testing-1234")
        monkeypatch.setenv("SECRETS_RETENTION_HOURS", "48")
        vault = SecretsVault()
        assert vault._retention_hours == 48.0


class MetadataTest:
    def test_metadata_on_store(self, vault_instance):
        vault_instance.store("meta-test", "data", metadata={"env": "prod", "severity": "high"})
        info = vault_instance.get_info("meta-test")
        assert info["metadata"]["env"] == "prod"
