from __future__ import annotations

import json
import os
import tempfile

import pytest

from conftest import AuditLogger


class TestAuditLogger:
    def test_log_entry_creation(self, audit_logger):
        entry_hash = audit_logger.log(
            agent_id="recon-1",
            action="scan_port",
            target="10.0.0.1:22",
            result="open",
        )
        assert entry_hash is not None
        assert len(entry_hash) == 64

    def test_log_entry_with_metadata(self, audit_logger):
        entry_hash = audit_logger.log(
            agent_id="exploit-5",
            action="run_exploit",
            target="CVE-2026-1234",
            result="success",
            correlation_id="corr-001",
            metadata={"payload": "reverse_shell", "port": 4444},
        )
        entries = audit_logger.read_entries(correlation_id="corr-001")
        assert len(entries) == 1
        assert entries[0]["metadata"]["payload"] == "reverse_shell"

    def test_log_entry_with_correlation_id(self, audit_logger):
        audit_logger.log("a1", "scan", "10.0.0.1", "open", correlation_id="corr-001")
        audit_logger.log("a2", "exploit", "10.0.0.1", "success", correlation_id="corr-001")
        entries = audit_logger.read_entries(correlation_id="corr-001")
        assert len(entries) == 2


class TestHmacChain:
    def test_hmac_chain_integrity(self, audit_logger):
        audit_logger.log("agent-1", "action-1", "target-1", "ok")
        audit_logger.log("agent-2", "action-2", "target-2", "ok")
        current = audit_logger._resolve_current_file()
        with open(current, "r") as f:
            lines = f.read().strip().split("\n")
        assert len(lines) == 2
        entry1 = json.loads(lines[0])
        entry2 = json.loads(lines[1])
        assert entry2["previous_hash"] == entry1["entry_hash"]

    def test_chain_verification_passes(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        audit_logger.log("agent-2", "exploit", "10.0.0.1", "success")
        audit_logger.log("agent-3", "cleanup", "10.0.0.1", "done")
        assert audit_logger.verify_chain() is True

    def test_chain_verification_fails_on_tamper(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        audit_logger.log("agent-2", "exploit", "10.0.0.1", "success")
        current = audit_logger._resolve_current_file()
        with open(current, "r") as f:
            content = f.read()
        tampered = content.replace("open", "closed")
        with open(current, "w") as f:
            f.write(tampered)
        assert audit_logger.verify_chain() is False

    def test_hmac_tamper_detection(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        current = audit_logger._resolve_current_file()
        with open(current, "r") as f:
            entry = json.loads(f.readline())
        entry["hmac"] = "0000" + entry["hmac"][4:]
        with open(current, "w") as f:
            f.write(json.dumps(entry) + "\n")
        assert audit_logger.verify_chain() is False


class TestReadEntries:
    def test_read_entries_filter_by_agent(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        audit_logger.log("agent-2", "scan", "10.0.0.2", "open")
        entries = audit_logger.read_entries(agent_id="agent-1")
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "agent-1"

    def test_read_entries_filter_by_action(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        audit_logger.log("agent-1", "exploit", "10.0.0.1", "success")
        entries = audit_logger.read_entries(action="exploit")
        assert len(entries) == 1

    def test_read_entries_limit(self, audit_logger):
        for i in range(10):
            audit_logger.log(f"agent-{i}", "scan", "target", "ok")
        entries = audit_logger.read_entries(limit=3)
        assert len(entries) == 3

    def test_read_entries_empty_file(self, audit_logger):
        entries = audit_logger.read_entries()
        assert entries == []


class TestLogRotation:
    def test_session_log_rotation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key = b"test-key-32-bytes-long-for-hmac!!"
            logger = AuditLogger(tmpdir, hmac_key=key, max_file_size_mb=0)
            logger.log("agent-1", "action", "target", "ok")
            logger.log("agent-1", "action", "target", "ok")
            current = logger._resolve_current_file()
            assert current.exists()
            archive_files = list(logger.archive_directory.glob("audit_*.jsonl"))
            assert len(archive_files) >= 1

    def test_rotation_preserves_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key = b"test-key-32-bytes-long-for-hmac!!"
            logger = AuditLogger(tmpdir, hmac_key=key, max_file_size_mb=0)
            logger.log("agent-1", "action-1", "target-1", "ok")
            logger.log("agent-2", "action-2", "target-2", "ok")
            logger.log("agent-3", "action-3", "target-3", "ok")
            current = logger._resolve_current_file()
            current_exists = current.exists() and current.stat().st_size > 0
            archive_files = list(logger.archive_directory.glob("audit_*.jsonl"))
            total_logs = (1 if current_exists else 0) + len(archive_files)
            assert total_logs >= 2


class TestExport:
    def test_export_to_file(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        audit_logger.log("agent-2", "exploit", "10.0.0.1", "success")
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "export.jsonl")
            count = audit_logger.export_to_file(out_path)
            assert count == 2
            assert os.path.isfile(out_path)


class TestArchivedLogs:
    def test_list_archived_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key = b"test-key-32-bytes-long-for-hmac!!"
            logger = AuditLogger(tmpdir, hmac_key=key, max_file_size_mb=0)
            logger.log("agent-1", "action", "target", "ok")
            archived = logger.list_archived_logs()
            assert isinstance(archived, list)


class TestStats:
    def test_get_stats(self, audit_logger):
        audit_logger.log("agent-1", "scan", "10.0.0.1", "open")
        stats = audit_logger.get_stats()
        assert stats["total_entries"] == 1
        assert stats["last_entry_timestamp"] is not None
