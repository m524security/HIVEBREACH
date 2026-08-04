"""
HiveBreach — Immutable Audit Logger

Provides the AuditLogger class for recording all agent actions
in an append-only, integrity-verified JSON Lines log file.

Features:
  - Append-only writes (immutable history)
  - HMAC-SHA256 integrity chain (each entry hash includes previous entry hash)
  - Automatic log rotation and archival
  - JSON Lines format for easy parsing
  - Thread-safe writes
"""

import os
import json
import hmac
import hashlib
import logging
import threading
import datetime
import shutil
import glob
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("hivebreach.audit")


class AuditLogger:
    """
    Immutable, append-only audit logger with hash-chain integrity.

    Each log entry is a JSON object containing:
      - timestamp: ISO-8601 UTC
      - agent_id: identifier of the acting agent
      - action: action performed
      - target: target of the action
      - result: outcome summary
      - correlation_id: traceability ID linking related actions
      - previous_hash: SHA-256 of the previous entry (chain)
      - entry_hash: SHA-256 of this entry (self)

    Usage:
        logger = AuditLogger("audit/logs/")
        logger.log("recon-agent-1", "scan_port", "10.0.0.1:443", "open")
    """

    def __init__(
        self,
        log_directory: str,
        hmac_key: Optional[bytes] = None,
        max_file_size_mb: int = 100,
        archive_directory: Optional[str] = None,
    ):
        """
        Initialize the audit logger.

        Args:
            log_directory: Directory where log files are stored.
            hmac_key: Key for HMAC signing of entries.
                      If None, a random key is generated.
            max_file_size_mb: Maximum log file size before rotation (MB).
            archive_directory: Where rotated logs are archived.
                               Defaults to <log_directory>/archive/.
        """
        self.log_directory = Path(log_directory).resolve()
        self.log_directory.mkdir(parents=True, exist_ok=True)

        self.max_file_size = max_file_size_mb * 1024 * 1024

        self.archive_directory = Path(archive_directory or self.log_directory / "archive")
        self.archive_directory.mkdir(parents=True, exist_ok=True)

        if hmac_key is None:
            hmac_key = os.urandom(32)
            logger.warning(
                "No HMAC key provided — generated random key. "
                "For production, set a persistent key for chain verification."
            )
        self.hmac_key = hmac_key

        self._lock = threading.Lock()

        self._current_file = self._resolve_current_file()
        self._previous_hash = self._load_last_hash()

    def _resolve_current_file(self) -> Path:
        """Get the current active log file path."""
        return self.log_directory / "audit.jsonl"

    def _load_last_hash(self) -> str:
        """
        Load the hash of the last entry in the log file (if any).
        Returns empty string for a new file.
        """
        current = self._resolve_current_file()
        if not current.exists():
            return ""

        last_line = None
        with open(current, "r", encoding="utf-8") as f:
            for line in f:
                last_line = line.strip()

        if not last_line:
            return ""

        try:
            last_entry = json.loads(last_line)
            return last_entry.get("entry_hash", "")
        except (json.JSONDecodeError, KeyError):
            logger.warning("Could not parse last log entry — starting new chain.")
            return ""

    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of a log entry dictionary."""
        serialized = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def _compute_hmac(self, entry: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 of the entry for integrity verification."""
        serialized = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hmac.new(self.hmac_key, serialized, hashlib.sha256).hexdigest()

    def _check_rotation(self) -> None:
        """Rotate log file if it exceeds the maximum size."""
        current = self._resolve_current_file()
        if current.exists() and current.stat().st_size > self.max_file_size:
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            rotated_name = f"audit_{timestamp}.jsonl"
            rotated_path = self.archive_directory / rotated_name
            shutil.move(str(current), str(rotated_path))
            logger.info("Rotated audit log to %s", rotated_path)

            self._previous_hash = ""

    def log(
        self,
        agent_id: str,
        action: str,
        target: str,
        result: str,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Write an audit log entry.

        Args:
            agent_id: Identifier of the agent performing the action.
            action: The action being logged (e.g., "scan_port", "exploit_run").
            target: The target of the action (e.g., IP, hostname, file path).
            result: Outcome (e.g., "open", "failed", "extracted", "blocked").
            correlation_id: Optional ID linking related actions across agents.
            metadata: Optional additional structured data.

        Returns:
            The entry_hash of the written entry for cross-referencing.
        """
        entry: Dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "agent_id": agent_id,
            "action": action,
            "target": target,
            "result": result,
            "correlation_id": correlation_id or "",
            "previous_hash": self._previous_hash,
        }

        if metadata:
            entry["metadata"] = metadata

        entry["entry_hash"] = self._compute_entry_hash(entry)
        entry["hmac"] = self._compute_hmac(entry)

        line = json.dumps(entry, ensure_ascii=False) + "\n"

        with self._lock:
            self._check_rotation()

            current = self._resolve_current_file()
            with open(current, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

            self._previous_hash = entry["entry_hash"]

        logger.debug(
            "Audit: agent=%s action=%s target=%s result=%s hash=%s",
            agent_id, action, target, result, entry["entry_hash"],
        )

        return entry["entry_hash"]

    def verify_chain(self, log_file: Optional[Path] = None) -> bool:
        """
        Verify the integrity of the entire audit log chain.

        Checks:
          1. Every entry links to the previous entry via previous_hash.
          2. Every entry's self-reported entry_hash matches its content.
          3. (If HMAC key is available) Every entry's HMAC is valid.

        Args:
            log_file: Path to the log file to verify.
                      Defaults to the current active file.

        Returns:
            True if the entire chain is valid, False otherwise.
        """
        log_file = log_file or self._resolve_current_file()
        if not log_file.exists():
            logger.warning("Log file does not exist: %s", log_file)
            return True

        previous_hash = ""
        all_valid = True
        line_number = 0

        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line_number += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.error("Line %d: Invalid JSON — %s", line_number, e)
                    all_valid = False
                    continue

                # Save hmac and entry_hash (not present during original hash computation)
                stored_hmac = entry.pop("hmac", "")
                stored_entry_hash = entry.pop("entry_hash", "")

                # Verify self hash
                self_hash = self._compute_entry_hash(entry)
                if self_hash != stored_entry_hash:
                    logger.error(
                        "Line %d: entry_hash mismatch. "
                        "Computed: %s, Stored: %s",
                        line_number,
                        self_hash,
                        stored_entry_hash,
                    )
                    all_valid = False

                # Verify chain link
                if entry.get("previous_hash", "") != previous_hash:
                    logger.error(
                        "Line %d: Chain break. "
                        "Expected previous_hash: %s, Got: %s",
                        line_number,
                        previous_hash,
                        entry.get("previous_hash", ""),
                    )
                    all_valid = False

                # Verify HMAC (entry_hash must be present, hmac must not)
                entry["entry_hash"] = stored_entry_hash
                expected_hmac = self._compute_hmac(entry)
                if stored_hmac != expected_hmac:
                    logger.error(
                        "Line %d: HMAC mismatch. "
                        "Computed: %s, Stored: %s",
                        line_number,
                        expected_hmac,
                        stored_hmac,
                    )
                    all_valid = False

                # Restore for chain linking
                entry["hmac"] = stored_hmac
                entry["entry_hash"] = stored_entry_hash

                previous_hash = stored_entry_hash

        if all_valid:
            logger.info("Audit log chain verification PASSED (%d entries)", line_number)
        else:
            logger.error("Audit log chain verification FAILED (%d entries checked)", line_number)

        return all_valid

    def read_entries(
        self,
        log_file: Optional[Path] = None,
        agent_id: Optional[str] = None,
        action: Optional[str] = None,
        correlation_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list:
        """
        Read and filter audit log entries.

        Args:
            log_file: Path to log file (defaults to current).
            agent_id: Filter by agent ID.
            action: Filter by action.
            correlation_id: Filter by correlation ID.
            start_time: ISO-8601 start timestamp (inclusive).
            end_time: ISO-8601 end timestamp (inclusive).
            limit: Maximum number of entries to return.

        Returns:
            List of matching log entries (oldest first).
        """
        log_file = log_file or self._resolve_current_file()
        if not log_file.exists():
            return []

        results = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if agent_id and entry.get("agent_id") != agent_id:
                    continue
                if action and entry.get("action") != action:
                    continue
                if correlation_id and entry.get("correlation_id") != correlation_id:
                    continue
                if start_time and entry.get("timestamp", "") < start_time:
                    continue
                if end_time and entry.get("timestamp", "") > end_time:
                    continue

                results.append(entry)

                if limit and len(results) >= limit:
                    break

        return results

    def export_to_file(
        self,
        output_path: Path,
        log_file: Optional[Path] = None,
        **filters,
    ) -> int:
        """
        Export filtered entries to a separate JSON Lines file.

        Args:
            output_path: Path to write the export to.
            log_file: Source log file.
            **filters: Same filters as read_entries().

        Returns:
            Number of entries exported.
        """
        entries = self.read_entries(log_file=log_file, **filters)
        with open(output_path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return len(entries)

    def list_archived_logs(self) -> list:
        """List all archived log files sorted by creation time."""
        files = []
        for f in self.archive_directory.glob("audit_*.jsonl"):
            files.append({
                "path": str(f),
                "size": f.stat().st_size,
                "created": datetime.datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
            })
        return sorted(files, key=lambda x: x["created"])

    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics about the audit log."""
        current = self._resolve_current_file()
        stats = {
            "current_file": str(current),
            "current_file_size_bytes": current.stat().st_size if current.exists() else 0,
            "archive_directory": str(self.archive_directory),
            "archived_files": len(list(self.archive_directory.glob("audit_*.jsonl"))),
            "total_entries": 0,
            "last_entry_timestamp": None,
        }

        if current.exists():
            with open(current, "r", encoding="utf-8") as f:
                last_line = None
                for line in f:
                    stats["total_entries"] += 1
                    last_line = line.strip()
            if last_line:
                try:
                    last_entry = json.loads(last_line)
                    stats["last_entry_timestamp"] = last_entry.get("timestamp")
                except json.JSONDecodeError:
                    pass

        return stats


# ---------------------------------------------------------------------------
# Standalone usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLogger(tmpdir)

        # Simulate agent actions
        audit.log("recon-agent-1", "scan_port", "10.0.0.1:22", "open",
                  correlation_id="corr-001")
        audit.log("recon-agent-1", "scan_port", "10.0.0.1:80", "open",
                  correlation_id="corr-001")
        audit.log("exploit-agent-5", "run_exploit", "CVE-2026-1234", "success",
                  correlation_id="corr-002",
                  metadata={"target_version": "1.2.3", "payload": "reverse_shell"})
        audit.log("creed-creds-agent", "extract_hash", "10.0.0.1:445", "captured",
                  correlation_id="corr-002",
                  metadata={"hash_type": "NTLM", "user": "administrator"})

        # Verify chain integrity
        print(f"Chain valid: {audit.verify_chain()}")

        # Read filtered entries
        recon_actions = audit.read_entries(agent_id="recon-agent-1")
        print(f"Recon agent actions: {len(recon_actions)}")

        # Get stats
        stats = audit.get_stats()
        print(f"Total entries: {stats['total_entries']}")

        # Read all entries
        print("\nAll entries:")
        for entry in audit.read_entries():
            print(f"  [{entry['timestamp']}] {entry['agent_id']}: {entry['action']} -> {entry['result']}")
