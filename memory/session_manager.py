"""ECC-style session memory manager with disk persistence and auto-compression."""

from __future__ import annotations

import json
import gzip
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SESSION_DIR = Path("sessions")
MAX_SESSION_SIZE_BYTES = 512_000
COMPRESS_AFTER_BYTES = 256_000


class Session:
    """Represents a single penetration testing session."""

    def __init__(
        self,
        session_id: str,
        agents_used: list[str] | None = None,
        targets: list[str] | None = None,
    ) -> None:
        self.session_id: str = session_id
        self.timestamp: str = datetime.now(timezone.utc).isoformat()
        self.agents_used: list[str] = agents_used or []
        self.targets: list[str] = targets or []
        self.finding_count: int = 0
        self.data: dict[str, Any] = {}
        self._compressed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "agents_used": self.agents_used,
            "targets": self.targets,
            "finding_count": self.finding_count,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        session = cls(
            session_id=data["session_id"],
            agents_used=data.get("agents_used", []),
            targets=data.get("targets", []),
        )
        session.timestamp = data.get("timestamp", session.timestamp)
        session.finding_count = data.get("finding_count", 0)
        session.data = data.get("data", {})
        return session


class SessionManager:
    """Manage sessions with save/load, compression, and metadata tracking."""

    def __init__(self, session_dir: str | Path | None = None) -> None:
        self.session_dir = Path(session_dir) if session_dir else SESSION_DIR
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._current: Session | None = None

    def create_session(
        self,
        session_id: str,
        agents_used: list[str] | None = None,
        targets: list[str] | None = None,
    ) -> Session:
        self._current = Session(
            session_id=session_id,
            agents_used=agents_used,
            targets=targets,
        )
        return self._current

    def save_session(self, session: Session | None = None) -> Path:
        s = session or self._current
        if s is None:
            raise RuntimeError("No session to save — create one first")
        s.timestamp = datetime.now(timezone.utc).isoformat()

        data = s.to_dict()
        raw = json.dumps(data, indent=2).encode("utf-8")
        path = self.session_dir / f"{s.session_id}.json"

        if len(raw) > COMPRESS_AFTER_BYTES:
            path = path.with_suffix(".json.gz")
            with gzip.open(path, "wt", encoding="utf-8") as f:
                json.dump(data, f)
            s._compressed = True
            logger.info("Session '%s' compressed (%d bytes -> %d bytes)", s.session_id, len(raw), path.stat().st_size)
        else:
            path.write_bytes(raw)
            logger.info("Session '%s' saved to %s (%d bytes)", s.session_id, path, len(raw))

        if len(raw) > MAX_SESSION_SIZE_BYTES and not s._compressed:
            logger.warning("Session '%s' exceeds max size (%d > %d)", s.session_id, len(raw), MAX_SESSION_SIZE_BYTES)

        return path

    def load_session(self, session_id: str) -> Session:
        json_path = self.session_dir / f"{session_id}.json"
        gz_path = self.session_dir / f"{session_id}.json.gz"

        if gz_path.exists():
            with gzip.open(gz_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
            session = Session.from_dict(data)
            session._compressed = True
            logger.info("Loaded compressed session '%s'", session_id)
        elif json_path.exists():
            raw = json_path.read_bytes()
            if len(raw) > COMPRESS_AFTER_BYTES:
                self._migrate_to_compressed(json_path, gz_path, raw)
            data = json.loads(raw)
            session = Session.from_dict(data)
            logger.info("Loaded session '%s'", session_id)
        else:
            raise FileNotFoundError(f"Session '{session_id}' not found in {self.session_dir}")

        self._current = session
        return session

    def _migrate_to_compressed(self, json_path: Path, gz_path: Path, raw: bytes) -> None:
        data = json.loads(raw)
        with gzip.open(gz_path, "wt", encoding="utf-8") as f:
            json.dump(data, f)
        json_path.unlink()
        logger.info("Migrated '%s' to compressed format", json_path.stem)

    def list_sessions(self) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        for p in self.session_dir.glob("*"):
            if p.suffix not in (".json", ".gz"):
                continue
            try:
                if p.suffix == ".gz":
                    with gzip.open(p, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                else:
                    data = json.loads(p.read_bytes())
                sessions.append({
                    "session_id": data.get("session_id"),
                    "timestamp": data.get("timestamp"),
                    "targets": data.get("targets", []),
                    "finding_count": data.get("finding_count", 0),
                    "size": p.stat().st_size,
                })
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read session file %s: %s", p.name, exc)
        sessions.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
        return sessions

    def delete_session(self, session_id: str) -> None:
        for p in self.session_dir.glob(f"{session_id}.*"):
            p.unlink()
            logger.info("Deleted session file '%s'", p.name)

    def get_current(self) -> Session | None:
        return self._current
