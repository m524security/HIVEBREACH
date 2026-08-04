"""
communication-bus — Agent-to-Agent Message Bus

Thread-safe async message passing for HiveBreach's multi-agent swarm.
Implements the Blackboard pattern for shared findings with
publish/subscribe by finding type, agent registration, and a
full audit history.

Message types: FINDING, HANDOFF, REQUEST_HELP, STATUS, CHALLENGE
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MessageType(Enum):
    FINDING = "finding"
    HANDOFF = "handoff"
    REQUEST_HELP = "request_help"
    STATUS = "status"
    CHALLENGE = "challenge"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A security finding discovered by an agent."""

    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    target: str = ""
    technique_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    verified: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "agent_type": self.agent_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "target": self.target,
            "technique_id": self.technique_id,
            "owasp_id": self.owasp_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "evidence": self.evidence,
            "verified": self.verified,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Message:
    """A message sent between agents via the bus."""

    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    message_type: MessageType = MessageType.STATUS
    sender: str = ""
    recipient: Optional[str] = None  # None = broadcast
    payload: Dict[str, Any] = field(default_factory=dict)
    finding: Optional[Finding] = None
    correlation_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "message_id": self.message_id,
            "message_type": self.message_type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.finding:
            d["finding"] = self.finding.to_dict()
        return d


@dataclass
class AgentRegistration:
    """Registration record for an agent on the bus."""

    agent_id: str
    agent_type: str
    address: Optional[str] = None
    status: AgentStatus = AgentStatus.IDLE
    subscribed_types: Set[str] = field(default_factory=set)
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# MessageBus (Singleton)
# ---------------------------------------------------------------------------

class MessageBus:
    """
    Thread-safe singleton message bus for agent-to-agent communication.

    Implements:
    - Agent registration / deregistration
    - Blackboard pattern (shared finding repository)
    - Publish/subscribe by finding type and message type
    - Message history / audit log
    - Async first, with synchronous wrappers
    """

    _instance: Optional["MessageBus"] = None
    _instance_lock: threading.Lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "MessageBus":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, max_history: int = 10000):
        if self._initialized:
            return
        self._initialized = True

        self.max_history = max_history

        # Thread synchronization
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

        # Agent registry
        self._agents: Dict[str, AgentRegistration] = {}

        # Message history (audit log)
        self._message_history: List[Message] = []

        # Blackboard: shared findings repository
        self._findings: Dict[str, Finding] = {}

        # Publish/subscribe: finding_type -> set of agent_ids
        self._finding_subscribers: Dict[str, Set[str]] = {}

        # Message type subscribers
        self._message_subscribers: Dict[MessageType, Set[str]] = {}

        # Async queues for each agent
        self._agent_queues: Dict[str, asyncio.Queue] = {}

        # Callbacks for real-time notification
        self._callbacks: List[Callable[[Message], None]] = []

        logger.info("MessageBus initialised (max_history=%d)", max_history)

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        address: Optional[str] = None,
        subscribe_to: Optional[List[str]] = None,
    ) -> AgentRegistration:
        """
        Register an agent on the bus. Returns the registration record.
        """
        with self._lock:
            reg = AgentRegistration(
                agent_id=agent_id,
                agent_type=agent_type,
                address=address,
                subscribed_types=set(subscribe_to or []),
            )
            self._agents[agent_id] = reg
            self._agent_queues[agent_id] = asyncio.Queue()

            # Subscribe to message types based on agent type
            self._auto_subscribe(agent_id, agent_type)

            logger.info(
                "Agent registered: %s (type=%s, subs=%d)",
                agent_id, agent_type, len(reg.subscribed_types),
            )
            return reg

    def _auto_subscribe(self, agent_id: str, agent_type: str) -> None:
        """Set up default subscriptions based on agent type."""
        # All agents receive STATUS messages
        self._ensure_subscriber(MessageType.STATUS, agent_id)

        # Verification and Report agents receive all FINDINGS
        if "verification" in agent_type or "report" in agent_type:
            for msg_type in MessageType:
                self._ensure_subscriber(msg_type, agent_id)

    def deregister_agent(self, agent_id: str) -> bool:
        """
        Remove an agent from the bus. Returns True if found.
        """
        with self._lock:
            if agent_id not in self._agents:
                return False

            del self._agents[agent_id]
            self._agent_queues.pop(agent_id, None)

            # Remove from all subscriber lists
            for subs in self._finding_subscribers.values():
                subs.discard(agent_id)
            for subs in self._message_subscribers.values():
                subs.discard(agent_id)

            logger.info("Agent deregistered: %s", agent_id)
            return True

    def get_agent(self, agent_id: str) -> Optional[AgentRegistration]:
        with self._lock:
            return self._agents.get(agent_id)

    def list_agents(self) -> Dict[str, AgentRegistration]:
        with self._lock:
            return dict(self._agents)

    def get_agents_by_type(self, agent_type: str) -> List[str]:
        with self._lock:
            return [
                aid for aid, reg in self._agents.items()
                if reg.agent_type == agent_type
            ]

    def update_agent_status(self, agent_id: str, status: AgentStatus) -> bool:
        with self._lock:
            reg = self._agents.get(agent_id)
            if not reg:
                return False
            reg.status = status
            reg.last_heartbeat = datetime.now(timezone.utc)
            return True

    def heartbeat(self, agent_id: str) -> bool:
        with self._lock:
            reg = self._agents.get(agent_id)
            if not reg:
                return False
            reg.last_heartbeat = datetime.now(timezone.utc)
            return True

    # ------------------------------------------------------------------
    # Publish / Subscribe
    # ------------------------------------------------------------------

    def _ensure_subscriber(self, msg_type: MessageType, agent_id: str) -> None:
        if msg_type not in self._message_subscribers:
            self._message_subscribers[msg_type] = set()
        self._message_subscribers[msg_type].add(agent_id)

    def subscribe(self, agent_id: str, message_type: MessageType) -> None:
        with self._lock:
            self._ensure_subscriber(message_type, agent_id)

    def subscribe_to_finding_type(self, agent_id: str, finding_type: str) -> None:
        with self._lock:
            if finding_type not in self._finding_subscribers:
                self._finding_subscribers[finding_type] = set()
            self._finding_subscribers[finding_type].add(agent_id)

    def unsubscribe(self, agent_id: str, message_type: MessageType) -> None:
        with self._lock:
            subs = self._message_subscribers.get(message_type)
            if subs:
                subs.discard(agent_id)

    # ------------------------------------------------------------------
    # Sending messages
    # ------------------------------------------------------------------

    async def send_message(self, message: Message) -> bool:
        """
        Send a message on the bus. If recipient is set, delivers only
        to that agent. Otherwise, broadcasts to all subscribers of
        the message type.
        """
        with self._lock:
            self._message_history.append(message)
            if len(self._message_history) > self.max_history:
                self._message_history = self._message_history[-self.max_history:]

            if message.recipient:
                # Direct message
                queue = self._agent_queues.get(message.recipient)
                if queue:
                    await queue.put(message)
                    return True
                logger.warning(
                    "Recipient %s not found on bus", message.recipient
                )
                return False

            # Broadcast to subscribers of this message type
            subs = self._message_subscribers.get(message.message_type, set())
            for agent_id in subs:
                queue = self._agent_queues.get(agent_id)
                if queue:
                    await queue.put(message)

            # Notify callbacks
            for cb in self._callbacks:
                try:
                    cb(message)
                except Exception as exc:
                    logger.warning("Callback error: %s", exc)

            return True

    def send_message_sync(self, message: Message) -> bool:
        """
        Synchronous wrapper for send_message.
        Creates a temporary event loop if needed.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.send_message(message))
            finally:
                loop.close()
        else:
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.send_message(message), loop
                )
                return True
            return loop.run_until_complete(self.send_message(message))

    # ------------------------------------------------------------------
    # Receiving messages
    # ------------------------------------------------------------------

    async def receive_message(
        self, agent_id: str, timeout: Optional[float] = None
    ) -> Optional[Message]:
        """
        Wait for the next message addressed to *agent_id*.
        Returns None on timeout.
        """
        with self._lock:
            queue = self._agent_queues.get(agent_id)

        if not queue:
            logger.warning("Agent %s has no message queue", agent_id)
            return None

        try:
            message = await asyncio.wait_for(queue.get(), timeout=timeout)
            return message
        except asyncio.TimeoutError:
            return None

    def receive_message_sync(
        self, agent_id: str, timeout: Optional[float] = None
    ) -> Optional[Message]:
        """Synchronous wrapper for receive_message."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    self.receive_message(agent_id, timeout)
                )
            finally:
                loop.close()

        if loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                self.receive_message(agent_id, timeout), loop
            )
            return future.result(timeout + 1 if timeout else None)
        return loop.run_until_complete(
            self.receive_message(agent_id, timeout)
        )

    # ------------------------------------------------------------------
    # Blackboard (shared findings)
    # ------------------------------------------------------------------

    def publish_finding(self, finding: Finding) -> None:
        """
        Publish a finding to the blackboard. Notifies all subscribers
        whose finding type matches.
        """
        with self._lock:
            self._findings[finding.finding_id] = finding

            # Notify subscribers
            finding_type = finding.technique_id or finding.agent_type
            subs = self._finding_subscribers.get(finding_type, set())
            subs.update(self._finding_subscribers.get("*", set()))

            # Create notification message
            notify_msg = Message(
                message_type=MessageType.FINDING,
                sender=finding.agent_type,
                payload={
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                },
                finding=finding,
            )

            for agent_id in subs:
                queue = self._agent_queues.get(agent_id)
                if queue:
                    try:
                        asyncio.ensure_future(queue.put(notify_msg))
                    except Exception:
                        pass

            logger.info(
                "Finding published: %s (%s) by %s",
                finding.finding_id[:8],
                finding.severity.value,
                finding.agent_type,
            )

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._lock:
            return self._findings.get(finding_id)

    def get_findings(
        self,
        agent_type: Optional[str] = None,
        severity: Optional[FindingSeverity] = None,
        verified: Optional[bool] = None,
        limit: int = 100,
    ) -> List[Finding]:
        """Query findings with optional filters."""
        with self._lock:
            results: List[Finding] = []
            for finding in self._findings.values():
                if agent_type and finding.agent_type != agent_type:
                    continue
                if severity and finding.severity != severity:
                    continue
                if verified is not None and finding.verified != verified:
                    continue
                results.append(finding)
                if len(results) >= limit:
                    break
            return results

    def update_finding_verification(
        self, finding_id: str, verified: bool
    ) -> bool:
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            finding.verified = verified
            return True

    def get_all_findings(self) -> Dict[str, Finding]:
        with self._lock:
            return dict(self._findings)

    # ------------------------------------------------------------------
    # Message history / audit
    # ------------------------------------------------------------------

    def get_message_history(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        msg_type: Optional[MessageType] = None,
        limit: int = 100,
    ) -> List[Message]:
        """Query message history with filters."""
        with self._lock:
            results: List[Message] = []
            for msg in reversed(self._message_history):
                if sender and msg.sender != sender:
                    continue
                if recipient and msg.recipient != recipient:
                    continue
                if msg_type and msg.message_type != msg_type:
                    continue
                results.append(msg)
                if len(results) >= limit:
                    break
            return results

    def get_audit_log(
        self,
        since: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Get the full audit log as serialisable dicts."""
        with self._lock:
            results: List[Message] = []
            for msg in self._message_history:
                if since and msg.timestamp < since:
                    continue
                results.append(msg)
            if len(results) > limit:
                results = results[-limit:]
            return [m.to_dict() for m in results]

    def clear_history(self) -> None:
        with self._lock:
            self._message_history.clear()

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def add_callback(self, callback: Callable[[Message], None]) -> None:
        with self._lock:
            self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[Message], None]) -> None:
        with self._lock:
            self._callbacks = [cb for cb in self._callbacks if cb is not callback]

    # ------------------------------------------------------------------
    # Stat helpers
    # ------------------------------------------------------------------

    @property
    def agent_count(self) -> int:
        with self._lock:
            return len(self._agents)

    @property
    def finding_count(self) -> int:
        with self._lock:
            return len(self._findings)

    @property
    def message_count(self) -> int:
        with self._lock:
            return len(self._message_history)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "agents": len(self._agents),
                "findings": len(self._findings),
                "messages_logged": len(self._message_history),
                "finding_subscriber_topics": len(self._finding_subscribers),
                "message_subscriber_topics": len(self._message_subscribers),
                "agent_statuses": {
                    aid: reg.status.value
                    for aid, reg in self._agents.items()
                },
            }

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Full reset — clears all state."""
        with self._lock:
            self._agents.clear()
            self._message_history.clear()
            self._findings.clear()
            self._finding_subscribers.clear()
            self._message_subscribers.clear()
            self._agent_queues.clear()
            self._callbacks.clear()
            logger.info("MessageBus reset")
