"""HiveBreach Communication Bus — agent pub/sub message bus with blackboard pattern."""

from __future__ import annotations

import importlib.util
import os
import sys

_BUS_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_BUS_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_mod = _load_module("_comm_bus_mod", "message_bus.py")

MessageBus = _mod.MessageBus
Message = _mod.Message
MessageType = _mod.MessageType
Finding = _mod.Finding
FindingSeverity = _mod.FindingSeverity
AgentStatus = _mod.AgentStatus
AgentRegistration = _mod.AgentRegistration

__all__ = [
    "MessageBus",
    "Message",
    "MessageType",
    "Finding",
    "FindingSeverity",
    "AgentStatus",
    "AgentRegistration",
]
