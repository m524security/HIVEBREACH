"""HiveBreach Sanity Check Layer — pre-delegation invariant validation."""

from __future__ import annotations

import importlib.util
import os
import sys

_SANITY_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_SANITY_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_mod = _load_module("_sanity_mod", "sanity.py")

DelegationSanityChecker = _mod.DelegationSanityChecker
DelegationTask = _mod.DelegationTask
SanityCheckResult = _mod.SanityCheckResult
SanityStatus = _mod.SanityStatus
AgentType = _mod.AgentType
AGENT_CAPABILITIES = _mod.AGENT_CAPABILITIES
AGENT_DEPENDENCIES = _mod.AGENT_DEPENDENCIES

__all__ = [
    "DelegationSanityChecker",
    "DelegationTask",
    "SanityCheckResult",
    "SanityStatus",
    "AgentType",
    "AGENT_CAPABILITIES",
    "AGENT_DEPENDENCIES",
]
