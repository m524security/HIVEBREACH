"""HiveBreach Scope Auth Gate — deterministic scope enforcement (non-LLM)."""

from __future__ import annotations

import importlib.util
import os
import sys

_GATE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_GATE_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_mod = _load_module("_scope_gate_mod", "gate.py")

ScopeEnforcer = _mod.ScopeEnforcer
ScopeCheckReport = _mod.ScopeCheckReport
ScopeCheckResult = _mod.ScopeCheckResult
ActionType = _mod.ActionType
RoEDocument = _mod.RoEDocument
AuthHeader = _mod.AuthHeader

__all__ = [
    "ScopeEnforcer",
    "ScopeCheckReport",
    "ScopeCheckResult",
    "ActionType",
    "RoEDocument",
    "AuthHeader",
]
