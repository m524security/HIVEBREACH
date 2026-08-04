"""HiveBreach LLM Router — model selection, provider abstraction, fallback chain."""

from __future__ import annotations

import importlib.util
import os
import sys

_ROUTER_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(module_name: str, file_subpath: str):
    path = os.path.join(_ROUTER_DIR, file_subpath)
    if not os.path.isfile(path):
        raise ImportError(f"Cannot find module at {path}")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_mod = _load_module("_llm_router_mod", "router.py")

ModelRouter = _mod.ModelRouter
LLMResponse = _mod.LLMResponse
TaskDifficulty = _mod.TaskDifficulty
LLMBackend = _mod.LLMBackend
OllamaBackend = _mod.OllamaBackend
NIMBackend = _mod.NIMBackend
PaidAPIBackend = _mod.PaidAPIBackend
RateLimiter = _mod.RateLimiter
ModelConfig = _mod.ModelConfig
DIFFICULTY_WEIGHT = _mod.DIFFICULTY_WEIGHT

__all__ = [
    "ModelRouter",
    "LLMResponse",
    "TaskDifficulty",
    "LLMBackend",
    "OllamaBackend",
    "NIMBackend",
    "PaidAPIBackend",
    "RateLimiter",
    "ModelConfig",
    "DIFFICULTY_WEIGHT",
]
