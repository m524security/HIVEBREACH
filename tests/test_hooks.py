from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from conftest import HookRegistry, register_hook, execute, BASE

import importlib.util
import sys

hooks_path = BASE / "hooks" / "registry.py"
spec = importlib.util.spec_from_file_location("hooks_registry", str(hooks_path))
hooks_mod = importlib.util.module_from_spec(spec)
sys.modules["hooks_registry"] = hooks_mod
spec.loader.exec_module(hooks_mod)

LIFECYCLE_POINTS = hooks_mod.LIFECYCLE_POINTS

# We need to clear the registry between tests
# Access the module-level _registry directly
_registry = hooks_mod._registry
register_hook_mod = hooks_mod.register_hook
execute_mod = hooks_mod.execute
HookRegistry_mod = hooks_mod.HookRegistry
HOOK_PROFILE_mod = hooks_mod.HOOK_PROFILE


def clear_registry():
    for point in LIFECYCLE_POINTS:
        _registry[point].clear()


class TestHookRegistration:
    def test_hook_registration(self):
        clear_registry()
        def my_hook(ctx):
            ctx["ran"] = True
            return ctx
        register_hook_mod("test-hook", "pre_scan", my_hook, priority=50)
        hooks = _registry.get("pre_scan", [])
        assert len(hooks) == 1
        assert hooks[0].name == "test-hook"

    def test_register_at_unknown_lifecycle_point(self):
        clear_registry()
        with pytest.raises(ValueError, match="Unknown lifecycle point"):
            register_hook_mod("bad", "invalid_point", lambda x: x)

    def test_register_hook_via_class(self):
        clear_registry()
        def hook_fn(ctx):
            return ctx
        HookRegistry_mod.register("class-hook", "post_scan", hook_fn)
        hooks = _registry.get("post_scan", [])
        assert len(hooks) == 1
        assert hooks[0].name == "class-hook"


class TestHookExecution:
    def test_hook_execution(self):
        clear_registry()
        def my_hook(ctx):
            ctx["modified"] = True
            return ctx
        register_hook_mod("modifier", "pre_scan", my_hook)
        result = execute_mod("pre_scan", {"target": "10.0.0.1"})
        assert result["modified"] is True
        assert result["target"] == "10.0.0.1"

    def test_hook_execution_chains(self):
        clear_registry()
        def hook_a(ctx):
            ctx["a"] = 1
            return ctx
        def hook_b(ctx):
            ctx["b"] = ctx.get("a", 0) + 1
            return ctx
        register_hook_mod("a", "on_finding", hook_a, priority=10)
        register_hook_mod("b", "on_finding", hook_b, priority=20)
        result = execute_mod("on_finding", {})
        assert result["a"] == 1
        assert result["b"] == 2

    def test_hook_execution_unknown_point(self):
        clear_registry()
        with pytest.raises(ValueError, match="Unknown lifecycle point"):
            execute_mod("nonexistent", {})


class TestHookPriority:
    def test_hook_priority(self):
        clear_registry()
        order = []
        def hook_low(ctx):
            order.append("low")
            return ctx
        def hook_high(ctx):
            order.append("high")
            return ctx
        register_hook_mod("low", "pre_scan", hook_low, priority=100)
        register_hook_mod("high", "pre_scan", hook_high, priority=10)
        execute_mod("pre_scan", {})
        assert order == ["high", "low"]

    def test_hooks_sorted_by_priority(self):
        clear_registry()
        register_hook_mod("z", "pre_scan", lambda x: x, priority=999)
        register_hook_mod("a", "pre_scan", lambda x: x, priority=1)
        hooks = _registry["pre_scan"]
        priorities = [h.priority for h in hooks]
        assert priorities == sorted(priorities)


class TestProfileFiltering:
    def test_minimal_profile_shows_minimal_hooks(self):
        clear_registry()
        def minimal_hook(ctx):
            ctx["minimal_ran"] = True
            return ctx
        def standard_hook(ctx):
            ctx["standard_ran"] = True
            return ctx
        register_hook_mod("min", "pre_scan", minimal_hook, profile="minimal")
        register_hook_mod("std", "pre_scan", standard_hook, profile="standard")
        with patch.dict(os.environ, {"ECC_HOOK_PROFILE": "minimal"}):
            hooks_mod.HOOK_PROFILE = "minimal"
            result = execute_mod("pre_scan", {})
        assert result.get("minimal_ran") is True

    def test_strict_profile_runs_all(self):
        clear_registry()
        def hook_fn(ctx):
            ctx["ran"] = True
            return ctx
        register_hook_mod("strict-ok", "pre_scan", hook_fn, profile="strict")
        register_hook_mod("std", "pre_scan", hook_fn, profile="standard")
        with patch.dict(os.environ, {"ECC_HOOK_PROFILE": "strict"}):
            hooks_mod.HOOK_PROFILE = "strict"
            result = execute_mod("pre_scan", {"target": "test"})
        assert result.get("target") == "test"


class TestListHooks:
    def test_list_all_hooks(self):
        clear_registry()
        register_hook_mod("h1", "pre_scan", lambda x: x)
        register_hook_mod("h2", "post_scan", lambda x: x)
        hooks = HookRegistry_mod.list_hooks()
        assert len(hooks) == 2

    def test_list_by_lifecycle_point(self):
        clear_registry()
        register_hook_mod("h1", "pre_scan", lambda x: x)
        register_hook_mod("h2", "post_scan", lambda x: x)
        hooks = HookRegistry_mod.list_hooks("pre_scan")
        assert len(hooks) == 1
        assert hooks[0].name == "h1"


class TestErrorHandling:
    def test_hook_exception_caught(self):
        clear_registry()
        hooks_mod.HOOK_PROFILE = "standard"
        def broken_hook(ctx):
            raise ValueError("Hook failed")
        register_hook_mod("broken", "pre_scan", broken_hook)
        result = execute_mod("pre_scan", {"target": "test"})
        assert result["target"] == "test"

    def test_strict_profile_raises_on_error(self):
        clear_registry()
        def broken_hook(ctx):
            raise ValueError("Strict failure")
        register_hook_mod("broken", "pre_scan", broken_hook, profile="strict")
        with patch.dict(os.environ, {"ECC_HOOK_PROFILE": "strict"}):
            hooks_mod.HOOK_PROFILE = "strict"
            with pytest.raises(ValueError):
                execute_mod("pre_scan", {"target": "test"})


class TestAllHooksRun:
    def test_all_hooks_run_on_scan(self):
        clear_registry()
        ran = set()
        def pre_hook(ctx):
            ran.add("pre")
            ctx["pre_done"] = True
            return ctx
        def post_hook(ctx):
            ran.add("post")
            ctx["post_done"] = True
            return ctx
        def finding_hook(ctx):
            ran.add("finding")
            ctx["finding_done"] = True
            return ctx
        register_hook_mod("pre", "pre_scan", pre_hook)
        register_hook_mod("post", "post_scan", post_hook)
        register_hook_mod("finding", "on_finding", finding_hook)
        ctx = {"target": "10.0.0.1", "findings": []}
        ctx = execute_mod("pre_scan", ctx)
        ctx = execute_mod("post_scan", {"target": "10.0.0.1", "findings": []})
        ctx = execute_mod("on_finding", {"target": "10.0.0.1", "finding": {"id": "F1"}})
        assert ran == {"pre", "post", "finding"}


class TestHookContext:
    def test_hook_returns_modified_context(self):
        clear_registry()
        def enrich(ctx):
            ctx["enriched"] = True
            ctx["target"] = ctx.get("target", "").upper()
            return ctx
        register_hook_mod("enricher", "pre_scan", enrich)
        result = execute_mod("pre_scan", {"target": "example.com"})
        assert result["enriched"] is True
        assert result["target"] == "EXAMPLE.COM"
