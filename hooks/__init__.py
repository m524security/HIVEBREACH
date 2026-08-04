"""Hooks package — ECC lifecycle hook system."""

from hooks.registry import (
    HookRegistry,
    execute,
    register_hook,
    HOOK_PROFILE,
)

__all__ = [
    "HookRegistry",
    "execute",
    "register_hook",
    "HOOK_PROFILE",
]
