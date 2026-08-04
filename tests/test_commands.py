from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import pytest


@dataclass
class Command:
    name: str
    args: list[str] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)


class CommandRegistry:
    def __init__(self):
        self._handlers: Dict[str, Callable] = {}

    def register(self, name: str, handler: Callable):
        self._handlers[name] = handler

    def dispatch(self, command: Command) -> Any:
        handler = self._handlers.get(command.name)
        if not handler:
            raise KeyError(f"Unknown command: {command.name}")
        return handler(*command.args, **command.kwargs)

    def list_commands(self) -> list[str]:
        return list(self._handlers.keys())


class HelpBuilder:
    @staticmethod
    def build(registry: CommandRegistry) -> str:
        lines = ["Available commands:"]
        for cmd in sorted(registry.list_commands()):
            lines.append(f"  {cmd}")
        return "\n".join(lines)


@pytest.fixture
def registry():
    return CommandRegistry()


class TestCommandParsing:
    def test_command_parsing_simple(self):
        cmd = Command(name="scan", args=["10.0.0.1"])
        assert cmd.name == "scan"
        assert cmd.args == ["10.0.0.1"]

    def test_command_parsing_with_kwargs(self):
        cmd = Command(name="exploit", args=["10.0.0.1"], kwargs={"port": 443})
        assert cmd.name == "exploit"
        assert cmd.kwargs["port"] == 443

    def test_command_parsing_empty(self):
        cmd = Command(name="help")
        assert cmd.name == "help"
        assert cmd.args == []


class TestCommandRouting:
    def test_command_routing(self, registry):
        results = []
        def scan_handler(target: str):
            results.append(f"Scanning {target}")
            return f"Scanned {target}"

        registry.register("scan", scan_handler)
        cmd = Command(name="scan", args=["10.0.0.1"])
        result = registry.dispatch(cmd)
        assert result == "Scanned 10.0.0.1"

    def test_command_routing_multiple_args(self, registry):
        def exploit_handler(target: str, port: int):
            return f"Exploiting {target}:{port}"

        registry.register("exploit", exploit_handler)
        cmd = Command(name="exploit", args=["10.0.0.1"], kwargs={"port": 443})
        result = registry.dispatch(cmd)
        assert result == "Exploiting 10.0.0.1:443"

    def test_command_routing_returns_value(self, registry):
        def recon_handler(target: str):
            return {"target": target, "status": "complete"}

        registry.register("recon", recon_handler)
        cmd = Command(name="recon", args=["10.0.0.1"])
        result = registry.dispatch(cmd)
        assert result["status"] == "complete"
        assert result["target"] == "10.0.0.1"


class TestUnknownCommand:
    def test_unknown_command(self, registry):
        cmd = Command(name="nonexistent")
        with pytest.raises(KeyError, match="Unknown command"):
            registry.dispatch(cmd)

    def test_unknown_command_with_args(self, registry):
        cmd = Command(name="bad_command", args=["arg1", "arg2"])
        with pytest.raises(KeyError):
            registry.dispatch(cmd)

    def test_empty_registry(self, registry):
        assert registry.list_commands() == []


class TestHelpCommand:
    def test_help_command(self, registry):
        def scan_h(t): return None
        def exploit_h(t): return None
        registry.register("scan", scan_h)
        registry.register("exploit", exploit_h)
        help_text = HelpBuilder.build(registry)
        assert "scan" in help_text
        assert "exploit" in help_text
        assert "Available commands:" in help_text

    def test_help_with_no_commands(self, registry):
        help_text = HelpBuilder.build(registry)
        assert "Available commands:" in help_text
        assert help_text.strip().count("\n") == 0

    def test_help_sorted_output(self, registry):
        def b(t): return None
        def a(t): return None
        def c(t): return None
        registry.register("b", b)
        registry.register("a", a)
        registry.register("c", c)
        help_text = HelpBuilder.build(registry)
        lines = help_text.strip().split("\n")[1:]
        command_names = [line.strip().replace("  ", "") for line in lines]
        assert command_names == sorted(command_names)


class TestCommandChaining:
    def test_multiple_commands_sequential(self, registry):
        log = []
        def scan_h(t):
            log.append(f"scan:{t}")
            return f"scan-ok"
        def exploit_h(t):
            log.append(f"exploit:{t}")
            return f"exploit-ok"
        registry.register("scan", scan_h)
        registry.register("exploit", exploit_h)
        r1 = registry.dispatch(Command("scan", ["10.0.0.1"]))
        r2 = registry.dispatch(Command("exploit", ["10.0.0.1"]))
        assert r1 == "scan-ok"
        assert r2 == "exploit-ok"
        assert log == ["scan:10.0.0.1", "exploit:10.0.0.1"]

    def test_handler_override(self, registry):
        def handler1(t): return "v1"
        def handler2(t): return "v2"
        registry.register("cmd", handler1)
        assert registry.dispatch(Command("cmd", ["t"])) == "v1"
        registry.register("cmd", handler2)
        assert registry.dispatch(Command("cmd", ["t"])) == "v2"


class TestErrorHandling:
    def test_handler_raises_exception(self, registry):
        def broken(t):
            raise RuntimeError("Handler crashed")
        registry.register("broken", broken)
        with pytest.raises(RuntimeError):
            registry.dispatch(Command("broken", ["t"]))

    def test_wrong_arg_count(self, registry):
        def needs_two(a, b):
            return a + b
        registry.register("add", needs_two)
        with pytest.raises(TypeError):
            registry.dispatch(Command("add", ["only_one"]))
