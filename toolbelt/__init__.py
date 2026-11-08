# HiveBreach Tool Belt — ECC-style tool registry and loader
# Loads tool definitions from registry.json for agent consumption.
# Each tool entry maps to MITRE ATT&CK techniques and agent ownership.

from pathlib import Path
import json

_registry: list[dict] | None = None

def load_registry() -> list[dict]:
    global _registry
    if _registry is not None:
        return _registry
    path = Path(__file__).parent / "registry.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    _registry = data if isinstance(data, list) else data.get("tools", [])
    return _registry

def get_tools(category: str | None = None, agent: str | None = None) -> list[dict]:
    tools = load_registry()
    if category:
        tools = [t for t in tools if t.get("category") == category]
    if agent:
        tools = [t for t in tools if agent in t.get("agent_mapping", [])]
    return tools

def get_tool(name: str) -> dict | None:
    for t in load_registry():
        if t["name"] == name:
            return t
    return None

__all__ = ["load_registry", "get_tools", "get_tool"]
