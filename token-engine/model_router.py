"""ECC token optimization: smart model selection based on task type and difficulty."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ModelProvider:
    name: str
    provider: str
    cost_per_1k_input: float
    cost_per_1k_output: float
    context_window: int
    max_output: int
    strengths: list[str] = field(default_factory=list)


PROVIDERS: list[ModelProvider] = [
    ModelProvider("claude-opus-4", "anthropic", 0.015, 0.075, 200_000, 8192, ["reasoning", "planning", "hard"]),
    ModelProvider("claude-sonnet-4", "anthropic", 0.003, 0.015, 200_000, 8192, ["code", "analysis", "creative"]),
    ModelProvider("claude-haiku-3.5", "anthropic", 0.001, 0.005, 200_000, 8192, ["review", "easy", "quick"]),
    ModelProvider("gpt-4o", "openai", 0.005, 0.015, 128_000, 4096, ["code", "analysis", "creative"]),
    ModelProvider("gpt-4o-mini", "openai", 0.0005, 0.0015, 128_000, 4096, ["review", "easy", "quick"]),
    ModelProvider("gemini-2.5-pro", "google", 0.0025, 0.010, 1_000_000, 8192, ["analysis", "long-context", "code"]),
]

TASK_DIFFICULTY: dict[str, str] = {
    "code": "medium",
    "reasoning": "hard",
    "creative": "medium",
    "analysis": "medium",
    "planning": "hard",
    "review": "easy",
}


class ModelRouter:
    """Select optimal LLM provider given task, difficulty, and cost constraints."""

    def __init__(self, providers: list[ModelProvider] | None = None) -> None:
        self.providers = providers or PROVIDERS

    def route(
        self,
        task_type: str,
        difficulty: str | None = None,
        max_cost: float | None = None,
        context_needed: int | None = None,
    ) -> dict[str, Any]:
        difficulty = difficulty or TASK_DIFFICULTY.get(task_type, "medium")
        candidates = [p for p in self.providers if difficulty in p.strengths or task_type in p.strengths]

        if not candidates:
            candidates = list(self.providers)

        if context_needed:
            candidates = [p for p in candidates if p.context_window >= context_needed]

        if max_cost is not None:
            candidates = [p for p in candidates if p.cost_per_1k_input <= max_cost]

        if not candidates:
            return {
                "error": f"No provider found for task_type={task_type}, difficulty={difficulty}",
                "estimated_cost": None,
            }

        selected = candidates[0]
        estimated_cost = self._estimate_cost(selected, context_needed or 4000)

        return {
            "provider": selected.provider,
            "model": selected.name,
            "difficulty": difficulty,
            "context_window": selected.context_window,
            "estimated_cost_usd": estimated_cost,
            "candidates_considered": len(self.providers),
            "candidates_filtered": len(candidates),
        }

    def _estimate_cost(self, provider: ModelProvider, input_tokens: int, output_tokens: int = 1000) -> float:
        input_cost = (input_tokens / 1000) * provider.cost_per_1k_input
        output_cost = (output_tokens / 1000) * provider.cost_per_1k_output
        return round(input_cost + output_cost, 6)

    def list_providers(self) -> list[dict[str, Any]]:
        return [
            {
                "name": p.name,
                "provider": p.provider,
                "context_window": p.context_window,
                "cost_per_1k_input": p.cost_per_1k_input,
                "strengths": p.strengths,
            }
            for p in self.providers
        ]
