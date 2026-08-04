"""
llm-router — HiveBreach LLM Backend Router

Routes LLM requests to Ollama (local/free), NVIDIA NIM (free hosted),
or paid API keys (OpenAI/Anthropic) with rate-limit awareness,
task-difficulty-based model selection, and automatic fallback.
"""

from __future__ import annotations

import os
import json
import time
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & constants
# ---------------------------------------------------------------------------

class TaskDifficulty(Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    CRITICAL = "critical"


DIFFICULTY_WEIGHT: Dict[TaskDifficulty, int] = {
    TaskDifficulty.TRIVIAL: 1,
    TaskDifficulty.EASY: 2,
    TaskDifficulty.MEDIUM: 5,
    TaskDifficulty.HARD: 8,
    TaskDifficulty.CRITICAL: 10,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class LLMResponse:
    content: str
    model_used: str
    backend_name: str
    latency_ms: float
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    error: Optional[str] = None
    fallback_chain: List[str] = field(default_factory=list)


@dataclass
class ModelConfig:
    name: str
    provider: str
    context_window: int = 8192
    supports_vision: bool = False
    supports_tools: bool = False
    cost_per_1k_in: float = 0.0
    cost_per_1k_out: float = 0.0
    difficulty_max: TaskDifficulty = TaskDifficulty.CRITICAL


# ---------------------------------------------------------------------------
# Rate limiter (simple token-bucket per backend)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Token-bucket rate limiter for API backends."""

    def __init__(self, max_per_minute: int, burst: Optional[int] = None):
        self.max_per_minute = max_per_minute
        self.burst = burst or max_per_minute
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1, timeout: float = 60.0) -> bool:
        """Acquire *tokens* within *timeout* seconds. Returns True if granted."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            time.sleep(0.05)
        return False

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        rate = self.max_per_minute / 60.0
        self.tokens = min(float(self.burst), self.tokens + elapsed * rate)
        self.last_refill = now


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """Base class for all LLM backends."""

    def __init__(self, config: Dict[str, Any]):
        self.name = config.get("name", self.__class__.__name__)
        self.models: List[ModelConfig] = []
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs: Any,
    ) -> LLMResponse:
        ...

    @abstractmethod
    def list_available_models(self) -> List[ModelConfig]:
        ...

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(120.0))
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# OllamaBackend
# ---------------------------------------------------------------------------

class OllamaBackend(LLMBackend):
    """Local Ollama inference — zero cost, hardware-limited."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get(
            "base_url",
            os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
        )
        self.default_model = config.get("default_model", "llama3.1:8b")
        self._model_cache: Optional[List[ModelConfig]] = None
        self._rate_limiter = RateLimiter(
            max_per_minute=config.get("max_per_minute", 60),
            burst=config.get("burst", 10),
        )

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs: Any,
    ) -> LLMResponse:
        model_name = model or self.default_model
        if not self._rate_limiter.acquire():
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=0,
                error="Rate limit exceeded on Ollama",
            )

        client = await self.get_client()
        payload: Dict[str, Any] = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt
        payload.update(kwargs.get("extra_body", {}))

        t0 = time.monotonic()
        try:
            resp = await client.post(
                urljoin(self.base_url, "/api/generate"),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            elapsed = (time.monotonic() - t0) * 1000
            return LLMResponse(
                content=data.get("response", ""),
                model_used=model_name,
                backend_name=self.name,
                latency_ms=elapsed,
                tokens_in=data.get("prompt_eval_count"),
                tokens_out=data.get("eval_count"),
            )
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - t0) * 1000
            logger.warning("Ollama request failed: %s", exc)
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=elapsed,
                error=str(exc),
            )

    def list_available_models(self) -> List[ModelConfig]:
        if self._model_cache is not None:
            return self._model_cache
        try:
            resp = httpx.get(urljoin(self.base_url, "/api/tags"), timeout=10)
            resp.raise_for_status()
            data = resp.json()
            models: List[ModelConfig] = []
            for m in data.get("models", []):
                models.append(ModelConfig(
                    name=m["name"],
                    provider="ollama",
                    context_window=m.get("context_length", 4096),
                ))
            self._model_cache = models
            return models
        except Exception as exc:
            logger.warning("Could not list Ollama models: %s", exc)
            return [ModelConfig(name=self.default_model, provider="ollama")]


# ---------------------------------------------------------------------------
# NIMBackend
# ---------------------------------------------------------------------------

class NIMBackend(LLMBackend):
    """NVIDIA NIM hosted inference — free tier, ~40 req/min shared limit."""

    NIM_API_BASE = "https://api.nvcf.nim.com/v1"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get(
            "api_key",
            os.environ.get("NVIDIA_NIM_API_KEY", ""),
        )
        self.default_model = config.get("default_model", "meta/llama3.1-8b-instruct")
        self._rate_limiter = RateLimiter(
            max_per_minute=config.get("max_per_minute", 38),
            burst=config.get("burst", 5),
        )

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs: Any,
    ) -> LLMResponse:
        model_name = model or self.default_model
        fallback_chain: List[str] = []

        if not self._rate_limiter.acquire():
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=0,
                error="Rate limit exceeded on NVIDIA NIM",
            )

        if not self.api_key:
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=0,
                error="No NVIDIA NIM API key configured",
            )

        client = await self.get_client()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        payload.update(kwargs.get("extra_body", {}))

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        t0 = time.monotonic()
        try:
            resp = await client.post(
                f"{self.NIM_API_BASE}/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            elapsed = (time.monotonic() - t0) * 1000
            choice = data["choices"][0]
            return LLMResponse(
                content=choice["message"]["content"],
                model_used=data.get("model", model_name),
                backend_name=self.name,
                latency_ms=elapsed,
                tokens_in=data.get("usage", {}).get("prompt_tokens"),
                tokens_out=data.get("usage", {}).get("completion_tokens"),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                logger.info("NIM rate-limited, backing off")
                fallback_chain.append(f"nim_429_{model_name}")
            elapsed = (time.monotonic() - t0) * 1000
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=elapsed,
                error=str(exc),
                fallback_chain=fallback_chain,
            )
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=elapsed,
                error=str(exc),
                fallback_chain=fallback_chain,
            )

    def list_available_models(self) -> List[ModelConfig]:
        return [
            ModelConfig(name="meta/llama3.1-8b-instruct", provider="nim", context_window=131072),
            ModelConfig(name="meta/llama3.1-70b-instruct", provider="nim", context_window=131072),
            ModelConfig(name="nvidia/nemotron-4-340b-instruct", provider="nim", context_window=4096),
            ModelConfig(name="mistralai/mistral-7b-instruct-v0.3", provider="nim", context_window=32768),
        ]


# ---------------------------------------------------------------------------
# PaidAPIBackend (OpenAI / Anthropic)
# ---------------------------------------------------------------------------

class PaidAPIBackend(LLMBackend):
    """OpenAI or Anthropic API — paid per-token, highest reasoning quality."""

    PROVIDER_OPENAI = "openai"
    PROVIDER_ANTHROPIC = "anthropic"

    OPENAI_BASE = "https://api.openai.com/v1"
    ANTHROPIC_BASE = "https://api.anthropic.com/v1"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.provider = config.get("provider", self.PROVIDER_OPENAI)
        self.api_key: str = ""

        if self.provider == self.PROVIDER_OPENAI:
            self.api_key = config.get(
                "api_key",
                os.environ.get("OPENAI_API_KEY", ""),
            )
            self.base_url = config.get("base_url", self.OPENAI_BASE)
            self.default_model = config.get("default_model", "gpt-4o")
        elif self.provider == self.PROVIDER_ANTHROPIC:
            self.api_key = config.get(
                "api_key",
                os.environ.get("ANTHROPIC_API_KEY", ""),
            )
            self.base_url = config.get("base_url", self.ANTHROPIC_BASE)
            self.default_model = config.get("default_model", "claude-3-5-sonnet-20241022")
        else:
            raise ValueError(f"Unsupported paid provider: {self.provider}")

        self._rate_limiter = RateLimiter(
            max_per_minute=config.get("max_per_minute", 60),
            burst=config.get("burst", 10),
        )

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs: Any,
    ) -> LLMResponse:
        model_name = model or self.default_model
        fallback_chain: List[str] = []

        if not self._rate_limiter.acquire():
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=0,
                error="Rate limit exceeded",
            )

        if not self.api_key:
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=0,
                error=f"No API key configured for {self.provider}",
            )

        client = await self.get_client()
        t0 = time.monotonic()

        try:
            if self.provider == self.PROVIDER_OPENAI:
                resp = await self._call_openai(
                    client, model_name, prompt, system_prompt,
                    temperature, max_tokens, kwargs,
                )
            else:
                resp = await self._call_anthropic(
                    client, model_name, prompt, system_prompt,
                    temperature, max_tokens, kwargs,
                )
            elapsed = (time.monotonic() - t0) * 1000
            return LLMResponse(
                content=resp["content"],
                model_used=resp.get("model", model_name),
                backend_name=self.name,
                latency_ms=elapsed,
                tokens_in=resp.get("tokens_in"),
                tokens_out=resp.get("tokens_out"),
            )
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return LLMResponse(
                content="",
                model_used=model_name,
                backend_name=self.name,
                latency_ms=elapsed,
                error=str(exc),
                fallback_chain=fallback_chain,
            )

    async def _call_openai(
        self,
        client: httpx.AsyncClient,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int,
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        payload.update(kwargs.get("extra_body", {}))

        resp = await client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        return {
            "content": choice["message"]["content"],
            "model": data.get("model", model),
            "tokens_in": data.get("usage", {}).get("prompt_tokens"),
            "tokens_out": data.get("usage", {}).get("completion_tokens"),
        }

    async def _call_anthropic(
        self,
        client: httpx.AsyncClient,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int,
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt
        payload.update(kwargs.get("extra_body", {}))

        resp = await client.post(
            f"{self.base_url}/messages",
            json=payload,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        content = "".join(
            b["text"] for b in data.get("content", []) if b.get("type") == "text"
        )
        return {
            "content": content,
            "model": data.get("model", model),
            "tokens_in": data.get("usage", {}).get("input_tokens"),
            "tokens_out": data.get("usage", {}).get("output_tokens"),
        }

    def list_available_models(self) -> List[ModelConfig]:
        if self.provider == self.PROVIDER_OPENAI:
            return [
                ModelConfig(name="gpt-4o", provider="openai", context_window=128000,
                            supports_tools=True, supports_vision=True,
                            cost_per_1k_in=0.0025, cost_per_1k_out=0.01),
                ModelConfig(name="gpt-4o-mini", provider="openai", context_window=128000,
                            supports_tools=True,
                            cost_per_1k_in=0.00015, cost_per_1k_out=0.0006),
                ModelConfig(name="o1-mini", provider="openai", context_window=128000,
                            difficulty_max=TaskDifficulty.HARD,
                            cost_per_1k_in=0.0011, cost_per_1k_out=0.0044),
            ]
        return [
            ModelConfig(name="claude-3-5-sonnet-20241022", provider="anthropic",
                        context_window=200000, supports_tools=True, supports_vision=True,
                        cost_per_1k_in=0.003, cost_per_1k_out=0.015),
            ModelConfig(name="claude-3-haiku-20240307", provider="anthropic",
                        context_window=200000, supports_tools=True,
                        cost_per_1k_in=0.00025, cost_per_1k_out=0.00125),
        ]


# ---------------------------------------------------------------------------
# ModelRouter
# ---------------------------------------------------------------------------

class ModelRouter:
    """
    Routes LLM requests to the appropriate backend based on task difficulty,
    configured backends, and availability. Implements automatic fallback.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.backends: Dict[str, LLMBackend] = {}
        self._model_rank: Dict[str, Tuple[str, ModelConfig]] = {}
        self._agent_model_map: Dict[str, str] = {}
        self._default_difficulty_model: Dict[str, str] = {}
        self._config = self._load_config(config_path)
        self._init_backends()

    def _load_config(self, path: Optional[str]) -> Dict[str, Any]:
        import yaml
        paths_to_try = [
            path,
            os.environ.get("LLM_ROUTER_CONFIG"),
            os.path.join(os.path.dirname(__file__), "config.yaml"),
            os.path.join(os.getcwd(), "orchestration", "llm-router", "config.yaml"),
        ]
        for p in paths_to_try:
            if p and os.path.isfile(p):
                try:
                    with open(p, "r") as fh:
                        return yaml.safe_load(fh) or {}
                except Exception as exc:
                    logger.warning("Failed to load config %s: %s", p, exc)
        logger.info("No LLM router config found; using defaults")
        return {}

    def _init_backends(self) -> None:
        backend_configs = self._config.get("backends", {})
        agent_config = self._config.get("agent_model_map", {})

        # Ollama
        ollama_cfg = backend_configs.get("ollama", {})
        if ollama_cfg.get("enabled", True):
            self.backends["ollama"] = OllamaBackend(ollama_cfg)

        # NVIDIA NIM
        nim_cfg = backend_configs.get("nim", {})
        if nim_cfg.get("enabled", True):
            self.backends["nim"] = NIMBackend(nim_cfg)

        # Paid APIs
        for provider in ("openai", "anthropic"):
            cfg = backend_configs.get(provider, {})
            if cfg.get("enabled", False):
                cfg["provider"] = provider
                self.backends[provider] = PaidAPIBackend(cfg)

        # Agent → model mapping
        self._agent_model_map = agent_config.get("mappings", {})

        # Difficulty-based defaults
        diff_map = self._config.get("difficulty_model_map", {})
        for k, v in diff_map.items():
            try:
                diff = TaskDifficulty(k)
                self._default_difficulty_model[diff.value] = v
            except ValueError:
                pass

        # Build model rank (for selection ordering)
        for name, backend in self.backends.items():
            for mc in backend.list_available_models():
                key = f"{name}:{mc.name}"
                self._model_rank[key] = (name, mc)

    def select_backend_and_model(
        self,
        task_difficulty: TaskDifficulty = TaskDifficulty.MEDIUM,
        agent_type: Optional[str] = None,
        requires_vision: bool = False,
        requires_tools: bool = False,
    ) -> Tuple[str, str, str]:
        """
        Select the best backend and model for the given task parameters.

        Returns (backend_name, model_name, provider).
        """
        preferred_model = None
        if agent_type:
            preferred_model = self._agent_model_map.get(agent_type)

        candidates: List[Tuple[int, str, str, str]] = []

        for key, (backend_name, mc) in self._model_rank.items():
            if mc.difficulty_max.value and TaskDifficulty(mc.difficulty_max).value:
                pass
            diff_weight = DIFFICULTY_WEIGHT.get(task_difficulty, 5)
            mc_max_weight = DIFFICULTY_WEIGHT.get(
                TaskDifficulty(mc.difficulty_max.value)
                if isinstance(mc.difficulty_max, TaskDifficulty)
                else TaskDifficulty(mc.difficulty_max)
                if isinstance(mc.difficulty_max, str)
                else TaskDifficulty.CRITICAL,
                10,
            )
            if diff_weight > mc_max_weight:
                continue
            if requires_vision and not mc.supports_vision:
                continue
            if requires_tools and not mc.supports_tools:
                continue

            priority = 0
            if preferred_model and (mc.name == preferred_model or mc.name.endswith(f"/{preferred_model}")):
                priority = 100
            cost_penalty = int(mc.cost_per_1k_in * 10000 + mc.cost_per_1k_out * 10000)
            candidates.append((-priority, cost_penalty, backend_name, mc.name))

        if not candidates:
            fallback = list(self.backends.keys())
            if fallback:
                fb = self.backends[fallback[0]]
                fb_models = fb.list_available_models()
                return (fallback[0], fb_models[0].name if fb_models else "unknown", "unknown")
            return ("", "", "")

        candidates.sort(key=lambda x: (x[0], x[1]))
        _, _, backend_name, model_name = candidates[0]
        return (backend_name, model_name, self._get_provider(backend_name))

    def _get_provider(self, backend_name: str) -> str:
        if backend_name in ("openai", "anthropic"):
            return backend_name
        return backend_name

    async def route(
        self,
        prompt: str,
        task_difficulty: TaskDifficulty = TaskDifficulty.MEDIUM,
        agent_type: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        require_vision: bool = False,
        require_tools: bool = False,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Route a prompt to the best available LLM backend.

        Implements automatic fallback: if the primary backend fails,
        tries all other backends in cost order.
        """
        backend_name, model_name, _ = self.select_backend_and_model(
            task_difficulty=task_difficulty,
            agent_type=agent_type,
            requires_vision=require_vision,
            requires_tools=require_tools,
        )

        if not backend_name:
            return LLMResponse(
                content="",
                model_used="none",
                backend_name="none",
                latency_ms=0,
                error="No available backends",
            )

        primary = self.backends[backend_name]
        result = await primary.generate(
            prompt=prompt,
            model=model_name,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        if result.error and len(self.backends) > 1:
            logger.info(
                "Primary backend %s failed (%s); attempting fallback",
                backend_name, result.error,
            )
            for fb_name, fb_backend in self.backends.items():
                if fb_name == backend_name:
                    continue
                fb_result = await fb_backend.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
                fb_result.fallback_chain = [backend_name, fb_name]
                if not fb_result.error:
                    return fb_result

        return result

    async def close_all(self) -> None:
        for backend in self.backends.values():
            await backend.close()
