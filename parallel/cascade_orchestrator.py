"""ECC cascade method: chain dependent tasks, parallelise independent ones."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class Task:
    name: str
    handler: Callable[..., Any] = field(repr=False)
    dependencies: list[str] = field(default_factory=list)
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None


class CascadeOrchestrator:
    """Build a dependency graph of tasks and execute in optimal parallel/serial order."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def add_task(
        self,
        name: str,
        handler: Callable[..., Any],
        dependencies: list[str] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if name in self._tasks:
            raise ValueError(f"Task '{name}' already registered")
        self._tasks[name] = Task(
            name=name,
            handler=handler,
            dependencies=dependencies or [],
            args=args,
            kwargs=kwargs,
        )

    def validate_graph(self) -> list[str]:
        errors: list[str] = []
        for name, task in self._tasks.items():
            for dep in task.dependencies:
                if dep not in self._tasks:
                    errors.append(f"Task '{name}' depends on unknown task '{dep}'")
        return errors

    def topo_sort(self) -> list[list[str]]:
        in_degree: dict[str, int] = {n: 0 for n in self._tasks}
        adj: dict[str, list[str]] = defaultdict(list)

        for name, task in self._tasks.items():
            for dep in task.dependencies:
                adj[dep].append(name)
                in_degree[name] = in_degree.get(name, 0) + 1

        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        waves: list[list[str]] = []

        while queue:
            wave = list(queue)
            waves.append(wave)
            next_queue: deque[str] = deque()
            for node in wave:
                for neighbour in adj[node]:
                    in_degree[neighbour] -= 1
                    if in_degree[neighbour] == 0:
                        next_queue.append(neighbour)
            queue = next_queue

        executed = {n for wave in waves for n in wave}
        missing = set(self._tasks) - executed
        if missing:
            logger.warning("Circular dependency detected for tasks: %s", missing)

        return waves

    async def execute_async(self, max_concurrent: int = 4) -> dict[str, Any]:
        errors = self.validate_graph()
        if errors:
            for e in errors:
                logger.error(e)
            return {"status": "failed", "errors": errors}

        waves = self.topo_sort()
        logger.info("Cascade plan: %d waves", len(waves))

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _run_task(task_name: str) -> None:
            task = self._tasks[task_name]
            async with semaphore:
                try:
                    if asyncio.iscoroutinefunction(task.handler):
                        task.result = await task.handler(*task.args, **task.kwargs)
                    else:
                        loop = asyncio.get_running_loop()
                        task.result = await loop.run_in_executor(
                            None, task.handler, *task.args, **task.kwargs
                        )
                    logger.info("Task '%s' completed", task_name)
                except Exception as exc:
                    task.error = str(exc)
                    logger.error("Task '%s' failed: %s", task_name, exc)

        for wave_idx, wave in enumerate(waves):
            logger.info("Executing wave %d/%d (%d tasks)", wave_idx + 1, len(waves), len(wave))
            await asyncio.gather(*[_run_task(n) for n in wave])

        failed = [n for n, t in self._tasks.items() if t.error]
        status = "completed" if not failed else "completed_with_errors"

        return {
            "status": status,
            "total_tasks": len(self._tasks),
            "waves": len(waves),
            "failed_tasks": failed,
            "results": {n: {"result": t.result, "error": t.error} for n, t in self._tasks.items()},
        }
