# /multi-plan — ECC Parallel Plan Execution

## Overview

The `/multi-plan` command takes an existing plan (from `/plan`) and executes it across multiple agent instances in parallel where dependencies allow. It implements the ECC cascade method for optimal throughput.

## Usage

```
/multi-plan <plan-id> [--workers N] [--timeout S]
```

## Behaviour

1. **Dependency analysis** — Reads the plan DAG to identify parallelisable work
2. **Worker allocation** — Spawns up to `--workers` concurrent agent instances
3. **Cascade execution** — Independent tasks run in parallel; dependent tasks wait for their prerequisites
4. **Synchronisation barriers** — Phase gates ensure all tasks in a wave complete before the next wave starts

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | 4 | Max concurrent agent instances |
| `--timeout` | 300 | Per-task timeout in seconds |
| `--retry` | 2 | Failed task retry count |
| `--no-merge` | false | Skip git worktree merge on completion |

## Cascade Execution Model

```
Wave 1: T1 ─── T2 ─── T3          (parallel)
               │
Wave 2:        T4 ─── T5           (after T2, T3 complete)
                      │
Wave 3:               T6           (after T5)
```

## See Also

- `/plan` — Create execution plans
- `parallel/worktree_manager.py` — Git worktree isolation
- `parallel/cascade_orchestrator.py` — Cascade engine internals
