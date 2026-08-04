# /plan — ECC Task Decomposition & Execution Planning

## Overview

The `/plan` command decomposes complex work into an ordered execution plan with dependency resolution. It is the primary orchestration entry point for multi-agent workflows.

## Usage

```
/plan <description of work to plan>
```

The command parses the natural-language description and produces a structured plan with:

- **Phases** — Ordered stages of work
- **Tasks** — Individual units with clear scope
- **Dependencies** — Edges between tasks (blocking relationships)
- **Agent assignments** — Recommended agent type for each task
- **Verification criteria** — How each task is confirmed complete

## Output Format

```
┌─ Phase 1: Reconnaissance ─────────────────────┐
│  T1: Port scan target (depends on: none)      │
│  T2: DNS enumeration    (depends on: T1)      │
│  T3: Web discovery      (depends on: T1)      │
└────────────────────────────────────────────────┘
┌─ Phase 2: Exploitation ───────────────────────┐
│  T4: Credential attack  (depends on: T2, T3)  │
└────────────────────────────────────────────────┘
```

## DAG Resolution

Tasks are arranged in a directed acyclic graph. The planner:

1. Identifies all mentioned tasks from the description
2. Infers dependency relationships
3. Topologically sorts for optimal execution order
4. Groups independent tasks for parallel execution

## Integration

Plans feed into `/multi-plan` for parallel execution across agent instances. Each task becomes a work item in the cascade orchestrator.

## See Also

- `/multi-plan` — Execute plans in parallel
- `parallel/cascade_orchestrator.py` — Cascade execution engine
- `orchestration/` — Plan storage and state tracking
