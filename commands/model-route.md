# /model-route — ECC Intelligent Model Selection

## Overview

The `/model-route` command selects the optimal LLM provider and model for a given task based on difficulty, cost constraints, and context requirements. It implements the token-engine routing logic.

## Usage

```
/model-route <task-type> [--difficulty <easy|medium|hard>] [--max-cost <N>] [--context <N>]
```

## Task Types

| Task Type | Default Difficulty | Recommended Provider |
|-----------|-------------------|---------------------|
| `code` | medium | Claude Sonnet / GPT-4o |
| `reasoning` | hard | Claude Opus / o3 |
| `creative` | medium | Claude Sonnet / Gemini |
| `analysis` | medium | Claude Haiku / GPT-4o-mini |
| `planning` | hard | Claude Opus / o3 |
| `review` | easy | Claude Haiku / Gemini Flash |

## Routing Logic

1. **Difficulty assessment** — Auto-detect from task description or use `--difficulty`
2. **Cost constraint** — Filter out providers exceeding `--max-cost`
3. **Context matching** — Ensure provider context window exceeds requirement
4. **Selection** — Pick best match (quality within budget)

## See Also

- `token-engine/model_router.py` — Routing engine implementation
- `token-engine/prompt_slimmer.py` — Context compression
