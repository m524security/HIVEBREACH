# Python Style Rules — ECC Language Rule

## Standards

Follow PEP 8 with these HiveBreach-specific additions.

## Type Hints
- All function signatures MUST have type annotations
- Use `from __future__ import annotations` for forward references
- Use `Any` sparingly; prefer generic types (`dict[str, Any]` over `dict`)
- Use `dataclass` for data containers; `TypedDict` for dictionary schemas
- Return types: prefer explicit `None` over implicit

## Docstrings
- Use Google-style docstrings
- Every public function, class, and module requires a docstring
- Document parameters, return values, and raised exceptions
- One-line docstrings are acceptable for trivial functions

## Error Handling
- Catch specific exceptions, never bare `except:`
- Use `logger.exception()` inside exception handlers
- Re-raise with `raise` (not `raise e`) to preserve traceback
- Define custom exceptions per module where appropriate

## Naming
- `snake_case` for functions, methods, variables
- `PascalCase` for classes
- `UPPER_CASE` for constants
- `_leading_underscore` for internal/private members
- `__dunder__` for magic methods only

## Imports
Order: standard library → third-party → first-party
Group with a blank line between each section.

## Project Structure
- One class per file (or closely related group of classes)
- `__init__.py` exports public API only
- Tests mirror source tree under `tests/`
