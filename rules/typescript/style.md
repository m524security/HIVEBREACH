# TypeScript Style Rules — ECC Language Rule

## Standards

Follow the TypeScript ESLint recommended config with strict mode.

## Types & Interfaces
- Prefer `interface` over `type` for object shapes
- Prefer `type` for unions, intersections, and utility types
- Use `readonly` for immutable properties
- Avoid `any` — use `unknown` and narrow with type guards
- Use `as const` for literal types and enum-like constants

## Naming
- `camelCase` for variables, functions, methods
- `PascalCase` for classes, interfaces, types, enums
- `UPPER_CASE` for global constants
- `kebab-case` for file names

## Async Patterns
- Prefer `async/await` over raw Promises
- Use `Promise.all` for independent parallel async work
- Handle promise rejections with `.catch()` or try/catch
- No floating promises — always await or return

## Functions
- Arrow functions for callbacks and short bodies
- Named function declarations for exports
- Document public API with TSDoc (`/** ... */`)
- Default parameters over conditional assignment

## Imports
- Use ES module syntax (`import`/`export`)
- Named exports over default exports
- Barrel files (`index.ts`) for package exports
- Path aliases configured in `tsconfig.json`
