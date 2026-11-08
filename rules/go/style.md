# Go Style Rules — ECC Language Rule

## Standards

Follow `go fmt` and `go vet` with zero tolerance for warnings.

## Conventions
- Use `gofmt` for formatting — never override
- Run `go vet` and `staticcheck` before committing
- Follow standard Go project layout (`cmd/`, `internal/`, `pkg/`)

## Error Handling
- Always check errors — never use `_` for error returns
- Return early, avoid deep nesting
- Use `fmt.Errorf("context: %w", err)` for error wrapping
- Define sentinel errors with `var ErrFoo = errors.New("foo")`
- Use `errors.Is()` and `errors.As()` for error inspection

## Naming
- `camelCase` for unexported; `PascalCase` for exported
- Single-letter receivers discouraged (except very short-lived)
- File names: `snake_case.go`
- Avoid `get`/`set` prefix — name after the property

## Project Layout
- `cmd/` for main entry points
- `internal/` for private packages
- `pkg/` for public reusable packages
- Avoid `src/` or `lib/` directories
