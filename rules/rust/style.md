# Rust Style Rules — ECC Language Rule

## Standards

Follow the Rust API Guidelines and `clippy` with zero warnings.

## Conventions
- Run `cargo fmt` and `cargo clippy` before committing
- All public items must have doc comments (`///`)
- Use `#![deny(missing_docs)]` in library crates
- Run `cargo audit` for dependency vulnerability checking

## Error Handling
- Use `thiserror` for library error types
- Use `anyhow` for application-level error handling
- Prefer `Result<T, E>` over panics
- Use `unwrap()` only in tests and examples
- Document panics with `# Panics` section in doc comments

## Unsafe Code
- `unsafe` blocks must have a SAFETY comment explaining invariants
- Wrap unsafe code in safe abstractions
- Prohibit `unsafe` in application code by default — library only
- Use `#![forbid(unsafe_code)]` where possible

## Naming
- `snake_case` for functions, methods, variables, modules
- `PascalCase` for types, traits, enums
- `SCREAMING_SNAKE_CASE` for constants
- File names match module names (`foo.rs` for `mod foo`)

## Project Layout
- `src/lib.rs` for library entry
- `src/main.rs` for binary entry
- `examples/` for usage examples
- `tests/` for integration tests
