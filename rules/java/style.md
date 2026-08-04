# Java Style Rules — ECC Language Rule

## Standards

Follow Google Java Style Guide with these HiveBreach additions.

## Conventions
- Use a linter (checkstyle) and formatter before committing
- Source encoding: UTF-8
- Line length: 120 characters max
- Indentation: 4 spaces (no tabs)

## Error Handling
- Prefer checked exceptions for recoverable errors
- Use unchecked exceptions (RuntimeException) for programming errors
- Never swallow exceptions in empty catch blocks
- Use try-with-resources for AutoCloseable objects
- Log exceptions at the appropriate level (error for failures, warn for recoverable)

## Naming
- `camelCase` for methods, variables
- `PascalCase` for classes, interfaces, enums
- `UPPER_SNAKE_CASE` for constants (`static final`)
- `lowerCamelCase` for packages (no underscores)

## Dependency Management
- Use Maven or Gradle (not Ant)
- Pin all dependency versions
- Run `mvn dependency-check` or Gradle equivalent for CVE scanning
- Prefer Jakarta EE over Java EE

## Project Layout
Standard Maven/Gradle layout:
```
src/main/java/
src/main/resources/
src/test/java/
src/test/resources/
```

## Records & Pattern Matching
- Prefer Java 17+ records for simple data carriers
- Use sealed classes for restricted hierarchies
- Prefer `instanceof` pattern matching over explicit casts
