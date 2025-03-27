# Envbuilder Development Guide

## Build/Test/Lint Commands
- Build: `make build`
- Run tests: `go test -count=1 ./...`
- Run tests with race detection: `go test -race -count=3 ./...`
- Run a single test: `go test -v -count=1 ./path/to/package -run TestName`
- Lint Go code: `make lint/go`
- Lint shell scripts: `make lint/shellcheck`

## Code Style Guidelines
- Imports: Standard Go import grouping (stdlib, external, internal)
- Error handling: Return errors with context using `fmt.Errorf("operation: %w", err)`
- Logging: Use the provided logger (`options.Logger`) with appropriate log levels
- Testing: Use testify for assertions and test setup
- Types: Strong typing with proper interfaces, use Go 1.22+ features
- Naming: Follow Go conventions (camelCase for unexported, PascalCase for exported)
- Documentation: Write clear godoc comments for exported functions and types
- File organization: Keep related functionality in the same package