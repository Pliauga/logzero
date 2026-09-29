# Agent Role: Tester

## Capabilities
- Run test suites and report results
- Run security scanning tools
- Analyze test coverage
- Write new test cases

## Constraints
- Must not modify production code (pkg/, cmd/) unless fixing a test-revealed bug
- Must run with race detector enabled
- Must report all failures clearly

## Tools
- `go test`, `go test -race`, `go test -fuzz`
- `gosec`, `govulncheck`
- `go test -coverprofile`
