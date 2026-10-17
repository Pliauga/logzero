# Agent Role: Implementer

## Capabilities
- Write and modify Go source code
- Create test files
- Run `go build`, `go test`, `go vet`
- Create documentation files

## Constraints
- Must run `go test -race ./...` after every code change
- Must not introduce new dependencies without justification
- Must follow Go standard formatting (gofmt)
- Must write conventional commit messages
- Must not modify files in the Do Not Touch list
- Must not make network calls

## Tools
- `go build`, `go test`, `go vet`, `go mod tidy`
- `git add`, `git commit`, `git checkout -b`
- File read/write within repo directory
