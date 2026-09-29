# Contributing to LogZero

First off, thank you for considering contributing to LogZero!

## Setup
1. Clone the repository
2. Ensure you have Go 1.22+ installed
3. Run `go mod download`

## Testing
- Unit and E2E tests are required for new features
- Always run the test suite before submitting: `go test -race ./...`

## Commit Conventions
We follow [Conventional Commits](https://www.conventionalcommits.org/).
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation updates
- `chore:` for maintenance tasks

## PR Process
1. Create a branch from `main`
2. Make your changes
3. Ensure all tests pass
4. Open a Pull Request detailing the changes and linking to any relevant issues
