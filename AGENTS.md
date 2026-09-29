# LogZero — Agent & Development Guide

## Project Overview

LogZero is a zero-egress, client-side CLI tool that synthesizes least-privilege IAM policies from AWS CloudTrail events. It reads CloudTrail JSON (offline file or live API), normalizes observed API calls, and emits either an IAM JSON policy document or a Terraform HCL `aws_iam_policy_document` data source.

The tool's core promise is that **no security data leaves the operator's environment**. No telemetry, no third-party endpoints, no phone-home behaviour. This constraint is non-negotiable and applies to code, tests, CI, and agent tooling.

## Repository Structure

- `cmd/logzero/` — CLI entrypoint and Cobra commands

- `pkg/models/` — Core data structures, ARN validation, string sanitization

- `pkg/aws/` — AWS SDK v2 CloudTrail client, file/reader ingestion, NDJSON support

- `pkg/parser/` — Event normalization, service mapping, action aggregation

- `pkg/synthesis/` — IAM JSON and Terraform HCL generation, atomic file writes

- `testdata/` — Read-only CloudTrail fixtures (do not modify)

- `agents/` — DSH agent role definitions

- `tasks/` — DSH task board

## Tech Stack

- Go 1.25

- Cobra (CLI)

- hashicorp/hcl/v2 and zclconf/go-cty (HCL generation)

- AWS SDK for Go v2

- testify (testing only)

## Build & Test Commands

```

go build -o logzero ./cmd/logzero     # build binary

go test -race ./...                    # full test suite with race detector

go test -race -count=1 ./...           # bypass cache

go vet ./...                           # static checks

gosec ./...                            # SAST (must be pre-installed)

govulncheck ./...                      # vulnerability scan (must be pre-installed)

goreleaser check                       # validate release config

goreleaser build --snapshot --clean    # local snapshot build

```

### Sandboxed environments

When running inside the DSH sandbox, the default `GOCACHE`

`~/Library/Caches/go-build`) and `GOMODCACHE` `~/go/pkg/mod`) are

read-only. Set workspace-local caches before running any Go command:

```

export GOCACHE=$PWD/.gocache

export GOMODCACHE=$PWD/.gomodcache

```

The `.gocache/` and `.gomodcache/` directories are gitignored. Do not commit

them. The `writing stat cache: ... operation not permitted` warning on stderr

is cosmetic and does not affect build results.

## Architecture

```

CloudTrail JSON (file or live API)

    → pkg/aws       (ingestion)

    → pkg/models    (typed structures, sanitization)

    → pkg/parser    (normalization, aggregation)

    → pkg/synthesis (IAM JSON / HCL emission)

    → stdout or file

```

## Testing Philosophy

- Unit tests for all core logic

- Fuzz tests for parser and ingestion robustness

- End-to-end tests covering the CLI pipeline

- Race detector enabled on every test run

- **No current test count is hardcoded in docs** — the criterion is "all tests in `./...` pass with `-race`"

## Security Rules

- **Zero egress to third parties.** No telemetry, no analytics, no non-AWS network calls at runtime.

- **AWS API calls are limited to live-mode CloudTrail ingestion.** Live mode uses the operator's existing AWS credentials and only calls CloudTrail APIs. This is not "egress" in the LogZero sense — it is the operator's own AWS account. Document this distinction clearly wherever the zero-egress claim appears.

- **No `go install` for LogZero itself.** LogZero is distributed only as pre-built signed binaries and a hardened container image. Do not add `go install github.com/Pliauga/logzero@latest` as a supported installation path. (Note: this rule is about *how users install LogZero*. It does **not** apply to tooling that agents or CI install — see [DSH.md](DSH.md) for agent tooling policy.)

- **Strict input sanitization.** All CloudTrail input is treated as untrusted. PII fields are excluded during unmarshal. ARNs are validated against a multi-partition allowlist `aws`, `aws-us-gov`, `aws-cn`).

- **Path traversal protection** is enforced in the synthesis writer. Do not weaken it.

- **Never commit secrets, credentials, tokens, or real AWS account identifiers.** Test fixtures use documented placeholder account IDs `123456789012`, `111122223333`, etc.).

## Code Style

- Standard `gofmt` formatting

- Static binaries only `CGO_ENABLED=0`)

- All exported types and functions must have doc comments

- Prefer explicit error wrapping `fmt.Errorf("...: %w", err)`)

- No new dependencies without justification in the PR description

## Branch & Commit Strategy

**Branching:**

- `main` — protected. Stable releases only. **DSH agents must never commit or push to `main`.**

- `dev` — integration branch. All DSH work lands here via PR.

- `dsh/LZ-{id}` — per-task branch created off `dev` by the DSH agent for task `{id}`.

- `feature/{description}` or `fix/{description}` — for human contributors.

**Flow:**

1. DSH agent creates `dsh/LZ-{id}` off `dev`.

2. Agent commits work with conventional commit messages referencing the task ID.

3. Agent opens a PR targeting `dev` (never `main`).

4. CI must pass on the PR before merge.

5. Human promotes `dev` → `main` at release time.

**Commits:** Conventional Commits, with task ID suffix:

```

feat(synthesis): add GovCloud ARN handling [LZ-109]

fix(parser): sanitize eventName before normalization [LZ-110]

test(aws): add NDJSON edge case coverage [LZ-101]

```

## Do Not Touch

- `go.sum` — auto-generated; managed by Go tooling only. **Exception:** a task may run `go mod tidy`, which is permitted to rewrite `go.sum` as its normal function.

- `testdata/` — read-only fixtures for tests

- `.git/` — never manipulate git internals

- `LICENSE` — do not modify

- Signed release artifacts `checksums.txt`, `.sig`, `.cert`, SBOMs) — immutable

- `initial-audit.md` — historical reference, do not modify or delete

- `cmd/logzero/main.go` version variables — populated by ldflags at build time; do not hardcode values

## PR Process

- Branch from `dev` (or, for human contributors, from `main` for hotfixes)

- All tests must pass: `go test -race ./...`

- `go vet ./...` clean

- `gosec ./...` and `govulncheck ./...` clean (or findings documented)

- Conventional commit message with task ID

- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes