# LogZero — DSH Handoff

This file is the entry point for a DeepSeek Harness session working on LogZero. Read it first, then read `AGENTS.md`, then `tasks/board.yaml`.

## Current State

- **Build:** ✅ `go build ./...` passes
- **Tests:** ✅ All tests in `./...` pass with `-race` (`go test -race -count=1 ./...`)
- **Vet:** ✅ `go vet ./...` clean
- **Core engine:** Functional. CloudTrail JSON → normalized actions → IAM JSON / HCL synthesis works end to end.
- **CLI:** Cobra-based, supports `--format json|hcl`, offline file ingestion and live CloudTrail API mode.
- **CI security:** GitHub Actions `security.yml` runs gosec, govulncheck, CodeQL, and dependency review.
- **CI release:** GitHub Actions `release.yml` runs GoReleaser with Cosign signing, Syft SBOM generation, and multi-arch Grype image scanning. Images are built via `dockers_v2` from `Dockerfile.goreleaser`. Release is gated on a passing scan (draft release is un-drafted only on success).
- **Distribution:** GoReleaser produces static binaries for linux/darwin/windows on amd64/arm64, signed checksums, SPDX SBOMs, and multi-arch Docker manifests from a distroless base.

## What Is Done

1. CloudTrail ingestion: file, reader, NDJSON, `Records` wrapper, raw array, live API mode
2. Event normalization with AWS service prefix mapping
3. Action aggregation with deduplication and statement consolidation
4. IAM JSON and Terraform HCL policy synthesis
5. CLI with offline and live modes
6. Fuzz testing, PII-exclusion tests, multi-partition ARN validation tests, path-traversal rejection, atomic-write tests, performance benchmarks
7. Security workflows (gosec, govulncheck, CodeQL, dependency review)
8. Release workflow (GoReleaser v2 with dockers_v2, Cosign, Syft, multi-arch Grype gated draft release)
9. Distroless Dockerfile pinned by digest
10. Documentation: README, SECURITY, AGENTS, ARCHITECTURE, CONTRIBUTING, CHANGELOG, TESTING

## What Remains

See `tasks/board.yaml` for the authoritative list. The P0 alignment and P1 hardening tasks (including Grype, goreleaser v2 migration, distroless digest, and synthesis edge-case tests) are complete. Remaining work focuses on broader integration testing (LZ-110) and deeper code hardening.

## How to Use This Handoff (DSH Workflow)

1. Start a DSH session with `logzero` selected as the workspace, `DeepSeek-4.1-Flash` as the model, and **Workspace Write** permission mode.
2. Paste the bootstrap prompt (see below) that tells the agent to read `AGENTS.md`, `HANDOFF.md`, and `tasks/board.yaml` and summarise before acting.
3. Review the agent's summary. If it describes LogZero correctly, approve **one task at a time**.
4. After each task completes, review the diff, run the checks, and only then queue the next task.
5. Do not let the agent work the entire board unsupervised on a first session.

## Bootstrap Prompt (paste into a new DSH session)

```
Read these files in order and wait for my next message:

1. AGENTS.md
2. HANDOFF.md
3. tasks/board.yaml

Do not start any task yet. After reading, give me:
- A one-paragraph summary of what LogZero is
- The first task ID you intend to execute and why
- Any contradictions or ambiguities you noticed between the three files

Wait for my confirmation before writing anything.
```

## Next Steps

Review `tasks/board.yaml` for remaining open tasks. The core codebase is currently passing `go test -race ./...` and `goreleaser check`.

## Do Not Touch

- `go.sum` — auto-generated (except when a task runs `go mod tidy`)
- `testdata/` — read-only fixtures
- `.git/` — do not manipulate
- `LICENSE` — do not modify
- Signed release artifacts — immutable
- `initial-audit.md` — historical reference
- `main` branch — agents must not push to `main`

## Entry-Point Files

1. `HANDOFF.md` (this file) — current state and workflow
2. `AGENTS.md` — repo-wide rules, conventions, branch strategy
3. `tasks/board.yaml` — task queue
4. `agents/*.md` — role definitions
5. `DSH.md` — DSH session usage notes