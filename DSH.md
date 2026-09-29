# DSH Session Guide

The DeepSeek Harness (DSH) is a local GUI agent workspace. There is no control plane, no container orchestration, and no queue backend to configure. You open a session, select the `logzero` workspace, choose a model, and interact through a chat box.

This file documents how to use it productively on LogZero. It does not describe a runtime that LogZero implements — LogZero is the thing the DSH works *on*, not a component of the DSH.

## Session Setup

- **Workspace:** `logzero`
- **Model:** `DeepSeek-4.1-Flash`
- **Permission mode:** `Workspace Write` for any task that writes files (including writing new files). `Standard` only for genuinely read-only tasks that produce no file output.
- **Branch:** the agent must create `dsh/LZ-{id}` off `dev` for any task that writes files

## Pre-Flight (do once, before first session)

Install required tooling in your shell so agents don't spend context on it:

```
go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

Install GoReleaser (not available via `go install`; use Homebrew on macOS):

```
brew install goreleaser/tap/goreleaser
goreleaser --version
```

Verify everything resolves:

```
gosec --version
govulncheck --version
goreleaser --version
docker --version
```

When running gosec locally in the sandbox, exclude the workspace GOMODCACHE:
`gosec -exclude-dir=.gomodcache ./...`. This keeps local findings consistent
with CI and avoids scanning dependency sources as first-party code.

Ensure a `dev` branch exists:

```
git checkout dev
git push -u origin dev
```

Confirm the working tree is clean:

```
git status
```

## Working Protocol

1. **One task per session.** Do not ask the agent to "do the whole board."
2. **Read before write.** Always start with the bootstrap prompt that forces the agent to read `AGENTS.md`, `HANDOFF.md`, and `tasks/board.yaml` and summarise before acting.
3. **Review between tasks.** After each task, inspect `git diff`, run the checks yourself, and decide whether to continue.
4. **Never push to `main`.** The agent works on `dsh/LZ-{id}` branches, PRs go to `dev`.
5. **Kill the session if the agent hallucinates the repo.** If it describes files or packages that don't exist, stop immediately — do not try to "correct" it mid-session.

## Per-Task Prompt Template

```
Execute task {LZ-xxx} from tasks/board.yaml.

- Create branch `dsh/{LZ-xxx}` off `dev`
- Follow the constraints and done_criteria in the task
- Run the checks listed in the task's `commands` and `tests`
- Commit with a conventional commit message ending in `[{LZ-xxx}]`
- Open a PR targeting `dev`
- Report: files changed, commands run, results, any deviations from the task spec

Stop after this task and wait for my review.
```

## What the DSH Must Not Do

- Push to `main`
- Modify `testdata/` fixtures
- Modify `go.sum` directly (running `go mod tidy` is fine)
- Delete or rewrite `initial-audit.md`
- Add dependencies without justification
- Add telemetry, analytics, or non-AWS network calls to the tool
- Add `go install` as a supported installation path for LogZero itself

## Logging

Session transcripts live in the DSH UI. If you need durable logs, copy transcripts into `docs/sessions/` manually after each session. Do not create a `.harness/` directory — it is not part of this project.