# # DSH Session Guide

The DeepSeek Harness (DSH) is a local GUI agent workspace. There is no control plane, no container orchestration, and no queue backend to configure. You open a session, select the `logzero` workspace, choose a model, and interact through a chat box.

This file documents how to use it productively on LogZero. It does not describe a runtime that LogZero implements — LogZero is the thing the DSH works *on*, not a component of the DSH.

## Session Setup

- **Workspace:** `logzero`
- **Model:** `DeepSeek-4.1-Flash` (verified against the DSH model picker)
- **Permission mode:** `Workspace Write` for implementation tasks; `Standard` for read-only verification tasks
- **Branch:** the agent must create `dsn/LZ-{id}` off `dev` for any task that writes files

## Pre-Flight (do once, before first session)

Install required tooling in your shell so agents don't spend context on it:

```

go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0

go install golang.org/x/vuln/cmd/govulncheck@v1.8.0

gosec --version

govulncheck -version

```

Ensure a `dev` branch exists:

```

git checkout -b dev

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
4. **Never push to `main`.** The agent works on `dsn/LZ-{id}` branches, PRs go to `dev`.
5. **Kill the session if the agent hallucinates the repo.** If it describes files or packages that don't exist, stop immediately — do not try to "correct" it mid-session.

## Per-Task Prompt Template

```

Execute task {LZ-xxx} from tasks/board.yaml.

- Create branch `dsn/{LZ-xxx}` off `dev`

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
- Modify `go.sum` directly
- Delete or rewrite `initial-audit.md`
- Add dependencies without justification
- Add telemetry, analytics, or non-AWS network calls to the tool
- Add `go install` as a supported installation path for LogZero itself

## Logging

Session transcripts live in the DSH UI. If you need durable logs, copy transcripts into `docs/sessions/` manually after each session. Do not create a `.harness/` directory — it is not part of this project.