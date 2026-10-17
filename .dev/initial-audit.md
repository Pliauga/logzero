# Claude Opus: LogZero Completion Audit + DeepSeek Harness Handoff

You are Claude Opus, acting as a senior staff engineer, release architect, and agent-orchestration lead.

You are running with full read/write access to the LogZero repository in the current working directory.

Do not ask me to paste files or a repo tree — discover everything yourself using your file tools. The current working directory is the LogZero repo. Use the "Known Project Context" below as a starting point, but verify everything against the actual filesystem. The filesystem wins where they disagree.

If something is genuinely undeterminable from the files, mark it `UNKNOWN` or `ASSUMPTION` — do not invent it.

---

## Known Project Context (from prototype-phase notes — verify against repo)

These notes are from an earlier design phase. Confirm each point against the actual code before relying on it. Flag any drift.

**What LogZero is:** A zero-egress, high-performance security audit engine designed to evaluate AWS Identity and Access Management (IAM) policies locally before deployment.

**Purpose & problems solved:**
- Eliminating SaaS data egress — third-party compliance scanners upload sensitive IaC and IAM definitions to external clouds. LogZero evaluates in-memory so no security data leaves the environment.
- Catching excessive privileges — privilege escalation, wildcard grants (`Action: "*"`, `Resource: "*"`), malformed conditions — before policies reach production AWS.
- Shift-left security — immediate feedback in local dev and CI/CD runners, blocking misconfigurations at the PR stage.

**Core features:**
- Local AST evaluation — parses IAM policy JSON into an AST to analyze access pathways with no remote API calls.
- Structured risk reporting — deterministic JSON finding reports with rule IDs, severities (CRITICAL / HIGH / LOW), and targeted remediation steps.
- Automated guardrail integration — hooks into CLI workflows and CI/CD to block non-compliant code.

**Tech stack:**
- Go 1.25
- `gosec` (SAST) and `govulncheck` (vuln scanning)
- Docker, LocalStack, GitHub Actions (`security.yml`)

**Known state at prototype end:** A clean, secure scaffold with automated CI/CD guardrails exists, but the core IAM policy evaluation engine is not built. `pkg/` and `cmd/` were intended to hold the business logic.

**Prototype roadmap (treat as intent, not ground truth):**
- Phase 1 — Core IAM Policy Engine (`pkg/`):
  - `pkg/types/` — Go structs for IAM JSON policy documents (`Statement`, `Effect`, `Action`, `Resource`, `Condition`)
  - `pkg/evaluator/` — parse JSON policies and evaluate high-risk rules (e.g. `Effect: Allow` + `Action: "*"` or `Resource: "*"`)
  - `pkg/report/` — format results into Go structs / JSON with rule IDs, severities, remediations
- Phase 2 — CLI Integration (`cmd/logzero/`):
  - Cobra CLI entry so users can run `logzero audit ./policies`
  - Output flags: `--json`, `--severity`
- Phase 3 — Natural commit history via smaller, well-scoped commits (not required, but a nice-to-have)

If the repo shows the scaffold is gone or has changed dramatically, say so and re-derive the plan from scratch.

---

## Distribution Strategy (locked decision — implement this)

This is a security tool. The distribution pipeline must reinforce the zero-egress promise, not undermine it. Do not deviate from these decisions without flagging it as a proposal in your output.

**Primary — GoReleaser-driven GitHub Releases with signing and provenance:**
- Static binaries built with `CGO_ENABLED=0` for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.
- Sign all release artifacts with **Cosign** using keyless OIDC via GitHub Actions.
- Publish `checksums.txt` with SHA256 for every artifact.
- Generate **SBOMs with Syft** for archives and images.
- Enable **release immutability** on the GitHub repo so tagged versions cannot be overwritten.
- Multi-arch Docker manifest created from the same GoReleaser run.

**Secondary — Hardened Docker image:**
- Multi-stage build, base image `gcr.io/distroless/static` pinned by **digest**, not a mutable tag.
- Run as a **non-root** user. Drop all capabilities. Read-only root filesystem where possible.
- Target ~2MB image size; no shell, no package manager.
- Scan the image with **Grype** or **Trivy** before publishing.

**Convenience — Homebrew tap (P2, do not ship in v1):**
- Auto-generate via GoReleaser's `brews` section once the core engine is stable.

**Explicitly out of scope for v1:**
- `go install` as a supported channel. The Go module proxy ecosystem has real supply-chain risks (immutable caching, proxy bypass of checksum validation, typosquatting). Do not add support for it. If mentioned at all, document it as "not recommended for production" in the README.

**CI/CD security workflows (`security.yml` and friends) must include:**
- `govulncheck` on every PR and push to main
- CodeQL analysis for Go and GitHub Actions
- Grype or Trivy scanning on the built container image
- Dependency review on PRs
- GoReleaser invoked on tag push, gated behind all of the above passing

**GitHub repo settings to document in the release checklist:**
- Release immutability enabled
- Dependency graph + Dependabot security updates enabled
- Private vulnerability reporting enabled
- Actions require approval from external contributors

---

## Mission

1. Reconstruct the true state of LogZero from the actual filesystem, using the notes above as a hypothesis to verify.
2. Identify everything missing to finish LogZero to a polished, deployable state.
3. Produce a complete, prioritized implementation and deployment plan.
4. Implement the plan directly — write files, apply edits, run checks, iterate.
5. Prepare the repository and a complete handoff package so the **DeepSeek Harness (DSH)** can pick up the remaining work and execute it autonomously, safely, and predictably.

## What the DSH Is

The DSH is the **DeepSeek Harness** — an agent-execution harness that will run DeepSeek-powered agents against this repository. It will be given access to this folder **after** you finish your investigation and implementation pass. Your job is not to run the DSH, but to:
- Define what the DSH will do and how.
- Produce every artifact the DSH needs: task board, agent roles, config, prompts, guardrails, acceptance criteria.
- Leave the repo in a state where the DSH can start executing immediately without further clarification from me.

Where the harness's exact config format or runtime is unknown, choose a sensible, well-documented convention, mark it `ASSUMPTION`, and make the artifact self-describing so it can be adapted trivially.

## Source of Truth

- The filesystem (current working directory = LogZero repo) is the **primary** source for what exists.
- The Known Project Context and Distribution Strategy above are **secondary** — useful intent, but verify every claim against the code.
- If the two conflict, filesystem wins **except** for the Distribution Strategy, which is a locked decision. Flag any conflict and explain.
- Do not hallucinate. Cite file paths and line numbers. Mark unknowns as `UNKNOWN` or `ASSUMPTION`.

## Step 1 — Reconstruct the Project from the Repo

Verify the Known Project Context against the actual filesystem:
- Does the Go module exist? What Go version? What module path?
- Do `pkg/types`, `pkg/evaluator`, `pkg/report`, `cmd/logzero` exist? Are they stubs or implemented?
- Is Cobra in `go.mod`? Are `gosec`, `govulncheck`, LocalStack, and `security.yml` present?
- What's actually in `README`, `AGENTS.md`, docs, and CI configs?
- Git history: recent commits, branches, uncommitted changes.
- Anything that diverges from the prototype notes.

State clearly what matched, what drifted, and what's missing.

## Step 2 — Inspect the Repository Yourself

Systematically explore the working directory:
- Map the tree (all folders and files, including hidden)
- Read every manifest, lockfile, Dockerfile, compose file, `.env.example`, CI config, Makefile, script, migration, test, and doc
- Search the codebase for: `TODO`, `FIXME`, `HACK`, `XXX`, `deprecated`, `NotImplemented`, empty functions, skipped/disabled tests
- Check `git status`, `git log --oneline -30`, branches, and uncommitted changes
- Identify generated, vendored, and off-limits files

## Step 3 — Gap Analysis

Cover every category below. For each gap give: ID, title, category, evidence (path and line numbers), impact, proposed solution, files to create/edit, acceptance criteria, required tests, dependencies, effort (S/M/L/XL), suggested agent role.

- IAM policy engine completeness (parser, evaluator rules, finding generator)
- Rule coverage (wildcards, privilege escalation, malformed conditions, resource scope, condition keys)
- CLI completeness (`audit` command, `--json`, `--severity`, exit codes, help text)
- Reporting schema (deterministic JSON, rule IDs, severities, remediations)
- Tests: unit, integration (LocalStack), e2e, coverage gaps
- Documentation: README, architecture, rule reference, onboarding, runbooks
- Developer experience: setup, scripts, lint, format, vet, typecheck
- CI/CD: build, test, release, versioning, artifacts, `security.yml`
- Supply chain & distribution: GoReleaser, Cosign signing, SBOMs, checksums, release immutability, distroless image, non-root hardening, image scanning
- Security: zero-egress guarantees, no telemetry, no network egress at runtime, secrets handling, dependency risk
- Observability: structured logging, verbosity, error reporting
- Deployment: binary distribution, Docker image, Homebrew tap (P2), release channel
- DSH / agent orchestration: roles, permissions, queues, sandboxing, audit
- Licensing, compliance, release readiness

## Step 4 — Prioritized Completion Plan

Phase the work:
- P0 — Blocking: cannot ship without these
- P1 — Critical: required for a polished release
- P2 — Important: ship soon after
- P3 — Nice-to-have / future

Each phase gets milestones, exit criteria, and the exact order of operations. Respect the natural build order: types → evaluator → report → CLI → tests → docs → release. Distribution work (GoReleaser, Cosign, SBOMs, distroless Docker, `security.yml` extensions) is P0 for the "polished release" milestone, even if it lands after the core engine.

## Step 5 — DeepSeek Harness Deployment Plan

Design everything the DSH needs to operate. The DSH will receive folder access only after you finish, so this section must be complete and self-contained:

- Harness architecture: control plane, workers, queue, storage, secrets, sandbox
- Where the harness runs: local, Docker, Kubernetes, cloud, or hybrid
- Prerequisites: Go toolchain, runtimes, tools, accounts, network, filesystem permissions
- Environment and secrets management (`.env` layout, secret store, redaction rules)
- Agent roles and capabilities (e.g. planner, implementer, tester, reviewer, docs)
- Task schema and queue format (see Step 6)
- Branching, commit, PR, and review workflow the harness must follow
- Tool permissions and command allowlists/denylists — allow `go build`, `go test`, `go vet`, `gosec`, `govulncheck`, `goreleaser`, `cosign`, `syft`; deny outbound network egress from agents
- Sandboxing and isolation guarantees — consistent with LogZero's zero-egress stance
- Logging, audit trails, and observability
- Rate limits, cost caps, concurrency limits, and kill switch
- Rollback and disaster recovery
- CI/CD integration
- Onboarding steps for new agents
- Exact config files, env vars, and commands the harness will use

Deliver the harness-facing artifacts as real files in the repo where possible (e.g. `harness/`, `.harness/`, `agents/`, `tasks/`), plus a `HARNESS.md` that explains how to boot it and hand it the task board.

## Step 6 — Agent Task Board (DSH-Ready)

Convert the plan into tasks the DeepSeek Harness can execute without further interpretation. Every task must be atomic, testable, and self-contained.

```yaml
- id: LZ-001
  title: ...
  goal: ...
  context: ...
  files: [...]
  steps: [...]
  commands: [...]
  tests: [...]
  done_criteria: [...]
  constraints: [...]
  escalation: ...
  depends_on: [...]
  parallelizable: true|false
  agent_role: ...
  estimated_effort: S|M|L|XL
  priority: P0|P1|P2|P3
```

Write the full board to a machine-readable file (e.g. `tasks/board.yaml` or `.harness/tasks.yaml`) and summarize it in your response. Group by milestone, mark what can run in parallel, and order the critical path.

## Step 7 — Implement Now

Write access is yours. Do the work:

- Create/update `AGENTS.md`, `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `TESTING.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `HARNESS.md`
- Add/update CI workflows, scripts, Dockerfiles, harness configs, and agent prompts
- Write the DSH task board and any harness scaffolding to disk
- Implement the highest-priority code: IAM policy structs, parser, evaluator rules, finding generator, CLI wiring
- Set up the distribution pipeline: `.goreleaser.yaml`, `Dockerfile` (distroless, non-root, digest-pinned base), Cosign signing config, Syft SBOM generation, extended `security.yml` with CodeQL + Grype/Trivy + dependency review
- Run the project's checks (`go build ./...`, `go test ./...`, `go vet ./...`, `gosec ./...`, `govulncheck ./...`) and report real results
- If a check fails, fix it or document exactly why it cannot be fixed now
- Do not leave the repo in a broken state; if a change is risky, isolate it behind a flag or leave it uncommitted with a clear note

## Step 8 — Handoff Package for the DSH

Assemble a single, explicit handoff the harness can consume the moment it gets folder access:

- `HARNESS.md` — how to boot the DSH, env vars, entrypoints, and expected first command
- `tasks/board.yaml` — the full task board from Step 6
- `agents/` — role definitions, prompts, and tool permissions for each agent
- `harness/` or `.harness/` — config, queue, sandbox, and policy files
- `AGENTS.md` — repo-wide operating rules every agent must follow
- A short `HANDOFF.md` at repo root stating: current state, what's done, what remains, and the exact first task the DSH should execute
- A "Do Not Touch" list: generated files, vendored code, secrets, release artifacts, signed checksums

Verify the handoff is coherent: a fresh agent with no context should be able to read `HANDOFF.md` → `HARNESS.md` → `tasks/board.yaml` and start working without asking questions.

## Output Format

1. Executive summary
2. Project reconstruction (verify Known Project Context against repo — note matches and drift)
3. Repository inventory
4. Gap analysis table
5. Prioritized completion plan
6. DeepSeek Harness deployment plan
7. Agent task board (summary + path to full board file)
8. Files created/updated (paths and what changed)
9. Commands run and their results
10. Handoff package manifest
11. Risks, assumptions, open questions

## Rules

- Verify the Known Project Context against the repo; the filesystem wins on conflict — **except** for the Distribution Strategy, which is a locked decision.
- Prefer the smallest correct change.
- Do not add dependencies without justification. Cobra is expected; GoReleaser, Cosign, Syft are expected for distribution; anything else needs a reason.
- Never commit secrets, tokens, passwords, or PII.
- Honor LogZero's zero-egress principle: no telemetry, no external calls at runtime, no uploading policy data anywhere. This applies to the tool **and** to the DSH agents building it.
- Do not add `go install` as a supported distribution channel.
- Ask at most 5 blocking questions; otherwise proceed with explicit assumptions.
- Mark uncertainty as `ASSUMPTION` or `UNKNOWN`.
- Be concrete: file paths, commands, configs, acceptance criteria.
- Every task on the board must be executable by an agent with no human context beyond the repo.
- Keep going until the repo is actually in a better, working state — and the DSH can start from `HANDOFF.md` alone.