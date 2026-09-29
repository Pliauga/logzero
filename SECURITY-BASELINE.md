# LogZero — Security Scan Baseline

Baseline record produced by task **LZ-102**. This document captures the state of
static analysis and dependency vulnerability scanning at a known-good point so
that future findings can be compared against it.

- **Scan date (UTC):** 2026-09-29T20:44:59Z
- **Repository revision:** `23a5eb8173b7479a11e76f0f931315a38befb838` (`dev`)
- **Task branch:** `dsh/LZ-102`

## Tool versions

| Tool | Version | Path | Notes |
| --- | --- | --- | --- |
| gosec | v2.29.0 | `/opt/local/bin/gosec` | Git tag `v2.29.0`, built with go1.27.1 |
| govulncheck | v1.8.0 | `/Users/ep/go/bin/govulncheck` | Built with go1.27.1; see §Tooling caveat |

Both tools were confirmed pre-installed. The `govulncheck` on `PATH`
(`/opt/local/bin/govulncheck`) is **not** usable in this environment; the
v1.8.0 build in `GOPATH/bin` was used instead. See §Tooling caveat for the full
explanation.

## Summary of results

| Scan | Result | Exit code |
| --- | --- | --- |
| `gosec ./...` | 2 findings, both MEDIUM, both first-party | 1 |
| `gosec -exclude-dir=.gomodcache ./...` | 2 findings, both MEDIUM | 1 |
| `govulncheck ./...` | **No vulnerabilities found** | 0 |

**No HIGH or CRITICAL findings were detected by either tool.** No follow-up task
IDs are therefore required by the LZ-102 done-criteria.

## gosec findings

Scan scope: 5 first-party packages, 739 lines, 88 files, 0 `nosec` directives.

> **Scope note.** The `./...` pattern also matches the repository-local module
> cache at `.gomodcache/` (introduced by the sandbox workaround documented in
> `AGENTS.md`), which inflates the raw count to 34 findings / 12,074 lines.
> 32 of those 34 findings are `G104` (unhandled errors, LOW) inside vendored
> third-party sources under `.gomodcache/` — notably
> `github.com/hashicorp/hcl/v2@v2.22.0/diagnostic_text.go` and
> `github.com/mitchellh/go-wordwrap`. **These are artifacts of the in-repo
> module cache, not findings in LogZero's own code**, and they are excluded from
> the baseline below. This is a known consequence of the workspace-local
> `GOMODCACHE`; it does not occur in CI, where the cache lives outside the
> repository.

### Finding 1 — G304 / CWE-22: Potential file inclusion via variable

- **Location:** `pkg/synthesis/hcl.go:116`
- **Severity:** MEDIUM · **Confidence:** HIGH
- **Code:** `file, err := os.OpenFile(cleanedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)`

The flagged path is already validated before use by
`ValidateOutputPath` (`pkg/synthesis/hcl.go:22-36`), which applies
`filepath.Clean` and then rejects any path containing a `..` component:

```go
cleaned := filepath.Clean(rawPath)
parts := strings.Split(cleaned, string(filepath.Separator))
for _, part := range parts {
    if part == ".." {
        return "", fmt.Errorf("%w: %s", ErrPathTraversal, rawPath)
    }
}
```

The taint source is the operator-supplied `--output` CLI flag
(`cmd/logzero/main.go:53`), i.e. a value the operator sets for themselves rather
than remote untrusted input. The existing protection is covered by
`TestPathTraversalRejection`.

gosec's suggested autofix is to adopt `os.Root` (Go >= 1.24) to scope file
access under a fixed root. That would be a defence-in-depth improvement, but it
would change the intended semantics: LogZero deliberately writes to a
caller-chosen path, so restricting writes to a fixed root would break the
documented `--output <path>` behaviour. Treated as **accepted risk**, not a
defect. AGENTS.md explicitly states "Path traversal protection is enforced in
the synthesis writer. Do not weaken it" — this baseline documents the control
rather than proposing to relax it.

### Finding 2 — G301 / CWE-276: Expect directory permissions to be 0750 or less

- **Location:** `pkg/synthesis/hcl.go:111`
- **Severity:** MEDIUM · **Confidence:** HIGH
- **Code:** `if err := os.MkdirAll(dir, 0755); err != nil {`

The output directory is created with mode `0755` (world-readable/traversable).
The file written inside it is created with `0600` (owner-only), so the policy
payload itself is not exposed; the concern is only that the containing
directory is group/other-traversable.

**Proposed follow-up: `LZ-114`** *(proposed ID — not yet present on
`tasks/board.yaml`; requires board addition)* — change
`os.MkdirAll(dir, 0755)` to `os.MkdirAll(dir, 0750)` and add a test asserting the
created directory mode. This is a one-line, low-risk hardening change. It is the
only finding from this baseline that warrants code change.

Because this finding is MEDIUM rather than HIGH/CRITICAL, LZ-102's done-criteria
("any HIGH/CRITICAL findings have a follow-up task ID") is satisfied
vacuously — there are none — and LZ-114 is raised as a recommendation, not a
requirement.

## govulncheck results

```
No vulnerabilities found.
```

Scanned with `govulncheck@v1.8.0` in symbol mode (default) against vulnerability
database `https://vuln.go.dev`, DB updated `2026-09-28 16:43:40 +0000 UTC`.

This is a clean result: no known vulnerabilities in LogZero's dependency graph
that are actually reachable from LogZero's code.

## Tooling caveat — `govulncheck` on `PATH` is unusable

The `govulncheck` binary at `/opt/local/bin/govulncheck` **fails on this
repository** and must not be used for the baseline. Its failure is a toolchain
mismatch, not a finding:

```
govulncheck: Loading packages failed, possibly due to a mismatch between the Go version
used to build govulncheck and the Go version on PATH.
```

Root cause, established via `go version -m`:

| Property | `PATH` binary | `GOPATH/bin` binary (used) |
| --- | --- | --- |
| Built with Go | go1.26.6 | **go1.27.1** |
| Module version reported | `golang.org/x/vuln (devel)` | `golang.org/x/vuln v1.8.0` |
| `--version` scanner string | `govulncheck@v0.0.0` | **`govulncheck@v1.8.0`** |
| Verdict on this repo | errors out | **No vulnerabilities found** |

The `PATH` binary was built with go1.26.6 while the active toolchain is go1.27.1,
so its source-processing packages cannot parse go1.27 standard-library and
vendored sources (`math/rand/v2`, `golang.org/x/text/unicode/norm`), producing
`method must have no type parameters` and `file requires newer Go version
go1.27` errors. The `GOPATH/bin` binary was rebuilt with go1.27.1 and runs
cleanly.

This also means the board's documented command `govulncheck -version` reports the
*misleading* string `Scanner: govulncheck@v0.0.0` when run against the `PATH`
binary, despite the operator confirming "v1.8.0". The version is only truthful
when read from `GOPATH/bin`. **Recommendation:** invoke govulncheck by explicit
path, or ensure the rebuilt binary shadows the MacPorts copy on `PATH`.

## Provenance

Both tools were verified by inspecting embedded module metadata with
`go version -m` and cross-checked against independent external sources.

### `go version -m` evidence

```
# /opt/local/bin/gosec: go1.27.1
	path	github.com/securego/gosec/v2/cmd/gosec
	mod	github.com/securego/gosec/v2	(devel)
	build	-ldflags="-w -s -X 'main.Version=v2.29.0' -X 'main.GitTag=v2.29.0' -X 'main.BuildDate='"
	build	CGO_ENABLED=0

# /Users/ep/go/bin/govulncheck: go1.27.1
	path	golang.org/x/vuln/cmd/govulncheck
	mod	golang.org/x/vuln	v1.8.0	h1:clG4qBU6zH5VKjti8n5j8BBuYzoSha392xXMkXS351U=
```

### Cross-checks against `proxy.golang.org`

| Artefact | Expected | Observed | Verdict |
| --- | --- | --- | --- |
| `github.com/securego/gosec/v2@v2.29.0` | tag exists | `v2.29.0`, published 2026-08-25T08:37:38Z, commit `deb54465fea23d19a77f037e11e6589021f8501d` | ✅ match |
| `golang.org/x/vuln@v1.8.0` | tag exists | `v1.8.0`, published 2026-09-08T20:52:42Z, commit `709015412431dd2b5b28a53c06c70bc02d49074c` | ✅ match |
| `golang.org/x/vuln@v1.8.0` module hash | proxy `Sum` | `h1:clG4qBU6zH5VKjti8n5j8BBuYzoSha392xXMkXS351U=` | ✅ **byte-for-byte match** with the hash embedded in the binary |
| `gosec@v2.29.0` release notes | upstream tag page | tag `v2.29.0` published 2026-08-26T08:34:58Z | ✅ match |
| `gosec` AI SDK dependencies | upstream `go.mod` | `anthropic-sdk-go v1.66.0`, `openai-go/v3 v3.52.0`, `genai v1.69.0` | ✅ confirmed in upstream `go.mod` **and** embedded in the binary |

The module hash check is the strongest evidence: `go mod download` resolved
`golang.org/x/vuln@v1.8.0` from the module proxy and produced the *identical*
hash embedded in the `govulncheck` binary, confirming the binary was built from
the genuine published module.

### Note on the gosec AI SDK dependencies

`gosec` v2.29.0 genuinely depends on Anthropic, OpenAI, and Google GenAI SDKs.
This is **verified upstream behaviour, not a supply-chain compromise**: the three
dependencies appear in the official `go.mod` at tag `v2.29.0`, and the binary
exposes corresponding AI flags including `-ai-api-key`, `-ai-api-provider`, and
`-ai-base-url` (help text lists providers `atlas`, `gemini`, `claude`, and
`gpt-5.4`). The feature generates suggested autofixes for reported issues.

**Zero-egress relevance.** These flags enable a *new* egress path but are
**off by default** — no AI flags were passed in this baseline, and the scan
completed with no AI provider configured. Because gosec is developer/CI tooling
and not part of the LogZero runtime, this does not affect LogZero's zero-egress
guarantee for security data. It is recorded here because a future contributor
adding `-ai-api-key` to CI would transmit source excerpts to a third party, which
*would* violate the spirit of AGENTS.md's zero-egress rule. No AI flags should be
added to CI.

### Provenance limitation

`gosec` reports its module as `(devel)` rather than `v2.29.0`, indicating it was
built from a local source checkout rather than via
`go install ...@v2.29.0`. Its *version string* is therefore attested only by the
`-ldflags` values embedded at build time. To eliminate reliance on that
self-reported string, the release notes and `go.mod` for tag `v2.29.0` were
independently fetched from GitHub and matched. A stricter reproduction would
rebuild from a pinned tag and compare hashes; that is out of scope for LZ-102 but
is the recommended direction for LZ-104.

## Reproduction

All commands run from the repository root with the sandbox caches from
`AGENTS.md`:

```bash
export GOCACHE=$PWD/.gocache
export GOMODCACHE=$PWD/.gomodcache

# Versions
gosec --version
$(go env GOPATH)/bin/govulncheck --version

# Static analysis — first-party only (authoritative baseline)
gosec -exclude-dir=.gomodcache ./...

# Static analysis — raw, includes in-repo module cache noise
gosec ./...

# Machine-readable findings
gosec -fmt=json -out=/tmp/gosec.json ./...

# Dependency vulnerabilities (NOTE: use the GOPATH binary, see §Tooling caveat)
$(go env GOPATH)/bin/govulncheck ./...

# Provenance
go version -m /opt/local/bin/gosec
go version -m "$(go env GOPATH)/bin/govulncheck"
go mod download -json golang.org/x/vuln@v1.8.0
```

## Relationship to CI

`.github/workflows/security.yml` currently runs:

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
$(go env GOPATH)/bin/gosec -no-fail -fmt sarif -out gosec.sarif ./...
```

Two observations relevant to the P1 hardening tasks:

1. **`-no-fail` means the exit code is discarded**, so gosec findings never block
   CI today. Adopting a real gate is task **LZ-108**, which should use this
   baseline to choose the threshold: `-severity=medium` would flag exactly the
   two first-party MEDIUM findings above. Since neither is a HIGH/CRITICAL risk,
   a gate of `-severity=high` would pass cleanly today while still catching
   future high-severity regressions.
2. **`@latest` is unpinned**, contradicting the supply-chain posture. Pinning is
   task **LZ-104**, which should use `v2.29.0` and `v1.8.0` to match this
   baseline. Note that CI installs govulncheck via `go install` against whatever
   Go toolchain the runner provides, which avoids the `PATH` mismatch documented
   above.

## Assessment

The codebase is in good security shape: **no HIGH or CRITICAL findings, no known
reachable dependency vulnerabilities, and no unhandled-error issues in
first-party code.** The two MEDIUM gosec findings are both in the synthesis
writer's file-output path; one (G301, directory mode) is a trivial hardening
change proposed as **LZ-114**, and the other (G304, variable file path) is an
accepted, deliberately designed behaviour already guarded by path-traversal
validation and a regression test.