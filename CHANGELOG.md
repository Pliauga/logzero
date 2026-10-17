# Changelog

All notable changes to LogZero will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- CloudTrail JSON log ingestion (file, reader, NDJSON)
- Live AWS CloudTrail API query via SDK v2
- IAM policy synthesis (JSON and Terraform HCL)
- Multi-partition ARN support (aws, aws-us-gov, aws-cn, aws-iso)
- Input sanitization and PII exclusion
- Fuzz testing for parser robustness
- CLI with Cobra (--file, --format, --role-arn, --since, --output)
- GitHub Actions workflows (security, release)
- GoReleaser configuration with Cosign signing and SBOM generation
- GitHub Action composite for CI/CD integration

### Changed
- Moved internal agent and project-management files (`AGENTS.md`, `DSH.md`,
  `HANDOFF.md`, `initial-audit.md`, `SECURITY-BASELINE.md`, the `tasks/` task
  board, and the `agents/` role definitions) into a `.dev/` directory so the
  repository root shows only user-facing project files. Internal cross-references
  in the moved documents were updated to the new `.dev/` paths. No runtime or
  published artifact is affected.

### Changed
- Aligned the Go module path and all repository references with the renamed
  GitHub repository (previously published under the `logzero/logzero` module
  path), which is now `github.com/Pliauga/logzero`. This includes Go import
  paths, OCI image source labels, GHCR image paths (`ghcr.io/pliauga/logzero`),
  and documentation URLs. Consumers importing the module as a Go dependency
  must update their import paths accordingly.
- Updated the Go toolchain used in CI (`security.yml`, `release.yml`) from 1.22
  to 1.25, matching the `go 1.25.0` directive in `go.mod`.
- Path validation in `pkg/synthesis` now rejects any `..` segment in the raw
  input path, including cases that previously normalized harmlessly (e.g.
  `foo/../bar`). Users must supply normalized paths.
- Output file writes in `pkg/synthesis` are now atomic (temp file + rename).

### Fixed
- `--format` flag now returns an error for unsupported values instead of
  silently falling through to HCL output.
- `IngestFromReader` now correctly errors on corrupt input and ignores
  non-CloudTrail JSON objects, preventing silent data loss.
