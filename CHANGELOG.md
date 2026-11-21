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
- Aligned the Go module path and all repository references with the renamed
  GitHub repository (previously published under the `logzero/logzero` module
  path), which is now `github.com/Pliauga/logzero`. This includes Go import
  paths, OCI image source labels, GHCR image paths (`ghcr.io/pliauga/logzero`),
  and documentation URLs. Consumers importing the module as a Go dependency
  must update their import paths accordingly.
- Updated the Go toolchain used in CI (`security.yml`, `release.yml`) and the
  Docker builder image to 1.26, matching the `go 1.26.0` directive and the
  toolchain declared in `go.mod`.
- Bumped the Go toolchain from `go1.26.9` to `go1.26.11` in `go.mod` and aligned
  the Docker builder image (`golang:1.26.11-alpine`) and the GitHub Actions
  `setup-go` pins. Go 1.26.11 is the first release containing the fixes for
  GO-2026-6859 (`net/http` HTTP/1 server crash via `MaxBytesReader` header race)
  and GO-2026-6809 (`crypto/x509` now distrusts the compromised intermediate
  certificates), so this closes both standard-library findings reported by
  `govulncheck ./...` against the previous toolchain.
- Path validation in `pkg/synthesis` now rejects any `..` segment in the raw
  input path, including cases that previously normalized harmlessly (e.g.
  `foo/../bar`). Users must supply normalized paths.
- Output file writes in `pkg/synthesis` are now atomic (temp file + rename).

### Fixed
- `--format` flag now returns an error for unsupported values instead of
  silently falling through to HCL output.
- `IngestFromReader` now correctly errors on corrupt input and ignores
  non-CloudTrail JSON objects, preventing silent data loss.
- ARN normalization no longer rewrites valid identifiers: `@`, `+`, `=`, `,`
  and spaces in IAM role names and S3 object keys are preserved, so distinct
  ARNs can no longer collapse into one grant.
- Live mode now filters events by caller identity (`userIdentity.arn`,
  `sessionContext.sessionIssuer.arn`, assumed-role ARN) instead of by
  `ResourceName`, which selected events where the role was the target.
- Generated policies that fall back to `"*"` are reported as a warning instead
  of expanding silently.
- `--role-arn` is validated before any AWS client is created, and `--name`
  is validated against the HCL identifier grammar before synthesis.
- Non-positive lookback durations and inverted time windows are rejected, and
  windows longer than CloudTrail's 90-day retention are flagged.
- The "Unique Actions" summary now counts distinct `service:action` pairs
  instead of `service:action:resource` triples.
- CLI failures print a single `Error:` line instead of two.

### Removed
- Unused `parser.ActionAggregator.GetNormalizedActions` and
  `models.NormalizedAction` (dead code, no callers).
