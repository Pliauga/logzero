# LogZero

> **Status:** Active development. Core engine functional; distribution pipeline in progress.

LogZero is a **zero-egress CLI tool** that observes AWS CloudTrail API events (live or offline log fixtures) and synthesizes tightened, least-privilege Terraform IAM policy documents.

**No data leaves your environment.** All parsing, normalization, and policy generation happen locally in memory.

## Features

- **Zero Egress** — All processing happens locally. No telemetry, no network egress, no third-party data sharing.
- **Offline & Live Ingestion** — Process local CloudTrail JSON exports or query the AWS CloudTrail API directly.
- **Deterministic Policy Synthesis** — Generates clean IAM JSON policies or Terraform HCL `data "aws_iam_policy_document"` blocks.
- **Multi-Partition Support** — Handles `aws`, `aws-us-gov`, `aws-cn`, `aws-iso`, and `aws-iso-b` partitions.
- **Input Sanitization** — ARN validation, PII exclusion from synthesized structs, and injection-safe string handling.
- **Fuzz Tested** — Parser includes fuzz testing for robustness against malformed inputs.

## Installation

### From GitHub Releases (Recommended)

Download the latest signed binary from [GitHub Releases](https://github.com/Pliauga/logzero/releases).

All release artifacts are signed with [Cosign](https://github.com/sigstore/cosign) and include SHA256 checksums and SBOMs.

```bash
# Verify signature (optional but recommended)
cosign verify-blob \
  --certificate checksums.txt.cert \
  --signature checksums.txt.sig \
  checksums.txt
```

### From Source

```bash
git clone https://github.com/Pliauga/logzero.git
cd logzero
make build
# Binary at ./bin/logzero
```

### Docker

```bash
docker run --rm -v $(pwd):/data ghcr.io/pliauga/logzero:latest --file /data/cloudtrail.json --format hcl
```

> **Note:** `go install` is **not recommended** for production use due to supply-chain risks in the Go module proxy ecosystem.

## Quick Start

### Offline: Analyze a CloudTrail JSON export

```bash
# Generate Terraform HCL (default)
logzero --file ./cloudtrail-export.json

# Generate IAM JSON policy
logzero --file ./cloudtrail-export.json --format json

# Write output to file
logzero --file ./cloudtrail-export.json --output policy.tf --name app_role_policy
```

### Live: Query AWS CloudTrail API

```bash
# Query the last hour of events (default)
logzero

# Query events for a specific role
logzero --role-arn "arn:aws:iam::123456789012:role/AppRole" --since 2h

# Custom time window
logzero --start-time 2026-09-05T12:00:00Z --end-time 2026-09-05T14:00:00Z
```

## Architecture

```
CloudTrail JSON ──→ Ingestion ──→ Normalization ──→ Aggregation ──→ Synthesis ──→ IAM JSON / HCL
 (file/API)       (pkg/aws)     (pkg/parser)     (pkg/parser)    (pkg/synthesis)
```

| Package | Purpose |
|---------|------------------------------------------|
| `pkg/models` | Core data structures, ARN validation, sanitization |
| `pkg/aws` | CloudTrail file/reader/API ingestion |
| `pkg/parser` | Event normalization, action aggregation |
| `pkg/synthesis` | IAM JSON + Terraform HCL generation |
| `cmd/logzero` | CLI entrypoint with Cobra |

## Development

```bash
make test       # Run tests with race detector
make lint       # go vet + golangci-lint
make fuzz       # Fuzz test the parser (30s)
make vulncheck  # govulncheck
make build      # Static binary → bin/logzero
```

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

MIT License — see [LICENSE](LICENSE) for details.
