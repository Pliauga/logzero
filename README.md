# LogZero

[![CI](https://github.com/Pliauga/logzero/actions/workflows/security.yml/badge.svg)](https://github.com/Pliauga/logzero/actions/workflows/security.yml)
[![Release](https://github.com/Pliauga/logzero/actions/workflows/release.yml/badge.svg)](https://github.com/Pliauga/logzero/actions/workflows/release.yml)

LogZero is a zero-egress CLI for synthesizing least-privilege IAM policies from AWS CloudTrail logs. It ingests events (offline JSON or live API), normalizes actions by ARN, and emits Terraform HCL (`data "aws_iam_policy_document"`) or IAM JSON.

No data leaves your environment. No telemetry.

## Features

- **Offline & Live Ingestion**: Parse local CloudTrail JSON exports (array, `{"Records": []}`, or NDJSON) or query the AWS API directly.
- **Deterministic Synthesis**: Consolidates duplicate actions and generates clean Terraform HCL or IAM JSON.
- **Multi-Partition Support**: Handles standard `aws`, `aws-us-gov`, `aws-cn`, `aws-iso`, and `aws-iso-b` ARNs.
- **Zero Egress**: All parsing and policy generation happen locally in memory.
- **Hardened Supply Chain**: Multi-arch Docker images, Cosign signatures, Syft SBOMs, and Grype vulnerability scanning in CI.

## Installation

### Pre-built Binaries (Recommended)

Download the latest signed binaries from [GitHub Releases](https://github.com/Pliauga/logzero/releases).

Verify the checksums with Cosign before running:

```bash
cosign verify-blob \
  --certificate checksums.txt.cert \
  --signature checksums.txt.sig \
  checksums.txt
```

### Docker

```bash
docker run --rm -v $(pwd):/data ghcr.io/pliauga/logzero:latest --file /data/cloudtrail.json --format hcl
```

> **Note:** `go install` is **not recommended**. LogZero is a security tool and is distributed as signed binaries to mitigate Go module proxy supply-chain risks.

## CLI Usage

### Offline: CloudTrail JSON export

```bash
# Generate Terraform HCL (default)
logzero --file ./cloudtrail-export.json --output policy.tf --name app_policy

# Generate IAM JSON
logzero --file ./cloudtrail-export.json --format json
```

### Live: AWS CloudTrail API

Uses your existing AWS credential chain.

```bash
# Query the last 2 hours for a specific IAM role
logzero --role-arn "arn:aws:iam::123456789012:role/AppRole" --since 2h --format hcl

# Specific time window
logzero --start-time 2026-09-05T12:00:00Z --end-time 2026-09-05T14:00:00Z
```

## Library Usage

LogZero is designed primarily as a CLI, but the core packages can be used directly.

```go
package main

import (
	"fmt"
	"os"

	"github.com/Pliauga/logzero/pkg/aws"
	"github.com/Pliauga/logzero/pkg/parser"
	"github.com/Pliauga/logzero/pkg/synthesis"
)

func main() {
	// Initialize the aggregator
	aggregator := parser.NewActionAggregator()

	// Ingest events directly into the aggregator
	count, err := aws.IngestFromFile("cloudtrail-export.json", aggregator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingestion failed: %v\n", err)
		os.Exit(1)
	}

	// Generate HCL
	statements := aggregator.Statements()
	hclBytes, err := synthesis.GenerateHCLPolicy("tightened_policy", statements)
	if err != nil {
		fmt.Fprintf(os.Stderr, "synthesis failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Processed %d events.\n\n%s\n", count, string(hclBytes))
}
```

## Development

Requires Go 1.26.9+.

```bash
make test       # Run tests with race detector
make lint       # golangci-lint
make vulncheck  # govulncheck
make build      # Compile local binary to ./bin/logzero
```

## License

MIT License. See [LICENSE](LICENSE).
