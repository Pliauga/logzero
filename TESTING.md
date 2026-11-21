# Testing Strategy

LogZero relies on a multi-layered test suite to guarantee correct IAM policy
synthesis, byte-stable output, and zero-egress operation.

## Commands

Run from the repository root. The full gate is:

```bash
go build ./...
go vet ./...
gofmt -l .                     # must print nothing
golangci-lint run ./...
go test -race -cover ./...
go test -cover ./pkg/models    # must be >= 85%
go test -fuzz=FuzzIngestFromReader -fuzztime=20s ./pkg/aws
```

## Unit Tests

- `pkg/models` — ARN grammar across every supported partition (`aws`,
  `aws-us-gov`, `aws-cn`, `aws-iso`, `aws-iso-b`), invalid inputs, `GetARN`
  precedence, and JSON round-tripping of `CloudTrailRawEvent` including
  `userIdentity`/`errorCode`.
- `pkg/parser` — service-prefix normalization, action-name validation, ARN
  preservation (`@`, `+`, `=`, `,`, spaces), error-code filtering, wildcard
  accounting, and the `Stats` counters.
- `pkg/synthesis` — HCL/JSON generation, path-traversal rejection, atomic
  write, `0600` file mode, and `0750` directory mode.
- `cmd/logzero` — flag validation, lookback-window resolution, and the
  end-to-end CLI path.

Coverage is enforced at **85% or better for `pkg/models`**; other packages are
reported but not gated. Latest measured snapshot:

| Package | Coverage |
| --- | --- |
| `pkg/models` | 100.0% |
| `pkg/parser` | 87.2% |
| `pkg/synthesis` | 80.0% |
| `cmd/logzero` | 72.8% |
| `pkg/aws` | 60.6% |

## Fuzz Tests

`FuzzIngestFromReader` (`pkg/aws`) targets malformed, truncated, and
adversarial CloudTrail JSON across all three accepted shapes (JSON array,
`{"Records": [...]}` wrapper, NDJSON). A 20-second run is part of the gate;
seeds live in the test file and are exercised in normal `go test` runs.

## E2E Tests

`TestAllFixturesStructuralHCL` (`cmd/logzero`) runs every fixture through
`IngestFromFile -> Statements() -> GenerateHCLPolicy` and parses the result
with `github.com/hashicorp/hcl/v2/hclparse`, so the assertion is structural
validity rather than substring matching:

| Fixture | Events | Statements | Wildcard statements |
| --- | --- | --- | --- |
| `sample_cloudtrail.json` | 2 | 2 | 0 |
| `cloudtrail_fixture.json` | 7 | 4 | 0 |
| `standard-workload.json` | 4 | 3 | 0 |
| `govcloud-multi-partition.json` | 2 | 2 | 1 |
| `edge-case-sanitization.json` | 1 | 0 | 0 |

The edge-case fixture carries an event name outside the action-name grammar;
it is rejected at aggregation, and an empty statement set is rejected rather
than emitting an empty policy.

## Test Fixtures

- All static test data is stored in the `testdata/` directory.
- **Rules:** Do not modify these fixtures unless fixing a bug in the fixture
  itself. They are intended to be read-only inputs for tests.
- Every fixture in `testdata/` is covered by the integration test above.

## Race Detection

- All tests must be run with the Go race detector enabled (`go test -race`).

## Performance Benchmarks

- `TestPerformanceAndMemoryConstraint` synthesizes 5000 events and asserts
  completion under 3 seconds and under 25 MiB of allocated memory.
