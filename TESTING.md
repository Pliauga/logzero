# Testing Strategy

LogZero relies on a robust, multi-layered testing strategy to guarantee correct IAM policy synthesis and zero-egress compliance.

## Unit Tests
- Thorough coverage of core logic in `pkg/models`, `pkg/parser`, and `pkg/synthesis`.
- Mock AWS dependencies where appropriate.

## Fuzz Tests
- Focused on parser robustness to handle malformed, unexpected, or malicious CloudTrail JSON formats.

## E2E Tests
- Verify the end-to-end CLI flow from ingestion to file output.
- Validate the standard user paths using fixtures.

## Test Fixtures
- All static test data is stored in the `testdata/` directory.
- **Rules:** Do not modify these fixtures unless fixing a bug in the fixture itself. They are intended to be read-only inputs for tests.

## Race Detection
- All tests must be run with the Go race detector enabled (`go test -race`).

## Performance Benchmarks
- Included to guarantee our target of < 3s parsing for 5000 events and < 25MB RAM usage.
