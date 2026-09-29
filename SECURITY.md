# Security Policy

## Zero-Egress Design Principles
LogZero operates strictly client-side. There are absolutely no network connections established outside of the initial AWS API queries (when in live mode).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < 1.0   | :x:                |

## Vulnerability Reporting
Please report vulnerabilities privately via GitHub Security Advisories. Do not open public issues for security vulnerabilities.

## Security Design
- **No Telemetry / Phone-Home:** We do not collect metrics, usage data, or errors.
- **PII Exclusion:** The parser drops irrelevant fields which might contain sensitive context before processing.
- **ARN Validation & Sanitization:** String inputs and ARNs are strictly validated to prevent injection or path traversal attacks.
- **Static Binary Distribution:** LogZero is distributed as a statically compiled binary to minimize the runtime dependency footprint.

## Supply Chain Security
- Releases are signed via **Cosign**.
- **SBOM** is generated using Syft.
- Includes `checksums.txt` for integrity verification.
- **Distroless Docker Images** are provided for containerized usage.

## Dependency Policy
- We keep external dependencies to an absolute minimum.
- `govulncheck` is run on every PR to prevent the introduction of vulnerable dependencies.
