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
