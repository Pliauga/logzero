# LogZero

Turns AWS CloudTrail events into a least-privilege IAM policy, as Terraform HCL
or IAM JSON. It runs on your machine: no telemetry, no upload, no AWS calls
unless you ask it to query CloudTrail directly.

## Install

Pick one. The binary is the simplest.

### 1. Binary

Download the archive for your OS and architecture from
[Releases](https://github.com/Pliauga/logzero/releases), then:

```bash
tar -xzf logzero_*.tar.gz
chmod +x logzero
sudo mv logzero /usr/local/bin/
logzero --help
```

Releases also ship `checksums.txt`, a Cosign signature, and SBOMs. Verifying is
optional:

```bash
cosign verify-blob --certificate checksums.txt.cert \
  --signature checksums.txt.sig checksums.txt
sha256sum -c checksums.txt
```

### 2. Docker

```bash
docker run --rm -v "$PWD:/data:ro" ghcr.io/pliauga/logzero:latest \
  --file /data/events.json > policy.tf
```

### 3. From source

Needs Go 1.26.9 or newer.

```bash
git clone https://github.com/Pliauga/logzero
cd logzero
go build -o bin/logzero ./cmd/logzero
```

`go install` works but is not recommended for a security tool: it pulls the
module through the Go proxy instead of a signed release.

## Quick start

You need a CloudTrail events file. Two common ways to get one:

```bash
# Straight from the API (management events, last 90 days)
aws cloudtrail lookup-events --max-results 50 --output json > events.json

# Or copy a JSON export from your CloudTrail S3 bucket
```

Then:

```bash
logzero --file events.json --output policy.tf --name app_policy
```

That writes Terraform HCL and prints a summary to stderr:

```text
[Summary]
  • Ingested Events:     7
  • Unique Actions:      6
  • Synthesized Blocks:  4
```

The output:

```hcl
data "aws_iam_policy_document" "app_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::reports/report@2024.pdf"]
  }
}
```

For IAM JSON instead, add `--format json`. To write to stdout instead of a file,
drop `--output` or set it to `-`.

Accepted input: a JSON array of events, a `{"Records": [...]}` export, or
NDJSON, one event per line.

## Live mode

Skip `--file` to query CloudTrail with your normal AWS credential chain
(environment variables, profile, SSO, instance role).

```bash
# Events where this role is the caller, last 2 hours
logzero --role-arn arn:aws:iam::123456789012:role/AppRole --since 2h

# Explicit window
logzero --start-time 2026-09-05T12:00:00Z --end-time 2026-09-05T14:00:00Z
```

`--role-arn` must be a full ARN. A role name is rejected before any AWS call is
made.

Live mode reads management events only, and only the last 90 days. Data-plane
events such as S3 `GetObject` do not appear. Longer windows print a warning and
quietly miss older activity. The API returns up to 50 events per page at roughly
2 requests per second, so large windows take time.

## Flags

| Flag | Short | Default | Meaning |
| --- | --- | --- | --- |
| `--file` | `-f` | | Offline events file. Omit it to use the API. |
| `--role-arn` | `-r` | | Role ARN to filter live events by caller identity. |
| `--since` | `-s` | `1h` | Lookback duration: `15m`, `1h`, `24h`. |
| `--time-window` | `-w` | | Same as `--since`. |
| `--start-time` | | | RFC3339 start. Use with `--end-time`. |
| `--end-time` | | | RFC3339 end. Must be after the start. |
| `--output` | `-o` | `-` | Output path. `-` means stdout. |
| `--format` | | `hcl` | `hcl` or `json`. |
| `--name` | `-n` | `tightened_policy` | Terraform block name. |
| `--region` | | | AWS region override. |
| `--profile` | | | AWS profile override. |

## Before you apply the policy

- Any action seen without a usable resource ARN becomes `"*"` for that action,
  and logzero prints `WARNING: N generated statement(s) use "*"`. Read those
  statements and narrow them by hand.
- The policy reflects what was observed, not what is safe. A role that did
  nothing during the window gets an empty result, and logzero exits with an
  error rather than writing an empty policy.
- Output files are written atomically with mode `0600`.

## Development

```bash
make build      # ./bin/logzero
make test       # go test -race -cover ./...
make lint       # golangci-lint run ./...
make vulncheck  # govulncheck ./...
make fuzz       # 30s fuzz of the event reader
```

## License

MIT. See [LICENSE](LICENSE).
