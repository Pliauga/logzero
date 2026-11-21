package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Pliauga/logzero/pkg/aws"
	"github.com/Pliauga/logzero/pkg/models"
	"github.com/Pliauga/logzero/pkg/parser"
	"github.com/Pliauga/logzero/pkg/synthesis"
	"github.com/hashicorp/hcl/v2/hclparse"
)

func TestEndToEndFixtureIngestion(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "cloudtrail_fixture.json")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		fixturePath = filepath.Join("testdata", "cloudtrail_fixture.json")
	}

	aggregator := parser.NewActionAggregator()
	count, err := aws.IngestFromFile(fixturePath, aggregator)
	if err != nil {
		t.Fatalf("IngestFromFile failed: %v", err)
	}

	// 7 total events in fixture, 1 is AccessDenied, so 6 valid events
	if count != 7 {
		t.Errorf("Expected 7 raw events, got %d", count)
	}

	// Unique actions: S3:GetObject, S3:PutObject, DynamoDB:GetItem, DynamoDB:Query, SecretsManager:GetSecretValue, KMS:Decrypt
	if aggregator.TotalUniqueActions() != 6 {
		t.Errorf("Expected 6 unique actions, got %d", aggregator.TotalUniqueActions())
	}

	statements := aggregator.Statements()
	if len(statements) != 4 {
		t.Fatalf("Expected 4 consolidated statements, got %d", len(statements))
	}

	hclBytes, err := synthesis.GenerateHCLPolicy("app_policy", statements)
	if err != nil {
		t.Fatalf("GenerateHCLPolicy failed: %v", err)
	}

	hclStr := string(hclBytes)
	expectedTokens := []string{
		`data "aws_iam_policy_document" "app_policy"`,
		`"s3:GetObject"`,
		`"s3:PutObject"`,
		`"dynamodb:GetItem"`,
		`"dynamodb:Query"`,
		`"secretsmanager:GetSecretValue"`,
		`"kms:Decrypt"`,
		`"arn:aws:s3:::production-data-vault/customer_payload_secret.json"`,
		`"arn:aws:dynamodb:us-east-1:123456789012:table/UserSessions"`,
	}

	for _, token := range expectedTokens {
		if !strings.Contains(hclStr, token) {
			t.Errorf("HCL output missing expected token: %s\nGenerated HCL:\n%s", token, hclStr)
		}
	}

	// Verify AccessDenied event was excluded
	if strings.Contains(hclStr, "DeleteRole") || strings.Contains(hclStr, "AdminRole") {
		t.Errorf("Unauthorized action (DeleteRole) leaked into policy HCL!")
	}
}

func TestPerformanceAndMemoryConstraint(t *testing.T) {
	// Generate 5,000 synthetic events
	aggregator := parser.NewActionAggregator()
	eventCount := 5000

	start := time.Now()
	for i := 0; i < eventCount; i++ {
		serviceIdx := i % 5
		var eventSource, eventName, arn string

		switch serviceIdx {
		case 0:
			eventSource = "s3.amazonaws.com"
			eventName = fmt.Sprintf("Action%d", i%10)
			arn = fmt.Sprintf("arn:aws:s3:::bucket-%d/*", i%5)
		case 1:
			eventSource = "dynamodb.amazonaws.com"
			eventName = fmt.Sprintf("Action%d", i%10)
			arn = fmt.Sprintf("arn:aws:dynamodb:us-east-1:123456789012:table/Table-%d", i%5)
		case 2:
			eventSource = "sqs.amazonaws.com"
			eventName = fmt.Sprintf("Action%d", i%10)
			arn = fmt.Sprintf("arn:aws:sqs:us-east-1:123456789012:queue-%d", i%5)
		case 3:
			eventSource = "kms.amazonaws.com"
			eventName = fmt.Sprintf("Action%d", i%10)
			arn = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/key-%d", i%5)
		case 4:
			eventSource = "secretsmanager.amazonaws.com"
			eventName = fmt.Sprintf("Action%d", i%10)
			arn = fmt.Sprintf("arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-%d", i%5)
		}

		aggregator.IngestRawEvent(models.CloudTrailRawEvent{
			EventSource: eventSource,
			EventName:   eventName,
			Resources: []models.CloudTrailResource{
				{ARN: arn, Type: "AWS::Resource"},
			},
		})
	}

	statements := aggregator.Statements()
	hclBytes, err := synthesis.GenerateHCLPolicy("perf_policy", statements)
	if err != nil {
		t.Fatalf("GenerateHCLPolicy failed: %v", err)
	}

	duration := time.Since(start)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	allocMB := float64(mem.Alloc) / 1024 / 1024

	t.Logf("Processed %d events in %v, Alloc RAM: %.2f MB, Output Size: %d bytes",
		eventCount, duration, allocMB, len(hclBytes))

	if duration > 3*time.Second {
		t.Errorf("Performance constraint violated: 5000 events took %v (limit: < 3.0s)", duration)
	}
	if allocMB > 25.0 {
		t.Errorf("Memory constraint violated: Alloc RAM is %.2f MB (limit: < 25.0 MB)", allocMB)
	}
}

// TestRunRootCmdRejectsUnknownFormat verifies that an unsupported --format
// value is rejected with an explicit error, rather than silently falling
// through to HCL output.
func TestRunRootCmdRejectsUnknownFormat(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "cloudtrail_fixture.json")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		fixturePath = filepath.Join("testdata", "cloudtrail_fixture.json")
	}

	tests := []struct {
		format      string
		expectUnsup bool
	}{
		{format: "yaml", expectUnsup: true},
		{format: "json", expectUnsup: false},
		{format: "hcl", expectUnsup: false},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "policy.out")

			cmd := newRootCmd()
			cmd.SetArgs([]string{
				"--file", fixturePath,
				"--format", tc.format,
				"--output", outPath,
			})

			err := cmd.Execute()

			gotUnsup := err != nil && strings.Contains(err.Error(), "unsupported format")
			if gotUnsup != tc.expectUnsup {
				t.Fatalf("--format %s: unsupported-format error = %v (err = %v), want %v",
					tc.format, gotUnsup, err, tc.expectUnsup)
			}
			if tc.expectUnsup && err != nil {
				t.Logf("--format %s correctly rejected: %v", tc.format, err)
			}
		})
	}
}

func fixturePath(name string) string {
	path := filepath.Join("..", "..", "testdata", name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("testdata", name)
	}
	return path
}

func TestResolveLookbackWindow(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	t.Run("relative lookback", func(t *testing.T) {
		start, end, exceeds, err := resolveLookbackWindow(now, "", "", "1h")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if start == nil || !start.Equal(now.Add(-time.Hour)) {
			t.Fatalf("start = %v, want %v", start, now.Add(-time.Hour))
		}
		if end != nil {
			t.Fatalf("end = %v, want nil", end)
		}
		if exceeds {
			t.Fatal("90-day retention warning fired for a 1h window")
		}
	})

	t.Run("zero lookback rejected", func(t *testing.T) {
		if _, _, _, err := resolveLookbackWindow(now, "", "", "0s"); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("err = %v, want positive-duration error", err)
		}
	})

	t.Run("negative lookback rejected", func(t *testing.T) {
		if _, _, _, err := resolveLookbackWindow(now, "", "", "-5m"); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("err = %v, want positive-duration error", err)
		}
	})

	t.Run("inverted explicit window rejected", func(t *testing.T) {
		_, _, _, err := resolveLookbackWindow(now, "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", "")
		if err == nil || !strings.Contains(err.Error(), "must be after start time") {
			t.Fatalf("err = %v, want inverted-window error", err)
		}
	})

	t.Run("equal start and end rejected", func(t *testing.T) {
		_, _, _, err := resolveLookbackWindow(now, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "")
		if err == nil || !strings.Contains(err.Error(), "must be after start time") {
			t.Fatalf("err = %v, want inverted-window error", err)
		}
	})

	t.Run("retention window flagged", func(t *testing.T) {
		_, _, exceeds, err := resolveLookbackWindow(now, "2026-01-01T00:00:00Z", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !exceeds {
			t.Fatal("expected 90-day retention warning for a >90d window")
		}
	})

	t.Run("window inside retention not flagged", func(t *testing.T) {
		_, _, exceeds, err := resolveLookbackWindow(now, "2026-11-01T00:00:00Z", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exceeds {
			t.Fatal("unexpected 90-day retention warning for a 20d window")
		}
	})
}

func TestRunRootCmdRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "role name instead of ARN",
			args: []string{"--role-arn", "AppRole"},
			want: "invalid --role-arn",
		},
		{
			name: "invalid block name",
			args: []string{
				"--file", fixturePath("cloudtrail_fixture.json"),
				"--name", "bad name.with!chars",
				"--output", filepath.Join(t.TempDir(), "policy.tf"),
			},
			want: "invalid --name",
		},
		{
			name: "non-positive since",
			args: []string{"--since", "0s"},
			want: "must be positive",
		},
		{
			name: "inverted explicit window",
			args: []string{
				"--start-time", "2026-01-02T00:00:00Z",
				"--end-time", "2026-01-01T00:00:00Z",
			},
			want: "must be after start time",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestAllFixturesStructuralHCL ingests every repository fixture, checks the
// aggregation outcome, and structurally parses the generated HCL with the
// HashiCorp parser rather than matching substrings (LZ-110 / A15).
func TestAllFixturesStructuralHCL(t *testing.T) {
	tests := []struct {
		fixture        string
		wantEvents     int
		wantStatements int
		wantWildcard   int
	}{
		{fixture: "sample_cloudtrail.json", wantEvents: 2, wantStatements: 2, wantWildcard: 0},
		{fixture: "cloudtrail_fixture.json", wantEvents: 7, wantStatements: 4, wantWildcard: 0},
		{fixture: "standard-workload.json", wantEvents: 4, wantStatements: 3, wantWildcard: 0},
		{fixture: "govcloud-multi-partition.json", wantEvents: 2, wantStatements: 2, wantWildcard: 1},
		{fixture: "edge-case-sanitization.json", wantEvents: 1, wantStatements: 0, wantWildcard: 0},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			aggregator := parser.NewActionAggregator()
			count, err := aws.IngestFromFile(fixturePath(tc.fixture), aggregator)
			if err != nil {
				t.Fatalf("IngestFromFile(%s) failed: %v", tc.fixture, err)
			}
			if count != tc.wantEvents {
				t.Errorf("ingested %d events, want %d", count, tc.wantEvents)
			}

			statements := aggregator.Statements()
			if len(statements) != tc.wantStatements {
				t.Fatalf("synthesized %d statements, want %d: %+v", len(statements), tc.wantStatements, statements)
			}
			if got := aggregator.Stats().WildcardStmts; got != tc.wantWildcard {
				t.Errorf("WildcardStmts = %d, want %d", got, tc.wantWildcard)
			}

			if tc.wantStatements == 0 {
				if _, err := synthesis.GenerateHCLPolicy("empty_policy", statements); err == nil {
					t.Fatal("expected an error for an empty statement set")
				}
				return
			}

			hclBytes, err := synthesis.GenerateHCLPolicy("fixture_policy", statements)
			if err != nil {
				t.Fatalf("GenerateHCLPolicy failed: %v", err)
			}

			hclParser := hclparse.NewParser()
			if _, diags := hclParser.ParseHCL(hclBytes, tc.fixture+".tf"); diags.HasErrors() {
				t.Fatalf("generated HCL is not structurally valid: %s\n%s", diags.Error(), hclBytes)
			}
		})
	}
}

// TestEmptyInlineInputProducesNoStatements covers the empty-input boundary for
// the reader path (an empty export is not an error at ingestion time, but it
// must never synthesize a policy).
func TestEmptyInlineInputProducesNoStatements(t *testing.T) {
	aggregator := parser.NewActionAggregator()
	count, err := aws.IngestFromReader(strings.NewReader(""), aggregator)
	if err != nil {
		t.Fatalf("IngestFromReader(empty) returned error: %v", err)
	}
	if count != 0 {
		t.Errorf("ingested %d events from empty input, want 0", count)
	}
	if statements := aggregator.Statements(); len(statements) != 0 {
		t.Errorf("empty input produced %d statements, want 0", len(statements))
	}
}
