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
