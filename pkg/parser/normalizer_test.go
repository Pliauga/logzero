package parser

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Pliauga/logzero/pkg/models"
)

func TestZeroPIIUnmarshaling(t *testing.T) {
	// Synthetic event containing sensitive requestParameters, userIdentity, and responseElements
	rawJSON := `{
		"eventSource": "s3.amazonaws.com",
		"eventName": "GetObject",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "AIDACKCEVSQ6C2EXAMPLE",
			"arn": "arn:aws:iam::123456789012:user/Alice",
			"accountId": "123456789012",
			"accessKeyId": "AKIAIOSFODNN7EXAMPLE",
			"userName": "Alice"
		},
		"requestParameters": {
			"bucketName": "confidential-hr-records",
			"key": "2026_salaries_ssn.pdf",
			"creditCardNumber": "4111-2222-3333-4444"
		},
		"responseElements": {
			"x-amz-request-id": "3D6F506D4E72F19E",
			"secretToken": "super_secret_payload_token"
		},
		"resources": [
			{
				"type": "AWS::S3::Object",
				"arn": "arn:aws:s3:::confidential-hr-records/2026_salaries_ssn.pdf"
			}
		]
	}`

	var event models.CloudTrailRawEvent
	if err := json.Unmarshal([]byte(rawJSON), &event); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	if event.EventSource != "s3.amazonaws.com" {
		t.Errorf("Expected eventSource s3.amazonaws.com, got %s", event.EventSource)
	}
	if event.EventName != "GetObject" {
		t.Errorf("Expected eventName GetObject, got %s", event.EventName)
	}
	if len(event.Resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(event.Resources))
	}

	// Use GetARN() to resolve lowercase "arn" or uppercase "ARN" keys correctly
	expectedARN := "arn:aws:s3:::confidential-hr-records/2026_salaries_ssn.pdf"
	if event.Resources[0].GetARN() != expectedARN {
		t.Errorf("Unexpected resource ARN: %s (expected %s)", event.Resources[0].GetARN(), expectedARN)
	}

	// Verify sensitive request/response payloads and user names are absent
	// from the modelled event. The caller ARN is retained deliberately so
	// live mode can scope events to a role (A2); every other identity field
	// is dropped.
	rawReencoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to re-marshal struct: %v", err)
	}
	reencodedStr := string(rawReencoded)
	if strings.Contains(reencodedStr, "creditCardNumber") || strings.Contains(reencodedStr, "super_secret_payload_token") || strings.Contains(reencodedStr, "accessKeyId") || strings.Contains(reencodedStr, "\"userName\"") {
		t.Errorf("Security Violation: PII or sensitive payload leaked into re-marshaled event struct: %s", reencodedStr)
	}
}

func TestMultiPartitionARNValidation(t *testing.T) {
	validARNs := []string{
		"arn:aws:s3:::my-test-bucket",
		"arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
		"arn:aws-us-gov:s3:::gov-compliance-bucket",
		"arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-1234567890abcdef0",
		"arn:aws-iso:s3:::classified-bucket",
		"arn:aws-iso-b:kms:us-isob-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
	}

	for _, arn := range validARNs {
		if !models.IsValidARN(arn) {
			t.Errorf("Expected valid ARN for %s, got invalid", arn)
		}
	}

	invalidARNs := []string{
		"not-an-arn",
		"arn:azure:compute:123",
		"arn:aws:::incomplete",
		"../../../etc/passwd",
	}

	for _, arn := range invalidARNs {
		if models.IsValidARN(arn) {
			t.Errorf("Expected invalid ARN for %s, got valid", arn)
		}
	}
}

func TestActionNameValidation(t *testing.T) {
	aggregator := NewActionAggregator()
	aggregator.IngestRawEvent(models.CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   `GetObject"; malicious_cmd(); //`,
		Resources: []models.CloudTrailResource{
			{ARN: "arn:aws:s3:::my-bucket/app/*"},
		},
	})

	if got := len(aggregator.Statements()); got != 0 {
		t.Fatalf("malformed action name must not be ingested, got %d statements", got)
	}
	if stats := aggregator.Stats(); stats.Invalid != 1 {
		t.Errorf("Expected 1 invalid event, got %d", stats.Invalid)
	}
}

func TestARNPreservation(t *testing.T) {
	preserved := []string{
		"arn:aws:s3:::bucket/report@2024.pdf",
		"arn:aws:s3:::bucket/report2024.pdf",
		"arn:aws:s3:::bucket/report+final=1,copy.pdf",
		"arn:aws:iam::123456789012:role/App.Role@Corp",
		"arn:aws:s3:::bucket/with space.pdf",
	}

	aggregator := NewActionAggregator()
	for _, arn := range preserved {
		aggregator.IngestRawEvent(models.CloudTrailRawEvent{
			EventSource: "s3.amazonaws.com",
			EventName:   "GetObject",
			Resources:   []models.CloudTrailResource{{ARN: arn}},
		})
	}

	statements := aggregator.Statements()
	if len(statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(statements))
	}

	got := make(map[string]bool, len(statements[0].Resources))
	for _, resource := range statements[0].Resources {
		got[resource] = true
	}

	if len(got) != len(preserved) {
		t.Fatalf("Expected %d distinct resources, got %d: %v", len(preserved), len(got), got)
	}
	for _, want := range preserved {
		if !got[want] {
			t.Errorf("ARN was not preserved byte-for-byte: %q (got %v)", want, got)
		}
	}
}

func TestNormalizeService(t *testing.T) {
	cases := map[string]string{
		"monitoring.amazonaws.com":     "cloudwatch",
		"s3.amazonaws.com":             "s3",
		"dynamodb.amazonaws.com":       "dynamodb",
		"secretsmanager.amazonaws.com": "secretsmanager",
		"kinesis.amazonaws.com":        "kinesis",
	}

	for input, expected := range cases {
		result := NormalizeService(input)
		if result != expected {
			t.Errorf("For %s expected %s, got %s", input, expected, result)
		}
	}

	invalid := []string{"", "s3!evil.amazonaws.com", "../etc/passwd"}
	for _, input := range invalid {
		if result := NormalizeService(input); result != "" {
			t.Errorf("For invalid %q expected empty service, got %q", input, result)
		}
	}
}

func TestActionAggregator(t *testing.T) {
	aggregator := NewActionAggregator()

	// Ingest successful event
	aggregator.IngestRawEvent(models.CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
		Resources: []models.CloudTrailResource{
			{ARN: "arn:aws:s3:::my-bucket/app/*"},
		},
	})

	// Ingest duplicate event
	aggregator.IngestRawEvent(models.CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
		Resources: []models.CloudTrailResource{
			{ARN: "arn:aws:s3:::my-bucket/app/*"},
		},
	})

	// Ingest another action on same resource
	aggregator.IngestRawEvent(models.CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "PutObject",
		Resources: []models.CloudTrailResource{
			{ARN: "arn:aws:s3:::my-bucket/app/*"},
		},
	})

	// Ingest failed error event (should be filtered out by ErrorCode)
	aggregator.IngestRawEvent(models.CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "DeleteBucket",
		ErrorCode:   "AccessDenied",
	})

	if aggregator.TotalUniqueActions() != 2 {
		t.Errorf("Expected 2 unique actions, got %d", aggregator.TotalUniqueActions())
	}

	stmts := aggregator.Statements()
	if len(stmts) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(stmts))
	}
	if len(stmts[0].Actions) != 2 {
		t.Errorf("Expected 2 actions in statement, got %d", len(stmts[0].Actions))
	}
}
