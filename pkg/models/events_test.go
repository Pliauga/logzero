package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestIsValidARN(t *testing.T) {
	valid := []string{
		"arn:aws:s3:::my-bucket",
		"arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
		"arn:aws-us-gov:s3:::gov-compliance-bucket",
		"arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-1234567890abcdef0",
		"arn:aws-iso:s3:::classified-bucket",
		"arn:aws-iso-b:kms:us-isob-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		"arn:aws:iam::*:role/AnyRole",
		"arn:aws:s3:::bucket/report@2024.pdf",
		"arn:aws:s3:::bucket/report+final=1,copy.pdf",
		"arn:aws:iam::123456789012:role/App.Role@Corp",
		"arn:aws:s3:::bucket/with space.pdf",
	}

	for _, arn := range valid {
		if !IsValidARN(arn) {
			t.Errorf("IsValidARN(%q) = false, want true", arn)
		}
	}

	invalid := []string{
		"",
		"not-an-arn",
		"arn:azure:compute:123",
		"ARN:aws:s3:::upper-case-prefix",
		" arn:aws:s3:::leading-space",
		"arn:aws:s3:::",
		"arn:aws:s3",
		"../../etc/passwd",
	}

	for _, arn := range invalid {
		if IsValidARN(arn) {
			t.Errorf("IsValidARN(%q) = true, want false", arn)
		}
	}
}

func TestGetARNPriority(t *testing.T) {
	tests := []struct {
		name     string
		resource CloudTrailResource
		want     string
	}{
		{
			name:     "upper-case ARN wins",
			resource: CloudTrailResource{ARN: "arn:aws:s3:::upper", ARNLower: "arn:aws:s3:::lower"},
			want:     "arn:aws:s3:::upper",
		},
		{
			name:     "lower-case fallback",
			resource: CloudTrailResource{ARNLower: "arn:aws:s3:::lower"},
			want:     "arn:aws:s3:::lower",
		},
		{
			name:     "empty resource",
			resource: CloudTrailResource{},
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.resource.GetARN(); got != tc.want {
				t.Errorf("GetARN() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCloudTrailRawEventJSONRoundTrip(t *testing.T) {
	original := CloudTrailRawEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
		ErrorCode:   "AccessDenied",
		UserIdentity: &CloudTrailUserIdentity{
			Type: "AssumedRole",
			ARN:  "arn:aws:sts::123456789012:assumed-role/AppRole/session-1",
			SessionContext: &CloudTrailSessionContext{
				SessionIssuer: &CloudTrailSessionIssuer{
					Type: "Role",
					ARN:  "arn:aws:iam::123456789012:role/AppRole",
				},
			},
		},
		Resources: []CloudTrailResource{
			{ARN: "arn:aws:s3:::bucket/key", Type: "AWS::S3::Object"},
			{ARNLower: "arn:aws:s3:::lower-key", TypeLower: "AWS::S3::Object"},
		},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	for _, key := range []string{"eventSource", "eventName", "errorCode", "userIdentity", "sessionIssuer", "resources", "ARN", "arn"} {
		if !strings.Contains(string(encoded), `"`+key+`"`) {
			t.Errorf("encoded event is missing JSON key %q: %s", key, encoded)
		}
	}

	var decoded CloudTrailRawEvent
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("round trip mismatch:\n original = %+v\n decoded  = %+v", original, decoded)
	}
}

// TestSanitizeString documents the deprecated legacy rewrite. The function is
// retained only for API compatibility and must not be used on event data.
func TestSanitizeString(t *testing.T) {
	if got := SanitizeString("report@2024.pdf"); got != "report2024.pdf" {
		t.Errorf("legacy SanitizeString(%q) = %q, want %q", "report@2024.pdf", got, "report2024.pdf")
	}
	if got := SanitizeString("no-special_chars.json"); got != "no-special_chars.json" {
		t.Errorf("legacy SanitizeString(%q) = %q, want unchanged", "no-special_chars.json", got)
	}
}
