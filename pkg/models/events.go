package models

import "regexp"

type CloudTrailResource struct {
	ARN       string `json:"ARN"`
	Type      string `json:"resourceType"`
	ARNLower  string `json:"arn,omitempty"`
	TypeLower string `json:"type,omitempty"`
}

func (r CloudTrailResource) GetARN() string {
	if r.ARN != "" {
		return r.ARN
	}
	return r.ARNLower
}

type CloudTrailSessionIssuer struct {
	Type string `json:"type,omitempty"`
	ARN  string `json:"arn,omitempty"`
}

type CloudTrailSessionContext struct {
	SessionIssuer *CloudTrailSessionIssuer `json:"sessionIssuer,omitempty"`
}

// CloudTrailUserIdentity intentionally keeps only the fields needed to decide
// whether an event was issued by a given role. User names, account IDs,
// access keys, and request parameters are never modelled, so they cannot
// reach a generated policy.
type CloudTrailUserIdentity struct {
	Type           string                    `json:"type,omitempty"`
	ARN            string                    `json:"arn,omitempty"`
	SessionContext *CloudTrailSessionContext `json:"sessionContext,omitempty"`
}

type CloudTrailRawEvent struct {
	EventSource  string                  `json:"eventSource"`
	EventName    string                  `json:"eventName"`
	ErrorCode    string                  `json:"errorCode,omitempty"`
	UserIdentity *CloudTrailUserIdentity `json:"userIdentity,omitempty"`
	Resources    []CloudTrailResource    `json:"resources,omitempty"`
}

type IAMStatement struct {
	Effect    string   `json:"Effect"`
	Actions   []string `json:"Action"`
	Resources []string `json:"Resource"`
}

type IAMPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []IAMStatement `json:"Statement"`
}

// ARNRegex handles commercial, GovCloud, China, and ISO partitions with optional account IDs for S3/global resources
var ARNRegex = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_]*:([0-9]{12}|\*)?:.+`)

// ActionNameRegex matches CloudTrail API action names, which consist of
// letters and digits only.
var ActionNameRegex = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// ServicePrefixRegex matches normalized AWS service prefixes.
var ServicePrefixRegex = regexp.MustCompile(`^[a-z0-9-]+$`)

// SafeStringRegex is retained only for backwards compatibility.
//
// Deprecated: SafeStringRegex deletes characters (@, +, =, ,, spaces) that are
// legal in IAM role names and S3 object keys, so applying it to CloudTrail
// data corrupts otherwise valid ARNs.
var SafeStringRegex = regexp.MustCompile(`[^a-zA-Z0-9:*_\-./]`)

// SanitizeString is retained only for backwards compatibility.
//
// Deprecated: SanitizeString is a non-injective rewrite: it silently merges
// distinct identifiers (for example report@2024.pdf and report2024.pdf).
// Validate with IsValidARN, ActionNameRegex and ServicePrefixRegex instead.
func SanitizeString(input string) string {
	return SafeStringRegex.ReplaceAllString(input, "")
}

func IsValidARN(arn string) bool {
	return ARNRegex.MatchString(arn)
}
