package parser

import (
	"sort"
	"strings"
	"sync"

	"github.com/Pliauga/logzero/pkg/models"
)

var ServicePrefixMap = map[string]string{
	"monitoring.amazonaws.com":           "cloudwatch",
	"logs.amazonaws.com":                 "logs",
	"events.amazonaws.com":               "events",
	"s3.amazonaws.com":                   "s3",
	"dynamodb.amazonaws.com":             "dynamodb",
	"sqs.amazonaws.com":                  "sqs",
	"sns.amazonaws.com":                  "sns",
	"secretsmanager.amazonaws.com":       "secretsmanager",
	"kms.amazonaws.com":                  "kms",
	"sts.amazonaws.com":                  "sts",
	"iam.amazonaws.com":                  "iam",
	"lambda.amazonaws.com":               "lambda",
	"elasticloadbalancing.amazonaws.com": "elasticloadbalancing",
	"ec2.amazonaws.com":                  "ec2",
	"rds.amazonaws.com":                  "rds",
	"ecs.amazonaws.com":                  "ecs",
	"eks.amazonaws.com":                  "eks",
	"ssm.amazonaws.com":                  "ssm",
	"athena.amazonaws.com":               "athena",
	"cloudformation.amazonaws.com":       "cloudformation",
	"cognito-idp.amazonaws.com":          "cognito-idp",
	"apigateway.amazonaws.com":           "apigateway",
	"elasticfilesystem.amazonaws.com":    "elasticfilesystem",
}

func NormalizeService(eventSource string) string {
	cleaned := strings.TrimSpace(strings.ToLower(eventSource))
	if prefix, found := ServicePrefixMap[cleaned]; found {
		return prefix
	}

	parts := strings.Split(cleaned, ".")
	if len(parts) > 0 && models.ServicePrefixRegex.MatchString(parts[0]) {
		return parts[0]
	}

	return ""
}

// Stats reports ingestion and synthesis counters.
type Stats struct {
	Events        int
	Denied        int
	Invalid       int
	WildcardStmts int
}

type ActionAggregator struct {
	mu          sync.RWMutex
	seenKeys    map[string]struct{}
	resourceMap map[string]map[string]struct{}
	stats       Stats
}

func NewActionAggregator() *ActionAggregator {
	return &ActionAggregator{
		seenKeys:    make(map[string]struct{}),
		resourceMap: make(map[string]map[string]struct{}),
	}
}

func (a *ActionAggregator) IngestRawEvent(event models.CloudTrailRawEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stats.Events++

	if event.ErrorCode != "" {
		a.stats.Denied++
		return
	}

	service := NormalizeService(event.EventSource)
	actionName := strings.TrimSpace(event.EventName)
	if service == "" || !models.ActionNameRegex.MatchString(actionName) {
		a.stats.Invalid++
		return
	}

	fullAction := service + ":" + actionName

	var targetARNs []string
	for _, res := range event.Resources {
		trimmedARN := strings.TrimSpace(res.GetARN())
		if trimmedARN != "" && models.IsValidARN(trimmedARN) {
			targetARNs = append(targetARNs, trimmedARN)
		}
	}

	if len(targetARNs) == 0 {
		targetARNs = []string{"*"}
	}

	for _, resARN := range targetARNs {
		key := service + ":" + actionName + ":" + resARN
		if _, exists := a.seenKeys[key]; exists {
			continue
		}
		a.seenKeys[key] = struct{}{}

		if _, exists := a.resourceMap[resARN]; !exists {
			a.resourceMap[resARN] = make(map[string]struct{})
		}
		a.resourceMap[resARN][fullAction] = struct{}{}
	}
}

func (a *ActionAggregator) Statements() []models.IAMStatement {
	a.mu.Lock()
	defer a.mu.Unlock()

	type actionSetKey string
	actionSetToResources := make(map[actionSetKey][]string)

	for resARN, actions := range a.resourceMap {
		var actionList []string
		for act := range actions {
			actionList = append(actionList, act)
		}
		sort.Strings(actionList)
		key := actionSetKey(strings.Join(actionList, ","))
		actionSetToResources[key] = append(actionSetToResources[key], resARN)
	}

	var statements []models.IAMStatement
	for key, resources := range actionSetToResources {
		actionList := strings.Split(string(key), ",")
		sort.Strings(resources)

		statements = append(statements, models.IAMStatement{
			Effect:    "Allow",
			Actions:   actionList,
			Resources: resources,
		})
	}

	sort.Slice(statements, func(i, j int) bool {
		if len(statements[i].Resources) > 0 && len(statements[j].Resources) > 0 {
			if statements[i].Resources[0] == "*" && statements[j].Resources[0] != "*" {
				return true
			}
			if statements[i].Resources[0] != "*" && statements[j].Resources[0] == "*" {
				return false
			}
			return statements[i].Resources[0] < statements[j].Resources[0]
		}
		return false
	})

	wildcards := 0
	for _, stmt := range statements {
		for _, resource := range stmt.Resources {
			if resource == "*" {
				wildcards++
				break
			}
		}
	}
	a.stats.WildcardStmts = wildcards

	return statements
}

// Stats returns a snapshot of the aggregator counters. WildcardStmts is
// populated by the most recent call to Statements.
func (a *ActionAggregator) Stats() Stats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

func (a *ActionAggregator) TotalUniqueActions() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	unique := make(map[string]struct{}, len(a.seenKeys))
	for key := range a.seenKeys {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) >= 2 {
			unique[parts[0]+":"+parts[1]] = struct{}{}
		}
	}
	return len(unique)
}
