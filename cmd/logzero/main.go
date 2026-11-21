package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"time"

	"github.com/Pliauga/logzero/pkg/aws"
	"github.com/Pliauga/logzero/pkg/models"
	"github.com/Pliauga/logzero/pkg/parser"
	"github.com/Pliauga/logzero/pkg/synthesis"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	roleARN    string
	since      string
	timeWindow string
	startTime  string
	endTime    string
	filePath   string
	output     string
	format     string
	blockName  string
	region     string
	profile    string
)

// blockNameRegex is the grammar Terraform requires for an HCL identifier.
var blockNameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// cloudTrailRetention is the period for which LookupEvents serves management
// events; wider windows silently lose data, so they are reported.
const cloudTrailRetention = 90 * 24 * time.Hour

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logzero",
		Short: "Synthesize least-privilege Terraform IAM policies from AWS CloudTrail events",
		Long: `logzero is a zero-egress, client-side CLI tool that observes AWS CloudTrail
API event streams (live or offline fixtures) and generates tightened, least-privilege
Terraform IAM policy documents (data "aws_iam_policy_document").`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runRootCmd,
	}

	cmd.Flags().StringVarP(&roleARN, "role-arn", "r", "", "Target IAM Role ARN to filter CloudTrail events (role names are not accepted)")
	cmd.Flags().StringVarP(&since, "since", "s", "1h", "Lookback duration from now (e.g. 15m, 1h, 24h)")
	cmd.Flags().StringVarP(&timeWindow, "time-window", "w", "", "Alias for --since lookback duration (e.g. 15m, 1h, 24h)")
	cmd.Flags().StringVar(&startTime, "start-time", "", "RFC3339 start timestamp (e.g. 2026-09-05T12:00:00Z)")
	cmd.Flags().StringVar(&endTime, "end-time", "", "RFC3339 end timestamp (e.g. 2026-09-05T13:00:00Z)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to offline CloudTrail JSON fixture/log export file")
	cmd.Flags().StringVarP(&output, "output", "o", "-", "Output file path (use '-' or leave empty for stdout)")
	cmd.Flags().StringVar(&format, "format", "hcl", "Output format: 'hcl' (Terraform) or 'json'")
	cmd.Flags().StringVarP(&blockName, "name", "n", "tightened_policy", "Terraform data block identifier name")
	cmd.Flags().StringVar(&region, "region", "", "AWS Region override")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS Profile to use from credentials chain")

	return cmd
}

// resolveLookbackWindow turns the CLI time flags into a concrete window. It
// rejects non-positive lookbacks and inverted explicit ranges, and reports
// whether the window exceeds CloudTrail's 90-day retention.
func resolveLookbackWindow(now time.Time, startArg, endArg, sinceArg string) (start, end *time.Time, exceedsRetention bool, err error) {
	if startArg != "" {
		t, parseErr := time.Parse(time.RFC3339, startArg)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("invalid --start-time format (must be RFC3339): %w", parseErr)
		}
		start = &t
	} else if sinceArg != "" {
		d, parseErr := time.ParseDuration(sinceArg)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("invalid --since / --time-window duration format: %w", parseErr)
		}
		if d <= 0 {
			return nil, nil, false, fmt.Errorf("invalid --since / --time-window duration %q: must be positive", sinceArg)
		}
		t := now.Add(-d)
		start = &t
	}

	if endArg != "" {
		t, parseErr := time.Parse(time.RFC3339, endArg)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("invalid --end-time format (must be RFC3339): %w", parseErr)
		}
		end = &t
	}

	if start != nil && end != nil && !end.After(*start) {
		return nil, nil, false, fmt.Errorf("invalid time window: end time %s must be after start time %s",
			end.Format(time.RFC3339), start.Format(time.RFC3339))
	}

	if start != nil {
		windowEnd := now
		if end != nil {
			windowEnd = *end
		}
		exceedsRetention = windowEnd.Sub(*start) > cloudTrailRetention
	}

	return start, end, exceedsRetention, nil
}

func runRootCmd(cmd *cobra.Command, args []string) error {
	startTimer := time.Now()

	if !blockNameRegex.MatchString(blockName) {
		return fmt.Errorf("invalid --name %q: must match %s", blockName, blockNameRegex.String())
	}

	aggregator := parser.NewActionAggregator()
	var totalEvents int

	// Support --time-window as alias for --since
	effectiveSince := since
	if timeWindow != "" {
		effectiveSince = timeWindow
	}

	if filePath != "" {
		// Offline Ingestion Mode
		fmt.Fprintf(os.Stderr, "==> Ingesting CloudTrail events from offline fixture: %s\n", filePath)
		count, err := aws.IngestFromFile(filePath, aggregator)
		if err != nil {
			return fmt.Errorf("ingestion failed: %w", err)
		}
		totalEvents = count
	} else {
		// Validate every input before any AWS client is constructed, so
		// malformed flags fail fast instead of after credential resolution.
		if roleARN != "" && !models.IsValidARN(roleARN) {
			return fmt.Errorf("invalid --role-arn %q: expected a role ARN such as arn:aws:iam::123456789012:role/MyRole", roleARN)
		}

		now := time.Now().UTC()
		start, end, exceedsRetention, err := resolveLookbackWindow(now, startTime, endTime, effectiveSince)
		if err != nil {
			return err
		}
		if exceedsRetention {
			fmt.Fprintln(os.Stderr, "WARNING: CloudTrail LookupEvents retains only 90 days of management events; the requested window is longer and older events will be unavailable.")
		}

		ctx := context.Background()
		client, err := aws.NewClient(ctx, region, profile)
		if err != nil {
			return fmt.Errorf("AWS initialization failed: %w", err)
		}

		opts := aws.IngestionOptions{
			RoleARN:   roleARN,
			Region:    region,
			Profile:   profile,
			StartTime: start,
			EndTime:   end,
		}

		fmt.Fprintf(os.Stderr, "==> Querying AWS CloudTrail (window: %v to %v)...\n",
			formatTimePtr(opts.StartTime), formatTimePtr(opts.EndTime))

		count, err := client.IngestEvents(ctx, opts, aggregator)
		if err != nil {
			return fmt.Errorf("AWS CloudTrail query error: %w", err)
		}
		totalEvents = count
	}

	statements := aggregator.Statements()
	stats := aggregator.Stats()
	if stats.WildcardStmts > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d generated statement(s) use \"*\" because no valid resource ARN was observed for those actions; review them before applying.\n", stats.WildcardStmts)
	}

	if len(statements) == 0 {
		return fmt.Errorf("no valid, authorized API actions observed in the specified window")
	}

	var payload []byte
	var err error

	switch format {
	case "json":
		payload, err = synthesis.GenerateJSONPolicy(statements)
	case "hcl":
		payload, err = synthesis.GenerateHCLPolicy(blockName, statements)
	default:
		return fmt.Errorf("unsupported format %q: must be \"hcl\" or \"json\"", format)
	}

	if err != nil {
		return fmt.Errorf("policy synthesis error: %w", err)
	}

	if err := synthesis.WriteOutput(output, payload, os.Stdout); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	elapsed := time.Since(startTimer)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	fmt.Fprintf(os.Stderr, "\n[Summary]\n")
	fmt.Fprintf(os.Stderr, "  • Ingested Events:     %d\n", totalEvents)
	fmt.Fprintf(os.Stderr, "  • Unique Actions:      %d\n", aggregator.TotalUniqueActions())
	fmt.Fprintf(os.Stderr, "  • Synthesized Blocks:  %d\n", len(statements))
	fmt.Fprintf(os.Stderr, "  • Memory (Allocated):  %.2f MB\n", float64(memStats.Alloc)/1024/1024)
	fmt.Fprintf(os.Stderr, "  • Elapsed Time:        %v\n", elapsed)

	return nil
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "unbounded"
	}
	return t.Format(time.RFC3339)
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
