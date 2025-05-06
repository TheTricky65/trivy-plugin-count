package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// New flag for local file
	reportPath := flag.String("report", "", "path to local Trivy JSON report file")
	publishedBefore := flag.String("published-before", "", "take vulnerabilities published before the specified timestamp (ex. 2019-11-04)")
	publishedAfter := flag.String("published-after", "", "take vulnerabilities published after the specified timestamp (ex. 2019-11-04)")
	severityFilter := flag.String("severity", "", "comma-separated list of severity levels (e.g., Critical,High)")

	flag.Parse()

	if *reportPath == "" {
		return fmt.Errorf("report path must be provided using the --report flag")
	}

	// Open the report file
	file, err := os.Open(*reportPath)
	if err != nil {
		return fmt.Errorf("failed to open report file: %w", err)
	}
	defer file.Close()

	var report types.Report
	if err := json.NewDecoder(file).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode JSON report: %w", err)
	}

	// Parse date filters
	var before, after time.Time
	if *publishedBefore != "" {
		before, err = time.Parse("2006-01-02", *publishedBefore)
		if err != nil {
			return fmt.Errorf("invalid --published-before date: %w", err)
		}
	}
	if *publishedAfter != "" {
		after, err = time.Parse("2006-01-02", *publishedAfter)
		if err != nil {
			return fmt.Errorf("invalid --published-after date: %w", err)
		}
	}
// Parse severity filter
var severities map[string]bool
if *severityFilter != "" {
	severities = make(map[string]bool)
	for _, severity := range strings.Split(*severityFilter, ",") {
		upperSeverity := strings.ToUpper(strings.TrimSpace(severity))
		severities[upperSeverity] = true
	}
	//fmt.Printf("Severity filter (normalized): %v\n", severities)
}

// Apply filters and count per severity
counts := make(map[string]int)
totalCount := 0
totalCountSeverities := 0

for _, result := range report.Results {
	for _, vuln := range result.Vulnerabilities {
		if (!before.IsZero() || !after.IsZero()) && vuln.PublishedDate == nil {
			continue
		}
		if (!before.IsZero() && vuln.PublishedDate.After(before)) ||
			(!after.IsZero() && vuln.PublishedDate.Before(after)) {
			continue
		}

		totalCount++
		severity := strings.ToUpper(vuln.Severity)

		if len(severities) > 0 && !severities[severity] {
			continue
		}

		counts[severity]++
		totalCountSeverities++
	}
}


fmt.Println("Vulnerability count by severity:")
for severity := range severities {
	fmt.Printf("  %s: %d\n", severity, counts[severity])
}
fmt.Printf("Total vulnerabilities -  selected severities: %d\n", totalCountSeverities)
fmt.Printf("Total vulnerabilities - all severities: %d\n", totalCount)
return nil
}