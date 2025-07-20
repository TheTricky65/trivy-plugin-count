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
	// Decode report from stdin
	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode report from stdin: %w", err)
	}

	// Flags
	publishedBefore := flag.String("published-before", "", "take vulnerabilities published before the specified timestamp (ex. 2019-11-04)")
	publishedAfter := flag.String("published-after", "", "take vulnerabilities published after the specified timestamp (ex. 2019-11-04)")
	severityFilter := flag.String("severity-plugin", "", "comma-separated list of severity levels (e.g., Critical,High)")
	flag.Parse()

	// Parse dates
	var before, after time.Time
	var err error
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

	// Parse and normalize severity filter
	var severityFilterMap map[string]bool
	if *severityFilter != "" {
		severityFilterMap = make(map[string]bool)
		for _, s := range strings.Split(*severityFilter, ",") {
			normalized := strings.ToUpper(strings.TrimSpace(s))
			if normalized != "" {
				severityFilterMap[normalized] = true
			}
		}
	}

	// Count severities
	counts := make(map[string]int)
	total := 0
	filteredSeverityTotal := 0
	publishedBeforeCount := 0
	publishedAfterCount := 0

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {

			if (!before.IsZero() || !after.IsZero()) && vuln.PublishedDate == nil {
				continue
			}
			if !before.IsZero() && vuln.PublishedDate.After(before) {
				continue
			}
			if !after.IsZero() && vuln.PublishedDate.Before(after) {
				continue
			}

			total++

			// Count for before/after filters individually
			if !before.IsZero() && vuln.PublishedDate != nil && vuln.PublishedDate.Before(before) {
				publishedBeforeCount++
			}
			if !after.IsZero() && vuln.PublishedDate != nil && vuln.PublishedDate.After(after) {
				publishedAfterCount++
			}

			severity := strings.ToUpper(strings.TrimSpace(vuln.Severity))
			if severity == "" {
				severity = "UNKNOWN"
			}

			counts[severity]++

			if severityFilterMap != nil && severityFilterMap[severity] {
				filteredSeverityTotal++
			}
		}
	}

	// === OUTPUT FORMATTING ===

	if severityFilterMap != nil {
		for severity := range severityFilterMap {
			fmt.Printf(`Number of "%s" vulnerabilities: %d`+"\n", severity, counts[severity])
		}
	}

	if *publishedAfter != "" {
		fmt.Printf(`Number of vulns published after "%s": %d`+"\n", *publishedAfter, publishedAfterCount)
	}

	if *publishedBefore != "" {
		fmt.Printf(`Number of vulns published before "%s": %d`+"\n", *publishedBefore, publishedBeforeCount)
	}

	if *publishedAfter == "" && *publishedBefore == "" && severityFilterMap == nil {
		fmt.Printf("Number of total vulnerabilities: %d\n", total)
	}

	return nil
}
