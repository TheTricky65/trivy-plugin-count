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
	} else {
		severityFilterMap = nil
	}


	// Count severities
	counts := make(map[string]int)
	countTotalfiltered := 0
	total := 0 


	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {

			//total ++	
			if (!before.IsZero() || !after.IsZero()) && vuln.PublishedDate == nil {
				continue
			}
			if (!before.IsZero() && vuln.PublishedDate.After(before)) ||
				(!after.IsZero() && vuln.PublishedDate.Before(after)) {
				continue
			}
			total ++
			severity := strings.ToUpper(strings.TrimSpace(vuln.Severity))
			if severity == "" {
				severity = "UNKNOWN"
			}

			counts[severity]++
		
		}
	}

	// Print all severities
	///fmt.Println("\nVulnerability count by severity:")
	///for severity, count := range counts {
	///	fmt.Printf("  %s: %d\n", severity, count)
	//}

	// Print selected severities (if filtered)
	if severityFilterMap != nil {
		fmt.Println("\nFiltered severities (selected via --severity-plugin):")
		for severity := range severityFilterMap {
			fmt.Printf("  %s: %d\n", severity, counts[severity])
			countTotalfiltered += counts[severity]
		}
	}

	fmt.Printf("Number of vulnerabilities for selected severities: %d\n", countTotalfiltered)
	fmt.Printf("Number of total vulnerabilities: %d\n", total)


	return nil
}
