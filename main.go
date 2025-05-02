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
	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return err
	}

	publishedBefore := flag.String("published-before", "", "take vulnerabilities published before the specified timestamp (ex. 2019-11-04)")
	publishedAfter := flag.String("published-after", "", "take vulnerabilities published after the specified timestamp (ex. 2019-11-04)")
	severityFilter := flag.String("severity", "", "comma-separated list of severity levels (e.g., Critical,High)")

	flag.Parse()

	var before, after time.Time
	var err error
	if *publishedBefore != "" {
		before, err = time.Parse("2006-01-02", *publishedBefore)
		if err != nil {
			return err
		}
	}
	if *publishedAfter != "" {
		after, err = time.Parse("2006-01-02", *publishedAfter)
		if err != nil {
			return err
		}
	}

	var severities map[string]bool
	if *severityFilter != "" {
		severities = make(map[string]bool)
		for _, severity := range strings.Split(*severityFilter, ",") {
			severities[strings.TrimSpace(severity)] = true
		}
	}

	var count int
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if (!before.IsZero() || !after.IsZero()) && vuln.PublishedDate == nil {
				continue
			}
			if (!before.IsZero() && vuln.PublishedDate.After(before)) ||
				(!after.IsZero() && vuln.PublishedDate.Before(after)) {
				continue
			}
			if len(severities) > 0 && !severities[vuln.Severity] {
				continue
			}
			count++
		}
	}

	fmt.Printf("Number of vulnerabilities: %d\n", count)
	return nil
}
