package formats

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Voskan/codexsentinel/report"
)

// WriteJSONReport serializes the provided issues into a pretty JSON format and writes them to a file.
func WriteJSONReport(issues []report.Issue, path string, gitMeta *report.GitMetadata) error {
	// Create full report structure
	summary := computeSummary(issues)
	reportData := report.ReportData{
		Summary:     summary,
		Issues:      issues,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}
	
	if gitMeta != nil {
		reportData.Git = *gitMeta
	}

	data, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report to file: %w", err)
	}

	return nil
}


