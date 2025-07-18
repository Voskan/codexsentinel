package formats

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/Voskan/codexsentinel/report"
	reporttpl "github.com/Voskan/codexsentinel/report/template"
)

// WriteHTMLReport generates a static HTML report from the given issues and writes it to the provided path.
func WriteHTMLReport(issues []report.Issue, outPath string, gitMeta *report.GitMetadata) error {
	summary := computeSummary(issues)

	data := struct {
		Issues      []report.Issue
		Summary     report.Summary
		GeneratedAt string
		Git         *report.GitMetadata
	}{
		Issues:      issues,
		Summary:     summary,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Git:         gitMeta,
	}

	tmpl, err := template.New("report").Parse(reporttpl.HTMLTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse embedded HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render HTML template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return os.WriteFile(outPath, buf.Bytes(), 0644)
}

// computeSummary aggregates issue severity counts.
func computeSummary(issues []report.Issue) report.Summary {
	s := report.Summary{Total: len(issues)}
	for _, i := range issues {
		switch i.Severity {
		case report.SeverityCritical:
			s.Critical++
		case report.SeverityHigh:
			s.High++
		case report.SeverityMedium:
			s.Medium++
		case report.SeverityLow:
			s.Low++
		case report.SeverityInfo:
			s.Info++
		}
	}
	return s
}
