// Package report provides functionality to generate various types of reports.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	reporttpl "github.com/Voskan/codexsentinel/report/template"
)

// SeverityLevel defines the level of issue severity.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityInfo     SeverityLevel = "INFO"
)

// Issue represents a single security/code issue found during analysis.
type Issue struct {
	RuleID      string        `json:"rule_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    SeverityLevel `json:"severity"`
	File        string        `json:"file"`
	Line        int           `json:"line"`
	Code        string        `json:"code"`
	Package     string        `json:"package"`
	Reference   string        `json:"reference,omitempty"`
	Suggestion  string        `json:"suggestion,omitempty"`
}

// Summary aggregates issue counts per severity level.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	// Category counts for charts
	Security int `json:"security"`
	Style    int `json:"style"`
	Metrics  int `json:"metrics"`
	License  int `json:"license"`
}

// ReportData represents the full report structure.
type ReportData struct {
	Summary     Summary `json:"summary"`
	Issues      []Issue `json:"issues"`
	GeneratedAt string  `json:"generated_at"`
}

// GenerateReport creates a report in the specified format (json, html).
func GenerateReport(issues []Issue, format, outPath string) error {
	summary := computeSummary(issues)
	data := ReportData{
		Summary:     summary,
		Issues:      issues,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	switch format {
	case "json":
		return writeJSONReport(data, outPath)
	case "html":
		return writeHTMLReport(data, outPath)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

// computeSummary calculates issue counts by severity.
func computeSummary(issues []Issue) Summary {
	s := Summary{Total: len(issues)}
	for _, i := range issues {
		// Count by severity
		switch i.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
		
		// Count by category (based on rule ID patterns)
		switch {
		case contains(i.RuleID, "sql-injection", "xss", "command-exec", "ssrf", "access-control", "taint"):
			s.Security++
		case contains(i.RuleID, "global-variable", "unused-import", "naming", "style"):
			s.Style++
		case contains(i.RuleID, "complexity", "size", "dead-code", "duplication"):
			s.Metrics++
		case contains(i.RuleID, "license", "dependency"):
			s.License++
		default:
			// Default to security if no specific category matches
			s.Security++
		}
	}
	return s
}

// contains checks if any of the patterns match the rule ID
func contains(ruleID string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(ruleID, pattern) {
			return true
		}
	}
	return false
}

// writeJSONReport serializes report to JSON file.
func writeJSONReport(data ReportData, outPath string) error {
	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create JSON report file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// writeHTMLReport renders report using HTML template.
func writeHTMLReport(data ReportData, outPath string) error {
	tmpl, err := template.New("report").Parse(reporttpl.HTMLTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to render HTML template: %w", err)
	}

	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	return os.WriteFile(outPath, buf.Bytes(), 0644)
}
