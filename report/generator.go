// Package report provides functionality to generate various types of reports.
package report

import (
	"time"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
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
	EndLine     int                  `json:"end_line,omitempty"`
	EndColumn   int                  `json:"end_column,omitempty"`
	Confidence  float64              `json:"confidence,omitempty"`
	CWE         string               `json:"cwe,omitempty"`
	OWASP       string               `json:"owasp,omitempty"`
	Trace       []result.TraceStep   `json:"trace,omitempty"`
	Fix         *result.SuggestedFix `json:"fix,omitempty"`
	Fingerprint string               `json:"fingerprint,omitempty"`
	Reachable   *bool                `json:"reachable,omitempty"`
	RuleID      string               `json:"rule_id"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Severity    SeverityLevel        `json:"severity"`
	File        string               `json:"file"`
	Column      int                  `json:"column,omitempty"`
	Category    string               `json:"category"`
	References  []string             `json:"references,omitempty"`
	Line        int                  `json:"line"`
	Code        string               `json:"code"`
	Package     string               `json:"package"`
	Reference   string               `json:"reference,omitempty"`
	Suggestion  string               `json:"suggestion,omitempty"`
}

// Summary aggregates issue counts per severity level.
type Summary struct {
	Architecture int `json:"architecture"`
	SupplyChain  int `json:"supply_chain"`
	Total        int `json:"total"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Info         int `json:"info"`
	// Category counts for charts
	Security    int `json:"security"`
	Reliability int `json:"reliability"`
	Style       int `json:"style"`
	Metrics     int `json:"metrics"`
	License     int `json:"license"`
	Correctness int `json:"correctness"`
	Suppression int `json:"suppression"`
}

// GitMetadata represents Git repository information.
type GitMetadata struct {
	RepoRoot    string    `json:"repo_root,omitempty"`
	Branch      string    `json:"branch,omitempty"`
	CommitHash  string    `json:"commit_hash,omitempty"`
	CommitShort string    `json:"commit_short,omitempty"`
	Author      string    `json:"author,omitempty"`
	Email       string    `json:"email,omitempty"`
	Message     string    `json:"message,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"`
	IsDirty     bool      `json:"is_dirty,omitempty"`
}

// ReportData represents the full report structure.
type ReportData struct {
	Summary     Summary     `json:"summary"`
	Issues      []Issue     `json:"issues"`
	GeneratedAt string      `json:"generated_at"`
	Git         GitMetadata `json:"git,omitempty"`
}

// ComputeSummary counts findings by severity and explicit category.
func ComputeSummary(issues []Issue) Summary {
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

		switch i.Category {
		case "security":
			s.Security++
		case "reliability":
			s.Reliability++
		case "style":
			s.Style++
		case "metrics":
			s.Metrics++
		case "license":
			s.License++
		case "architecture":
			s.Architecture++
		case "supply-chain":
			s.SupplyChain++
		case "correctness":
			s.Correctness++
		case "suppression":
			s.Suppression++
		}
	}
	return s
}

// FromResults converts analysis findings into report issues.
func FromResults(results []result.Issue) []Issue {
	out := make([]Issue, len(results))
	for i, issue := range results {
		out[i] = Issue{
			RuleID:      issue.ID,
			Title:       issue.Title,
			Description: issue.Description,
			Severity:    SeverityLevel(issue.Severity.String()),
			File:        issue.Location.File,
			Line:        issue.Location.Line,
			Column:      issue.Location.Column,
			EndLine:     issue.Location.EndLine,
			EndColumn:   issue.Location.EndColumn,
			Category:    issue.Category,
			Package:     issue.Location.PackagePath,
			References:  issue.References,
			Suggestion:  issue.Suggestion,
			Confidence:  issue.Confidence,
			CWE:         issue.CWE,
			OWASP:       issue.OWASP,
			Trace:       issue.Trace,
			Fix:         issue.Fix,
			Fingerprint: issue.Fingerprint,
			Reachable:   issue.Reachable,
		}
		if len(issue.References) > 0 {
			out[i].Reference = issue.References[0]
		}
	}
	return out
}
