package formats

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/Voskan/codexsentinel/report"
	reporttpl "github.com/Voskan/codexsentinel/report/template"
)

// htmlBar is one row of a bar chart in the report.
type htmlBar struct {
	Label   string
	Class   string
	Count   int
	Percent int
}

// htmlIssue is a finding prepared for the template.
type htmlIssue struct {
	report.Issue
	Class      string
	Location   string
	Confidence string
	Reach      string
	DocURL     string
	Patch      []string
}

// htmlView is the data the HTML template renders.
type htmlView struct {
	GeneratedAt string
	Git         *report.GitMetadata
	Summary     report.Summary
	Severities  []htmlBar
	Categories  []htmlBar
	Issues      []htmlIssue
}

// WriteHTMLReport writes a self-contained HTML report: styles and the small
// filter script are inline and nothing is loaded from the network, so the
// report opens offline and in restricted CI environments.
func WriteHTMLReport(issues []report.Issue, outPath string, gitMeta *report.GitMetadata) error {
	if gitMeta == nil {
		gitMeta = &report.GitMetadata{}
	}
	view := buildHTMLView(issues, gitMeta, time.Now())

	tmpl, err := template.New("report").Parse(reporttpl.HTMLTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse embedded HTML template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return fmt.Errorf("failed to render HTML template: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	return os.WriteFile(outPath, buf.Bytes(), 0o644)
}

func buildHTMLView(issues []report.Issue, gitMeta *report.GitMetadata, now time.Time) htmlView {
	summary := report.ComputeSummary(issues)
	view := htmlView{GeneratedAt: now.Format(time.RFC3339), Git: gitMeta, Summary: summary}

	for _, s := range []struct {
		label string
		count int
	}{{"Critical", summary.Critical}, {"High", summary.High}, {"Medium", summary.Medium}, {"Low", summary.Low}, {"Info", summary.Info}} {
		view.Severities = append(view.Severities, htmlBar{s.label, strings.ToLower(s.label), s.count, percent(s.count, summary.Total)})
	}

	byCategory := map[string]int{}
	for _, is := range issues {
		category := is.Category
		if category == "" {
			category = "other"
		}
		byCategory[category]++
	}
	for category, count := range byCategory {
		view.Categories = append(view.Categories, htmlBar{category, "category", count, percent(count, summary.Total)})
	}
	sort.Slice(view.Categories, func(i, j int) bool {
		a, b := view.Categories[i], view.Categories[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Label < b.Label
	})

	for _, is := range sortedIssues(issues) {
		item := htmlIssue{Issue: is, Class: strings.ToLower(string(is.Severity)), Location: agentLocation(is)}
		if is.Confidence > 0 {
			item.Confidence = strconv.Itoa(int(is.Confidence*100+0.5)) + "%"
		}
		if is.Reachable != nil {
			item.Reach = "not reachable from the program"
			if *is.Reachable {
				item.Reach = "reachable from the program"
			}
		}
		if _, ok := catalog.Lookup(is.RuleID); ok {
			item.DocURL = catalog.DocURL(is.RuleID)
		}
		if is.Fix != nil {
			for _, e := range is.Fix.Edits {
				item.Patch = append(item.Patch, agentEdit(e, is.File))
			}
		}
		view.Issues = append(view.Issues, item)
	}
	return view
}

func percent(n, total int) int {
	if total == 0 {
		return 0
	}
	return (n*100 + total/2) / total
}
