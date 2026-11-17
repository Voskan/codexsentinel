package formats

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/report"
)

// WriteAgentReport writes a compact, line-oriented remediation report meant
// to be read by automation: one status line, then one block per finding with
// its exact location, rule and CWE, the reason, the data flow, the fix and,
// when available, the edits that apply it. Output is deterministic: findings
// are sorted by severity, then location.
func WriteAgentReport(issues []report.Issue, outPath string, _ *report.GitMetadata) error {
	return writeOutput(outPath, []byte(AgentReport(issues)))
}

// AgentReport renders issues in the compact remediation format.
func AgentReport(issues []report.Issue) string {
	if len(issues) == 0 {
		return "STATUS: PASS (0 issues)\n"
	}
	sorted := sortedIssues(issues)
	s := report.ComputeSummary(issues)
	var b strings.Builder
	fmt.Fprintf(&b, "STATUS: FAIL (%d issues: critical=%d high=%d medium=%d low=%d info=%d)\n",
		len(issues), s.Critical, s.High, s.Medium, s.Low, s.Info)
	for _, is := range sorted {
		writeAgentIssue(&b, is)
	}
	return b.String()
}

// sortedIssues returns a copy of issues ordered by severity, most severe
// first, then by location and rule.
func sortedIssues(issues []report.Issue) []report.Issue {
	sorted := append([]report.Issue(nil), issues...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
	return sorted
}

func writeAgentIssue(b *strings.Builder, is report.Issue) {
	b.WriteString("---\n")
	fmt.Fprintf(b, "ISSUE [%s] %s", is.Severity, is.RuleID)
	if is.CWE != "" {
		fmt.Fprintf(b, " (%s)", is.CWE)
	}
	fmt.Fprintf(b, " at %s\n", agentLocation(is))
	why := oneLine(is.Description)
	if why == "" {
		why = oneLine(is.Title)
	}
	fmt.Fprintf(b, "WHY: %s\n", why)
	if flow := agentFlow(is.Trace); flow != "" {
		fmt.Fprintf(b, "FLOW: %s\n", flow)
	}
	fix := oneLine(is.Suggestion)
	if is.Fix != nil && is.Fix.Message != "" {
		fix = oneLine(is.Fix.Message)
	}
	if fix != "" {
		fmt.Fprintf(b, "FIX: %s\n", fix)
	}
	if is.Fix != nil {
		for _, e := range is.Fix.Edits {
			fmt.Fprintf(b, "PATCH: %s\n", agentEdit(e, is.File))
		}
	}
}

func agentLocation(is report.Issue) string {
	loc := is.File
	if is.Line <= 0 {
		return loc
	}
	loc += ":" + strconv.Itoa(is.Line)
	if is.Column > 0 {
		loc += ":" + strconv.Itoa(is.Column)
		if is.EndLine > 0 && is.EndColumn > 0 {
			loc += fmt.Sprintf("-%d:%d", is.EndLine, is.EndColumn)
		}
	}
	return loc
}

// agentFlow renders a trace as "file:line (kind: message) -> ...".
func agentFlow(trace []result.TraceStep) string {
	steps := make([]string, 0, len(trace))
	for _, st := range trace {
		loc := st.Location.File
		if st.Location.Line > 0 {
			loc += ":" + strconv.Itoa(st.Location.Line)
		}
		label := st.Kind
		if msg := oneLine(st.Message); msg != "" {
			label += ": " + msg
		}
		if label != "" {
			loc += " (" + label + ")"
		}
		steps = append(steps, loc)
	}
	return strings.Join(steps, " -> ")
}

// agentEdit renders one edit. Replacement text is shown in backquotes when it
// is a single line without backquotes, otherwise as a Go string literal.
func agentEdit(e result.TextEdit, issueFile string) string {
	span := fmt.Sprintf("%d:%d-%d:%d", e.StartLine, e.StartColumn, e.EndLine, e.EndColumn)
	if e.File != "" && e.File != issueFile {
		span = e.File + ":" + span
	}
	text := "`" + e.NewText + "`"
	if strings.ContainsAny(e.NewText, "`\n\r") {
		text = strconv.Quote(e.NewText)
	}
	if e.NewText == "" {
		return "delete " + span
	}
	return "replace " + span + " with " + text
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func severityRank(s report.SeverityLevel) int {
	switch s {
	case report.SeverityCritical:
		return 4
	case report.SeverityHigh:
		return 3
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 1
	}
	return 0
}
