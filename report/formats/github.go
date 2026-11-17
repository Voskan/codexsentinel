package formats

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/v2/report"
)

// WriteGitHubReport writes GitHub Actions workflow commands that annotate the
// findings' lines in pull requests: ::error for critical and high, ::warning
// for medium and ::notice for low and info findings.
func WriteGitHubReport(issues []report.Issue, outPath string, _ *report.GitMetadata) error {
	return writeOutput(outPath, []byte(GitHubAnnotations(issues)))
}

// GitHubAnnotations renders issues as workflow commands, one per line.
func GitHubAnnotations(issues []report.Issue) string {
	var b strings.Builder
	for _, is := range sortedIssues(issues) {
		var props []string
		if is.File != "" {
			props = append(props, "file="+escapeProperty(strings.TrimPrefix(is.File, "./")))
			if is.Line > 0 {
				props = append(props, "line="+strconv.Itoa(is.Line))
				if is.Column > 0 {
					props = append(props, "col="+strconv.Itoa(is.Column))
				}
				if is.EndLine >= is.Line {
					props = append(props, "endLine="+strconv.Itoa(is.EndLine))
					if is.EndLine == is.Line && is.EndColumn > is.Column && is.Column > 0 {
						props = append(props, "endColumn="+strconv.Itoa(is.EndColumn))
					}
				}
			}
		}
		props = append(props, "title="+escapeProperty(is.RuleID+": "+is.Title))
		fmt.Fprintf(&b, "::%s %s::%s\n", annotationLevel(is.Severity), strings.Join(props, ","), escapeData(annotationMessage(is)))
	}
	return b.String()
}

func annotationLevel(s report.SeverityLevel) string {
	switch s {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	}
	return "notice"
}

func annotationMessage(is report.Issue) string {
	var b strings.Builder
	b.WriteString(is.Description)
	if b.Len() == 0 {
		b.WriteString(is.Title)
	}
	var tags []string
	for _, t := range []string{string(is.Severity), is.CWE, is.OWASP} {
		if t != "" {
			tags = append(tags, t)
		}
	}
	b.WriteString(" [" + strings.Join(tags, ", ") + "]")
	if is.Suggestion != "" {
		b.WriteString("\nFix: " + is.Suggestion)
	}
	if lines := is.TraceLines(); len(lines) > 0 {
		b.WriteString("\nFlow:\n" + strings.Join(lines, "\n"))
	}
	return b.String()
}

// escapeData escapes a workflow command message.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// escapeProperty escapes a workflow command property value.
func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// maxSummaryIssues bounds the findings listed in a job summary, which GitHub
// limits to 1 MiB per step.
const maxSummaryIssues = 200

// AppendGitHubStepSummary appends a Markdown summary of the scan to path,
// typically $GITHUB_STEP_SUMMARY.
func AppendGitHubStepSummary(issues []report.Issue, path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(GitHubStepSummary(issues))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// GitHubStepSummary renders the Markdown job summary.
func GitHubStepSummary(issues []report.Issue) string {
	s := report.ComputeSummary(issues)
	var b strings.Builder
	b.WriteString("## CodexSentinel\n\n")
	if len(issues) == 0 {
		b.WriteString("**Status:** :white_check_mark: Passed, no issues found.\n\n")
		return b.String()
	}
	fmt.Fprintf(&b, "**Status:** :x: Issues Found (%d)\n\n", len(issues))
	b.WriteString("| Critical | High | Medium | Low | Info |\n| ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d |\n\n", s.Critical, s.High, s.Medium, s.Low, s.Info)
	b.WriteString("| Severity | Rule | Location | Finding |\n| --- | --- | --- | --- |\n")
	sorted := sortedIssues(issues)
	shown := sorted
	if len(shown) > maxSummaryIssues {
		shown = shown[:maxSummaryIssues]
	}
	var traced []report.Issue
	for _, is := range shown {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n", is.Severity, is.RuleID, cell(summaryLocation(is)), cell(is.Title))
		if len(is.Trace) > 0 {
			traced = append(traced, is)
		}
	}
	if len(sorted) > len(shown) {
		fmt.Fprintf(&b, "\n%d more issues are not listed.\n", len(sorted)-len(shown))
	}
	for _, is := range traced {
		fmt.Fprintf(&b, "\n<details><summary>Taint Flow Trace: <code>%s</code> at <code>%s</code></summary>\n\n", htmlEscape(is.RuleID), htmlEscape(summaryLocation(is)))
		for _, line := range is.TraceLines() {
			b.WriteString("- " + cell(line) + "\n")
		}
		b.WriteString("\n</details>\n")
	}
	b.WriteString("\n")
	return b.String()
}

func summaryLocation(is report.Issue) string {
	if is.Line > 0 {
		return is.File + ":" + strconv.Itoa(is.Line)
	}
	return is.File
}

// cell makes text safe inside a Markdown table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "\r", "").Replace(s)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
