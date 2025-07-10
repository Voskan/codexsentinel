package formats

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Voskan/codexsentinel/report"
)

// WriteMarkdownReport generates a Markdown (.md) report from issues and writes it to a file.
func WriteMarkdownReport(issues []report.Issue, path string) error {
	var b strings.Builder

	timestamp := time.Now().Format(time.RFC3339)
	b.WriteString("# 🛡️ CodexSentinel Report\n\n")
	b.WriteString(fmt.Sprintf("_Generated at: %s_\n\n", timestamp))
	b.WriteString(fmt.Sprintf("**Total Issues:** %d\n\n", len(issues)))

	for _, issue := range issues {
		b.WriteString("## ❗ ")
		b.WriteString(fmt.Sprintf("[%s] %s\n\n", issue.Severity, issue.Title))
		b.WriteString(fmt.Sprintf("- **Rule ID:** `%s`\n", issue.RuleID))
		b.WriteString(fmt.Sprintf("- **File:** `%s:%d`\n", issue.File, issue.Line))
		b.WriteString(fmt.Sprintf("- **Package:** `%s`\n", issue.Package))
		b.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", issue.Severity))
		if issue.Reference != "" {
			b.WriteString(fmt.Sprintf("- **Reference:** [%s](%s)\n", issue.Reference, issue.Reference))
		}
		if issue.Suggestion != "" {
			b.WriteString(fmt.Sprintf("- **Suggestion:** _%s_\n", issue.Suggestion))
		}
		b.WriteString("\n**Code:**\n")
		b.WriteString("```go\n")
		b.WriteString(issue.Code)
		b.WriteString("\n```\n\n")
		b.WriteString(fmt.Sprintf("_%s_\n\n---\n\n", issue.Description))
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}
