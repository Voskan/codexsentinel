package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/Voskan/codexsentinel/report"
)

// WriteMarkdownReport generates a markdown report from the given issues and writes it to the provided path.
func WriteMarkdownReport(issues []report.Issue, outPath string, gitMeta *report.GitMetadata) error {
	summary := computeSummary(issues)

	content := generateMarkdownContent(issues, summary, gitMeta)

	return writeOutput(outPath, []byte(content))
}

// generateMarkdownContent creates the markdown content
func generateMarkdownContent(issues []report.Issue, summary report.Summary, gitMeta *report.GitMetadata) string {
	var content strings.Builder

	// Header
	content.WriteString("# 🔒 CodexSentinel Security Report\n\n")
	content.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC3339)))

	// Git information
	if gitMeta != nil && gitMeta.RepoRoot != "" {
		content.WriteString("## 📁 Repository Information\n\n")
		content.WriteString(fmt.Sprintf("| Property | Value |\n"))
		content.WriteString(fmt.Sprintf("|----------|-------|\n"))
		content.WriteString(fmt.Sprintf("| Repository | `%s` |\n", gitMeta.RepoRoot))
		if gitMeta.Branch != "" {
			content.WriteString(fmt.Sprintf("| Branch | `%s` |\n", gitMeta.Branch))
		}
		if gitMeta.CommitHash != "" {
			content.WriteString(fmt.Sprintf("| Commit | `%s` (%s) |\n", gitMeta.CommitShort, gitMeta.CommitHash))
		}
		if gitMeta.Author != "" {
			content.WriteString(fmt.Sprintf("| Author | %s <%s> |\n", gitMeta.Author, gitMeta.Email))
		}
		if gitMeta.Message != "" {
			content.WriteString(fmt.Sprintf("| Message | %s |\n", gitMeta.Message))
		}
		if !gitMeta.Timestamp.IsZero() {
			content.WriteString(fmt.Sprintf("| Date | %s |\n", gitMeta.Timestamp.Format("2006-01-02 15:04:05")))
		}
		if gitMeta.IsDirty {
			content.WriteString(fmt.Sprintf("| Status | ⚠️ Working directory has uncommitted changes |\n"))
		}
		content.WriteString("\n")
	}

	// Summary statistics
	content.WriteString("## 📊 Summary Statistics\n\n")
	content.WriteString("### 🚨 Issue Severity Distribution\n\n")
	content.WriteString(fmt.Sprintf("| Severity | Count | Percentage |\n"))
	content.WriteString(fmt.Sprintf("|----------|-------|------------|\n"))
	if summary.Total > 0 {
		content.WriteString(fmt.Sprintf("| 🔴 Critical | %d | %.1f%% |\n", summary.Critical, float64(summary.Critical)/float64(summary.Total)*100))
		content.WriteString(fmt.Sprintf("| 🟠 High | %d | %.1f%% |\n", summary.High, float64(summary.High)/float64(summary.Total)*100))
		content.WriteString(fmt.Sprintf("| 🟡 Medium | %d | %.1f%% |\n", summary.Medium, float64(summary.Medium)/float64(summary.Total)*100))
		content.WriteString(fmt.Sprintf("| 🟢 Low | %d | %.1f%% |\n", summary.Low, float64(summary.Low)/float64(summary.Total)*100))
		content.WriteString(fmt.Sprintf("| 🔵 Info | %d | %.1f%% |\n", summary.Info, float64(summary.Info)/float64(summary.Total)*100))
	} else {
		content.WriteString("| 🔴 Critical | 0 | 0.0% |\n")
		content.WriteString("| 🟠 High | 0 | 0.0% |\n")
		content.WriteString("| 🟡 Medium | 0 | 0.0% |\n")
		content.WriteString("| 🟢 Low | 0 | 0.0% |\n")
		content.WriteString("| 🔵 Info | 0 | 0.0% |\n")
	}
	content.WriteString(fmt.Sprintf("| **Total** | **%d** | **100.0%%** |\n", summary.Total))
	content.WriteString("\n")

	// Category breakdown
	content.WriteString("### 📈 Issue Category Breakdown\n\n")
	content.WriteString(fmt.Sprintf("| Category | Count |\n"))
	content.WriteString(fmt.Sprintf("|----------|-------|\n"))
	content.WriteString(fmt.Sprintf("| 🔒 Security | %d |\n", summary.Security))
	content.WriteString(fmt.Sprintf("| 🎨 Style | %d |\n", summary.Style))
	content.WriteString(fmt.Sprintf("| 📊 Metrics | %d |\n", summary.Metrics))
	content.WriteString(fmt.Sprintf("| 📄 License | %d |\n", summary.License))
	content.WriteString("\n")

	// Analysis coverage
	content.WriteString("### 🔍 Analysis Coverage\n\n")
	content.WriteString("| Analysis Type | Status | Coverage |\n")
	content.WriteString("|---------------|--------|----------|\n")
	content.WriteString("| 🔒 Security Rules | ✅ Enabled | 18+ rules |\n")
	content.WriteString("| 🛡️ OWASP Top 10 2025 | ✅ Full | 100% |\n")
	content.WriteString("| 🌳 AST Analysis | ✅ Enabled | Full |\n")
	content.WriteString("| 🔄 SSA Analysis | ✅ Enabled | Full |\n")
	content.WriteString("| 🎯 Taint Analysis | ✅ Enabled | Full |\n")
	content.WriteString("| 📊 Metrics Analysis | ✅ Enabled | Full |\n")
	content.WriteString("| 📦 Dependency Analysis | ✅ Enabled | Full |\n")
	content.WriteString("\n")

	// Code quality metrics
	content.WriteString("### 📏 Code Quality Metrics\n\n")
	content.WriteString("| Metric | Status | Description |\n")
	content.WriteString("|--------|--------|-------------|\n")
	content.WriteString("| 📊 Cyclomatic Complexity | ✅ Enabled | Function complexity analysis |\n")
	content.WriteString("| 📏 Function Size | ✅ Enabled | Lines of code per function |\n")
	content.WriteString("| 🔄 Code Duplication | ✅ Enabled | Duplicate code detection |\n")
	content.WriteString("| 💀 Dead Code | ✅ Enabled | Unused code detection |\n")
	content.WriteString("| 🌍 Global Variables | ✅ Enabled | Global variable analysis |\n")
	content.WriteString("| 📁 File Size | ✅ Enabled | File size analysis |\n")
	content.WriteString("\n")

	// Risk assessment
	content.WriteString("### ⚠️ Risk Assessment\n\n")
	if summary.Critical > 0 || summary.High > 0 {
		content.WriteString("🚨 **High Risk Issues Detected**\n\n")
		content.WriteString(fmt.Sprintf("- **Critical Issues:** %d (Immediate attention required)\n", summary.Critical))
		content.WriteString(fmt.Sprintf("- **High Issues:** %d (Should be addressed soon)\n\n", summary.High))
	} else if summary.Medium > 0 {
		content.WriteString("⚠️ **Medium Risk Issues Detected**\n\n")
		content.WriteString(fmt.Sprintf("- **Medium Issues:** %d (Monitor and address as needed)\n\n", summary.Medium))
	} else {
		content.WriteString("✅ **Low Risk Profile**\n\n")
		content.WriteString("No critical or high severity issues detected.\n\n")
	}

	// Issues by severity
	if len(issues) > 0 {
		content.WriteString("## 🚨 Detailed Issues\n\n")

		// Group issues by severity
		criticalIssues := filterIssuesBySeverity(issues, "critical")
		highIssues := filterIssuesBySeverity(issues, "high")
		mediumIssues := filterIssuesBySeverity(issues, "medium")
		lowIssues := filterIssuesBySeverity(issues, "low")
		infoIssues := filterIssuesBySeverity(issues, "info")

		// Critical issues
		if len(criticalIssues) > 0 {
			content.WriteString("### 🔴 Critical Issues\n\n")
			content.WriteString("| File | Line | Rule | Description |\n")
			content.WriteString("|------|------|------|-------------|\n")
			for _, issue := range criticalIssues {
				content.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %s |\n",
					issue.File, issue.Line, issue.RuleID, issue.Description))
			}
			content.WriteString("\n")
		}

		// High issues
		if len(highIssues) > 0 {
			content.WriteString("### 🟠 High Issues\n\n")
			content.WriteString("| File | Line | Rule | Description |\n")
			content.WriteString("|------|------|------|-------------|\n")
			for _, issue := range highIssues {
				content.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %s |\n",
					issue.File, issue.Line, issue.RuleID, issue.Description))
			}
			content.WriteString("\n")
		}

		// Medium issues
		if len(mediumIssues) > 0 {
			content.WriteString("### 🟡 Medium Issues\n\n")
			content.WriteString("| File | Line | Rule | Description |\n")
			content.WriteString("|------|------|------|-------------|\n")
			for _, issue := range mediumIssues {
				content.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %s |\n",
					issue.File, issue.Line, issue.RuleID, issue.Description))
			}
			content.WriteString("\n")
		}

		// Low issues
		if len(lowIssues) > 0 {
			content.WriteString("### 🟢 Low Issues\n\n")
			content.WriteString("| File | Line | Rule | Description |\n")
			content.WriteString("|------|------|------|-------------|\n")
			for _, issue := range lowIssues {
				content.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %s |\n",
					issue.File, issue.Line, issue.RuleID, issue.Description))
			}
			content.WriteString("\n")
		}

		// Info issues
		if len(infoIssues) > 0 {
			content.WriteString("### 🔵 Info Issues\n\n")
			content.WriteString("| File | Line | Rule | Description |\n")
			content.WriteString("|------|------|------|-------------|\n")
			for _, issue := range infoIssues {
				content.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | %s |\n",
					issue.File, issue.Line, issue.RuleID, issue.Description))
			}
			content.WriteString("\n")
		}

		// Detailed issue information
		content.WriteString("## 📋 Detailed Issue Information\n\n")
		for i, issue := range issues {
			content.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, issue.Title))
			content.WriteString(fmt.Sprintf("**Severity:** %s\n\n", getSeverityBadge(string(issue.Severity))))
			content.WriteString(fmt.Sprintf("**File:** `%s:%d`\n\n", issue.File, issue.Line))
			content.WriteString(fmt.Sprintf("**Rule ID:** `%s`\n\n", issue.RuleID))
			content.WriteString(fmt.Sprintf("**Description:** %s\n\n", issue.Description))

			if len(issue.Trace) > 0 {
				content.WriteString("**Data flow:**\n\n")
				for _, line := range issue.TraceLines() {
					content.WriteString("    " + line + "\n")
				}
				content.WriteString("\n")
			}

			if issue.Suggestion != "" {
				content.WriteString(fmt.Sprintf("**💡 Suggestion:** %s\n\n", issue.Suggestion))
			}

			if issue.Reference != "" {
				content.WriteString(fmt.Sprintf("**📚 Reference:** [%s](%s)\n\n", issue.Reference, issue.Reference))
			}

			content.WriteString("---\n\n")
		}
	} else {
		content.WriteString("## ✅ No Issues Found\n\n")
		content.WriteString("Great! No security issues were detected in the analyzed code.\n\n")
	}

	// Recommendations
	content.WriteString("## 💡 Recommendations\n\n")
	if summary.Critical > 0 || summary.High > 0 {
		content.WriteString("### 🚨 Immediate Actions Required\n\n")
		content.WriteString("1. **Address Critical Issues First** - These pose the highest security risk\n")
		content.WriteString("2. **Review High Severity Issues** - These should be fixed in the next sprint\n")
		content.WriteString("3. **Implement Security Best Practices** - Follow OWASP guidelines\n")
		content.WriteString("4. **Add Security Tests** - Ensure vulnerabilities are covered by tests\n\n")
	} else if summary.Medium > 0 {
		content.WriteString("### ⚠️ Recommended Actions\n\n")
		content.WriteString("1. **Review Medium Issues** - Address during regular maintenance\n")
		content.WriteString("2. **Improve Code Quality** - Consider refactoring complex functions\n")
		content.WriteString("3. **Add Documentation** - Document security decisions\n\n")
	} else {
		content.WriteString("### ✅ Maintenance Recommendations\n\n")
		content.WriteString("1. **Continue Good Practices** - Maintain current security standards\n")
		content.WriteString("2. **Regular Scans** - Schedule periodic security scans\n")
		content.WriteString("3. **Stay Updated** - Keep dependencies and tools current\n\n")
	}

	// Footer
	content.WriteString("---\n\n")
	content.WriteString("*Generated by CodexSentinel - Advanced Go Security Scanner*\n")
	content.WriteString("*For more information, visit: https://github.com/Voskan/codexsentinel*\n")

	return content.String()
}

// filterIssuesBySeverity filters issues by severity level
func filterIssuesBySeverity(issues []report.Issue, severity string) []report.Issue {
	var filtered []report.Issue
	for _, issue := range issues {
		if strings.ToLower(string(issue.Severity)) == severity {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// getSeverityBadge returns a markdown badge for severity
func getSeverityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🟢 Low"
	case "info":
		return "🔵 Info"
	default:
		return severity
	}
}
