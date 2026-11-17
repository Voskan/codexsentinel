package formats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/report"
)

func ciIssues() []report.Issue {
	return []report.Issue{
		{RuleID: "weak-hash", Title: "Weak Hash", Severity: report.SeverityLow, File: "a.go", Line: 3, Description: "MD5 is broken."},
		{
			RuleID: "sql-injection", Title: "SQL Injection", Severity: report.SeverityCritical, CWE: "CWE-89", File: "./repo/user.go",
			Line: 42, Column: 15, EndLine: 42, EndColumn: 68, Description: "Query built from input,\nreached 100% of the time.",
			Suggestion: "Use placeholders.", Category: "security",
			Trace: []result.TraceStep{{Kind: "source", Message: "FormValue", Location: result.Location{File: "h.go", Line: 7}}},
		},
		{RuleID: "http-client-unsafe", Title: "Unsafe HTTP Client", Severity: report.SeverityMedium, File: "b.go", Line: 9, Category: "security"},
	}
}

func TestGitHubAnnotations(t *testing.T) {
	lines := strings.Split(strings.TrimSuffix(GitHubAnnotations(ciIssues()), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %q", lines)
	}
	want0 := "::error file=repo/user.go,line=42,col=15,endLine=42,endColumn=68,title=sql-injection%3A SQL Injection::" +
		"Query built from input,%0Areached 100%25 of the time. [CRITICAL, CWE-89]%0AFix: Use placeholders.%0AFlow:%0A1. [source] h.go:7 FormValue"
	if lines[0] != want0 {
		t.Errorf("error annotation:\n got %s\nwant %s", lines[0], want0)
	}
	if !strings.HasPrefix(lines[1], "::warning file=b.go,line=9,title=http-client-unsafe%3A Unsafe HTTP Client::") {
		t.Errorf("warning annotation: %s", lines[1])
	}
	if !strings.HasPrefix(lines[2], "::notice file=a.go,line=3,title=weak-hash%3A Weak Hash::MD5 is broken.") {
		t.Errorf("notice annotation: %s", lines[2])
	}
	if got := escapeProperty("a,b:c%\n"); got != "a%2Cb%3Ac%25%0A" {
		t.Errorf("escapeProperty = %q", got)
	}
	if GitHubAnnotations(nil) != "" {
		t.Error("annotations for no issues")
	}
}

func TestGitHubStepSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	if err := os.WriteFile(path, []byte("previous step\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendGitHubStepSummary(ciIssues(), path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"previous step\n## CodexSentinel",
		"Issues Found (3)",
		"| 1 | 0 | 1 | 1 | 0 |",
		"| CRITICAL | `sql-injection` | `./repo/user.go:42` | SQL Injection |",
		"<details><summary>Taint Flow Trace: <code>sql-injection</code>",
		"- 1. [source] h.go:7 FormValue",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
	if pass := GitHubStepSummary(nil); !strings.Contains(pass, "Passed") {
		t.Errorf("empty summary: %s", pass)
	}
}
