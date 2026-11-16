package formats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/report"
)

func TestAgentReportPass(t *testing.T) {
	if got := AgentReport(nil); got != "STATUS: PASS (0 issues)\n" {
		t.Fatalf("got %q", got)
	}
}

func TestAgentReportBlocks(t *testing.T) {
	issues := []report.Issue{
		{RuleID: "http-client-unsafe", Severity: report.SeverityMedium, File: "a.go", Line: 3, Description: "No timeout.", Suggestion: "Set Client.Timeout."},
		{
			RuleID: "sql-injection", Severity: report.SeverityHigh, CWE: "CWE-89", File: "internal/repo/user.go",
			Line: 42, Column: 15, EndLine: 42, EndColumn: 68,
			Description: "Untrusted input reaches\nSQL query execution.",
			Suggestion:  "Use parameterized placeholders.",
			Trace: []result.TraceStep{
				{Kind: "source", Message: "(*http.Request).FormValue", Location: result.Location{File: "handler/user.go", Line: 18}},
				{Kind: "call", Message: "GetUser", Location: result.Location{File: "service/user.go", Line: 27}},
				{Kind: "sink", Message: "(*sql.DB).QueryContext", Location: result.Location{File: "internal/repo/user.go", Line: 42}},
			},
			Fix: &result.SuggestedFix{Message: "Use a placeholder.", Edits: []result.TextEdit{
				{File: "internal/repo/user.go", StartLine: 42, StartColumn: 15, EndLine: 42, EndColumn: 68, NewText: `db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)`},
				{File: "internal/repo/other.go", StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 5, NewText: "a\nb"},
			}},
		},
		{RuleID: "weak-hash", Severity: report.SeverityHigh, File: "a.go", Line: 9, Title: "Weak Hash"},
	}
	got := AgentReport(issues)
	want := `STATUS: FAIL (3 issues: critical=0 high=2 medium=1 low=0 info=0)
---
ISSUE [HIGH] weak-hash at a.go:9
WHY: Weak Hash
---
ISSUE [HIGH] sql-injection (CWE-89) at internal/repo/user.go:42:15-42:68
WHY: Untrusted input reaches SQL query execution.
FLOW: handler/user.go:18 (source: (*http.Request).FormValue) -> service/user.go:27 (call: GetUser) -> internal/repo/user.go:42 (sink: (*sql.DB).QueryContext)
FIX: Use a placeholder.
PATCH: replace 42:15-42:68 with ` + "`" + `db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)` + "`" + `
PATCH: replace internal/repo/other.go:1:1-1:5 with "a\nb"
---
ISSUE [MEDIUM] http-client-unsafe at a.go:3
WHY: No timeout.
FIX: Set Client.Timeout.
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Input order does not change the output.
	reversed := []report.Issue{issues[2], issues[1], issues[0]}
	if AgentReport(reversed) != got {
		t.Fatal("output depends on input order")
	}
}

func TestWriteAgentReportFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.txt")
	if err := WriteAgentReport(nil, path, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), "STATUS: PASS") {
		t.Fatalf("data = %q, err = %v", data, err)
	}
}
