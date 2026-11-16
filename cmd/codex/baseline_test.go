package codex

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/baseline"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/git"
	"github.com/Voskan/codexsentinel/report"
)

const vulnerable = `package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		db.Query("SELECT * FROM t WHERE a = '" + r.FormValue("a") + "'")
	}
}

func main() { http.Handle("/", handler(nil)) }
`

const extra = `
func other(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		db.Exec("DELETE FROM t WHERE id = " + r.FormValue("id"))
	}
}
`

func reportIssues(t *testing.T, path string) []report.Issue {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Issues []report.Issue `json:"issues"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("%v: %s", err, data)
	}
	return out.Issues
}

func sqlIssues(issues []report.Issue) []report.Issue {
	var out []report.Issue
	for _, issue := range issues {
		if issue.RuleID == "sql-injection" {
			out = append(out, issue)
		}
	}
	return out
}

func TestBaselineCreateAndScan(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, vulnerable)
	basePath := filepath.Join(t.TempDir(), baseline.DefaultFile)
	if err := runCLI(t, "baseline", "create", dir, "--out", basePath); err != nil {
		t.Fatal(err)
	}
	known, err := baseline.Load(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(known.Entries) == 0 {
		t.Fatal("baseline recorded no findings")
	}

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("// Package main.\n"+vulnerable+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--baseline", basePath); err != nil {
		t.Fatal(err)
	}
	fresh := sqlIssues(reportIssues(t, out))
	if len(fresh) != 1 || fresh[0].Line != 19 || fresh[0].Fingerprint == "" {
		t.Fatalf("want only the new finding, got %+v", fresh)
	}
}

func TestScanDiffMode(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Chdir(t.TempDir())
	dir := fixture(t, vulnerable)
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-q", "-m", "init"}} {
		cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(vulnerable+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--diff", "HEAD"); err != nil {
		t.Fatal(err)
	}
	changed := sqlIssues(reportIssues(t, out))
	if len(changed) != 1 || changed[0].Line != 18 {
		t.Fatalf("want only the finding on the changed lines, got %+v", changed)
	}
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--diff", "no-such-ref"); err == nil {
		t.Fatal("unknown reference accepted")
	}
}

func TestFilterByDiffModuleFindings(t *testing.T) {
	changed := git.ChangedLines{"go.sum": {{Start: 1, End: 3}}}
	issues := filterByDiff(issuesAt("go.mod", 0, "a.go", 2), changed)
	if len(issues) != 1 || issues[0].Location.File != "go.mod" {
		t.Fatalf("module-level finding not kept for go.sum change: %+v", issues)
	}
}

func issuesAt(fileA string, lineA int, fileB string, lineB int) []result.Issue {
	return []result.Issue{
		{ID: "vulnerable-dependency", Location: result.Location{File: fileA, Line: lineA}},
		{ID: "sql-injection", Location: result.Location{File: fileB, Line: lineB}},
	}
}
