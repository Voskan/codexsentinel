package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
)

func countingRule(id, message string) *rules.Rule {
	return &rules.Rule{ID: id, Enabled: true, Engine: func(ac *analyzer.AnalyzerContext) ([]result.Issue, error) {
		if len(ac.Files) == 0 {
			return nil, nil
		}
		pos := ac.Fset.Position(ac.Files[0].Package)
		return []result.Issue{{ID: id, Description: message, Severity: result.SeverityLow, Category: "style", Location: result.NewLocationFromPos(pos, "", "")}}, nil
	}}
}

func TestRunWithOptionsIsRepeatable(t *testing.T) {
	rules.Clear()
	t.Cleanup(rules.Clear)
	if err := rules.Register(countingRule("per-run", "global")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/m\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{Rules: []*rules.Rule{countingRule("per-run", "override")}}
	for run := 0; run < 2; run++ {
		issues, err := RunWithOptions(context.Background(), dir, nil, opts)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		var got []string
		for _, issue := range issues {
			if issue.ID == "per-run" {
				got = append(got, issue.Description)
			}
		}
		if len(got) != 1 || got[0] != "override" {
			t.Fatalf("run %d: findings = %v, want [override]", run, got)
		}
	}
}

func TestEarlyFindingsCoverFocusPackages(t *testing.T) {
	rules.Clear()
	t.Cleanup(rules.Clear)
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.test/m\n\ngo 1.24\n",
		"a/a.go":  "package a\n",
		"a/a2.go": "package a\n",
		"b/b.go":  "package b\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var earlyCalls int
	var earlyIssues []result.Issue
	var earlyFiles []string
	opts := Options{
		Rules: []*rules.Rule{countingRule("per-package", "found")},
		Focus: []string{filepath.Join(dir, "a", "a2.go")},
		Early: func(issues []result.Issue, files []string) {
			earlyCalls++
			earlyIssues, earlyFiles = issues, files
		},
	}
	final, err := RunWithOptions(context.Background(), dir, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if earlyCalls != 1 {
		t.Fatalf("Early called %d times, want 1", earlyCalls)
	}
	if len(earlyFiles) != 2 || earlyFiles[0] != "a/a.go" || earlyFiles[1] != "a/a2.go" {
		t.Fatalf("early files = %v, want [a/a.go a/a2.go]", earlyFiles)
	}
	locations := func(issues []result.Issue) map[string]bool {
		out := map[string]bool{}
		for _, issue := range issues {
			if issue.ID == "per-package" {
				out[issue.Location.File] = true
			}
		}
		return out
	}
	if got := locations(earlyIssues); len(got) != 1 || !got["a/a.go"] && !got["a/a2.go"] {
		t.Fatalf("early findings in %v, want one in package a", got)
	}
	for _, issue := range earlyIssues {
		if issue.Fingerprint == "" {
			t.Fatalf("early finding %+v is not post-processed", issue)
		}
	}
	if got := locations(final); len(got) != 2 || got["b/b.go"] != true {
		t.Fatalf("final findings in %v, want packages a and b", got)
	}

	// A focus that matches no package publishes nothing early.
	earlyCalls = 0
	opts.Focus = []string{filepath.Join(dir, "go.mod")}
	if _, err := RunWithOptions(context.Background(), dir, nil, opts); err != nil {
		t.Fatal(err)
	}
	if earlyCalls != 0 {
		t.Fatalf("Early called %d times for a focus outside every package", earlyCalls)
	}
}
