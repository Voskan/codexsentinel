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
