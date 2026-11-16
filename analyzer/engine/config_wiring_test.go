package engine

import (
	"context"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
)

func TestRuleConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "query.go")
	src := "package sample\nimport \"database/sql\"\nfunc query(db *sql.DB, input string) { db.Query(\"SELECT * FROM users WHERE id = \" + input) }"
	if err := os.WriteFile(file, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig
	cfg.Metrics.Enable = false
	cfg.Dependencies.Enable = false
	cfg.Rules.Enabled = []string{"sql-injection"}
	issues, err := Run(context.Background(), file, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected enabled SQL rule to run")
	}
	cfg.Rules.Disabled = []string{"sql-injection"}
	issues, err = Run(context.Background(), file, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("disabled rule emitted findings: %+v", issues)
	}
}

func TestSeverityOverride(t *testing.T) {
	cfg := config.DefaultConfig
	cfg.Rules.SeverityOverrides = map[string]string{"high-complexity": "HIGH"}
	got := postProcess(&workspace.Workspace{Fset: token.NewFileSet()}, &cfg, []result.Issue{{ID: "high-complexity", Severity: result.SeverityMedium}})
	if len(got) != 1 || got[0].Severity != result.SeverityHigh {
		t.Fatalf("override not applied: %+v", got)
	}
}
