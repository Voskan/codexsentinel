package codexlint_test

import (
	"go/token"
	"regexp"
	"testing"

	"github.com/Voskan/codexsentinel/v2/config"
	"github.com/Voskan/codexsentinel/v2/pkg/codexlint"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzersValidate(t *testing.T) {
	analyzers := codexlint.Analyzers(nil)
	if len(analyzers) < 20 {
		t.Fatalf("only %d analyzers exported", len(analyzers))
	}
	if err := analysis.Validate(analyzers); err != nil {
		t.Fatal(err)
	}
	ident := regexp.MustCompile(`^codex_[a-z0-9_]+$`)
	seen := map[string]bool{}
	for _, a := range analyzers {
		if !ident.MatchString(a.Name) || !token.IsIdentifier(a.Name) || a.Doc == "" || seen[a.Name] {
			t.Errorf("invalid analyzer %q (doc %q)", a.Name, a.Doc)
		}
		seen[a.Name] = true
	}
	for _, want := range []string{"codex_sql_injection", "codex_path_traversal", "codex_sensitive_data_in_logs", "codex_http_unbounded_body_read"} {
		if !seen[want] {
			t.Errorf("missing analyzer %s", want)
		}
	}
}

func analyzerFor(t *testing.T, analyzers []*analysis.Analyzer, ruleID string) *analysis.Analyzer {
	t.Helper()
	for _, a := range analyzers {
		if a.Name == codexlint.AnalyzerName(ruleID) {
			return a
		}
	}
	t.Fatalf("no analyzer for %s", ruleID)
	return nil
}

func TestSQLInjectionAnalyzer(t *testing.T) {
	a := analyzerFor(t, codexlint.Analyzers(nil), "sql-injection")
	results := analysistest.Run(t, analysistest.TestData(), a, "sqli")
	for _, r := range results {
		for _, d := range r.Diagnostics {
			if d.Category != "sql-injection" {
				t.Errorf("diagnostic category = %q", d.Category)
			}
		}
	}
}

func TestRuleSelection(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Rules.Enabled = []string{"sql-inj*"}
	if got := codexlint.Analyzers(&cfg); len(got) != 1 || got[0].Name != "codex_sql_injection" {
		t.Fatalf("selected analyzers: %v", got)
	}
	analyzers, err := codexlint.New(map[string]any{"disabled": []string{"sql-injection"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range analyzers {
		if a.Name == "codex_sql_injection" {
			t.Fatal("disabled rule exported")
		}
	}
	plugin, err := codexlint.NewPlugin(map[string]any{"enabled": []string{"path-traversal"}})
	if err != nil {
		t.Fatal(err)
	}
	built, _ := plugin.BuildAnalyzers()
	if len(built) != 1 || plugin.GetLoadMode() != "typesinfo" {
		t.Fatalf("plugin analyzers: %v", built)
	}
	if _, err := codexlint.New(func() {}); err == nil {
		t.Fatal("unencodable settings accepted")
	}
}
