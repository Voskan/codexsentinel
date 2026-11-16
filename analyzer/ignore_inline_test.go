package analyzer_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
)

const inlineSource = `package p

import "fmt"

func a() { fmt.Println("x") } //codex:ignore rule-a -- trailing

//codex:ignore rule-b,rule-c -- next line
func b() { fmt.Println("y") }

func c() {
	// codex:ignore *
	fmt.Println("z")
	fmt.Println("w")
}

// d does things.
//
//codex:ignore rule-d -- whole declaration
func d() {
	fmt.Println("1")
	fmt.Println("2")
}
`

func collect(t *testing.T) *analyzer.InlineIgnores {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "/root/p/p.go", inlineSource, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer.CollectInlineIgnores(fset, []*ast.File{file}, "/root")
}

func TestInlineIgnoreScopes(t *testing.T) {
	ig := collect(t)
	cases := []struct {
		line int
		rule string
		want bool
	}{
		{5, "rule-a", true},
		{5, "rule-b", false},
		{6, "rule-a", false},
		{8, "rule-b", true},
		{8, "rule-c", true},
		{8, "rule-a", false},
		{7, "rule-b", true},
		{12, "anything", true},
		{13, "anything", false},
		{19, "rule-d", true},
		{20, "rule-d", true},
		{22, "rule-d", true},
		{23, "rule-d", false},
	}
	for _, c := range cases {
		if got := ig.Suppressed("p/p.go", c.line, c.rule); got != c.want {
			t.Errorf("line %d %s: got %v, want %v", c.line, c.rule, got, c.want)
		}
	}
	if ig.Suppressed("other.go", 5, "rule-a") {
		t.Error("directive applied to another file")
	}
}

func TestInlineIgnoreMissingReason(t *testing.T) {
	missing := collect(t).MissingReasons()
	if len(missing) != 1 || missing[0].ID != "ignore-missing-reason" || missing[0].Location.Line != 11 || missing[0].Severity != result.SeverityLow {
		t.Fatalf("missing reasons: %+v", missing)
	}
}

func writeModule(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"go.mod": "module example.com/app\n\ngo 1.24\n", "app/app.go": src} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const handlerSource = `package app

import (
	"database/sql"
	"net/http"
)

func Search(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		db.Query("SELECT * FROM items WHERE name = '" + q + "'")
	}
}

func Delete(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		db.Exec("DELETE FROM items WHERE id = " + id) //codex:ignore sql-injection
	}
}
`

func scan(t *testing.T, dir string, mutate func(*config.Config)) []result.Issue {
	t.Helper()
	cfg := config.NewDefaultConfig()
	cfg.Metrics.Enable = false
	cfg.Architecture.Enable = false
	cfg.Rules.Enabled = []string{"sql-injection", "ignore-missing-reason"}
	if mutate != nil {
		mutate(&cfg)
	}
	issues, err := engine.Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return issues
}

func TestEngineSuppressionAndDedup(t *testing.T) {
	dir := writeModule(t, handlerSource)
	issues := scan(t, dir, nil)
	var sqlLines []int
	for _, issue := range issues {
		if issue.ID == "sql-injection" {
			sqlLines = append(sqlLines, issue.Location.Line)
			if len(issue.Trace) == 0 {
				t.Errorf("duplicate kept the finding without a trace: %+v", issue)
			}
		}
	}
	if len(sqlLines) != 1 || sqlLines[0] != 11 {
		t.Fatalf("want one deduplicated finding on line 11, got lines %v (%+v)", sqlLines, issues)
	}

	strict := scan(t, dir, func(cfg *config.Config) { cfg.Suppression.RequireIgnoreReason = true })
	found := false
	for _, issue := range strict {
		found = found || (issue.ID == "ignore-missing-reason" && issue.Location.File == "app/app.go" && issue.Location.Line == 18)
	}
	if !found {
		t.Fatalf("missing reason not reported: %+v", strict)
	}

	ignoreFile := filepath.Join(dir, ".codexsentinel.ignore")
	if err := os.WriteFile(ignoreFile, []byte("app/*.go sql-injection,xss # reviewed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, issue := range scan(t, dir, nil) {
		if strings.HasPrefix(issue.ID, "sql-") {
			t.Fatalf("ignore file not applied: %+v", issue)
		}
	}
}
