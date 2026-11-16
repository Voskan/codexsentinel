package yaml

import (
	"context"
	"go/ast"
	"go/parser"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"golang.org/x/tools/go/analysis"
)

func compileYAML(t *testing.T, src string) *CompiledRule {
	t.Helper()
	parsed, err := ParseRules([]byte(src), "rule.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(parsed[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func register(c *CompiledRule) func(*analyzer.AnalyzerContext) {
	return func(ac *analyzer.AnalyzerContext) {
		ac.RegisterRule(&analyzer.Rule{ID: c.Rule.ID, Matcher: func(ac *analyzer.AnalyzerContext, _ *analysis.Pass) {
			issues, _ := c.Run(ac)
			for _, issue := range issues {
				ac.Report(issue)
			}
		}})
	}
}

func TestMatcherTypeFilter(t *testing.T) {
	t.Parallel()
	rule := compileYAML(t, `
id: fprintf-response
title: Formatted response
match:
  pattern: fmt.Fprintf($W, $MSG)
  filters:
    - type: type
      var: $W
      include: ["net/http.ResponseWriter"]
    - type: non_const
      var: $MSG
`)
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"bytes"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("m")
	fmt.Fprintf(w, msg) // want "fprintf-response"
	fmt.Fprintf(w, "static")
	var buf bytes.Buffer
	fmt.Fprintf(&buf, msg)
	fmt.Fprintf(w, msg, 1)
}
`}, register(rule))
}

func TestMatcherRepeatedMetavariable(t *testing.T) {
	t.Parallel()
	rule := compileYAML(t, "id: self-compare\npattern: $X == $X\n")
	testutil.RunRulesOnFiles(t, map[string]string{"cmp.go": `package app

type point struct{ x, y int }

func f(a, b int, p point) bool {
	_ = a == b
	_ = p.x == p.x // want "self-compare"
	return a == a // want "self-compare"
}
`}, register(rule))
}

func TestMatcherNotPatternAndEllipsis(t *testing.T) {
	t.Parallel()
	rule := compileYAML(t, `
id: raw-write
match:
  pattern: $W.Write([]byte($X))
  not_pattern: html.EscapeString($Y)
  filters:
    - type: type
      var: $W
      include: ["net/http.ResponseWriter"]
    - type: import
      include: ["net/http"]
`)
	logRule := compileYAML(t, `
id: log-fatal-library
pattern: log.Fatalf($...)
match:
  pattern: log.Fatalf($FMT, $...)
  filters:
    - type: package
      exclude: ["main"]
`)
	testutil.RunRulesOnFiles(t, map[string]string{"w.go": `package app

import (
	"html"
	stdlog "log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name)) // want "raw-write"
	w.Write([]byte(html.EscapeString(name)))
	w.Write([]byte("<b>" + html.EscapeString(name) + "</b>"))
	stdlog.Fatalf("bad %s %d", name, 1) // want "log-fatal-library"
	stdlog.Fatalf("bad") // want "log-fatal-library"
}
`}, func(ac *analyzer.AnalyzerContext) {
		register(rule)(ac)
		register(logRule)(ac)
	})
}

func TestMatcherStatementAndHelpers(t *testing.T) {
	p, err := CompilePattern("{{x}} = append({{x}}, ...)")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.node.(*ast.AssignStmt); !ok {
		t.Fatalf("statement pattern compiled to %T", p.node)
	}
	a, _ := parser.ParseExpr("f(x, y+1)")
	b, _ := parser.ParseExpr("f(x, y + 1)")
	c, _ := parser.ParseExpr("f(x, y+2)")
	if !astEqual(a, b) || astEqual(a, c) {
		t.Fatal("astEqual ignores formatting but not values")
	}
	pat, err := CompilePattern("f($A, $...)")
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := pat.Match(nil, a, nil); !ok || b["A"] == nil {
		t.Fatalf("untyped match failed: %v", b)
	}
	if _, err := CompilePattern("func ("); err == nil {
		t.Fatal("invalid pattern accepted")
	}
	if _, err := Compile(RuleYAML{ID: "x", Pattern: "f($X)", Match: &MatchConfig{Filters: []Filter{{Type: "bogus"}}}}); err == nil {
		t.Fatal("unknown filter accepted")
	}
}

func TestMatcherFixCompiles(t *testing.T) {
	t.Parallel()
	rule := compileYAML(t, `
id: replace-all
title: Use strings.ReplaceAll
suggestion: Use strings.ReplaceAll
pattern: strings.Replace($S, $OLD, $NEW, -1)
fix: strings.ReplaceAll($S, $OLD, $NEW)
`)
	files := map[string]string{"text.go": `package app

import "strings"

func clean(s string) string {
	s = strings.Replace(s, "\t", " ", -1)
	return strings.Replace(strings.TrimSpace(s), "  ", " ", -1)
}

func once(s string) string { return strings.Replace(s, "a", "b", 1) }
`}
	fx := testutil.LoadFixture(t, files, nil)
	issues := testutil.AnalyzeFixture(t, fx, register(rule))
	if len(issues) != 2 {
		t.Fatalf("want 2 issues, got %d: %+v", len(issues), issues)
	}
	for _, issue := range issues {
		if issue.Fix == nil || !strings.HasPrefix(issue.Fix.Edits[0].NewText, "strings.ReplaceAll(") {
			t.Fatalf("missing fix: %+v", issue)
		}
	}
	changed, err := ApplyFixes(issues)
	if err != nil || len(changed) != 1 {
		t.Fatalf("ApplyFixes = %v, %v", changed, err)
	}
	data, err := os.ReadFile(filepath.Join(fx.Dir, "text.go"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{`strings.ReplaceAll(s, "\t", " ")`, `strings.ReplaceAll(strings.TrimSpace(s), "  ", " ")`, `strings.Replace(s, "a", "b", 1)`} {
		if !strings.Contains(got, want) {
			t.Fatalf("fixed file lacks %q:\n%s", want, got)
		}
	}
	ws, err := workspace.Load(context.Background(), fx.Dir, fx.Config)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range ws.Packages {
		if len(pkg.Errors) > 0 {
			t.Fatalf("fixed package does not compile: %v", pkg.Errors)
		}
	}
}

func TestApplyFixesRejectsBrokenOutput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.go")
	src := "package a\n\nvar x = 1\n"
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(src, "1")
	issue := result.Issue{Fix: &result.SuggestedFix{Edits: []result.TextEdit{{File: file, StartOffset: start, EndOffset: start + 1, NewText: "("}}}}
	if _, err := ApplyFixes([]result.Issue{issue}); err == nil {
		t.Fatal("broken fix applied")
	}
	if data, _ := os.ReadFile(file); string(data) != src {
		t.Fatal("file modified despite error")
	}
}

func TestParseRulesFormats(t *testing.T) {
	multi := "id: a\npattern: f($X)\n---\nid: b\npattern: g($X)\n"
	list := "rules:\n  - id: a\n    pattern: f($X)\n  - id: b\n    pattern: g($X)\n    match:\n      not_pattern: [\"h($X)\"]\n"
	for _, src := range []string{multi, list} {
		parsed, err := ParseRules([]byte(src), "r.yaml")
		if err != nil || len(parsed) != 2 || parsed[1].ID != "b" {
			t.Fatalf("ParseRules(%q) = %+v, %v", src, parsed, err)
		}
	}
}

func TestShippedRuleFilesCompile(t *testing.T) {
	for _, path := range []string{"../../../assets/rules", "../../../custom_rules.yaml"} {
		var files []string
		if strings.HasSuffix(path, ".yaml") {
			files = []string{path}
		} else {
			matches, err := filepath.Glob(filepath.Join(path, "*.yaml"))
			if err != nil || len(matches) == 0 {
				t.Fatalf("no rule files in %s: %v", path, err)
			}
			files = matches
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRules(data, file)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range parsed {
				if _, err := Compile(r); err != nil {
					t.Errorf("%s: %s: %v", file, r.ID, err)
				}
			}
		}
	}
}

func TestShippedRulesOnSafeAndUnsafeCode(t *testing.T) {
	t.Parallel()
	var compiled []*CompiledRule
	for _, file := range []string{"../../../assets/rules/security-rules.yaml", "../../../assets/rules/style-rules.yaml", "../../../custom_rules.yaml"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRules(data, file)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range parsed {
			c, err := Compile(r)
			if err != nil {
				t.Fatal(err)
			}
			compiled = append(compiled, c)
		}
	}
	testutil.RunRulesOnFiles(t, map[string]string{"lib/lib.go": `package lib

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func f(id string, start time.Time, a, b []byte) {
	_, _ = http.Get("http://api.partner.com/v1") // want "go.security.plaintext-http-request"
	_, _ = http.Get("https://api.partner.com/v1")
	_, _ = http.Get("http://localhost:8080/health")
	_ = fmt.Sprintf("SELECT * FROM t WHERE id = '%s'", id) // want "CUSTOM001"
	_ = fmt.Sprintf("SELECT * FROM t LIMIT %d", 10)
	_ = fmt.Sprintf("user %s not found", id)
	_ = strings.Replace(id, "a", "b", -1) // want "go.style.strings-replace-all"
	_ = time.Now().Sub(start) // want "go.style.time-since"
	_ = bytes.Compare(a, b) == 0 // want "go.style.bytes-equal"
	id = id // want "go.correctness.self-assignment"
	if id == "" {
		log.Fatalf("missing id") // want "CUSTOM002"
	}
}
`}, func(ac *analyzer.AnalyzerContext) {
		for _, c := range compiled {
			if c.Rule.IsEnabled() {
				register(c)(ac)
			}
		}
	})
}
