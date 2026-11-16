package testutil

import (
	"go/ast"
	"go/types"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// dummyRule reports every call to a function named Danger and offers a fix
// that renames it to Safe.
func registerDummy(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{ID: "dummy-rule", Matcher: func(ac *analyzer.AnalyzerContext, pass *analysis.Pass) {
		for _, file := range pass.Files {
			tf := pass.Fset.File(file.Pos())
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var ident *ast.Ident
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					ident = fn
				case *ast.SelectorExpr:
					ident = fn.Sel
				}
				if ident == nil || ident.Name != "Danger" {
					return true
				}
				if _, ok := pass.TypesInfo.Uses[ident].(*types.Func); !ok {
					return true
				}
				pos := pass.Fset.Position(ident.Pos())
				end := pass.Fset.Position(ident.End())
				ac.Report(result.Issue{
					ID: "dummy-rule", Title: "Danger call", Description: "call to Danger is dangerous",
					Severity: result.SeverityLow, Location: result.NewLocationFromPos(pos, "", pass.Pkg.Path()),
					Fix: &result.SuggestedFix{Message: "use Safe", Edits: []result.TextEdit{{
						File: pos.Filename, StartLine: pos.Line, StartColumn: pos.Column, EndLine: end.Line, EndColumn: end.Column,
						StartOffset: tf.Offset(ident.Pos()), EndOffset: tf.Offset(ident.End()), NewText: "Safe",
					}}},
				})
				return true
			})
		}
	}})
}

const singleFile = `package main

func Danger() {}
func Safe()   {}

func main() {
	Danger() // want "dummy-rule"
	Safe()
	Danger() // want "dummy-rule:dangerous"
}
`

func TestRunRulesOnFilesMatchesAnnotations(t *testing.T) {
	issues := RunRulesOnFiles(t, map[string]string{"main.go": singleFile}, registerDummy)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
}

func TestDiffExpectationsReportsMissingAndUnexpected(t *testing.T) {
	files := map[string]string{"main.go": `package main

func main() {
	a() // want "dummy-rule"
	b()
}
`}
	wants, err := ParseExpectations(files)
	if err != nil {
		t.Fatal(err)
	}
	issues := []result.Issue{{ID: "dummy-rule", Location: result.Location{File: "/tmp/x/main.go", Line: 5}, Description: "fp"}}
	problems := DiffExpectations(wants, issues)
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems, got %v", problems)
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "missing expected issue dummy-rule at main.go:4") {
		t.Fatalf("missing TP not reported: %s", joined)
	}
	if !strings.Contains(joined, "unexpected issue dummy-rule at /tmp/x/main.go:5") {
		t.Fatalf("unexpected FP not reported: %s", joined)
	}
}

func TestParseExpectationsMultiple(t *testing.T) {
	wants, err := ParseExpectations(map[string]string{"a.go": "x() // want \"rule-a\" \"rule-b:msg\"\n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(wants) != 2 || wants[0].RuleID != "rule-a" || wants[1].RuleID != "rule-b" || wants[1].Message != "msg" {
		t.Fatalf("unexpected expectations: %+v", wants)
	}
	if _, err := ParseExpectations(map[string]string{"a.go": "x() // want rule\n"}); err == nil {
		t.Fatal("expected malformed annotation error")
	}
}

type recorder struct {
	testing.TB
	errors []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, format)
}

func TestCheckExpectationsFailsTB(t *testing.T) {
	rec := &recorder{TB: t}
	CheckExpectations(rec, map[string]string{"main.go": "package main // want \"x\"\n"}, nil)
	if len(rec.errors) != 1 {
		t.Fatalf("expected one error, got %d", len(rec.errors))
	}
}

func TestMultiPackageFixtureAndFixes(t *testing.T) {
	repo := `package repo

func Danger() {}
func Safe()   {}
`
	handler := `package handler

import "example.com/fixture/repo"

func Handle() {
	repo.Danger() // want "dummy-rule"
	repo.Safe()
}
`
	files := map[string]string{"repo/r.go": repo, "handler/h.go": handler}
	issues := RunRulesOnFiles(t, files, registerDummy)
	if len(issues) != 1 || issues[0].Location.File != "handler/h.go" {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	golden := strings.Replace(handler, "repo.Danger()", "repo.Safe()", 1)
	ApplyFixesAndCompare(t, handler, issues, golden)

	// Line/column based edits produce the same result.
	issues[0].Fix.Edits[0].StartOffset, issues[0].Fix.Edits[0].EndOffset = 0, 0
	ApplyFixesAndCompare(t, handler, issues, golden)
}
