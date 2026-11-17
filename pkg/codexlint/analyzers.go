// Package codexlint exposes the built-in CodexSentinel rules as standard
// golang.org/x/tools/go/analysis analyzers, so they can run inside gopls,
// "go vet -vettool", multichecker binaries and golangci-lint module plugins.
//
// A standalone checker:
//
//	package main
//
//	import (
//		"github.com/Voskan/codexsentinel/v2/pkg/codexlint"
//		"golang.org/x/tools/go/analysis/multichecker"
//	)
//
//	func main() { multichecker.Main(codexlint.Analyzers(nil)...) }
//
// Each analyzer is named after its rule ID with dashes replaced by
// underscores and a "codex_" prefix (sql-injection becomes
// codex_sql_injection); diagnostics carry the rule ID as their Category.
// Findings can be suppressed with //codex:ignore directives.
package codexlint

import (
	"go/token"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/analyzer/rules/builtin"
	"github.com/Voskan/codexsentinel/v2/config"
	"github.com/Voskan/codexsentinel/v2/internal/matcher"
	"golang.org/x/tools/go/analysis"
)

// Analyzers returns one analyzer per built-in rule enabled in cfg. A nil cfg
// selects the default configuration.
func Analyzers(cfg *config.Config) []*analysis.Analyzer {
	if cfg == nil {
		defaults := config.NewDefaultConfig()
		cfg = &defaults
	}
	registry := &analyzer.AnalyzerContext{}
	builtin.RegisterAll(registry)
	enabled, disabled := matcher.New(cfg.Rules.Enabled), matcher.New(cfg.Rules.Disabled)
	var out []*analysis.Analyzer
	for _, rule := range registry.Rules {
		if rule.Matcher == nil || (len(cfg.Rules.Enabled) > 0 && !enabled.Match(rule.ID)) || disabled.Match(rule.ID) {
			continue
		}
		out = append(out, newAnalyzer(rule, cfg))
	}
	return out
}

// AnalyzerName returns the analyzer name used for a rule ID.
func AnalyzerName(ruleID string) string {
	var b strings.Builder
	b.WriteString("codex_")
	for _, r := range ruleID {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func newAnalyzer(rule *analyzer.Rule, cfg *config.Config) *analysis.Analyzer {
	doc := rule.ID + ": " + rule.Title
	if rule.Summary != "" {
		doc += "\n\n" + rule.Summary
	}
	return &analysis.Analyzer{
		Name: AnalyzerName(rule.ID),
		Doc:  doc,
		URL:  "https://github.com/Voskan/codexsentinel",
		Run: func(pass *analysis.Pass) (any, error) {
			run(pass, rule, cfg)
			return nil, nil
		},
	}
}

func run(pass *analysis.Pass, rule *analyzer.Rule, cfg *config.Config) {
	ac := &analyzer.AnalyzerContext{
		Cfg: cfg, Fset: pass.Fset, Files: pass.Files, Types: pass.TypesInfo,
		PackageName: pass.Pkg.Path(), CustomData: map[string]any{},
	}
	if len(pass.Files) > 0 {
		ac.Filename = pass.Fset.Position(pass.Files[0].Pos()).Filename
	}
	rule.Matcher(ac, pass)
	var inline *analyzer.InlineIgnores
	if cfg.Suppression.EnableInlineIgnore {
		inline = analyzer.CollectInlineIgnores(pass.Fset, pass.Files, "")
	}
	files := fileIndex(pass)
	for _, issue := range ac.GetIssues() {
		if issue.ID != rule.ID || inline.Suppressed(filepath.ToSlash(issue.Location.File), issue.Location.Line, issue.ID) {
			continue
		}
		tf := files[filepath.Clean(issue.Location.File)]
		if tf == nil {
			continue
		}
		pos := position(tf, issue.Location.Line, issue.Location.Column)
		if !pos.IsValid() {
			continue
		}
		diag := analysis.Diagnostic{Pos: pos, Category: issue.ID, Message: message(issue)}
		if issue.Location.EndLine > 0 {
			diag.End = position(tf, issue.Location.EndLine, issue.Location.EndColumn)
		}
		if fix := suggestedFix(files, issue.Fix); fix != nil {
			diag.SuggestedFixes = []analysis.SuggestedFix{*fix}
		}
		pass.Report(diag)
	}
}

func fileIndex(pass *analysis.Pass) map[string]*token.File {
	files := map[string]*token.File{}
	for _, f := range pass.Files {
		if tf := pass.Fset.File(f.Pos()); tf != nil {
			files[filepath.Clean(tf.Name())] = tf
		}
	}
	return files
}

func message(issue result.Issue) string {
	text := issue.Description
	if text == "" {
		text = issue.Title
	}
	return text + " (" + issue.ID + ")"
}

// position converts a 1-based line and column into a position within tf.
func position(tf *token.File, line, column int) token.Pos {
	if line < 1 || line > tf.LineCount() {
		return token.NoPos
	}
	start := tf.LineStart(line)
	if column > 1 {
		offset := tf.Offset(start) + column - 1
		if offset > tf.Size() {
			offset = tf.Size()
		}
		return tf.Pos(offset)
	}
	return start
}

func suggestedFix(files map[string]*token.File, fix *result.SuggestedFix) *analysis.SuggestedFix {
	if fix == nil || len(fix.Edits) == 0 {
		return nil
	}
	out := &analysis.SuggestedFix{Message: fix.Message}
	for _, e := range fix.Edits {
		tf := files[filepath.Clean(e.File)]
		if tf == nil {
			return nil
		}
		var start, end token.Pos
		if e.EndOffset > 0 && e.EndOffset <= tf.Size() && e.StartOffset <= e.EndOffset {
			start, end = tf.Pos(e.StartOffset), tf.Pos(e.EndOffset)
		} else {
			start, end = position(tf, e.StartLine, e.StartColumn), position(tf, e.EndLine, e.EndColumn)
		}
		if !start.IsValid() || !end.IsValid() {
			return nil
		}
		out.TextEdits = append(out.TextEdits, analysis.TextEdit{Pos: start, End: end, NewText: []byte(e.NewText)})
	}
	return out
}
