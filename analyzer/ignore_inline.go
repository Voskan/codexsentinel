package analyzer

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/matcher"
)

// InlineIgnore is a //codex:ignore directive found in source code.
type InlineIgnore struct {
	File     string   // file path relative to the project root
	Line     int      // line of the directive comment
	FromLine int      // first suppressed line
	ToLine   int      // last suppressed line
	Rules    []string // suppressed rule IDs or globs; "*" suppresses every rule
	Reason   string   // justification given after "--"
	ids      *matcher.Matcher
}

// InlineIgnores indexes the inline suppression directives of a set of files.
type InlineIgnores struct {
	byFile map[string][]InlineIgnore
}

var inlineDirective = regexp.MustCompile(`^//\s*codex:ignore(?:\s+(.*))?$`)

// CollectInlineIgnores extracts //codex:ignore directives from files.
//
// Syntax: //codex:ignore rule-a[,rule-b|*] [-- reason]
//
// A directive at the end of a line of code suppresses findings on that line.
// A directive on its own line suppresses findings on the next line, or in the
// whole declaration when it precedes (or is part of the doc comment of) a
// declaration.
func CollectInlineIgnores(fset *token.FileSet, files []*ast.File, root string) *InlineIgnores {
	ig := &InlineIgnores{byFile: map[string][]InlineIgnore{}}
	for _, file := range files {
		name := relPath(root, fset.Position(file.Pos()).Filename)
		var lineEnds map[int]token.Pos
		for _, group := range file.Comments {
			for _, c := range group.List {
				m := inlineDirective.FindStringSubmatch(c.Text)
				if m == nil {
					continue
				}
				if lineEnds == nil {
					lineEnds = codeEnds(fset, file)
				}
				line := fset.Position(c.Pos()).Line
				d := InlineIgnore{File: name, Line: line, FromLine: line, ToLine: line}
				spec, reason, _ := strings.Cut(m[1], "--")
				d.Reason = strings.TrimSpace(reason)
				for _, id := range strings.Split(strings.Join(strings.Fields(spec), ""), ",") {
					if id != "" {
						d.Rules = append(d.Rules, id)
					}
				}
				if len(d.Rules) == 0 {
					d.Rules = []string{"*"}
				}
				d.ids = matcher.New(d.Rules)
				if end, ok := lineEnds[line]; !ok || end > c.Pos() {
					d.ToLine = line + 1
					if decl := declAfter(fset, file, group, line); decl != nil {
						d.ToLine = fset.Position(decl.End()).Line
					}
				}
				ig.byFile[name] = append(ig.byFile[name], d)
			}
		}
	}
	return ig
}

// codeEnds returns, for each line, the earliest end position of a syntax node
// ending on that line. A comment placed after such a position trails code.
func codeEnds(fset *token.FileSet, file *ast.File) map[int]token.Pos {
	ends := map[int]token.Pos{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n.(type) {
		case nil, *ast.Comment, *ast.CommentGroup, *ast.File:
			return n != nil
		}
		line := fset.Position(n.End()).Line
		if cur, ok := ends[line]; !ok || n.End() < cur {
			ends[line] = n.End()
		}
		return true
	})
	return ends
}

// declAfter returns the declaration that the directive at line annotates:
// one starting on the next line or documented by the directive's comment group.
func declAfter(fset *token.FileSet, file *ast.File, group *ast.CommentGroup, line int) ast.Decl {
	for _, decl := range file.Decls {
		var doc *ast.CommentGroup
		switch d := decl.(type) {
		case *ast.FuncDecl:
			doc = d.Doc
		case *ast.GenDecl:
			doc = d.Doc
		}
		if doc == group || fset.Position(decl.Pos()).Line == line+1 {
			return decl
		}
	}
	return nil
}

// Suppressed reports whether a finding of ruleID at file:line is covered by a
// directive. file is relative to the project root.
func (ig *InlineIgnores) Suppressed(file string, line int, ruleID string) bool {
	if ig == nil {
		return false
	}
	for _, d := range ig.byFile[filepath.ToSlash(file)] {
		if line >= d.FromLine && line <= d.ToLine && d.ids.Match(ruleID) {
			return true
		}
	}
	return false
}

// Directives returns all collected directives.
func (ig *InlineIgnores) Directives() []InlineIgnore {
	if ig == nil {
		return nil
	}
	var out []InlineIgnore
	for _, ds := range ig.byFile {
		out = append(out, ds...)
	}
	return out
}

// MissingReasons reports directives without a justification after "--".
func (ig *InlineIgnores) MissingReasons() []result.Issue {
	var issues []result.Issue
	for _, d := range ig.Directives() {
		if d.Reason != "" {
			continue
		}
		issues = append(issues, result.Issue{
			ID:          "ignore-missing-reason",
			Title:       "Suppression Without Justification",
			Description: "codex:ignore directive for " + strings.Join(d.Rules, ",") + " has no reason; add one after \"--\".",
			Severity:    result.SeverityLow,
			Confidence:  1,
			Category:    "suppression",
			Location:    result.Location{File: d.File, Line: d.Line, Column: 1},
			Suggestion:  "Document why the finding is safe: //codex:ignore <rule> -- <reason>.",
		})
	}
	return issues
}

func relPath(root, file string) string {
	if root != "" && filepath.IsAbs(file) {
		if rel, err := filepath.Rel(root, file); err == nil {
			file = rel
		}
	}
	return filepath.ToSlash(file)
}
