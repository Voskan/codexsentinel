package yaml

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/Voskan/codexsentinel/analyzer/fixer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var fixVar = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)|\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// RenderFix substitutes the source text of bound metavariables into template.
func RenderFix(fset *token.FileSet, template string, b Bindings) string {
	return fixVar.ReplaceAllStringFunc(template, func(v string) string {
		m := fixVar.FindStringSubmatch(v)
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if node, ok := b[name]; ok {
			return nodeText(fset, node)
		}
		return v
	})
}

func buildFix(fset *token.FileSet, m Match, template, message string) *result.SuggestedFix {
	return &result.SuggestedFix{Message: message, Edits: []result.TextEdit{replaceEdit(fset, m.Node, RenderFix(fset, template, m.Bindings))}}
}

func replaceEdit(fset *token.FileSet, n ast.Node, text string) result.TextEdit {
	start, end := fset.Position(n.Pos()), fset.Position(n.End())
	return result.TextEdit{
		File: start.Filename, StartLine: start.Line, StartColumn: start.Column, EndLine: end.Line, EndColumn: end.Column,
		StartOffset: start.Offset, EndOffset: end.Offset, NewText: text,
	}
}

// ApplyFixes writes the suggested fixes of issues to disk; edit paths are used
// as they are. It is kept for existing callers; see fixer.ApplyFixes.
func ApplyFixes(issues []result.Issue) ([]string, error) {
	return fixer.ApplyFixes("", issues)
}
