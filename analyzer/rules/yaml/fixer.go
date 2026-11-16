package yaml

import (
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"os"
	"regexp"
	"sort"

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

// ApplyFixes writes the suggested fixes of issues to disk. Fixes whose edits
// overlap an already accepted fix are skipped. Every rewritten file is
// formatted with go/format; a file that no longer parses is left untouched
// and reported as an error. It returns the files that were changed.
func ApplyFixes(issues []result.Issue) ([]string, error) {
	type fileEdits struct {
		edits []result.TextEdit
	}
	byFile := map[string]*fileEdits{}
	var order []string
	overlaps := func(list []result.TextEdit, e result.TextEdit) bool {
		for _, o := range list {
			if e.StartOffset < o.EndOffset && o.StartOffset < e.EndOffset || e.StartOffset == o.StartOffset {
				return true
			}
		}
		return false
	}
	for _, issue := range issues {
		if issue.Fix == nil || len(issue.Fix.Edits) == 0 {
			continue
		}
		ok := true
		for _, e := range issue.Fix.Edits {
			if e.EndOffset < e.StartOffset || e.File == "" {
				ok = false
				break
			}
			if fe := byFile[e.File]; fe != nil && overlaps(fe.edits, e) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, e := range issue.Fix.Edits {
			fe := byFile[e.File]
			if fe == nil {
				fe = &fileEdits{}
				byFile[e.File] = fe
				order = append(order, e.File)
			}
			fe.edits = append(fe.edits, e)
		}
	}
	sort.Strings(order)
	var changed []string
	var errs []error
	for _, file := range order {
		if err := applyFileEdits(file, byFile[file].edits); err != nil {
			errs = append(errs, err)
			continue
		}
		changed = append(changed, file)
	}
	return changed, errors.Join(errs...)
}

func applyFileEdits(file string, edits []result.TextEdit) error {
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].StartOffset > edits[j].StartOffset })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		if e.EndOffset > len(out) {
			return fmt.Errorf("%s: fix is out of range; the file changed since the scan", file)
		}
		out = append(out[:e.StartOffset:e.StartOffset], append([]byte(e.NewText), out[e.EndOffset:]...)...)
	}
	formatted, err := format.Source(out)
	if err != nil {
		return fmt.Errorf("%s: fixed source does not parse: %w", file, err)
	}
	return os.WriteFile(file, formatted, info.Mode().Perm())
}
