// Package baseline computes stable fingerprints for findings and records
// known findings so that later scans report only new ones.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// Fingerprint returns the identity of a finding that survives unrelated edits
// elsewhere in the file: it depends on the rule, the file, the enclosing
// declaration, the trimmed source line and the occurrence index of identical
// lines within that declaration, but not on the line number.
func Fingerprint(ruleID, file, scope, sourceLine string, occurrence int) string {
	h := sha256.New()
	for _, part := range []string{ruleID, filepath.ToSlash(file), scope, strings.TrimSpace(sourceLine), strconv.Itoa(occurrence)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type span struct {
	start, end int
	name       string
}

// Assign sets the Fingerprint of every issue. Issue files are relative to
// root; files provides the syntax used to find enclosing declarations.
func Assign(root string, fset *token.FileSet, files []*ast.File, issues []result.Issue) {
	scopes := declarationSpans(root, fset, files)
	lines := map[string][]string{}
	sourceLine := func(file string, line int) string {
		content, ok := lines[file]
		if !ok {
			path := file
			if !filepath.IsAbs(path) {
				path = filepath.Join(root, filepath.FromSlash(file))
			}
			if data, err := os.ReadFile(path); err == nil {
				content = strings.Split(string(data), "\n")
			}
			lines[file] = content
		}
		if line < 1 || line > len(content) {
			return ""
		}
		return strings.TrimSpace(content[line-1])
	}

	type group struct {
		rule, file, scope, text string
	}
	members := map[group][]int{}
	for i := range issues {
		loc := issues[i].Location
		scope := scopeAt(scopes[loc.File], loc.Line)
		if scope == "" {
			scope = loc.Function
		}
		g := group{issues[i].ID, loc.File, scope, sourceLine(loc.File, loc.Line)}
		members[g] = append(members[g], i)
	}
	for g, idx := range members {
		sort.SliceStable(idx, func(a, b int) bool {
			la, lb := issues[idx[a]].Location, issues[idx[b]].Location
			if la.Line != lb.Line {
				return la.Line < lb.Line
			}
			return la.Column < lb.Column
		})
		for n, i := range idx {
			issues[i].Fingerprint = Fingerprint(g.rule, g.file, g.scope, g.text, n)
		}
	}
}

// declarationSpans returns the line ranges of top-level functions and types per file.
func declarationSpans(root string, fset *token.FileSet, files []*ast.File) map[string][]span {
	out := map[string][]span{}
	for _, file := range files {
		name := fset.Position(file.Pos()).Filename
		if root != "" && filepath.IsAbs(name) {
			if rel, err := filepath.Rel(root, name); err == nil {
				name = rel
			}
		}
		name = filepath.ToSlash(name)
		for _, decl := range file.Decls {
			s := span{start: fset.Position(decl.Pos()).Line, end: fset.Position(decl.End()).Line}
			switch d := decl.(type) {
			case *ast.FuncDecl:
				s.name = declName(d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						s.name = sp.Name.Name
					case *ast.ValueSpec:
						if len(sp.Names) > 0 {
							s.name = sp.Names[0].Name
						}
					}
					if s.name != "" {
						break
					}
				}
			}
			if s.name != "" {
				out[name] = append(out[name], s)
			}
		}
	}
	return out
}

func declName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.ParenExpr:
			t = x.X
		case *ast.Ident:
			return x.Name + "." + fn.Name.Name
		default:
			return fn.Name.Name
		}
	}
}

func scopeAt(spans []span, line int) string {
	for _, s := range spans {
		if line >= s.start && line <= s.end {
			return s.name
		}
	}
	return ""
}
