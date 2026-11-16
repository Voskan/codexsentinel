package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var pathTraversalMeta = ruleMeta{
	ID: "path-traversal", Title: "Path Traversal", Severity: result.SeverityHigh, CWE: "CWE-22", OWASP: "A01:2025",
	Confidence: 0.9,
	Suggestion: "Use os.OpenRoot(baseDir) (Go 1.24+) to confine filesystem access and prevent symlink/TOCTOU path traversal, or restrict to filepath.Base(name).",
	References: []string{"https://cwe.mitre.org/data/definitions/22.html", "https://go.dev/blog/osroot"},
}

// RegisterPathTraversalRule reports filesystem calls whose path is derived from
// HTTP request input. Access through *os.Root is confined and never reported.
func RegisterPathTraversalRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{pathTraversalMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				lt := newLocalTaint(info, unit.Body)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					for _, idx := range fileSinkArgs(calleeFunc(info, call)) {
						if idx >= len(call.Args) {
							continue
						}
						arg := call.Args[idx]
						if isConst(info, arg) || !lt.tainted(arg, "path-traversal") {
							continue
						}
						desc := "Filesystem path is derived from HTTP request input."
						if joinsBaseDir(info, arg) {
							desc += " filepath.Join does not prevent '..' or absolute components from escaping the base directory; open the base with os.OpenRoot instead."
						}
						r.report(pathTraversalMeta, arg, desc)
						break
					}
					return true
				})
			}
		}
	})
}

func fileSinkArgs(fn *types.Func) []int {
	switch {
	case isFunc(fn, "os", "Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "ReadDir", "Mkdir", "MkdirAll", "Truncate", "Chmod", "Chown"):
		return []int{0}
	case isFunc(fn, "os", "Rename", "Symlink", "Link"):
		return []int{0, 1}
	case isFunc(fn, "io/ioutil", "ReadFile", "WriteFile", "ReadDir"):
		return []int{0}
	case isFunc(fn, "net/http", "ServeFile"):
		return []int{2}
	}
	return nil
}

func joinsBaseDir(info *types.Info, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := calleeFunc(info, call)
	if isFunc(fn, "path/filepath", "Clean") && len(call.Args) == 1 {
		return joinsBaseDir(info, call.Args[0])
	}
	return isFunc(fn, "path/filepath", "Join") && len(call.Args) > 1
}
