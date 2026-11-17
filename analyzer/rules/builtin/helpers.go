// Package builtin contains the built-in, type-aware security rules.
package builtin

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/typeutil"
)

// ruleMeta describes the issues produced by a rule ID.
type ruleMeta struct {
	ID         string
	Title      string
	Severity   result.Severity
	CWE        string
	OWASP      string
	Suggestion string
	References []string
	Confidence float64
	// Category defaults to "security".
	Category string
}

func (m ruleMeta) category() string {
	if m.Category == "" {
		return "security"
	}
	return m.Category
}

// reporter emits issues for a single rule ID during one package pass.
type reporter struct {
	ac   *analyzer.AnalyzerContext
	pass *analysis.Pass
	only string
	// tables caches constantTables.
	tables map[*types.Var][]ast.Expr
}

// registerRules registers one analyzer rule per ID. Every rule runs the shared
// matcher but only reports issues carrying its own ID, so rules can be enabled
// and disabled individually.
func registerRules(ctx *analyzer.AnalyzerContext, metas []ruleMeta, run func(r *reporter)) {
	for _, meta := range metas {
		id := meta.ID
		ctx.RegisterRule(&analyzer.Rule{
			ID:       id,
			Title:    meta.Title,
			Category: meta.category(),
			Severity: meta.Severity,
			Summary:  meta.Suggestion,
			Matcher: func(ac *analyzer.AnalyzerContext, pass *analysis.Pass) {
				if pass == nil || pass.TypesInfo == nil {
					return
				}
				run(&reporter{ac: ac, pass: pass, only: id})
			},
		})
	}
}

func (r *reporter) wants(id string) bool { return r.only == "" || r.only == id }

// report emits an issue for node.
func (r *reporter) report(meta ruleMeta, node ast.Node, desc string) {
	r.reportWith(meta, node, desc, meta.Severity, nil)
}

func (r *reporter) reportWith(meta ruleMeta, node ast.Node, desc string, severity result.Severity, fix *result.SuggestedFix) {
	if !r.wants(meta.ID) {
		return
	}
	pos := r.pass.Fset.Position(node.Pos())
	end := r.pass.Fset.Position(node.End())
	loc := result.NewLocationFromPos(pos, "", r.pass.Pkg.Path())
	loc.EndLine, loc.EndColumn = end.Line, end.Column
	conf := meta.Confidence
	if conf == 0 {
		conf = 1
	}
	if severity == "" {
		severity = meta.Severity
	}
	r.ac.Report(result.Issue{
		ID:          meta.ID,
		Title:       meta.Title,
		Description: desc,
		Severity:    severity,
		Confidence:  conf,
		CWE:         meta.CWE,
		OWASP:       meta.OWASP,
		Location:    loc,
		Category:    meta.category(),
		Suggestion:  meta.Suggestion,
		References:  meta.References,
		Fix:         fix,
	})
}

// replaceFix builds a fix replacing node with text.
func (r *reporter) replaceFix(message string, node ast.Node, text string) *result.SuggestedFix {
	tf := r.pass.Fset.File(node.Pos())
	if tf == nil {
		return nil
	}
	start, end := r.pass.Fset.Position(node.Pos()), r.pass.Fset.Position(node.End())
	return &result.SuggestedFix{Message: message, Edits: []result.TextEdit{{
		File: start.Filename, StartLine: start.Line, StartColumn: start.Column, EndLine: end.Line, EndColumn: end.Column,
		StartOffset: tf.Offset(node.Pos()), EndOffset: tf.Offset(node.End()), NewText: text,
	}}}
}

// calleeFunc resolves the function or method called by call, or nil.
func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	fn, _ := typeutil.Callee(info, call).(*types.Func)
	if fn != nil {
		fn = fn.Origin()
	}
	return fn
}

// pkgMatches reports whether path equals one of the candidates, ignoring a
// trailing major-version suffix such as /v5.
func pkgMatches(path string, candidates ...string) bool {
	for _, c := range candidates {
		if path == c {
			return true
		}
		if strings.HasPrefix(path, c+"/v") {
			if _, err := strconv.Atoi(path[len(c)+2:]); err == nil {
				return true
			}
		}
	}
	return false
}

func nameIn(name string, names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// isFunc reports whether fn is a package-level function of pkg named one of names.
func isFunc(fn *types.Func, pkg string, names ...string) bool {
	if fn == nil || fn.Pkg() == nil || recvOf(fn) != nil {
		return false
	}
	return pkgMatches(fn.Pkg().Path(), pkg) && nameIn(fn.Name(), names)
}

func recvOf(fn *types.Func) *types.Var {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return nil
	}
	return sig.Recv()
}

// isMethod reports whether fn is a method declared on pkg.recv named one of names.
func isMethod(fn *types.Func, pkg, recv string, names ...string) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	r := recvOf(fn)
	if r == nil || !pkgMatches(fn.Pkg().Path(), pkg) {
		return false
	}
	_, name := namedOf(r.Type())
	return name == recv && nameIn(fn.Name(), names)
}

// namedOf returns the package path and name of a (pointer to) named type.
func namedOf(t types.Type) (string, string) {
	if t == nil {
		return "", ""
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Path(), n.Obj().Name()
	}
	return "", ""
}

// typeIs reports whether t is (a pointer to) the named type pkg.name.
func typeIs(t types.Type, pkg, name string) bool {
	p, n := namedOf(t)
	return n == name && pkgMatches(p, pkg)
}

func typeOf(info *types.Info, e ast.Expr) types.Type {
	if tv, ok := info.Types[e]; ok {
		return tv.Type
	}
	return nil
}

// constValue returns the constant value of e, or nil.
func constValue(info *types.Info, e ast.Expr) constant.Value {
	if tv, ok := info.Types[e]; ok {
		return tv.Value
	}
	return nil
}

func isConst(info *types.Info, e ast.Expr) bool { return constValue(info, e) != nil }

func constString(info *types.Info, e ast.Expr) (string, bool) {
	v := constValue(info, e)
	if v == nil || v.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(v), true
}

func constInt(info *types.Info, e ast.Expr) (int64, bool) {
	v := constValue(info, e)
	if v == nil {
		return 0, false
	}
	v = constant.ToInt(v)
	if v.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(v)
}

func constBool(info *types.Info, e ast.Expr) (bool, bool) {
	v := constValue(info, e)
	if v == nil || v.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(v), true
}

// isTextType reports whether t is a string, byte slice or interface (may hold text).
func isTextType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Rune)
	case *types.Interface:
		return true
	}
	return false
}

// exprName returns a descriptive identifier for an expression: the variable,
// field or constant-key name it denotes.
func exprName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return exprName(x.X)
	case *ast.ParenExpr:
		return exprName(x.X)
	case *ast.IndexExpr:
		if lit, ok := x.Index.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				return s
			}
		}
		return exprName(x.X)
	case *ast.CallExpr:
		return exprName(x.Fun)
	}
	return ""
}

// funcUnit is a function declaration or literal with its body.
type funcUnit struct {
	Node ast.Node
	Type *ast.FuncType
	Body *ast.BlockStmt
	Name string
}

// funcUnits lists every function declaration and literal in file.
func funcUnits(file *ast.File) []funcUnit {
	var out []funcUnit
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				out = append(out, funcUnit{Node: fn, Type: fn.Type, Body: fn.Body, Name: fn.Name.Name})
			}
		case *ast.FuncLit:
			out = append(out, funcUnit{Node: fn, Type: fn.Type, Body: fn.Body, Name: "func literal"})
		}
		return true
	})
	return out
}

// inspectShallow walks body without descending into nested function literals.
func inspectShallow(body ast.Node, f func(ast.Node) bool) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok && n != body {
			return false
		}
		return f(n)
	})
}

// params returns the parameter objects of a function type.
func params(info *types.Info, ft *ast.FuncType) []*types.Var {
	var out []*types.Var
	if ft == nil || ft.Params == nil {
		return out
	}
	for _, field := range ft.Params.List {
		for _, name := range field.Names {
			if v, ok := info.Defs[name].(*types.Var); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// isHandlerFunc reports whether the function looks like an HTTP handler of
// net/http, gin, echo or fiber.
func isHandlerFunc(info *types.Info, ft *ast.FuncType) bool {
	for _, p := range params(info, ft) {
		t := p.Type()
		if typeIs(t, "net/http", "Request") || typeIs(t, "github.com/gin-gonic/gin", "Context") ||
			typeIs(t, "github.com/labstack/echo", "Context") || typeIs(t, "github.com/gofiber/fiber", "Ctx") {
			return true
		}
	}
	return false
}

// objOf returns the object an identifier expression refers to.
func objOf(info *types.Info, e ast.Expr) types.Object {
	switch x := e.(type) {
	case *ast.Ident:
		if obj := info.Uses[x]; obj != nil {
			return obj
		}
		return info.Defs[x]
	case *ast.SelectorExpr:
		return info.Uses[x.Sel]
	case *ast.ParenExpr:
		return objOf(info, x.X)
	}
	return nil
}

// assignments collects the expressions assigned to local variables in body.
func assignments(info *types.Info, body ast.Node) map[types.Object][]ast.Expr {
	out := map[types.Object][]ast.Expr{}
	if body == nil {
		return out
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == len(s.Rhs) {
				for i, lhs := range s.Lhs {
					if obj := objOf(info, lhs); obj != nil {
						if s.Tok == token.ASSIGN || s.Tok == token.DEFINE {
							out[obj] = append(out[obj], s.Rhs[i])
						} else {
							out[obj] = append(out[obj], &ast.BinaryExpr{X: lhs, Op: token.ADD, Y: s.Rhs[i]})
						}
					}
				}
			} else if len(s.Rhs) == 1 {
				for _, lhs := range s.Lhs {
					if obj := objOf(info, lhs); obj != nil {
						out[obj] = append(out[obj], s.Rhs[0])
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range s.Names {
				obj := info.Defs[name]
				if obj == nil {
					continue
				}
				if len(s.Values) == len(s.Names) {
					out[obj] = append(out[obj], s.Values[i])
				} else if len(s.Values) == 1 {
					out[obj] = append(out[obj], s.Values[0])
				}
			}
		case *ast.RangeStmt:
			for _, lhs := range []ast.Expr{s.Key, s.Value} {
				if lhs == nil {
					continue
				}
				if obj := objOf(info, lhs); obj != nil {
					out[obj] = append(out[obj], s.X)
				}
			}
		}
		return true
	})
	return out
}
