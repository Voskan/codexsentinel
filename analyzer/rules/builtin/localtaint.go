package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer/flow"
)

var taintCatalog = flow.DefaultRegistry()

// localTaint answers whether an expression inside one function is derived from
// untrusted HTTP input, following local variable assignments.
type localTaint struct {
	info     *types.Info
	assigns  map[types.Object][]ast.Expr
	visiting map[types.Object]bool
}

func newLocalTaint(info *types.Info, body ast.Node) *localTaint {
	return &localTaint{info: info, assigns: assignments(info, body), visiting: map[types.Object]bool{}}
}

func funcIdentity(fn *types.Func) (pkg, recv, name string) {
	if fn == nil || fn.Pkg() == nil {
		return "", "", ""
	}
	if r := recvOf(fn); r != nil {
		_, recv = namedOf(r.Type())
	}
	return fn.Pkg().Path(), recv, fn.Name()
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// isHTTPSource reports whether fn returns untrusted HTTP request data.
func isHTTPSource(fn *types.Func) bool {
	pkg, recv, name := funcIdentity(fn)
	if pkg == "" {
		return false
	}
	for _, s := range taintCatalog.Sources {
		if s.Kind == flow.SourceCall && hasTag(s.Tags, "http") && s.Package == pkg && s.Receiver == recv && s.Function == name {
			return true
		}
	}
	return false
}

// sanitizes reports whether fn cleans its input for category.
func sanitizes(fn *types.Func, category string) bool {
	pkg, recv, name := funcIdentity(fn)
	if pkg == "" {
		return false
	}
	for _, s := range taintCatalog.Sanitizers {
		if s.Package == pkg && s.Receiver == recv && s.Function == name {
			for _, c := range s.Categories {
				if c == "*" || c == category {
					return true
				}
			}
		}
	}
	return false
}

func isRequestField(info *types.Info, sel *ast.SelectorExpr) bool {
	if !typeIs(typeOf(info, sel.X), "net/http", "Request") {
		return false
	}
	for _, s := range taintCatalog.Sources {
		if s.Kind == flow.SourceField && s.Package == "net/http" && s.Receiver == "Request" && s.Function == sel.Sel.Name {
			return true
		}
	}
	return false
}

// tainted reports whether e carries untrusted HTTP data not sanitized for category.
func (lt *localTaint) tainted(e ast.Expr, category string) bool {
	if inner := wrappedExpr(e); inner != nil {
		return lt.tainted(inner, category)
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		return lt.taintedCall(x, category)
	case *ast.SelectorExpr:
		if isRequestField(lt.info, x) {
			return true
		}
		if _, ok := lt.info.Selections[x]; ok {
			return lt.tainted(x.X, category)
		}
	case *ast.Ident:
		return lt.taintedVar(x, category)
	case *ast.BinaryExpr:
		return lt.tainted(x.X, category) || lt.tainted(x.Y, category)
	case *ast.CompositeLit:
		return lt.anyTainted(x.Elts, category)
	}
	return false
}

func (lt *localTaint) anyTainted(exprs []ast.Expr, category string) bool {
	for _, e := range exprs {
		if lt.tainted(e, category) {
			return true
		}
	}
	return false
}

// taintedCall handles conversions, sources, sanitizers and calls whose
// receiver or arguments are tainted.
func (lt *localTaint) taintedCall(x *ast.CallExpr, category string) bool {
	if tv, ok := lt.info.Types[x.Fun]; ok && tv.IsType() {
		return len(x.Args) == 1 && lt.tainted(x.Args[0], category)
	}
	if t := typeOf(lt.info, x); t != nil && !carriesText(t) {
		return false
	}
	fn := calleeFunc(lt.info, x)
	if isHTTPSource(fn) {
		return true
	}
	if fn != nil && sanitizes(fn, category) {
		return false
	}
	if sel, ok := x.Fun.(*ast.SelectorExpr); ok && fn != nil && recvOf(fn) != nil && lt.tainted(sel.X, category) {
		return true
	}
	return lt.anyTainted(x.Args, category)
}

// taintedVar follows the local assignments of a variable.
func (lt *localTaint) taintedVar(id *ast.Ident, category string) bool {
	obj, ok := lt.info.Uses[id].(*types.Var)
	if !ok || lt.visiting[obj] {
		return false
	}
	lt.visiting[obj] = true
	defer delete(lt.visiting, obj)
	return lt.anyTainted(lt.assigns[obj], category)
}

// wrappedExpr returns the operand of expressions that carry their operand's
// data unchanged (parentheses, indexing, slicing, dereference, unary
// operators, type assertions and key-value pairs), or nil.
func wrappedExpr(e ast.Expr) ast.Expr {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return x.X
	case *ast.IndexExpr:
		return x.X
	case *ast.SliceExpr:
		return x.X
	case *ast.StarExpr:
		return x.X
	case *ast.UnaryExpr:
		return x.X
	case *ast.TypeAssertExpr:
		return x.X
	case *ast.KeyValueExpr:
		return x.Value
	}
	return nil
}

// carriesText reports whether a value of type t can hold injected text.
func carriesText(t types.Type) bool {
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&(types.IsNumeric|types.IsBoolean) == 0
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if carriesText(u.At(i).Type()) {
				return true
			}
		}
		return false
	}
	return true
}

// derivesFrom reports whether e is built from an expression matching source,
// following local assignments. Calls for which barrier returns true stop the search.
func derivesFrom(info *types.Info, assigns map[types.Object][]ast.Expr, e ast.Expr, source func(ast.Expr) bool, barrier func(*ast.CallExpr) bool) bool {
	d := derivation{info: info, assigns: assigns, source: source, barrier: barrier, visiting: map[types.Object]bool{}}
	return d.walk(e)
}

type derivation struct {
	info     *types.Info
	assigns  map[types.Object][]ast.Expr
	source   func(ast.Expr) bool
	barrier  func(*ast.CallExpr) bool
	visiting map[types.Object]bool
}

func (d *derivation) walk(e ast.Expr) bool {
	if e == nil {
		return false
	}
	if d.source(e) {
		return true
	}
	if _, isKV := e.(*ast.KeyValueExpr); !isKV {
		if inner := wrappedExpr(e); inner != nil {
			return d.walk(inner)
		}
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		return d.walkCall(x)
	case *ast.SelectorExpr:
		if _, ok := d.info.Selections[x]; ok {
			return d.walk(x.X)
		}
	case *ast.Ident:
		obj, ok := d.info.Uses[x].(*types.Var)
		if !ok || d.visiting[obj] {
			return false
		}
		d.visiting[obj] = true
		return d.walkAll(d.assigns[obj])
	case *ast.BinaryExpr:
		return d.walk(x.X) || d.walk(x.Y)
	}
	return false
}

func (d *derivation) walkCall(x *ast.CallExpr) bool {
	if d.barrier != nil && d.barrier(x) {
		return false
	}
	if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
		if _, isMethod := d.info.Selections[sel]; isMethod && d.walk(sel.X) {
			return true
		}
	}
	return d.walkAll(x.Args)
}

func (d *derivation) walkAll(exprs []ast.Expr) bool {
	for _, e := range exprs {
		if d.walk(e) {
			return true
		}
	}
	return false
}
