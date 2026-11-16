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
	switch x := e.(type) {
	case *ast.CallExpr:
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
		for _, arg := range x.Args {
			if lt.tainted(arg, category) {
				return true
			}
		}
	case *ast.SelectorExpr:
		if isRequestField(lt.info, x) {
			return true
		}
		if _, ok := lt.info.Selections[x]; ok {
			return lt.tainted(x.X, category)
		}
	case *ast.Ident:
		obj, ok := lt.info.Uses[x].(*types.Var)
		if !ok || lt.visiting[obj] {
			return false
		}
		lt.visiting[obj] = true
		defer delete(lt.visiting, obj)
		for _, rhs := range lt.assigns[obj] {
			if lt.tainted(rhs, category) {
				return true
			}
		}
	case *ast.BinaryExpr:
		return lt.tainted(x.X, category) || lt.tainted(x.Y, category)
	case *ast.ParenExpr:
		return lt.tainted(x.X, category)
	case *ast.IndexExpr:
		return lt.tainted(x.X, category)
	case *ast.SliceExpr:
		return lt.tainted(x.X, category)
	case *ast.StarExpr:
		return lt.tainted(x.X, category)
	case *ast.UnaryExpr:
		return lt.tainted(x.X, category)
	case *ast.TypeAssertExpr:
		return lt.tainted(x.X, category)
	case *ast.CompositeLit:
		for _, elt := range x.Elts {
			if lt.tainted(elt, category) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		return lt.tainted(x.Value, category)
	}
	return false
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
	visiting := map[types.Object]bool{}
	var walk func(ast.Expr) bool
	walk = func(e ast.Expr) bool {
		if e == nil {
			return false
		}
		if source(e) {
			return true
		}
		switch x := e.(type) {
		case *ast.CallExpr:
			if barrier != nil && barrier(x) {
				return false
			}
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if _, isMethod := info.Selections[sel]; isMethod && walk(sel.X) {
					return true
				}
			}
			for _, arg := range x.Args {
				if walk(arg) {
					return true
				}
			}
		case *ast.SelectorExpr:
			if _, ok := info.Selections[x]; ok {
				return walk(x.X)
			}
		case *ast.Ident:
			obj, ok := info.Uses[x].(*types.Var)
			if !ok || visiting[obj] {
				return false
			}
			visiting[obj] = true
			for _, rhs := range assigns[obj] {
				if walk(rhs) {
					return true
				}
			}
		case *ast.BinaryExpr:
			return walk(x.X) || walk(x.Y)
		case *ast.ParenExpr:
			return walk(x.X)
		case *ast.IndexExpr:
			return walk(x.X)
		case *ast.SliceExpr:
			return walk(x.X)
		case *ast.StarExpr:
			return walk(x.X)
		case *ast.UnaryExpr:
			return walk(x.X)
		case *ast.TypeAssertExpr:
			return walk(x.X)
		}
		return false
	}
	return walk(e)
}
