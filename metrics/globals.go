// Package metrics provides analysis of code quality metrics such as global state usage.
package metrics

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"golang.org/x/tools/go/packages"
)

// GlobalSymbol represents a package-level variable holding mutable shared state.
type GlobalSymbol struct {
	Name     string // Symbol name
	Kind     string // Always "var"; constants are immutable and never reported
	PkgPath  string // Full import path of the package
	File     string // File where symbol is defined
	Line     int    // Line number
	Exported bool   // Whether the symbol is exported
	Mutable  bool   // Whether the symbol can change at run time
	HasInit  bool   // Whether the symbol has an initializer
	Reason   string // Why the variable is considered mutable shared state
}

var errorType = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

// AnalyzeGlobals reports package-level variables of the workspace that hold
// mutable shared state. Idiomatic immutable package values are not reported:
// constants, sentinel errors, compiled regular expressions, embedded file
// systems, synchronization primitives and lookup tables that are never written.
func AnalyzeGlobals(ws *workspace.Workspace) []GlobalSymbol {
	writes := globalWrites(ws)
	var results []GlobalSymbol
	for _, pkg := range ws.Packages {
		for _, file := range ws.Files(pkg) {
			if strings.HasSuffix(ws.Fset.Position(file.Pos()).Filename, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					continue
				}
				for _, spec := range gen.Specs {
					results = append(results, mutableGlobals(ws.Fset, pkg, spec.(*ast.ValueSpec), writes)...)
				}
			}
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].File != results[j].File {
			return results[i].File < results[j].File
		}
		return results[i].Line < results[j].Line
	})
	return results
}

func mutableGlobals(fset *token.FileSet, pkg *packages.Package, spec *ast.ValueSpec, writes map[*types.Var]string) []GlobalSymbol {
	var out []GlobalSymbol
	for idx, name := range spec.Names {
		if name.Name == "_" {
			continue
		}
		v, ok := pkg.TypesInfo.Defs[name].(*types.Var)
		if !ok {
			continue
		}
		var value ast.Expr
		if len(spec.Values) == len(spec.Names) {
			value = spec.Values[idx]
		}
		if immutableValue(pkg.TypesInfo, v.Type(), value) {
			continue
		}
		reason := writes[v]
		if reason == "" && emptyContainer(v.Type(), value) {
			reason = "populated at run time"
		}
		if reason == "" {
			continue
		}
		pos := fset.Position(name.Pos())
		out = append(out, GlobalSymbol{
			Name: name.Name, Kind: "var", PkgPath: pkg.PkgPath, File: pos.Filename, Line: pos.Line,
			Exported: name.IsExported(), Mutable: true, HasInit: value != nil, Reason: reason,
		})
	}
	return out
}

// immutableValue reports whether a package variable follows an idiom for
// effectively immutable values.
func immutableValue(info *types.Info, t types.Type, value ast.Expr) bool {
	if types.Implements(t, errorType) {
		return true
	}
	if call, ok := ast.Unparen(value).(*ast.CallExpr); ok {
		if fn, ok := calleeObject(info, call).(*types.Func); ok && fn.Pkg() != nil {
			switch fn.Pkg().Path() + "." + fn.Name() {
			case "errors.New", "fmt.Errorf":
				return true
			}
		}
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	switch named.Obj().Pkg().Path() + "." + named.Obj().Name() {
	case "regexp.Regexp", "embed.FS", "sync.Mutex", "sync.RWMutex", "sync.Once", "sync.Pool", "sync.WaitGroup",
		"text/template.Template", "html/template.Template":
		return true
	}
	return false
}

func calleeObject(info *types.Info, call *ast.CallExpr) types.Object {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return info.Uses[fun]
	case *ast.SelectorExpr:
		return info.Uses[fun.Sel]
	}
	return nil
}

// emptyContainer reports whether a map, slice or channel variable starts empty,
// which means it is filled while the program runs.
func emptyContainer(t types.Type, value ast.Expr) bool {
	switch t.Underlying().(type) {
	case *types.Map, *types.Slice, *types.Chan:
	default:
		return false
	}
	switch x := ast.Unparen(value).(type) {
	case nil:
		return true
	case *ast.CompositeLit:
		return len(x.Elts) == 0
	case *ast.CallExpr:
		id, ok := ast.Unparen(x.Fun).(*ast.Ident)
		return ok && id.Name == "make"
	}
	return false
}

// globalWrites records package-level variables modified inside function bodies
// (other than package initializers), keyed to the first function that writes them.
func globalWrites(ws *workspace.Workspace) map[*types.Var]string {
	writes := map[*types.Var]string{}
	for _, pkg := range ws.Packages {
		info := pkg.TypesInfo
		for _, file := range ws.Files(pkg) {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || (fn.Recv == nil && fn.Name.Name == "init") {
					continue
				}
				record := func(e ast.Expr) {
					if v := rootGlobal(info, e); v != nil && writes[v] == "" {
						writes[v] = "modified in " + funcName(fn)
					}
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						if x.Tok != token.DEFINE {
							for _, lhs := range x.Lhs {
								record(lhs)
							}
						}
					case *ast.IncDecStmt:
						record(x.X)
					case *ast.UnaryExpr:
						if x.Op == token.AND {
							record(x.X)
						}
					case *ast.CallExpr:
						if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok && id.Name == "delete" && len(x.Args) > 0 {
							record(x.Args[0])
						}
					}
					return true
				})
			}
		}
	}
	return writes
}

// rootGlobal returns the package-level variable at the root of an lvalue such
// as cache[k], cfg.Field or *ptr.
func rootGlobal(info *types.Info, e ast.Expr) *types.Var {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[x]; ok {
				if sel.Kind() != types.FieldVal {
					return nil
				}
				e = x.X
				continue
			}
			return packageVar(info.Uses[x.Sel])
		case *ast.Ident:
			return packageVar(info.Uses[x])
		default:
			return nil
		}
	}
}

func packageVar(obj types.Object) *types.Var {
	v, ok := obj.(*types.Var)
	if !ok || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return nil
	}
	return v
}
