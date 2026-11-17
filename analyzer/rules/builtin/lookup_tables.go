package builtin

import (
	"go/ast"
	"go/token"
	"go/types"
)

// constantTables returns the package-level lookup tables of the package: map,
// slice and array variables initialized with a literal whose values are all
// constants and that the package only reads (indexes, ranges over or passes
// to len and cap). The result maps each table to its value expressions.
func (r *reporter) constantTables() map[*types.Var][]ast.Expr {
	if r.tables != nil {
		return r.tables
	}
	info := r.pass.TypesInfo
	tables := map[*types.Var][]ast.Expr{}
	for _, file := range r.pass.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					v, ok := info.Defs[name].(*types.Var)
					if !ok || i >= len(vs.Values) {
						continue
					}
					if values, ok := literalConstants(info, vs.Values[i]); ok {
						tables[v] = values
					}
				}
			}
		}
	}
	for _, file := range r.pass.Files {
		removeWrittenTables(info, file, tables)
	}
	r.tables = tables
	return tables
}

// literalConstants returns the element values of a map, slice or array
// literal when all of them are constants.
func literalConstants(info *types.Info, e ast.Expr) ([]ast.Expr, bool) {
	lit, ok := ast.Unparen(e).(*ast.CompositeLit)
	if !ok || len(lit.Elts) == 0 {
		return nil, false
	}
	switch typeOf(info, lit).Underlying().(type) {
	case *types.Map, *types.Slice, *types.Array:
	default:
		return nil, false
	}
	values := make([]ast.Expr, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		if !isConst(info, elt) {
			return nil, false
		}
		values = append(values, elt)
	}
	return values, true
}

// removeWrittenTables drops tables that file uses other than by reading.
func removeWrittenTables(info *types.Info, file *ast.File, tables map[*types.Var][]ast.Expr) {
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if id, ok := n.(*ast.Ident); ok {
			if v, ok := info.Uses[id].(*types.Var); ok {
				if _, isTable := tables[v]; isTable && !readOnlyUse(info, id, stack) {
					delete(tables, v)
				}
			}
		}
		stack = append(stack, n)
		return true
	})
}

// readOnlyUse reports whether the identifier, with its ancestors in stack
// (innermost last), is read: indexed outside an assignment target, ranged
// over, or passed to len or cap.
func readOnlyUse(info *types.Info, id *ast.Ident, stack []ast.Node) bool {
	if len(stack) == 0 {
		return false
	}
	switch p := stack[len(stack)-1].(type) {
	case *ast.IndexExpr:
		if p.X != id {
			return true // used as an index
		}
		if len(stack) < 2 {
			return true
		}
		switch gp := stack[len(stack)-2].(type) {
		case *ast.AssignStmt:
			for _, lhs := range gp.Lhs {
				if lhs == p {
					return false
				}
			}
		case *ast.IncDecStmt:
			return false
		case *ast.UnaryExpr:
			return gp.Op != token.AND
		}
		return true
	case *ast.RangeStmt:
		return p.X == id
	case *ast.CallExpr:
		if fn, ok := ast.Unparen(p.Fun).(*ast.Ident); ok {
			if b, ok := info.Uses[fn].(*types.Builtin); ok {
				return b.Name() == "len" || b.Name() == "cap"
			}
		}
	}
	return false
}

// expandConstantLookups replaces reads of constant lookup tables in assigns
// with the table's values, so that `col, ok := sortColumns[key]` is treated
// as one of the table's constant entries. Variables of another type, such as
// the ok result, are left unchanged.
func (r *reporter) expandConstantLookups(assigns map[types.Object][]ast.Expr) {
	info := r.pass.TypesInfo
	for obj, rhs := range assigns {
		var expanded []ast.Expr
		changed := false
		for _, e := range rhs {
			if values, ok := r.lookupValues(info, obj, e); ok {
				expanded = append(expanded, values...)
				changed = true
				continue
			}
			expanded = append(expanded, e)
		}
		if changed {
			assigns[obj] = expanded
		}
	}
}

func (r *reporter) lookupValues(info *types.Info, obj types.Object, e ast.Expr) ([]ast.Expr, bool) {
	ix, ok := ast.Unparen(e).(*ast.IndexExpr)
	if !ok {
		return nil, false
	}
	id, ok := ast.Unparen(ix.X).(*ast.Ident)
	if !ok {
		return nil, false
	}
	table, ok := info.Uses[id].(*types.Var)
	if !ok {
		return nil, false
	}
	values, ok := r.constantTables()[table]
	if !ok || !types.Identical(obj.Type(), typeOf(info, values[0])) && !types.AssignableTo(typeOf(info, values[0]), obj.Type()) {
		return nil, false
	}
	return values, true
}
