package builtin

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var sqlInjectionMeta = ruleMeta{
	ID: "sql-injection", Title: "SQL Injection", Severity: result.SeverityHigh, CWE: "CWE-89", OWASP: "A05:2025",
	Confidence: 0.8,
	Suggestion: "Use parameterized queries with placeholders ($1 or ?) instead of concatenating or formatting values into SQL.",
	References: []string{"https://cwe.mitre.org/data/definitions/89.html", "https://go.dev/doc/database/sql-injection"},
}

// RegisterSQLInjectionRule reports SQL statements built dynamically from
// non-constant text and passed to a real database API.
func RegisterSQLInjectionRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{sqlInjectionMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				assigns := assignments(info, unit.Body)
				r.expandConstantLookups(assigns)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					idx := sqlQueryArg(calleeFunc(info, call))
					if idx < 0 || idx >= len(call.Args) {
						return true
					}
					arg := call.Args[idx]
					if dynamicSQL(info, arg, assigns, 0) {
						r.report(sqlInjectionMeta, arg, "SQL statement is built from non-constant text and passed to "+callName(call)+".")
					}
					return true
				})
			}
		}
	})
}

// sqlQueryArg returns the index of the query argument of a SQL API call, or -1.
func sqlQueryArg(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	name := fn.Name()
	switch {
	case isMethod(fn, "database/sql", "DB") || isMethod(fn, "database/sql", "Tx") || isMethod(fn, "database/sql", "Conn"):
		switch name {
		case "Query", "QueryRow", "Exec", "Prepare":
			return 0
		case "QueryContext", "QueryRowContext", "ExecContext", "PrepareContext":
			return 1
		}
	case isMethod(fn, "github.com/jmoiron/sqlx", "DB") || isMethod(fn, "github.com/jmoiron/sqlx", "Tx"):
		switch name {
		case "Queryx", "QueryRowx", "MustExec", "NamedExec", "NamedQuery", "Preparex", "PrepareNamed":
			return 0
		case "Get", "Select", "QueryxContext", "QueryRowxContext", "MustExecContext", "NamedExecContext", "PreparexContext":
			return 1
		case "GetContext", "SelectContext":
			return 2
		}
	case fn.Pkg() != nil && (pkgMatches(fn.Pkg().Path(), "github.com/jackc/pgx") || strings.HasPrefix(fn.Pkg().Path(), "github.com/jackc/pgx/")):
		switch name {
		case "Query", "QueryRow", "Exec":
			return 1
		}
	case isMethod(fn, "gorm.io/gorm", "DB"):
		switch name {
		case "Raw", "Exec", "Where", "Or", "Not", "Order", "Having", "Group", "Joins":
			return 0
		}
	}
	return -1
}

func callName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return exprName(f.X) + "." + f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return "the call"
}

// dynamicSQL reports whether e builds SQL by concatenating or formatting a
// non-constant, non-numeric value. Local variables are followed to their assignments.
func dynamicSQL(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, depth int) bool {
	if depth > 6 || isConst(info, e) {
		return false
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		return dynamicSQL(info, x.X, assigns, depth+1)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return false
		}
		return nonConstText(info, x.X, assigns, depth) || nonConstText(info, x.Y, assigns, depth) ||
			dynamicSQL(info, x.X, assigns, depth+1) || dynamicSQL(info, x.Y, assigns, depth+1)
	case *ast.CallExpr:
		fn := calleeFunc(info, x)
		if isFunc(fn, "fmt", "Sprintf") && len(x.Args) > 1 {
			for _, arg := range x.Args[1:] {
				if nonConstText(info, arg, assigns, depth) {
					return true
				}
			}
		}
		if isFunc(fn, "strings", "Join", "Replace", "ReplaceAll") && len(x.Args) > 0 {
			for _, arg := range x.Args {
				if !isConst(info, arg) && isTextType(typeOf(info, arg)) {
					return true
				}
			}
		}
	case *ast.Ident:
		obj, ok := info.Uses[x].(*types.Var)
		if !ok {
			return false
		}
		for _, rhs := range assigns[obj] {
			if dynamicSQL(info, rhs, assigns, depth+1) {
				return true
			}
		}
	}
	return false
}

// nonConstText reports whether e is a non-constant textual operand. Operands
// that are themselves constant SQL fragments or numeric values are ignored.
func nonConstText(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, depth int) bool {
	if isConst(info, e) {
		return false
	}
	t := typeOf(info, e)
	if !isTextType(t) {
		return false
	}
	if call, ok := e.(*ast.CallExpr); ok {
		fn := calleeFunc(info, call)
		if fn != nil && (sanitizes(fn, "sql-injection") || isFunc(fn, "strconv", "Itoa", "FormatInt", "FormatUint", "FormatFloat", "FormatBool")) {
			return false
		}
	}
	if id, ok := e.(*ast.Ident); ok {
		if obj, ok := info.Uses[id].(*types.Var); ok {
			rhs := assigns[obj]
			if len(rhs) > 0 {
				for _, r := range rhs {
					if !isConst(info, r) && !builtFromConstants(info, r, assigns, map[types.Object]bool{obj: true}) {
						return true
					}
				}
				return false
			}
		}
	}
	// A concatenation of constants and variables holding constants.
	return !builtFromConstants(info, e, assigns, map[types.Object]bool{})
}

// builtFromConstants reports whether e is composed solely of constants and
// local variables holding constants (e.g. a query assembled from fixed fragments).
func builtFromConstants(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, visiting map[types.Object]bool) bool {
	if len(visiting) > 8 {
		return false
	}
	if isConst(info, e) {
		return true
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		return builtFromConstants(info, x.X, assigns, visiting)
	case *ast.BinaryExpr:
		return x.Op == token.ADD && builtFromConstants(info, x.X, assigns, visiting) && builtFromConstants(info, x.Y, assigns, visiting)
	case *ast.Ident:
		obj, ok := info.Uses[x].(*types.Var)
		if !ok || len(assigns[obj]) == 0 {
			return false
		}
		if visiting[obj] {
			return true
		}
		visiting[obj] = true
		defer delete(visiting, obj)
		for _, r := range assigns[obj] {
			if !builtFromConstants(info, r, assigns, visiting) {
				return false
			}
		}
		return true
	}
	return false
}
