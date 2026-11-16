package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var (
	gqlUnboundedMeta = ruleMeta{ID: "graphql-unbounded-query", Title: "GraphQL Query Complexity Not Limited", Severity: result.SeverityMedium, CWE: "CWE-400", OWASP: "A06:2025", Confidence: 0.8,
		Suggestion: "Add srv.Use(extension.FixedComplexityLimit(n)) to reject expensive nested queries.",
		References: []string{"https://gqlgen.com/reference/complexity/"}}
	gqlIntrospectionMeta = ruleMeta{ID: "graphql-introspection-enabled", Title: "GraphQL Introspection Enabled Unconditionally", Severity: result.SeverityLow, CWE: "CWE-200", OWASP: "A02:2025",
		Suggestion: "Enable extension.Introspection only in development builds or behind a configuration flag.",
		References: []string{"https://cwe.mitre.org/data/definitions/200.html"}}
)

const gqlgenHandler = "github.com/99designs/gqlgen/graphql/handler"

// RegisterGraphQLSecurityRule inspects gqlgen server construction.
func RegisterGraphQLSecurityRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{gqlUnboundedMeta, gqlIntrospectionMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				var servers []*ast.CallExpr
				limited := false
				inspectShallow(unit.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						fn := calleeFunc(info, x)
						switch {
						case isFunc(fn, gqlgenHandler, "New", "NewDefaultServer"):
							servers = append(servers, x)
						case fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/99designs/gqlgen/graphql/handler/extension" && fn.Name() == "FixedComplexityLimit":
							limited = true
						case isMethod(fn, gqlgenHandler, "Server", "Use") && len(x.Args) == 1:
							if introspection(info, x.Args[0]) && !conditional(unit.Body, x) {
								r.report(gqlIntrospectionMeta, x, "GraphQL schema introspection is enabled for every client.")
							}
						}
					case *ast.CompositeLit:
						if t := typeOf(info, x); typeIs(t, "github.com/99designs/gqlgen/graphql/handler/extension", "ComplexityLimit") {
							limited = true
						}
					}
					return true
				})
				if !limited {
					for _, s := range servers {
						r.report(gqlUnboundedMeta, s, "GraphQL server is created without a query complexity limit.")
					}
				}
			}
		}
	})
}

func introspection(info *types.Info, e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	return typeIs(typeOf(info, e), "github.com/99designs/gqlgen/graphql/handler/extension", "Introspection")
}

// conditional reports whether node is nested inside an if or switch statement in body.
func conditional(body ast.Node, node ast.Node) bool {
	var stack []ast.Node
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if n == node {
			for _, a := range stack {
				switch a.(type) {
				case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.CaseClause:
					found = true
				}
			}
			return false
		}
		stack = append(stack, n)
		return true
	})
	return found
}
