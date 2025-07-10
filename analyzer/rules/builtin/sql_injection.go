package builtin

import (
	"go/ast"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// SQLInjectionRule detects insecure SQL query constructions using string concatenation.
var SQLInjectionRule = &analysis.Analyzer{
	Name: "sql_injection",
	Doc:  "Detects potential SQL injection vulnerabilities in raw query constructions",
	Run:  runSQLInjection,
}

// runSQLInjection is the core logic to detect unsafe SQL query building.
func runSQLInjection(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			callExpr, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			selector, ok := callExpr.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			funcName := selector.Sel.Name
			if !isQueryFunc(funcName) {
				return true
			}

			if len(callExpr.Args) == 0 {
				return true
			}

			// Check if the first argument contains string concatenation
			if containsStringConcat(callExpr.Args[0]) {
				pass.Report(analysis.Diagnostic{
					Pos:     callExpr.Pos(),
					End:     callExpr.End(),
					Message: "Potential SQL injection: avoid building queries via string concatenation",
					SuggestedFixes: []analysis.SuggestedFix{
						{
							Message: "Use parameterized queries instead of raw string concatenation",
						},
					},
				})
			}

			return true
		})
	}
	return nil, nil
}

// isQueryFunc checks if the function name is a known SQL execution function.
func isQueryFunc(name string) bool {
	switch strings.ToLower(name) {
	case "query", "exec", "queryrow", "prepare":
		return true
	default:
		return false
	}
}

// containsStringConcat checks for use of '+' operator to build query strings.
func containsStringConcat(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if binExpr.Op == token.ADD {
		// Heuristic: if any side is a string literal, treat as potentially dangerous
		_, leftIsString := binExpr.X.(*ast.BasicLit)
		_, rightIsString := binExpr.Y.(*ast.BasicLit)
		return leftIsString || rightIsString || containsStringConcat(binExpr.X) || containsStringConcat(binExpr.Y)
	}
	return false
}
