package builtin

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterSQLInjectionRule registers the SQL injection detection rule.
func RegisterSQLInjectionRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "sql-injection",
		Title:    "Injection (A03:2025)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "SQL injection vulnerabilities allow attackers to execute malicious SQL queries.",
		Matcher:  matchSQLInjection,
	})
}

// matchSQLInjection detects SQL injection vulnerabilities
func matchSQLInjection(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
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
				pos := ctx.GetFset().Position(callExpr.Pos())
				ctx.Report(result.Issue{
					ID:          "sql-injection",
					Title:       "SQL Injection Vulnerability",
					Description: "Potential SQL injection: avoid building queries via string concatenation",
					Severity:    result.SeverityHigh,
					Location:    result.NewLocationFromPos(pos, "", ""),
					Category:    "security",
					Suggestion:  "Use parameterized queries instead of raw string concatenation",
					References:  []string{"https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"},
				})
			}

			return true
		})
	}
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
