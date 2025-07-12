package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterAccessControlRule registers the access control violation detection rule.
func RegisterAccessControlRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "broken-access-control",
		Title:    "Broken Access Control",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Missing or insufficient access control checks may lead to unauthorized access.",
		Matcher:  matchAccessControlViolations,
	})
}

// matchAccessControlViolations detects access control violations
func matchAccessControlViolations(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				// Check for functions that handle sensitive operations without proper auth
				if isSensitiveOperation(x.Name.Name) {
					if !hasAuthCheck(x) {
						pos := ctx.GetFset().Position(x.Pos())
						ctx.Report(result.Issue{
							ID:          "broken-access-control",
							Title:       "Missing Access Control",
							Description: "Sensitive operation without proper authentication/authorization checks",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Add proper authentication and authorization checks before sensitive operations",
						})
					}
				}
			case *ast.CallExpr:
				// Check for direct database access without auth
				if isDirectDBAccess(x) && !hasAuthCheck(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "broken-access-control",
						Title:       "Unauthorized Database Access",
						Description: "Direct database access without proper authorization",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Implement proper authorization checks before database operations",
					})
				}
			}
			return true
		})
	}
}

// isSensitiveOperation checks if function name suggests sensitive operations
func isSensitiveOperation(funcName string) bool {
	sensitiveOps := []string{
		"delete", "remove", "update", "modify", "create", "add",
		"admin", "root", "privileged", "sensitive", "confidential",
		"user", "password", "credential", "token", "session",
	}

	funcNameLower := strings.ToLower(funcName)
	for _, op := range sensitiveOps {
		if strings.Contains(funcNameLower, op) {
			return true
		}
	}
	return false
}

// hasAuthCheck checks if function has authentication/authorization checks
func hasAuthCheck(node ast.Node) bool {
	var hasAuth bool
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				// Check for common auth patterns
				authPatterns := []string{
					"Authenticate", "Authorize", "Validate", "CheckAuth",
					"RequireAuth", "VerifyToken", "ValidateSession",
					"IsAdmin", "HasPermission", "CheckRole",
				}
				for _, pattern := range authPatterns {
					if strings.Contains(funcName, pattern) {
						hasAuth = true
						return false
					}
				}
			}
		}
		return true
	})
	return hasAuth
}

// isDirectDBAccess checks if call is direct database access
func isDirectDBAccess(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := fun.X.(*ast.Ident); ok {
			// Check for direct database access patterns
			dbPatterns := []string{"db", "database", "sql", "query", "exec"}
			for _, pattern := range dbPatterns {
				if strings.Contains(strings.ToLower(ident.Name), pattern) {
					return true
				}
			}
		}
	}
	return false
}
