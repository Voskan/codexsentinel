package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterCSRFRule registers the CSRF detection rule.
func RegisterCSRFRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "csrf-vulnerability",
		Title:    "Cross-Site Request Forgery (CSRF)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Missing CSRF protection in state-changing operations may lead to unauthorized actions.",
		Matcher:  matchCSRFVulnerability,
	})
}

// matchCSRFVulnerability detects CSRF vulnerabilities in HTTP handlers.
func matchCSRFVulnerability(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				// Check for HTTP handlers that handle state-changing operations
				if isHTTPHandler(x) && isStateChangingOperation(x) {
					if !hasCSRFProtection(x) {
						pos := ctx.GetFset().Position(x.Pos())
						ctx.Report(result.Issue{
							ID:          "csrf-vulnerability",
							Title:       "Missing CSRF Protection",
							Description: "State-changing HTTP handler lacks CSRF protection",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Implement CSRF protection using tokens, SameSite cookies, or referrer validation",
							References:  []string{"https://owasp.org/www-community/attacks/csrf"},
						})
					}
				}
			case *ast.CallExpr:
				// Check for database operations without CSRF protection
				if isDatabaseOperation(x) && !hasCSRFProtection(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "csrf-vulnerability",
						Title:       "Database Operation Without CSRF Protection",
						Description: "Database write operation performed without CSRF protection",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Add CSRF token validation before database write operations",
						References:  []string{"https://owasp.org/www-community/attacks/csrf"},
					})
				}
			}
			return true
		})
	}
}

// isHTTPHandler checks if function is likely an HTTP handler
func isHTTPHandler(fn *ast.FuncDecl) bool {
	if fn.Recv == nil {
		return false
	}

	// Check for common HTTP handler patterns
	handlerPatterns := []string{
		"Handler", "ServeHTTP", "Handle", "Process",
		"Create", "Update", "Delete", "Post", "Put",
		"Login", "Logout", "Register", "Reset",
	}

	funcName := strings.ToLower(fn.Name.Name)
	for _, pattern := range handlerPatterns {
		if strings.Contains(funcName, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for http.ResponseWriter parameter
	for _, param := range fn.Type.Params.List {
		if sel, ok := param.Type.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "http" {
				if sel.Sel.Name == "ResponseWriter" {
					return true
				}
			}
		}
	}

	return false
}

// isStateChangingOperation checks if function performs state-changing operations
func isStateChangingOperation(fn *ast.FuncDecl) bool {
	stateChangingPatterns := []string{
		"create", "update", "delete", "remove", "modify",
		"insert", "save", "store", "write", "set",
		"login", "logout", "register", "reset", "change",
		"transfer", "payment", "order", "purchase",
	}

	funcName := strings.ToLower(fn.Name.Name)
	for _, pattern := range stateChangingPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}

	// Check for database write operations in function body
	var hasWriteOp bool
	ast.Inspect(fn, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if isDatabaseWriteOperation(x) {
				hasWriteOp = true
				return false
			}
		}
		return true
	})

	return hasWriteOp
}

// isDatabaseWriteOperation checks if call is a database write operation
func isDatabaseWriteOperation(call *ast.CallExpr) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(sel.Sel.Name)
		writePatterns := []string{
			"exec", "execute", "queryrow", "query",
			"insert", "update", "delete", "create",
			"save", "store", "write", "set",
		}
		for _, pattern := range writePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isDatabaseOperation checks if call is any database operation
func isDatabaseOperation(call *ast.CallExpr) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(sel.Sel.Name)
		dbPatterns := []string{
			"exec", "execute", "query", "queryrow",
			"insert", "update", "delete", "select",
			"create", "drop", "alter", "save",
		}
		for _, pattern := range dbPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// hasCSRFProtection checks if function has CSRF protection
func hasCSRFProtection(node ast.Node) bool {
	var hasProtection bool
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := strings.ToLower(sel.Sel.Name)
				// Check for CSRF protection patterns
				csrfPatterns := []string{
					"validatecsrf", "checkcsrf", "verifycsrf",
					"validatetoken", "checktoken", "verifytoken",
					"csrf", "xsrf", "antiforgery",
				}
				for _, pattern := range csrfPatterns {
					if strings.Contains(funcName, pattern) {
						hasProtection = true
						return false
					}
				}
			}
		case *ast.Ident:
			// Check for CSRF-related variable names
			varName := strings.ToLower(x.Name)
			csrfVars := []string{
				"csrftoken", "xsrftoken", "antiforgerytoken",
				"csrf_token", "xsrf_token", "antiforgery_token",
			}
			for _, pattern := range csrfVars {
				if strings.Contains(varName, pattern) {
					hasProtection = true
					return false
				}
			}
		}
		return true
	})
	return hasProtection
} 