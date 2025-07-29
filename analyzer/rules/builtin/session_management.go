package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterSessionManagementRule registers the Session Management Issues detection rule.
func RegisterSessionManagementRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "session-management",
		Title:    "Session Management Issues",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Session management vulnerabilities can lead to unauthorized access and session hijacking.",
		Matcher:  matchSessionManagement,
	})
}

// matchSessionManagement detects session management vulnerabilities
func matchSessionManagement(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				analyzeSessionManagementCall(x, ctx)
			case *ast.AssignStmt:
				analyzeSessionManagementAssignment(x, ctx)
			case *ast.IfStmt:
				analyzeSessionManagementCondition(x, ctx)
			case *ast.FuncDecl:
				analyzeSessionManagementFunction(x, ctx)
			}
			return true
		})
	}
}

// analyzeSessionManagementCall analyzes function calls for session management issues
func analyzeSessionManagementCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for session management function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isSessionManagementIssue(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "session-management-call",
				Title:       "Session Management Issue",
				Description: "Function call '" + fun.Name + "' may have session management vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review session management implementation for security issues",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}

	// Check for session management issues in function arguments
	for _, arg := range call.Args {
		if isSessionManagementArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "session-management-argument",
				Title:       "Session Management Argument Issue",
				Description: "Session management argument may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review session management arguments for security issues",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// analyzeSessionManagementAssignment analyzes assignments for session management issues
func analyzeSessionManagementAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for session management assignments
	for _, expr := range assign.Rhs {
		if isSessionManagementAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "session-management-assignment",
				Title:       "Session Management Assignment Issue",
				Description: "Session management assignment may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review session management assignments for security issues",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// analyzeSessionManagementCondition analyzes if statements for session management issues
func analyzeSessionManagementCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for session management conditions
	if ifStmt.Cond != nil {
		condStr := getSessionNodeString(ifStmt.Cond)
		if isSessionManagementCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "session-management-condition",
				Title:       "Session Management Condition Issue",
				Description: "Session management condition may have security vulnerabilities: " + condStr,
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review session management conditions for security issues",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// analyzeSessionManagementFunction analyzes function declarations for session management issues
func analyzeSessionManagementFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for session management function names
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isSessionManagementFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "session-management-function",
				Title:       "Session Management Function Issue",
				Description: "Function '" + fn.Name.Name + "' may have session management vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review session management function implementation for security issues",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// isSessionManagementIssue checks if function call indicates session management issues
func isSessionManagementIssue(funcName string) bool {
	sessionPatterns := []string{
		"session", "token", "cookie", "jwt", "auth",
		"login", "logout", "signin", "signout",
		"remember", "persist", "store", "save",
		"expire", "timeout", "refresh", "renew",
		"invalidate", "destroy", "clear", "remove",
		"set_session", "get_session", "create_session",
		"validate_session", "check_session", "verify_session",
		"session_id", "session_token", "session_key",
		"session_timeout", "session_expiry", "session_lifetime",
		"session_store", "session_cache", "session_db",
		"session_cookie", "session_header", "session_param",
	}

	for _, pattern := range sessionPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isSessionManagementArgument checks if function argument indicates session management issues
func isSessionManagementArgument(arg ast.Expr) bool {
	// Check for session management identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isSessionManagementIssue(strings.ToLower(ident.Name))
	}

	// Check for session management literals
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		sessionValues := []string{
			"session", "token", "cookie", "jwt", "auth",
			"login", "logout", "signin", "signout",
			"remember", "persist", "store", "save",
			"expire", "timeout", "refresh", "renew",
			"invalidate", "destroy", "clear", "remove",
		}
		for _, sessionValue := range sessionValues {
			if strings.Contains(value, sessionValue) {
				return true
			}
		}
	}

	return false
}

// isSessionManagementAssignment checks if assignment indicates session management issues
func isSessionManagementAssignment(expr ast.Expr) bool {
	// Check for session management identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isSessionManagementIssue(strings.ToLower(ident.Name))
	}

	// Check for session management literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		sessionValues := []string{
			"session", "token", "cookie", "jwt", "auth",
			"login", "logout", "signin", "signout",
			"remember", "persist", "store", "save",
			"expire", "timeout", "refresh", "renew",
			"invalidate", "destroy", "clear", "remove",
		}
		for _, sessionValue := range sessionValues {
			if strings.Contains(value, sessionValue) {
				return true
			}
		}
	}

	return false
}

// isSessionManagementCondition checks if condition indicates session management issues
func isSessionManagementCondition(condition string) bool {
	sessionPatterns := []string{
		"session", "token", "cookie", "jwt", "auth",
		"login", "logout", "signin", "signout",
		"remember", "persist", "store", "save",
		"expire", "timeout", "refresh", "renew",
		"invalidate", "destroy", "clear", "remove",
		"session == nil", "session == \"\"", "session == null",
		"token == nil", "token == \"\"", "token == null",
		"cookie == nil", "cookie == \"\"", "cookie == null",
		"jwt == nil", "jwt == \"\"", "jwt == null",
		"auth == nil", "auth == \"\"", "auth == null",
		"!session", "!token", "!cookie", "!jwt", "!auth",
		"session == false", "token == false", "cookie == false",
		"jwt == false", "auth == false",
		"session == 0", "token == 0", "cookie == 0",
		"jwt == 0", "auth == 0",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range sessionPatterns {
		if strings.Contains(condLower, pattern) {
			return true
		}
	}
	return false
}

// isSessionManagementFunction checks if function name indicates session management issues
func isSessionManagementFunction(funcName string) bool {
	sessionFunctions := []string{
		"session", "token", "cookie", "jwt", "auth",
		"login", "logout", "signin", "signout",
		"remember", "persist", "store", "save",
		"expire", "timeout", "refresh", "renew",
		"invalidate", "destroy", "clear", "remove",
		"set_session", "get_session", "create_session",
		"validate_session", "check_session", "verify_session",
		"session_id", "session_token", "session_key",
		"session_timeout", "session_expiry", "session_lifetime",
		"session_store", "session_cache", "session_db",
		"session_cookie", "session_header", "session_param",
		"create_token", "validate_token", "verify_token",
		"refresh_token", "revoke_token", "invalidate_token",
		"set_cookie", "get_cookie", "clear_cookie",
		"create_jwt", "validate_jwt", "verify_jwt",
		"refresh_jwt", "revoke_jwt", "invalidate_jwt",
		"login_user", "logout_user", "authenticate_user",
		"remember_user", "forget_user", "persist_user",
	}

	for _, sessionFunc := range sessionFunctions {
		if strings.Contains(funcName, sessionFunc) {
			return true
		}
	}
	return false
}

// getSessionNodeString returns a string representation of an AST node
func getSessionNodeString(node ast.Node) string {
	// This is a simplified implementation
	// In a real implementation, you would use go/printer to get the exact string
	switch x := node.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.BinaryExpr:
		return getNodeString(x.X) + " " + x.Op.String() + " " + getNodeString(x.Y)
	default:
		return "unknown"
	}
} 