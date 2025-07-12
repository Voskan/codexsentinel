package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterLoggingMonitoringRule registers the security logging and monitoring failure detection rule.
func RegisterLoggingMonitoringRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "security-logging-failure",
		Title:    "Security Logging and Monitoring Failures",
		Category: "security",
		Severity: result.SeverityMedium,
		Summary:  "Missing or insufficient security logging and monitoring for security events.",
		Matcher:  matchLoggingMonitoringFailures,
	})
}

// matchLoggingMonitoringFailures detects security logging and monitoring failures
func matchLoggingMonitoringFailures(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				// Check for security-sensitive functions without logging
				if isSecuritySensitiveFunction(x) && !hasSecurityLogging(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-logging-failure",
						Title:       "Missing Security Logging",
						Description: "Security-sensitive function lacks proper logging",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Add security event logging for authentication, authorization, and sensitive operations",
					})
				}
			case *ast.CallExpr:
				// Check for authentication/authorization without logging
				if isAuthOperation(x) && !hasAuthLogging(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-logging-failure",
						Title:       "Authentication Without Logging",
						Description: "Authentication/authorization operation without security logging",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Log authentication attempts, successes, and failures",
					})
				}

				// Check for error handling without logging
				if isErrorHandling(x) && !hasErrorLogging(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-logging-failure",
						Title:       "Error Handling Without Logging",
						Description: "Error handling without proper security logging",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Log security-related errors for monitoring and alerting",
					})
				}
			}
			return true
		})
	}
}

// isSecuritySensitiveFunction checks if function handles security-sensitive operations
func isSecuritySensitiveFunction(funcDecl *ast.FuncDecl) bool {
	funcName := strings.ToLower(funcDecl.Name.Name)
	securityPatterns := []string{
		"login", "logout", "auth", "authenticate", "authorize",
		"password", "token", "session", "credential", "permission",
		"admin", "user", "role", "privilege", "access",
	}

	for _, pattern := range securityPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// hasSecurityLogging checks if function has security logging
func hasSecurityLogging(funcDecl *ast.FuncDecl) bool {
	if funcDecl.Body == nil {
		return false
	}

	var hasLogging bool
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				// Check for logging patterns
				loggingPatterns := []string{
					"Log", "Logger", "Info", "Warn", "Error", "Debug",
					"Security", "Audit", "Event", "Monitor",
				}
				for _, pattern := range loggingPatterns {
					if strings.Contains(funcName, pattern) {
						hasLogging = true
						return false
					}
				}
			}
		}
		return true
	})
	return hasLogging
}

// isAuthOperation checks if call is an authentication/authorization operation
func isAuthOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		authPatterns := []string{
			"Login", "Logout", "Authenticate", "Authorize", "Validate",
			"CheckAuth", "VerifyToken", "ValidateSession", "CheckPermission",
		}

		for _, pattern := range authPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// hasAuthLogging checks if auth operation has logging
func hasAuthLogging(call *ast.CallExpr) bool {
	// Check if there are logging calls in the same scope
	var hasLogging bool
	ast.Inspect(call, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				if strings.Contains(funcName, "Log") ||
					strings.Contains(funcName, "Info") ||
					strings.Contains(funcName, "Warn") ||
					strings.Contains(funcName, "Error") {
					hasLogging = true
					return false
				}
			}
		}
		return true
	})
	return hasLogging
}

// isErrorHandling checks if call is error handling
func isErrorHandling(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		errorPatterns := []string{
			"Error", "Fatal", "Panic", "Handle", "Recover",
		}

		for _, pattern := range errorPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// hasErrorLogging checks if error handling has logging
func hasErrorLogging(call *ast.CallExpr) bool {
	var hasLogging bool
	ast.Inspect(call, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				if strings.Contains(funcName, "Log") ||
					strings.Contains(funcName, "Error") ||
					strings.Contains(funcName, "Fatal") {
					hasLogging = true
					return false
				}
			}
		}
		return true
	})
	return hasLogging
}
