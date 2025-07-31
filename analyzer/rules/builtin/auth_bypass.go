package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterAuthBypassRule registers the Authentication Bypass detection rule.
func RegisterAuthBypassRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "auth-bypass",
		Title:    "Identification and Authentication Failures (A07:2025)",
		Category: "security",
		Severity: result.SeverityCritical,
		Summary:  "Authentication bypass vulnerabilities allow unauthorized access to protected resources.",
		Matcher:  matchAuthBypass,
	})
}

// matchAuthBypass detects authentication bypass vulnerabilities
func matchAuthBypass(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				analyzeAuthBypassFunction(x, ctx)
			case *ast.IfStmt:
				analyzeAuthBypassCondition(x, ctx)
			case *ast.AssignStmt:
				analyzeAuthBypassAssignment(x, ctx)
			case *ast.CallExpr:
				analyzeAuthBypassCall(x, ctx)
			}
			return true
		})
	}
}

// analyzeAuthBypassFunction analyzes function declarations for auth bypass patterns
func analyzeAuthBypassFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for hardcoded authentication bypass
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isAuthBypassFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "auth-bypass-function",
				Title:       "Authentication Bypass Function",
				Description: "Function '" + fn.Name.Name + "' appears to bypass authentication",
				Severity:    result.SeverityCritical,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Remove or properly secure authentication bypass functions",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}

	// Check function body for auth bypass patterns
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			analyzeAuthBypassCondition(x, ctx)
		case *ast.AssignStmt:
			analyzeAuthBypassAssignment(x, ctx)
		case *ast.CallExpr:
			analyzeAuthBypassCall(x, ctx)
		}
		return true
	})
}

// analyzeAuthBypassCondition analyzes if statements for auth bypass patterns
func analyzeAuthBypassCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for hardcoded authentication bypass conditions
	if ifStmt.Cond != nil {
		condStr := getNodeString(ifStmt.Cond)
		if isAuthBypassCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "auth-bypass-condition",
				Title:       "Authentication Bypass Condition",
				Description: "Hardcoded authentication bypass condition detected: " + condStr,
				Severity:    result.SeverityCritical,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Remove hardcoded authentication bypass conditions and implement proper authentication",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// analyzeAuthBypassAssignment analyzes assignments for auth bypass patterns
func analyzeAuthBypassAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for hardcoded authentication bypass assignments
	for _, expr := range assign.Rhs {
		if isAuthBypassAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "auth-bypass-assignment",
				Title:       "Authentication Bypass Assignment",
				Description: "Hardcoded authentication bypass assignment detected",
				Severity:    result.SeverityCritical,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Remove hardcoded authentication bypass assignments and implement proper authentication",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// analyzeAuthBypassCall analyzes function calls for auth bypass patterns
func analyzeAuthBypassCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for authentication bypass function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isAuthBypassCall(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "auth-bypass-call",
				Title:       "Authentication Bypass Function Call",
				Description: "Function call '" + fun.Name + "' appears to bypass authentication",
				Severity:    result.SeverityCritical,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Remove or properly secure authentication bypass function calls",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}

	// Check for hardcoded authentication bypass in function arguments
	for _, arg := range call.Args {
		if isAuthBypassArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "auth-bypass-argument",
				Title:       "Authentication Bypass Argument",
				Description: "Hardcoded authentication bypass argument detected in function call",
				Severity:    result.SeverityCritical,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Remove hardcoded authentication bypass arguments and implement proper authentication",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"},
			})
		}
	}
}

// isAuthBypassFunction checks if function name indicates authentication bypass with improved accuracy
func isAuthBypassFunction(funcName string) bool {
	// Exclude internal scanner functions and safe patterns
	excludePatterns := []string{
		"loadFile", "validateRule", "setDefaultValues", "getRulePattern",
		"processFilters", "processParamFilter", "processCallFilter",
		"processFileExtFilter", "processPackageFilter",
		"NewSuppressionManager", "GetSuppressionReason",
		"isSafePattern", "isSafeSQLPattern", "isSafeXSSPattern",
		"isSafeCommandPattern", "isSafePathPattern",
		"validate", "check", "verify", "test", "assert",
		"safe", "secure", "protected", "guarded",
		"auth_check", "auth_validate", "auth_verify",
		"check_auth", "validate_auth", "verify_auth",
		"secure_auth", "protected_auth", "guarded_auth",
	}
	
	funcNameLower := strings.ToLower(funcName)
	
	// Check for exclude patterns first
	for _, exclude := range excludePatterns {
		if strings.Contains(funcNameLower, exclude) {
			return false
		}
	}
	
	bypassPatterns := []string{
		"bypass", "skip", "disable", "ignore", "override",
		"auth_bypass", "auth_skip", "auth_disable", "auth_ignore",
		"bypass_auth", "skip_auth", "disable_auth", "ignore_auth",
		"admin_bypass", "admin_skip", "admin_disable",
		"superuser", "root_access", "god_mode", "debug_mode",
		"test_auth", "dev_auth", "temp_auth", "fake_auth",
	}
	
	for _, pattern := range bypassPatterns {
		if strings.Contains(funcNameLower, pattern) {
			return true
		}
	}
	return false
}

// isAuthBypassCondition checks if condition indicates authentication bypass with improved accuracy
func isAuthBypassCondition(condition string) bool {
	bypassPatterns := []string{
		"true", "false", "1", "0", "admin", "root", "superuser",
		"bypass", "skip", "disable", "ignore", "override",
		"debug", "test", "dev", "temp", "fake",
		"auth == false", "auth == true", "auth == 0", "auth == 1",
		"!auth", "auth == nil", "auth == \"\"",
	}
	
	// Exclude safe patterns
	safePatterns := []string{
		"validate", "check", "verify", "test", "assert",
		"safe", "secure", "protected", "guarded",
		"auth_check", "auth_validate", "auth_verify",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range bypassPatterns {
		if strings.Contains(condLower, pattern) {
			// Double-check it's not a safe pattern
			for _, safe := range safePatterns {
				if strings.Contains(condLower, safe) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// isAuthBypassAssignment checks if assignment indicates authentication bypass with improved accuracy
func isAuthBypassAssignment(expr ast.Expr) bool {
	// Check for hardcoded authentication bypass values
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		bypassValues := []string{
			"true", "false", "1", "0", "admin", "root", "superuser",
			"bypass", "skip", "disable", "ignore", "override",
			"debug", "test", "dev", "temp", "fake", "god", "master",
		}
		
		// Exclude safe patterns
		safeValues := []string{
			"validate", "check", "verify", "test", "assert",
			"safe", "secure", "protected", "guarded",
		}
		
		for _, bypass := range bypassValues {
			if strings.Contains(value, bypass) {
				// Double-check it's not a safe pattern
				for _, safe := range safeValues {
					if strings.Contains(value, safe) {
						return false
					}
				}
				return true
			}
		}
	}

	// Check for hardcoded authentication bypass identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isAuthBypassFunction(strings.ToLower(ident.Name))
	}

	return false
}

// isAuthBypassCall checks if function call indicates authentication bypass with improved accuracy
func isAuthBypassCall(funcName string) bool {
	bypassCalls := []string{
		"bypass", "skip", "disable", "ignore", "override",
		"auth_bypass", "auth_skip", "auth_disable", "auth_ignore",
		"bypass_auth", "skip_auth", "disable_auth", "ignore_auth",
		"admin_bypass", "admin_skip", "admin_disable",
		"superuser", "root_access", "god_mode", "debug_mode",
		"test_auth", "dev_auth", "temp_auth", "fake_auth",
		"set_admin", "set_root", "set_superuser",
		"force_auth", "override_auth", "fake_auth",
	}
	
	// Exclude safe patterns
	safeCalls := []string{
		"validate", "check", "verify", "test", "assert",
		"safe", "secure", "protected", "guarded",
		"auth_check", "auth_validate", "auth_verify",
	}

	funcNameLower := strings.ToLower(funcName)
	for _, bypass := range bypassCalls {
		if strings.Contains(funcNameLower, bypass) {
			// Double-check it's not a safe pattern
			for _, safe := range safeCalls {
				if strings.Contains(funcNameLower, safe) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// isAuthBypassArgument checks if function argument indicates authentication bypass with improved accuracy
func isAuthBypassArgument(arg ast.Expr) bool {
	// Check for hardcoded authentication bypass values
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		bypassValues := []string{
			"true", "false", "1", "0", "admin", "root", "superuser",
			"bypass", "skip", "disable", "ignore", "override",
			"debug", "test", "dev", "temp", "fake", "god", "master",
		}
		
		// Exclude safe patterns
		safeValues := []string{
			"validate", "check", "verify", "test", "assert",
			"safe", "secure", "protected", "guarded",
		}
		
		for _, bypass := range bypassValues {
			if strings.Contains(value, bypass) {
				// Double-check it's not a safe pattern
				for _, safe := range safeValues {
					if strings.Contains(value, safe) {
						return false
					}
				}
				return true
			}
		}
	}

	// Check for hardcoded authentication bypass identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isAuthBypassFunction(strings.ToLower(ident.Name))
	}

	return false
}

// getNodeString returns a string representation of an AST node
func getNodeString(node ast.Node) string {
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