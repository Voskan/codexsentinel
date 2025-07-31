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

// matchSQLInjection detects SQL injection vulnerabilities with improved accuracy
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

			// Enhanced check for SQL injection with context analysis
			if isSQLInjectionVulnerable(callExpr.Args[0], pass) {
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

// isSQLInjectionVulnerable checks if an expression is vulnerable to SQL injection
func isSQLInjectionVulnerable(expr ast.Expr, pass *analysis.Pass) bool {
	// Check for string concatenation with user input
	if containsStringConcatWithUserInput(expr, pass) {
		return true
	}

	// Check for fmt.Sprintf with user input
	if containsFmtSprintfWithUserInput(expr, pass) {
		return true
	}

	// Check for template string with user input
	if containsTemplateStringWithUserInput(expr, pass) {
		return true
	}

	return false
}

// containsStringConcatWithUserInput checks for string concatenation with user input
func containsStringConcatWithUserInput(expr ast.Expr, pass *analysis.Pass) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	
	if binExpr.Op == token.ADD {
		// Check if either side contains user input
		leftHasUserInput := containsUserInput(binExpr.X, pass)
		rightHasUserInput := containsUserInput(binExpr.Y, pass)
		
		// Only report if at least one side contains user input
		if leftHasUserInput || rightHasUserInput {
			// Additional check: if both sides are string literals, it's safe
			_, leftIsString := binExpr.X.(*ast.BasicLit)
			_, rightIsString := binExpr.Y.(*ast.BasicLit)
			
			// If both are string literals, it's safe
			if leftIsString && rightIsString {
				return false
			}
			
			return true
		}
		
		// Recursively check nested expressions
		return containsStringConcatWithUserInput(binExpr.X, pass) || 
			   containsStringConcatWithUserInput(binExpr.Y, pass)
	}
	
	return false
}

// containsFmtSprintfWithUserInput checks for fmt.Sprintf with user input
func containsFmtSprintfWithUserInput(expr ast.Expr, pass *analysis.Pass) bool {
	callExpr, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check for fmt.Sprintf
	if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "fmt" {
		if selector.Sel.Name == "Sprintf" && len(callExpr.Args) > 1 {
			// Check if any argument after the format string contains user input
			for _, arg := range callExpr.Args[1:] {
				if containsUserInput(arg, pass) {
					return true
				}
			}
		}
	}

	return false
}

// containsTemplateStringWithUserInput checks for template strings with user input
func containsTemplateStringWithUserInput(expr ast.Expr, pass *analysis.Pass) bool {
	// This is a simplified check - in a real implementation, you'd need more sophisticated parsing
	// to detect template strings like `SELECT * FROM users WHERE name = '${userInput}'`
	return false
}

// containsUserInput checks if an expression contains user input
func containsUserInput(expr ast.Expr, pass *analysis.Pass) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return isUserInputVariable(e.Name)
	case *ast.SelectorExpr:
		return isUserInputSelector(e, pass)
	case *ast.CallExpr:
		return isUserInputCall(e, pass)
	case *ast.BasicLit:
		// String literals are not user input
		return false
	}
	return false
}

// isUserInputVariable checks if a variable name suggests user input
func isUserInputVariable(name string) bool {
	name = strings.ToLower(name)
	userInputPatterns := []string{
		"input", "param", "user", "query", "data", "value", 
		"body", "form", "arg", "cmd", "filename", "search",
		"id", "name", "email", "username", "password",
	}
	
	for _, pattern := range userInputPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isUserInputSelector checks if a selector expression suggests user input
func isUserInputSelector(selector *ast.SelectorExpr, pass *analysis.Pass) bool {
	// Check for HTTP request methods that return user input
	if pkg, ok := selector.X.(*ast.Ident); ok {
		if pkg.Name == "r" { // HTTP request
			userInputMethods := []string{
				"FormValue", "PostFormValue", "URL", "Query",
			}
			for _, method := range userInputMethods {
				if selector.Sel.Name == method {
					return true
				}
			}
		}
	}
	return false
}

// isUserInputCall checks if a function call returns user input
func isUserInputCall(call *ast.CallExpr, pass *analysis.Pass) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		// Check for os.Getenv
		if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "os" {
			if selector.Sel.Name == "Getenv" {
				return true
			}
		}
		
		// Check for other user input sources
		if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "flag" {
			if strings.HasPrefix(selector.Sel.Name, "String") || 
			   strings.HasPrefix(selector.Sel.Name, "Arg") {
				return true
			}
		}
	}
	return false
}
