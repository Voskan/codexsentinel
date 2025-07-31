package builtin

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterCommandExecRule registers the command injection detection rule.
func RegisterCommandExecRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "command-exec-taint",
		Title:    "Potential Command Injection via exec.Command",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Using user input in exec.Command without validation may lead to command injection.",
		Matcher:  matchExecCommandInjection,
	})
}

// matchExecCommandInjection detects untrusted input used in exec.Command or exec.CommandContext with improved accuracy
func matchExecCommandInjection(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}

			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			pkgIdent, ok := selector.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "exec" {
				return true
			}

			if selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
				return true
			}

			// Enhanced check for command injection with context analysis
			if isCommandInjectionVulnerable(call, pass) {
				pos := ctx.GetFset().Position(call.Pos())
				ctx.Report(result.Issue{
					ID:          "command-exec-taint",
					Title:       "Potential Command Injection",
					Description: "Untrusted input used in exec.Command may lead to command injection",
					Severity:    result.SeverityHigh,
					Location:    result.NewLocationFromPos(pos, "", ""),
					Category:    "security",
					Suggestion:  "Validate or sanitize the input before using it in exec.Command",
				})
			}
			return true
		})
	}
}

// isCommandInjectionVulnerable checks if exec.Command call is vulnerable to command injection
func isCommandInjectionVulnerable(call *ast.CallExpr, pass *analysis.Pass) bool {
	// Check if any argument comes from untrusted input
	for i, arg := range call.Args {
		// Skip the first argument if it's a safe command (like "echo", "ls", etc.)
		if i == 0 && isSafeCommand(arg) {
			continue
		}
		
		if isTaintedInput(arg, pass) {
			return true
		}
	}
	return false
}

// isSafeCommand checks if the command is considered safe
func isSafeCommand(expr ast.Expr) bool {
	if lit, ok := expr.(*ast.BasicLit); ok {
		command := strings.Trim(lit.Value, `"`)
		safeCommands := []string{
			"echo", "ls", "cat", "head", "tail", "grep", "find",
			"wc", "sort", "uniq", "cut", "awk", "sed",
			"ps", "top", "df", "du", "free", "uptime",
		}
		for _, safe := range safeCommands {
			if command == safe {
				return true
			}
		}
	}
	return false
}

// isTaintedInput checks whether an expression is tainted by user input with improved accuracy
func isTaintedInput(expr ast.Expr, pass *analysis.Pass) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return isCallExprTainted(e, pass)
	case *ast.SelectorExpr:
		return isSelectorExprTainted(e, pass)
	case *ast.Ident:
		return isIdentTainted(e, pass)
	case *ast.BasicLit:
		// String literals are not tainted
		return false
	}
	return false
}

// isCallExprTainted checks if a call expression is tainted
func isCallExprTainted(call *ast.CallExpr, pass *analysis.Pass) bool {
	if funIdent, ok := call.Fun.(*ast.SelectorExpr); ok {
		return isPackageCallTainted(funIdent, pass)
	}
	return false
}

// isPackageCallTainted checks if a package call is tainted
func isPackageCallTainted(funIdent *ast.SelectorExpr, pass *analysis.Pass) bool {
	pkgIdent, ok := funIdent.X.(*ast.Ident)
	if !ok {
		return false
	}

	switch pkgIdent.Name {
	case "os":
		return funIdent.Sel.Name == "Getenv"
	case "r":
		return isHTTPRequestTainted(funIdent.Sel.Name)
	case "flag":
		return isFlagCallTainted(funIdent.Sel.Name)
	}
	return false
}

// isHTTPRequestTainted checks if HTTP request methods are tainted
func isHTTPRequestTainted(methodName string) bool {
	taintedMethods := []string{
		"FormValue", "PostFormValue", "URL", "Query", "Header",
		"Cookie", "Body", "Get", "Post", "Put", "Delete",
	}
	for _, method := range taintedMethods {
		if methodName == method {
			return true
		}
	}
	return false
}

// isFlagCallTainted checks if flag package calls are tainted
func isFlagCallTainted(methodName string) bool {
	taintedMethods := []string{
		"String", "Int", "Bool", "Float64", "Duration",
		"Arg", "Args", "NArg", "NFlag",
	}
	for _, method := range taintedMethods {
		if strings.HasPrefix(methodName, method) {
			return true
		}
	}
	return false
}

// isSelectorExprTainted checks if a selector expression is tainted
func isSelectorExprTainted(selector *ast.SelectorExpr, pass *analysis.Pass) bool {
	if x, ok := selector.X.(*ast.SelectorExpr); ok {
		return isHTTPQueryTainted(x, selector, pass)
	}
	return false
}

// isHTTPQueryTainted checks if HTTP query parameters are tainted
func isHTTPQueryTainted(x *ast.SelectorExpr, selector *ast.SelectorExpr, pass *analysis.Pass) bool {
	if pkg, ok := x.X.(*ast.Ident); ok {
		return pkg.Name == "r" && x.Sel.Name == "URL" && selector.Sel.Name == "Query"
	}
	return false
}

// isIdentTainted checks if an identifier is tainted with improved accuracy
func isIdentTainted(ident *ast.Ident, pass *analysis.Pass) bool {
	// Check if variable name suggests user input
	if isVariableNameTainted(ident.Name) {
		return true
	}
	
	// Check type information if available
	return isTypeInfoTainted(ident, pass)
}

// isVariableNameTainted checks if a variable name suggests tainted input with improved patterns
func isVariableNameTainted(name string) bool {
	name = strings.ToLower(name)
	
	// More specific patterns to reduce false positives
	taintedPatterns := []string{
		"userinput", "input", "param", "cmd", "arg", "data", 
		"filename", "path", "url", "query", "search", "term",
		"command", "exec", "shell", "script", "program",
		"user", "client", "request", "form", "body",
	}
	
	// Exclude common safe patterns
	safePatterns := []string{
		"config", "setting", "option", "default", "constant",
		"static", "fixed", "hardcoded", "literal", "template",
		"safe", "validated", "sanitized", "escaped",
	}
	
	// Check for tainted patterns
	for _, pattern := range taintedPatterns {
		if strings.Contains(name, pattern) {
			// Double-check it's not a safe pattern
			for _, safe := range safePatterns {
				if strings.Contains(name, safe) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// isTypeInfoTainted checks if type information suggests tainted input
func isTypeInfoTainted(ident *ast.Ident, pass *analysis.Pass) bool {
	if pass.TypesInfo == nil {
		return false
	}
	
	obj := pass.TypesInfo.Uses[ident]
	if obj == nil {
		return false
	}
	
	if v, ok := obj.(*types.Var); ok && v.Pkg() != nil {
		// Heuristic: check if variable name contains suspicious input identifiers
		return isVariableNameTainted(ident.Name)
	}
	
	return false
}
