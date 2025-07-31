package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterXSSRule registers the XSS detection rule.
func RegisterXSSRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "xss-vulnerability-builtin",
		Title:    "Potential Cross-Site Scripting (XSS)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Unescaped user input written to HTTP response may lead to XSS attacks.",
		Matcher:  matchXSSVulnerabilityBuiltin,
	})
}

// matchXSSVulnerabilityBuiltin detects XSS vulnerabilities in HTTP handlers with improved accuracy
func matchXSSVulnerabilityBuiltin(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Detect w.Write([]byte(userInput)) with context analysis
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Write" {
					if len(call.Args) == 1 {
						if isUnescapedUserInputInWrite(call.Args[0], pass) {
							pos := pass.Fset.Position(call.Pos())
							ctx.Report(result.Issue{
								ID:          "xss-vulnerability-builtin",
								Title:       "Potential Cross-Site Scripting (XSS)",
								Description: "User input written to HTTP response without escaping.",
								Severity:    result.SeverityHigh,
								Location:    result.NewLocationFromPos(pos, "", ""),
								Category:    "security",
								Suggestion:  "Use html.EscapeString or html/template to escape user input before writing to response.",
							})
						}
					}
				}
			}

			// Detect fmt.Fprintf(w, ...userInput...) with improved context
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && (sel.Sel.Name == "Fprintf" || sel.Sel.Name == "Fprint") {
					if len(call.Args) > 1 {
						for _, arg := range call.Args[1:] {
							if isUnescapedUserInputInFmt(arg, pass) {
								pos := pass.Fset.Position(arg.Pos())
								ctx.Report(result.Issue{
									ID:          "xss-vulnerability-builtin",
									Title:       "Potential Cross-Site Scripting (XSS)",
									Description: "User input written to HTTP response via fmt.Fprintf without escaping.",
									Severity:    result.SeverityHigh,
									Location:    result.NewLocationFromPos(pos, "", ""),
									Category:    "security",
									Suggestion:  "Use html.EscapeString or html/template to escape user input before writing to response.",
								})
							}
						}
					}
				}
			}

			// Detect template.Execute(w, data) with improved analysis
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Execute" && len(call.Args) == 2 {
					if isUnsafeTemplateExecute(call.Args[1], pass) {
						pos := pass.Fset.Position(call.Args[1].Pos())
						ctx.Report(result.Issue{
							ID:          "xss-vulnerability-builtin",
							Title:       "Potential Cross-Site Scripting (XSS) in template.Execute",
							Description: "User input passed to template.Execute may be unsafe if not using html/template.",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Use html/template (not text/template) and ensure autoescaping is enabled.",
						})
					}
				}
			}

			return true
		})
	}
}

// isUnescapedUserInputInWrite checks if the expression is user input and not escaped in Write call
func isUnescapedUserInputInWrite(expr ast.Expr, pass *analysis.Pass) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for []byte(userInput)
		if fun, ok := e.Fun.(*ast.Ident); ok && fun.Name == "[]byte" && len(e.Args) == 1 {
			return isUnescapedUserInput(e.Args[0], pass)
		}
		// Check for html.EscapeString(userInput) - this is safe
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "html" && sel.Sel.Name == "EscapeString" {
				return false // Escaped
			}
			// Check for template.HTMLEscapeString
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "template" && sel.Sel.Name == "HTMLEscapeString" {
				return false // Escaped
			}
		}
		// Recursively check arguments
		for _, arg := range e.Args {
			if isUnescapedUserInput(arg, pass) {
				return true
			}
		}
		return false
	case *ast.BasicLit:
		return false // string literal, not user input
	case *ast.Ident:
		return isLikelyUserInput(e.Name)
	case *ast.SelectorExpr:
		return isLikelyUserInput(exprString(e))
	}
	return false
}

// isUnescapedUserInputInFmt checks if the expression is user input and not escaped in fmt call
func isUnescapedUserInputInFmt(expr ast.Expr, pass *analysis.Pass) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for html.EscapeString(userInput) - this is safe
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "html" && sel.Sel.Name == "EscapeString" {
				return false // Escaped
			}
			// Check for template.HTMLEscapeString
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "template" && sel.Sel.Name == "HTMLEscapeString" {
				return false // Escaped
			}
		}
		// Recursively check arguments
		for _, arg := range e.Args {
			if isUnescapedUserInput(arg, pass) {
				return true
			}
		}
		return false
	case *ast.BasicLit:
		return false // string literal, not user input
	case *ast.Ident:
		return isLikelyUserInput(e.Name)
	case *ast.SelectorExpr:
		return isLikelyUserInput(exprString(e))
	}
	return false
}

// isUnsafeTemplateExecute checks if template.Execute is unsafe
func isUnsafeTemplateExecute(expr ast.Expr, pass *analysis.Pass) bool {
	// Check if we're using text/template instead of html/template
	// This is a simplified check - in a real implementation, you'd need to track imports
	return isUnescapedUserInput(expr, pass)
}

// isUnescapedUserInput checks if the expression is user input and not escaped.
func isUnescapedUserInput(expr ast.Expr, pass *analysis.Pass) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for html.EscapeString(userInput)
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "html" && sel.Sel.Name == "EscapeString" {
				return false // Escaped
			}
			// Check for template.HTMLEscapeString
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "template" && sel.Sel.Name == "HTMLEscapeString" {
				return false // Escaped
			}
		}
		// Recursively check arguments
		for _, arg := range e.Args {
			if isUnescapedUserInput(arg, pass) {
				return true
			}
		}
		return false
	case *ast.BasicLit:
		return false // string literal, not user input
	case *ast.Ident:
		return isLikelyUserInput(e.Name)
	case *ast.SelectorExpr:
		return isLikelyUserInput(exprString(e))
	}
	return false
}

// isLikelyUserInput uses improved heuristics to detect user input variables
func isLikelyUserInput(name string) bool {
	name = strings.ToLower(name)
	
	// More specific patterns to reduce false positives
	userInputKeywords := []string{
		"input", "param", "user", "query", "data", "value", 
		"body", "form", "arg", "cmd", "filename", "search",
		"id", "name", "email", "username", "password",
		"content", "text", "message", "comment", "title",
		"description", "url", "link", "href", "src",
	}
	
	// Exclude common safe patterns
	safePatterns := []string{
		"template", "html", "css", "js", "json", "xml",
		"config", "setting", "option", "default", "constant",
		"static", "fixed", "hardcoded", "literal",
	}
	
	// Check for user input patterns
	for _, keyword := range userInputKeywords {
		if strings.Contains(name, keyword) {
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

// exprString returns a string representation of an expression.
func exprString(expr ast.Expr) string {
	var sb strings.Builder
	ast.Inspect(expr, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch v := n.(type) {
		case *ast.Ident:
			sb.WriteString(v.Name)
		case *ast.SelectorExpr:
			sb.WriteString(exprString(v.X))
			sb.WriteString(".")
			sb.WriteString(v.Sel.Name)
		}
		return true
	})
	return sb.String()
}
