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

// matchXSSVulnerabilityBuiltin detects XSS vulnerabilities in HTTP handlers.
func matchXSSVulnerabilityBuiltin(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Detect w.Write([]byte(userInput))
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Write" {
					if len(call.Args) == 1 {
						if isUnescapedUserInput(call.Args[0]) {
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

			// Detect fmt.Fprintf(w, ...userInput...)
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && (sel.Sel.Name == "Fprintf" || sel.Sel.Name == "Fprint") {
					if len(call.Args) > 1 {
						for _, arg := range call.Args[1:] {
							if isUnescapedUserInput(arg) {
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

			// Detect template.Execute(w, data) where data is user input (not robust, but basic check)
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Execute" && len(call.Args) == 2 {
					if isUnescapedUserInput(call.Args[1]) {
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

// isUnescapedUserInput checks if the expression is user input and not escaped.
func isUnescapedUserInput(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check for []byte(userInput)
		if fun, ok := e.Fun.(*ast.Ident); ok && fun.Name == "[]byte" && len(e.Args) == 1 {
			return isUnescapedUserInput(e.Args[0])
		}
		// Check for html.EscapeString(userInput)
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "html" && sel.Sel.Name == "EscapeString" {
				return false // Escaped
			}
		}
		// Recursively check arguments
		for _, arg := range e.Args {
			if isUnescapedUserInput(arg) {
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

// isLikelyUserInput uses heuristics to detect user input variables.
func isLikelyUserInput(name string) bool {
	name = strings.ToLower(name)
	keywords := []string{"input", "param", "user", "query", "data", "value", "body", "form", "arg", "cmd", "filename"}
	for _, kw := range keywords {
		if strings.Contains(name, kw) {
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
