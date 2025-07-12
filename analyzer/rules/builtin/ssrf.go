package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterSSRFRule registers the SSRF detection rule.
func RegisterSSRFRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "ssrf-vulnerability",
		Title:    "Server-Side Request Forgery (SSRF)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Making requests to untrusted URLs without proper validation may lead to SSRF attacks.",
		Matcher:  matchSSRFVulnerability,
	})
}

// matchSSRFVulnerability detects SSRF vulnerabilities
func matchSSRFVulnerability(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// Check for HTTP requests with user input
				if isHTTPRequest(x) && hasUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "ssrf-vulnerability",
						Title:       "Potential SSRF Vulnerability",
						Description: "HTTP request with user input may lead to SSRF attacks",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate and whitelist URLs before making requests",
					})
				}

				// Check for DNS lookups with user input
				if isDNSLookup(x) && hasUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "ssrf-vulnerability",
						Title:       "Potential SSRF via DNS Lookup",
						Description: "DNS lookup with user input may lead to SSRF attacks",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate hostnames before DNS resolution",
					})
				}

				// Check for file operations with user input
				if isFileOperation(x) && hasUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "ssrf-vulnerability",
						Title:       "Potential SSRF via File Operation",
						Description: "File operation with user input may lead to SSRF attacks",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate file paths and use safe file operations",
					})
				}
			}
			return true
		})
	}
}

// isHTTPRequest checks if call is an HTTP request
func isHTTPRequest(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		httpPatterns := []string{
			"Get", "Post", "Put", "Delete", "Head", "Options",
			"Request", "Do", "Send", "Fetch",
		}

		for _, pattern := range httpPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isDNSLookup checks if call is a DNS lookup
func isDNSLookup(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		dnsPatterns := []string{
			"Lookup", "Resolve", "GetHost", "GetIP",
		}

		for _, pattern := range dnsPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isFileOperation checks if call is a file operation
func isFileOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		filePatterns := []string{
			"Open", "Read", "Write", "Create", "Delete",
			"Stat", "Exists", "Copy", "Move",
		}

		for _, pattern := range filePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// hasUserInput checks if call has user input as argument
func hasUserInput(ctx *analyzer.AnalyzerContext, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isUserInput(ctx, arg) {
			return true
		}
	}
	return false
}

// isUserInput checks if an expression represents user input
func isUserInput(ctx *analyzer.AnalyzerContext, expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		if fun, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := fun.X.(*ast.Ident); ok {
				// Check for common user input sources
				switch pkg.Name {
				case "r":
					if fun.Sel.Name == "URL" || fun.Sel.Name == "FormValue" || fun.Sel.Name == "PostFormValue" {
						return true
					}
				case "os":
					if fun.Sel.Name == "Getenv" {
						return true
					}
				}
			}
		}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.SelectorExpr); ok {
			if pkg, ok := x.X.(*ast.Ident); ok {
				if pkg.Name == "r" && x.Sel.Name == "URL" && e.Sel.Name == "Query" {
					return true
				}
			}
		}
	case *ast.Ident:
		// Heuristic: variable name suggests user input
		userInputPatterns := []string{"userInput", "input", "param", "url", "host", "domain"}
		for _, pattern := range userInputPatterns {
			if strings.Contains(strings.ToLower(e.Name), pattern) {
				return true
			}
		}
	}
	return false
}
