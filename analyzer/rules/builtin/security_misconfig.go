package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterSecurityMisconfigRule registers the Security Misconfiguration detection rule.
func RegisterSecurityMisconfigRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "security-misconfiguration",
		Title:    "Security Misconfiguration (A05:2025)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Debug endpoints, unsafe settings, and security misconfigurations may expose sensitive information or create vulnerabilities.",
		Matcher:  matchSecurityMisconfiguration,
	})
}

// matchSecurityMisconfiguration detects security misconfigurations
func matchSecurityMisconfiguration(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// Check for debug endpoints
				if isDebugEndpoint(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Debug Endpoint Exposed",
						Description: "Debug endpoint detected in production code",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Remove debug endpoints from production code or secure them properly",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for unsafe CORS settings
				if isUnsafeCORSSetting(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Unsafe CORS Configuration",
						Description: "Unsafe CORS configuration detected (wildcard origin or missing security headers)",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Configure CORS with specific allowed origins and proper security headers",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for debug mode enabled
				if isDebugModeEnabled(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Debug Mode Enabled",
						Description: "Debug mode is enabled in production code",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Disable debug mode in production environments",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for verbose error messages
				if isVerboseErrorEnabled(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Verbose Error Messages",
						Description: "Verbose error messages may expose sensitive information",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use generic error messages in production to avoid information disclosure",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for insecure default settings
				if isInsecureDefaultSetting(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Insecure Default Setting",
						Description: "Insecure default configuration detected",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Change default settings to secure values",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for missing security headers
				if isMissingSecurityHeader(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Missing Security Header",
						Description: "Security header is missing from HTTP response",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Add appropriate security headers (X-Frame-Options, X-Content-Type-Options, etc.)",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for exposed configuration
				if isExposedConfiguration(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Exposed Configuration",
						Description: "Sensitive configuration is exposed to users",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Hide sensitive configuration from user responses",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}

				// Check for development tools in production
				if isDevelopmentToolInProduction(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "security-misconfiguration",
						Title:       "Development Tool in Production",
						Description: "Development tool or debug utility detected in production code",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Remove development tools and debug utilities from production code",
						References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
					})
				}
			}
			return true
		})
	}
}

// isDebugEndpoint checks if call is a debug endpoint
func isDebugEndpoint(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for debug endpoint patterns
		debugPatterns := []string{
			"debug", "dev", "test", "admin", "internal", "management",
			"health", "status", "info", "metrics", "profiling",
		}

		for _, pattern := range debugPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's an HTTP handler
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "http" || ident.Name == "mux" || ident.Name == "router" {
							return true
						}
					}
				}
				
				// Check for direct package usage
				if ident, ok := fun.X.(*ast.Ident); ok {
					if ident.Name == "debug" || ident.Name == "dev" || ident.Name == "admin" {
						return true
					}
				}
			}
		}

		// Check for specific debug function calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "debug" || ident.Name == "dev" {
					debugFuncs := []string{"Handler", "Endpoint", "Route", "HandlerFunc"}
					for _, funcName := range debugFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isUnsafeCORSSetting checks if call is an unsafe CORS setting
func isUnsafeCORSSetting(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for CORS-related patterns
		corsPatterns := []string{
			"cors", "origin", "alloworigin", "allowcredentials",
		}

		for _, pattern := range corsPatterns {
			if strings.Contains(funcName, pattern) {
				// Check for wildcard origin
				if len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok {
						if strings.Contains(lit.Value, "*") {
							return true
						}
					}
				}
				
				// Check for CORS package usage
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "cors" || ident.Name == "middleware" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isDebugModeEnabled checks if debug mode is enabled
func isDebugModeEnabled(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for debug mode patterns
		debugModePatterns := []string{
			"debug", "dev", "development", "verbose", "trace",
		}

		for _, pattern := range debugModePatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's setting debug mode to true
				if len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok {
						if lit.Value == "true" || lit.Value == "1" {
							return true
						}
					}
				}
				
				// Check for debug package usage
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "debug" || ident.Name == "config" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isVerboseErrorEnabled checks if verbose error messages are enabled
func isVerboseErrorEnabled(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for verbose error patterns
		verbosePatterns := []string{
			"verbose", "detailed", "trace", "debug", "stack",
		}

		for _, pattern := range verbosePatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's enabling verbose errors
				if len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok {
						if lit.Value == "true" || lit.Value == "1" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isInsecureDefaultSetting checks if insecure default settings are used
func isInsecureDefaultSetting(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for insecure default patterns
		insecurePatterns := []string{
			"default", "basic", "simple", "none", "empty",
		}

		for _, pattern := range insecurePatterns {
			if strings.Contains(funcName, pattern) {
				// Check for security-related settings
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "security" || ident.Name == "auth" || ident.Name == "config" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isMissingSecurityHeader checks if security headers are missing
func isMissingSecurityHeader(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for header-related patterns
		headerPatterns := []string{
			"header", "setheader", "addheader",
		}

		for _, pattern := range headerPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's setting security headers
				if len(call.Args) > 0 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok {
						headerName := strings.ToLower(lit.Value)
						securityHeaders := []string{
							"x-frame-options", "x-content-type-options", "x-xss-protection",
							"strict-transport-security", "content-security-policy",
						}
						for _, securityHeader := range securityHeaders {
							if strings.Contains(headerName, securityHeader) {
								return false // Security header is present
							}
						}
					}
				}
			}
		}
	}
	return false
}

// isExposedConfiguration checks if sensitive configuration is exposed
func isExposedConfiguration(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for configuration exposure patterns
		exposurePatterns := []string{
			"config", "setting", "env", "secret", "key", "password",
		}

		for _, pattern := range exposurePatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's writing to response
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "w" || ident.Name == "response" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isDevelopmentToolInProduction checks if development tools are used in production
func isDevelopmentToolInProduction(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for development tool patterns
		devToolPatterns := []string{
			"pprof", "trace", "debugger", "profiler", "monitor",
			"hotreload", "livereload", "devserver", "development",
		}

		for _, pattern := range devToolPatterns {
			if strings.Contains(funcName, pattern) {
				// Check for development package usage
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "pprof" || ident.Name == "debug" || ident.Name == "dev" {
							return true
						}
					}
				}
			}
		}
	}
	return false
} 