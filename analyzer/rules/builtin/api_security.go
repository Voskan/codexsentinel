package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterAPISecurityRule registers the API Security Issues detection rule.
func RegisterAPISecurityRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "api-security",
		Title:    "API Security Issues",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "API security vulnerabilities can lead to unauthorized access and data exposure.",
		Matcher:  matchAPISecurity,
	})
}

// matchAPISecurity detects API security vulnerabilities
func matchAPISecurity(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				analyzeAPISecurityCall(x, ctx)
			case *ast.AssignStmt:
				analyzeAPISecurityAssignment(x, ctx)
			case *ast.IfStmt:
				analyzeAPISecurityCondition(x, ctx)
			case *ast.FuncDecl:
				analyzeAPISecurityFunction(x, ctx)
			case *ast.StructType:
				analyzeAPISecurityStruct(x, ctx)
			}
			return true
		})
	}
}

// analyzeAPISecurityCall analyzes function calls for API security issues
func analyzeAPISecurityCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for API security function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isAPISecurityIssue(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "api-security-call",
				Title:       "API Security Issue",
				Description: "Function call '" + fun.Name + "' may have API security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review API security implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}

	// Check for API security issues in function arguments
	for _, arg := range call.Args {
		if isAPISecurityArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "api-security-argument",
				Title:       "API Security Argument Issue",
				Description: "API security argument may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review API security arguments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeAPISecurityAssignment analyzes assignments for API security issues
func analyzeAPISecurityAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for API security assignments
	for _, expr := range assign.Rhs {
		if isAPISecurityAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "api-security-assignment",
				Title:       "API Security Assignment Issue",
				Description: "API security assignment may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review API security assignments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeAPISecurityCondition analyzes if statements for API security issues
func analyzeAPISecurityCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for API security conditions
	if ifStmt.Cond != nil {
		condStr := getAPINodeString(ifStmt.Cond)
		if isAPISecurityCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "api-security-condition",
				Title:       "API Security Condition Issue",
				Description: "API security condition may have security vulnerabilities: " + condStr,
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review API security conditions for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeAPISecurityFunction analyzes function declarations for API security issues
func analyzeAPISecurityFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for API security function names
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isAPISecurityFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "api-security-function",
				Title:       "API Security Function Issue",
				Description: "Function '" + fn.Name.Name + "' may have API security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review API security function implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeAPISecurityStruct analyzes struct declarations for API security issues
func analyzeAPISecurityStruct(structType *ast.StructType, ctx *analyzer.AnalyzerContext) {
	// Check for API security struct fields
	if structType.Fields != nil {
		for _, field := range structType.Fields.List {
			if field.Names != nil {
				for _, name := range field.Names {
					fieldName := strings.ToLower(name.Name)
					if isAPISecurityField(fieldName) {
						pos := ctx.GetFset().Position(name.Pos())
						ctx.Report(result.Issue{
							ID:          "api-security-field",
							Title:       "API Security Field Issue",
							Description: "Field '" + name.Name + "' may have API security vulnerabilities",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Review API security field implementation for vulnerabilities",
							References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
						})
					}
				}
			}
		}
	}
}

// isAPISecurityIssue checks if function call indicates API security issues
func isAPISecurityIssue(funcName string) bool {
	apiPatterns := []string{
		"api", "endpoint", "route", "handler", "controller",
		"get", "post", "put", "delete", "patch", "head", "options",
		"request", "response", "http", "rest", "graphql",
		"auth", "authorize", "authenticate", "token", "jwt",
		"rate", "limit", "throttle", "quota", "throttling",
		"validate", "sanitize", "escape", "encode", "decode",
		"cors", "origin", "header", "content", "type",
		"version", "deprecated", "beta", "alpha", "experimental",
		"debug", "trace", "log", "monitor", "metrics",
		"cache", "cache_control", "etag", "last_modified",
		"compression", "gzip", "deflate", "brotli",
		"ssl", "tls", "certificate", "key", "pem",
		"oauth", "openid", "saml", "oidc", "federation",
		"api_key", "api_token", "api_secret", "api_password",
		"swagger", "openapi", "spec", "documentation",
		"schema", "model", "dto", "vo", "entity",
		"middleware", "interceptor", "filter", "gateway",
		"load_balancer", "proxy", "reverse_proxy", "cdn",
		"circuit_breaker", "retry", "timeout", "deadline",
		"bulk", "batch", "batch_size", "pagination", "offset",
		"sort", "order", "filter", "search", "query",
		"export", "import", "upload", "download", "file",
		"stream", "websocket", "sse", "event", "notification",
		"webhook", "callback", "redirect", "url", "uri",
		"status", "code", "error", "exception", "fault",
		"rate_limit", "throttle_limit", "quota_limit", "usage_limit",
		"api_version", "api_deprecated", "api_beta", "api_alpha", "api_experimental",
		"api_debug", "api_trace", "api_log", "api_monitor", "api_metrics",
		"api_cache", "api_compression", "api_ssl", "api_tls", "api_oauth",
		"api_openid", "api_saml", "api_oidc", "api_federation", "api_key_auth",
		"api_token_auth", "api_secret_auth", "api_password_auth", "api_swagger",
		"api_openapi", "api_spec", "api_documentation", "api_schema", "api_model",
		"api_dto", "api_vo", "api_entity", "api_middleware", "api_interceptor",
		"api_filter", "api_gateway", "api_load_balancer", "api_proxy",
		"api_reverse_proxy", "api_cdn", "api_circuit_breaker", "api_retry",
		"api_timeout", "api_deadline", "api_bulk", "api_batch", "api_pagination",
		"api_sort", "api_order", "api_filter", "api_search", "api_query",
		"api_export", "api_import", "api_upload", "api_download", "api_file",
		"api_stream", "api_websocket", "api_sse", "api_event", "api_notification",
		"api_webhook", "api_callback", "api_redirect", "api_url", "api_uri",
		"api_status", "api_code", "api_error", "api_exception", "api_fault",
	}

	for _, pattern := range apiPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isAPISecurityArgument checks if function argument indicates API security issues
func isAPISecurityArgument(arg ast.Expr) bool {
	// Check for API security identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isAPISecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for API security literals
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		apiValues := []string{
			"api", "endpoint", "route", "handler", "controller",
			"get", "post", "put", "delete", "patch", "head", "options",
			"request", "response", "http", "rest", "graphql",
			"auth", "authorize", "authenticate", "token", "jwt",
			"rate", "limit", "throttle", "quota", "throttling",
			"validate", "sanitize", "escape", "encode", "decode",
			"cors", "origin", "header", "content", "type",
			"version", "deprecated", "beta", "alpha", "experimental",
			"debug", "trace", "log", "monitor", "metrics",
			"cache", "cache_control", "etag", "last_modified",
			"compression", "gzip", "deflate", "brotli",
			"ssl", "tls", "certificate", "key", "pem",
			"oauth", "openid", "saml", "oidc", "federation",
			"api_key", "api_token", "api_secret", "api_password",
			"swagger", "openapi", "spec", "documentation",
			"schema", "model", "dto", "vo", "entity",
			"middleware", "interceptor", "filter", "gateway",
			"load_balancer", "proxy", "reverse_proxy", "cdn",
			"circuit_breaker", "retry", "timeout", "deadline",
			"bulk", "batch", "batch_size", "pagination", "offset",
			"sort", "order", "filter", "search", "query",
			"export", "import", "upload", "download", "file",
			"stream", "websocket", "sse", "event", "notification",
			"webhook", "callback", "redirect", "url", "uri",
			"status", "code", "error", "exception", "fault",
		}
		for _, apiValue := range apiValues {
			if strings.Contains(value, apiValue) {
				return true
			}
		}
	}

	return false
}

// isAPISecurityAssignment checks if assignment indicates API security issues
func isAPISecurityAssignment(expr ast.Expr) bool {
	// Check for API security identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isAPISecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for API security literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		apiValues := []string{
			"api", "endpoint", "route", "handler", "controller",
			"get", "post", "put", "delete", "patch", "head", "options",
			"request", "response", "http", "rest", "graphql",
			"auth", "authorize", "authenticate", "token", "jwt",
			"rate", "limit", "throttle", "quota", "throttling",
			"validate", "sanitize", "escape", "encode", "decode",
			"cors", "origin", "header", "content", "type",
			"version", "deprecated", "beta", "alpha", "experimental",
			"debug", "trace", "log", "monitor", "metrics",
			"cache", "cache_control", "etag", "last_modified",
			"compression", "gzip", "deflate", "brotli",
			"ssl", "tls", "certificate", "key", "pem",
			"oauth", "openid", "saml", "oidc", "federation",
			"api_key", "api_token", "api_secret", "api_password",
			"swagger", "openapi", "spec", "documentation",
			"schema", "model", "dto", "vo", "entity",
			"middleware", "interceptor", "filter", "gateway",
			"load_balancer", "proxy", "reverse_proxy", "cdn",
			"circuit_breaker", "retry", "timeout", "deadline",
			"bulk", "batch", "batch_size", "pagination", "offset",
			"sort", "order", "filter", "search", "query",
			"export", "import", "upload", "download", "file",
			"stream", "websocket", "sse", "event", "notification",
			"webhook", "callback", "redirect", "url", "uri",
			"status", "code", "error", "exception", "fault",
		}
		for _, apiValue := range apiValues {
			if strings.Contains(value, apiValue) {
				return true
			}
		}
	}

	return false
}

// isAPISecurityCondition checks if condition indicates API security issues
func isAPISecurityCondition(condition string) bool {
	apiPatterns := []string{
		"api", "endpoint", "route", "handler", "controller",
		"get", "post", "put", "delete", "patch", "head", "options",
		"request", "response", "http", "rest", "graphql",
		"auth", "authorize", "authenticate", "token", "jwt",
		"rate", "limit", "throttle", "quota", "throttling",
		"validate", "sanitize", "escape", "encode", "decode",
		"cors", "origin", "header", "content", "type",
		"version", "deprecated", "beta", "alpha", "experimental",
		"debug", "trace", "log", "monitor", "metrics",
		"cache", "cache_control", "etag", "last_modified",
		"compression", "gzip", "deflate", "brotli",
		"ssl", "tls", "certificate", "key", "pem",
		"oauth", "openid", "saml", "oidc", "federation",
		"api_key", "api_token", "api_secret", "api_password",
		"swagger", "openapi", "spec", "documentation",
		"schema", "model", "dto", "vo", "entity",
		"middleware", "interceptor", "filter", "gateway",
		"load_balancer", "proxy", "reverse_proxy", "cdn",
		"circuit_breaker", "retry", "timeout", "deadline",
		"bulk", "batch", "batch_size", "pagination", "offset",
		"sort", "order", "filter", "search", "query",
		"export", "import", "upload", "download", "file",
		"stream", "websocket", "sse", "event", "notification",
		"webhook", "callback", "redirect", "url", "uri",
		"status", "code", "error", "exception", "fault",
		"api == nil", "api == \"\"", "api == null",
		"endpoint == nil", "endpoint == \"\"", "endpoint == null",
		"route == nil", "route == \"\"", "route == null",
		"handler == nil", "handler == \"\"", "handler == null",
		"controller == nil", "controller == \"\"", "controller == null",
		"!api", "!endpoint", "!route", "!handler", "!controller",
		"api == false", "endpoint == false", "route == false",
		"handler == false", "controller == false",
		"api == 0", "endpoint == 0", "route == 0",
		"handler == 0", "controller == 0",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range apiPatterns {
		if strings.Contains(condLower, pattern) {
			return true
		}
	}
	return false
}

// isAPISecurityFunction checks if function name indicates API security issues
func isAPISecurityFunction(funcName string) bool {
	apiFunctions := []string{
		"api", "endpoint", "route", "handler", "controller",
		"get", "post", "put", "delete", "patch", "head", "options",
		"request", "response", "http", "rest", "graphql",
		"auth", "authorize", "authenticate", "token", "jwt",
		"rate", "limit", "throttle", "quota", "throttling",
		"validate", "sanitize", "escape", "encode", "decode",
		"cors", "origin", "header", "content", "type",
		"version", "deprecated", "beta", "alpha", "experimental",
		"debug", "trace", "log", "monitor", "metrics",
		"cache", "cache_control", "etag", "last_modified",
		"compression", "gzip", "deflate", "brotli",
		"ssl", "tls", "certificate", "key", "pem",
		"oauth", "openid", "saml", "oidc", "federation",
		"api_key", "api_token", "api_secret", "api_password",
		"swagger", "openapi", "spec", "documentation",
		"schema", "model", "dto", "vo", "entity",
		"middleware", "interceptor", "filter", "gateway",
		"load_balancer", "proxy", "reverse_proxy", "cdn",
		"circuit_breaker", "retry", "timeout", "deadline",
		"bulk", "batch", "batch_size", "pagination", "offset",
		"sort", "order", "filter", "search", "query",
		"export", "import", "upload", "download", "file",
		"stream", "websocket", "sse", "event", "notification",
		"webhook", "callback", "redirect", "url", "uri",
		"status", "code", "error", "exception", "fault",
		"create_api", "get_api", "update_api", "delete_api",
		"create_endpoint", "get_endpoint", "update_endpoint", "delete_endpoint",
		"create_route", "get_route", "update_route", "delete_route",
		"create_handler", "get_handler", "update_handler", "delete_handler",
		"create_controller", "get_controller", "update_controller", "delete_controller",
		"api_auth", "api_authorize", "api_authenticate", "api_token", "api_jwt",
		"api_rate_limit", "api_throttle", "api_quota", "api_throttling",
		"api_validate", "api_sanitize", "api_escape", "api_encode", "api_decode",
		"api_cors", "api_origin", "api_header", "api_content", "api_type",
		"api_version", "api_deprecated", "api_beta", "api_alpha", "api_experimental",
		"api_debug", "api_trace", "api_log", "api_monitor", "api_metrics",
		"api_cache", "api_cache_control", "api_etag", "api_last_modified",
		"api_compression", "api_gzip", "api_deflate", "api_brotli",
		"api_ssl", "api_tls", "api_certificate", "api_key", "api_pem",
		"api_oauth", "api_openid", "api_saml", "api_oidc", "api_federation",
		"api_key_auth", "api_token_auth", "api_secret_auth", "api_password_auth",
		"api_swagger", "api_openapi", "api_spec", "api_documentation",
		"api_schema", "api_model", "api_dto", "api_vo", "api_entity",
		"api_middleware", "api_interceptor", "api_filter", "api_gateway",
		"api_load_balancer", "api_proxy", "api_reverse_proxy", "api_cdn",
		"api_circuit_breaker", "api_retry", "api_timeout", "api_deadline",
		"api_bulk", "api_batch", "api_pagination", "api_sort", "api_order",
		"api_filter", "api_search", "api_query", "api_export", "api_import",
		"api_upload", "api_download", "api_file", "api_stream", "api_websocket",
		"api_sse", "api_event", "api_notification", "api_webhook", "api_callback",
		"api_redirect", "api_url", "api_uri", "api_status", "api_code",
		"api_error", "api_exception", "api_fault",
	}

	for _, apiFunc := range apiFunctions {
		if strings.Contains(funcName, apiFunc) {
			return true
		}
	}
	return false
}

// isAPISecurityField checks if struct field indicates API security issues
func isAPISecurityField(fieldName string) bool {
	apiFields := []string{
		"api", "endpoint", "route", "handler", "controller",
		"get", "post", "put", "delete", "patch", "head", "options",
		"request", "response", "http", "rest", "graphql",
		"auth", "authorize", "authenticate", "token", "jwt",
		"rate", "limit", "throttle", "quota", "throttling",
		"validate", "sanitize", "escape", "encode", "decode",
		"cors", "origin", "header", "content", "type",
		"version", "deprecated", "beta", "alpha", "experimental",
		"debug", "trace", "log", "monitor", "metrics",
		"cache", "cache_control", "etag", "last_modified",
		"compression", "gzip", "deflate", "brotli",
		"ssl", "tls", "certificate", "key", "pem",
		"oauth", "openid", "saml", "oidc", "federation",
		"api_key", "api_token", "api_secret", "api_password",
		"swagger", "openapi", "spec", "documentation",
		"schema", "model", "dto", "vo", "entity",
		"middleware", "interceptor", "filter", "gateway",
		"load_balancer", "proxy", "reverse_proxy", "cdn",
		"circuit_breaker", "retry", "timeout", "deadline",
		"bulk", "batch", "batch_size", "pagination", "offset",
		"sort", "order", "filter", "search", "query",
		"export", "import", "upload", "download", "file",
		"stream", "websocket", "sse", "event", "notification",
		"webhook", "callback", "redirect", "url", "uri",
		"status", "code", "error", "exception", "fault",
	}

	for _, apiField := range apiFields {
		if strings.Contains(fieldName, apiField) {
			return true
		}
	}
	return false
}

// getAPINodeString returns a string representation of an AST node
func getAPINodeString(node ast.Node) string {
	// This is a simplified implementation
	// In a real implementation, you would use go/printer to get the exact string
	switch x := node.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.BinaryExpr:
		return getAPINodeString(x.X) + " " + x.Op.String() + " " + getAPINodeString(x.Y)
	default:
		return "unknown"
	}
} 