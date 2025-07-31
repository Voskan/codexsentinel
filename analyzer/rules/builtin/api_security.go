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

// isAPISecurityFunction checks if function name indicates API security issues with improved accuracy
func isAPISecurityFunction(funcName string) bool {
	// Exclude internal scanner functions
	internalFuncs := []string{
		"loadFile", "validateRule", "setDefaultValues", "getRulePattern",
		"processFilters", "processParamFilter", "processCallFilter",
		"processFileExtFilter", "processPackageFilter",
		"NewSuppressionManager", "GetSuppressionReason",
		"isSafePattern", "isSafeSQLPattern", "isSafeXSSPattern",
		"isSafeCommandPattern", "isSafePathPattern",
		"isTestFile", "isSafeXSSPattern", "isSafeSQLPattern",
		"isSafeCommandPattern", "isSafePathPattern",
		"Register", "Get", "All", "EnabledRules", "Clear",
		"LoadFromDir", "LoadFromFile", "loadFile", "parseRuleYAML",
		"validateRule", "getRulePattern", "createYAMLRule",
		"processFilters", "processParamFilter", "processCallFilter",
		"processFileExtFilter", "processPackageFilter",
		"NewAnalyzerContext", "GetCustom", "SetCustom", "RegisterRule",
		"GetFset", "Report", "Info", "GetIssues", "ClearIssues",
		"NewContextAnalyzer", "AnalyzeContext", "analyzeValidationContext",
		"analyzeSanitizationContext", "analyzeSafePatternContext",
		"calculateConfidence", "findContainingFunction",
		"isValidationFunction", "isSanitizationFunction", "isSafePattern",
		"isSafeFunctionCall", "ShouldSuppress", "GetSeverityAdjustment",
		"NewConfidenceScorer", "ScoreConfidence", "calculateContextScore",
		"calculateValidationScore", "calculateSafePatternScore",
		"hasInputValidation", "isHardcodedValue", "GetRecommendation",
		"NewSuppressionManager", "ShouldSuppress", "GetSuppressionReason",
		"isSafeXSSPattern", "isSafeSQLPattern", "isSafeCommandPattern",
		"isSafePathPattern", "isTestFile", "isSafeXSSPattern",
		"isSafeSQLPattern", "isSafeCommandPattern", "isSafePathPattern",
	}
	
	for _, internal := range internalFuncs {
		if funcName == internal {
			return false
		}
	}
	
	// Check for API security patterns
	apiPatterns := []string{
		"api", "rest", "graphql", "soap", "rpc", "endpoint",
		"route", "handler", "controller", "service",
		"authentication", "authorization", "token", "jwt",
		"oauth", "openid", "saml", "ldap", "kerberos",
		"rate_limit", "throttling", "quota", "throttle",
		"compression", "gzip", "deflate", "brotli",
		"ssl", "tls", "certificate", "key", "pem",
		"debug", "trace", "log", "monitor", "metrics",
		"batch", "bulk", "batch_size", "batch_limit",
		"pagination", "page", "limit", "offset",
		"sorting", "ordering", "filter", "search",
		"query", "mutation", "subscription", "introspection",
		"schema", "type", "field", "argument", "directive",
		"validation", "sanitization", "escaping", "encoding",
		"serialization", "deserialization", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle", "route",
		"router", "dispatcher", "handler", "middleware",
		"interceptor", "filter", "gateway", "proxy",
		"load_balancer", "reverse_proxy", "cdn", "cache",
		"compression", "gzip", "deflate", "brotli", "lz4",
		"snappy", "zstd", "lzma", "heartbeat", "ping",
		"pong", "reconnection", "backoff", "jitter",
		"random", "secure", "tls", "ssl", "certificate",
		"key", "pem", "crt", "ca", "ca_bundle", "verify",
		"validation", "sanitize", "escape", "encode", "decode",
		"serialize", "deserialize", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle", "route",
		"router", "dispatcher", "handler", "middleware",
		"interceptor", "filter", "gateway", "proxy",
		"load_balancer", "reverse_proxy", "cdn", "cache",
		"compression", "gzip", "deflate", "brotli", "lz4",
		"snappy", "zstd", "lzma",
	}
	
	funcNameLower := strings.ToLower(funcName)
	
	for _, pattern := range apiPatterns {
		if strings.Contains(funcNameLower, pattern) {
			// Double-check it's not a safe pattern
			safePatterns := []string{
				"validate", "check", "verify", "test", "assert",
				"safe", "secure", "protected", "guarded",
				"api_check", "api_validate", "api_verify",
				"rest_check", "rest_validate", "rest_verify",
				"graphql_check", "graphql_validate", "graphql_verify",
				"soap_check", "soap_validate", "soap_verify",
				"rpc_check", "rpc_validate", "rpc_verify",
				"endpoint_check", "endpoint_validate", "endpoint_verify",
				"route_check", "route_validate", "route_verify",
				"handler_check", "handler_validate", "handler_verify",
				"controller_check", "controller_validate", "controller_verify",
				"service_check", "service_validate", "service_verify",
				"authentication_check", "authentication_validate", "authentication_verify",
				"authorization_check", "authorization_validate", "authorization_verify",
				"token_check", "token_validate", "token_verify",
				"jwt_check", "jwt_validate", "jwt_verify",
				"oauth_check", "oauth_validate", "oauth_verify",
				"openid_check", "openid_validate", "openid_verify",
				"saml_check", "saml_validate", "saml_verify",
				"ldap_check", "ldap_validate", "ldap_verify",
				"kerberos_check", "kerberos_validate", "kerberos_verify",
				"rate_limit_check", "rate_limit_validate", "rate_limit_verify",
				"throttling_check", "throttling_validate", "throttling_verify",
				"quota_check", "quota_validate", "quota_verify",
				"throttle_check", "throttle_validate", "throttle_verify",
				"compression_check", "compression_validate", "compression_verify",
				"gzip_check", "gzip_validate", "gzip_verify",
				"deflate_check", "deflate_validate", "deflate_verify",
				"brotli_check", "brotli_validate", "brotli_verify",
				"ssl_check", "ssl_validate", "ssl_verify",
				"tls_check", "tls_validate", "tls_verify",
				"certificate_check", "certificate_validate", "certificate_verify",
				"key_check", "key_validate", "key_verify",
				"pem_check", "pem_validate", "pem_verify",
				"debug_check", "debug_validate", "debug_verify",
				"trace_check", "trace_validate", "trace_verify",
				"log_check", "log_validate", "log_verify",
				"monitor_check", "monitor_validate", "monitor_verify",
				"metrics_check", "metrics_validate", "metrics_verify",
				"batch_check", "batch_validate", "batch_verify",
				"bulk_check", "bulk_validate", "bulk_verify",
				"batch_size_check", "batch_size_validate", "batch_size_verify",
				"batch_limit_check", "batch_limit_validate", "batch_limit_verify",
				"pagination_check", "pagination_validate", "pagination_verify",
				"page_check", "page_validate", "page_verify",
				"limit_check", "limit_validate", "limit_verify",
				"offset_check", "offset_validate", "offset_verify",
				"sorting_check", "sorting_validate", "sorting_verify",
				"ordering_check", "ordering_validate", "ordering_verify",
				"filter_check", "filter_validate", "filter_verify",
				"search_check", "search_validate", "search_verify",
				"query_check", "query_validate", "query_verify",
				"mutation_check", "mutation_validate", "mutation_verify",
				"subscription_check", "subscription_validate", "subscription_verify",
				"introspection_check", "introspection_validate", "introspection_verify",
				"schema_check", "schema_validate", "schema_verify",
				"type_check", "type_validate", "type_verify",
				"field_check", "field_validate", "field_verify",
				"argument_check", "argument_validate", "argument_verify",
				"directive_check", "directive_validate", "directive_verify",
				"validation_check", "validation_validate", "validation_verify",
				"sanitization_check", "sanitization_validate", "sanitization_verify",
				"escaping_check", "escaping_validate", "escaping_verify",
				"encoding_check", "encoding_validate", "encoding_verify",
				"serialization_check", "serialization_validate", "serialization_verify",
				"deserialization_check", "deserialization_validate", "deserialization_verify",
				"marshal_check", "marshal_validate", "marshal_verify",
				"unmarshal_check", "unmarshal_validate", "unmarshal_verify",
				"json_check", "json_validate", "json_verify",
				"xml_check", "xml_validate", "xml_verify",
				"protobuf_check", "protobuf_validate", "protobuf_verify",
				"msgpack_check", "msgpack_validate", "msgpack_verify",
				"avro_check", "avro_validate", "avro_verify",
				"thrift_check", "thrift_validate", "thrift_verify",
				"grpc_check", "grpc_validate", "grpc_verify",
				"rpc_check", "rpc_validate", "rpc_verify",
				"remote_check", "remote_validate", "remote_verify",
				"call_check", "call_validate", "call_verify",
				"invoke_check", "invoke_validate", "invoke_verify",
				"execute_check", "execute_validate", "execute_verify",
				"process_check", "process_validate", "process_verify",
				"handle_check", "handle_validate", "handle_verify",
				"route_check", "route_validate", "route_verify",
				"router_check", "router_validate", "router_verify",
				"dispatcher_check", "dispatcher_validate", "dispatcher_verify",
				"handler_check", "handler_validate", "handler_verify",
				"middleware_check", "middleware_validate", "middleware_verify",
				"interceptor_check", "interceptor_validate", "interceptor_verify",
				"filter_check", "filter_validate", "filter_verify",
				"gateway_check", "gateway_validate", "gateway_verify",
				"proxy_check", "proxy_validate", "proxy_verify",
				"load_balancer_check", "load_balancer_validate", "load_balancer_verify",
				"reverse_proxy_check", "reverse_proxy_validate", "reverse_proxy_verify",
				"cdn_check", "cdn_validate", "cdn_verify",
				"cache_check", "cache_validate", "cache_verify",
				"compression_check", "compression_validate", "compression_verify",
				"gzip_check", "gzip_validate", "gzip_verify",
				"deflate_check", "deflate_validate", "deflate_verify",
				"brotli_check", "brotli_validate", "brotli_verify",
				"lz4_check", "lz4_validate", "lz4_verify",
				"snappy_check", "snappy_validate", "snappy_verify",
				"zstd_check", "zstd_validate", "zstd_verify",
				"lzma_check", "lzma_validate", "lzma_verify",
				"heartbeat_check", "heartbeat_validate", "heartbeat_verify",
				"ping_check", "ping_validate", "ping_verify",
				"pong_check", "pong_validate", "pong_verify",
				"reconnection_check", "reconnection_validate", "reconnection_verify",
				"backoff_check", "backoff_validate", "backoff_verify",
				"jitter_check", "jitter_validate", "jitter_verify",
				"random_check", "random_validate", "random_verify",
				"secure_check", "secure_validate", "secure_verify",
				"tls_check", "tls_validate", "tls_verify",
				"ssl_check", "ssl_validate", "ssl_verify",
				"certificate_check", "certificate_validate", "certificate_verify",
				"key_check", "key_validate", "key_verify",
				"pem_check", "pem_validate", "pem_verify",
				"crt_check", "crt_validate", "crt_verify",
				"ca_check", "ca_validate", "ca_verify",
				"ca_bundle_check", "ca_bundle_validate", "ca_bundle_verify",
				"verify_check", "verify_validate", "verify_verify",
				"validation_check", "validation_validate", "validation_verify",
				"sanitize_check", "sanitize_validate", "sanitize_verify",
				"escape_check", "escape_validate", "escape_verify",
				"encode_check", "encode_validate", "encode_verify",
				"decode_check", "decode_validate", "decode_verify",
				"serialize_check", "serialize_validate", "serialize_verify",
				"deserialize_check", "deserialize_validate", "deserialize_verify",
				"marshal_check", "marshal_validate", "marshal_verify",
				"unmarshal_check", "unmarshal_validate", "unmarshal_verify",
				"json_check", "json_validate", "json_verify",
				"xml_check", "xml_validate", "xml_verify",
				"protobuf_check", "protobuf_validate", "protobuf_verify",
				"msgpack_check", "msgpack_validate", "msgpack_verify",
				"avro_check", "avro_validate", "avro_verify",
				"thrift_check", "thrift_validate", "thrift_verify",
				"grpc_check", "grpc_validate", "grpc_verify",
				"rpc_check", "rpc_validate", "rpc_verify",
				"remote_check", "remote_validate", "remote_verify",
				"call_check", "call_validate", "call_verify",
				"invoke_check", "invoke_validate", "invoke_verify",
				"execute_check", "execute_validate", "execute_verify",
				"process_check", "process_validate", "process_verify",
				"handle_check", "handle_validate", "handle_verify",
				"route_check", "route_validate", "route_verify",
				"router_check", "router_validate", "router_verify",
				"dispatcher_check", "dispatcher_validate", "dispatcher_verify",
				"handler_check", "handler_validate", "handler_verify",
				"middleware_check", "middleware_validate", "middleware_verify",
				"interceptor_check", "interceptor_validate", "interceptor_verify",
				"filter_check", "filter_validate", "filter_verify",
				"gateway_check", "gateway_validate", "gateway_verify",
				"proxy_check", "proxy_validate", "proxy_verify",
				"load_balancer_check", "load_balancer_validate", "load_balancer_verify",
				"reverse_proxy_check", "reverse_proxy_validate", "reverse_proxy_verify",
				"cdn_check", "cdn_validate", "cdn_verify",
				"cache_check", "cache_validate", "cache_verify",
				"compression_check", "compression_validate", "compression_verify",
				"gzip_check", "gzip_validate", "gzip_verify",
				"deflate_check", "deflate_validate", "deflate_verify",
				"brotli_check", "brotli_validate", "brotli_verify",
				"lz4_check", "lz4_validate", "lz4_verify",
				"snappy_check", "snappy_validate", "snappy_verify",
				"zstd_check", "zstd_validate", "zstd_verify",
				"lzma_check", "lzma_validate", "lzma_verify",
			}
			
			for _, safe := range safePatterns {
				if strings.Contains(funcNameLower, safe) {
					return false
				}
			}
			
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