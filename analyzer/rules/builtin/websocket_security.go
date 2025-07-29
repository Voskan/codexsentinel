package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterWebSocketSecurityRule registers the WebSocket Security Issues detection rule.
func RegisterWebSocketSecurityRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "websocket-security",
		Title:    "WebSocket Security Issues",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "WebSocket security vulnerabilities can lead to unauthorized access and data exposure.",
		Matcher:  matchWebSocketSecurity,
	})
}

// matchWebSocketSecurity detects WebSocket security vulnerabilities
func matchWebSocketSecurity(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				analyzeWebSocketSecurityCall(x, ctx)
			case *ast.AssignStmt:
				analyzeWebSocketSecurityAssignment(x, ctx)
			case *ast.IfStmt:
				analyzeWebSocketSecurityCondition(x, ctx)
			case *ast.FuncDecl:
				analyzeWebSocketSecurityFunction(x, ctx)
			case *ast.StructType:
				analyzeWebSocketSecurityStruct(x, ctx)
			}
			return true
		})
	}
}

// analyzeWebSocketSecurityCall analyzes function calls for WebSocket security issues
func analyzeWebSocketSecurityCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for WebSocket security function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isWebSocketSecurityIssue(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "websocket-security-call",
				Title:       "WebSocket Security Issue",
				Description: "Function call '" + fun.Name + "' may have WebSocket security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review WebSocket security implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}

	// Check for WebSocket security issues in function arguments
	for _, arg := range call.Args {
		if isWebSocketSecurityArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "websocket-security-argument",
				Title:       "WebSocket Security Argument Issue",
				Description: "WebSocket security argument may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review WebSocket security arguments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeWebSocketSecurityAssignment analyzes assignments for WebSocket security issues
func analyzeWebSocketSecurityAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for WebSocket security assignments
	for _, expr := range assign.Rhs {
		if isWebSocketSecurityAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "websocket-security-assignment",
				Title:       "WebSocket Security Assignment Issue",
				Description: "WebSocket security assignment may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review WebSocket security assignments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeWebSocketSecurityCondition analyzes if statements for WebSocket security issues
func analyzeWebSocketSecurityCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for WebSocket security conditions
	if ifStmt.Cond != nil {
		condStr := getWebSocketNodeString(ifStmt.Cond)
		if isWebSocketSecurityCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "websocket-security-condition",
				Title:       "WebSocket Security Condition Issue",
				Description: "WebSocket security condition may have security vulnerabilities: " + condStr,
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review WebSocket security conditions for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeWebSocketSecurityFunction analyzes function declarations for WebSocket security issues
func analyzeWebSocketSecurityFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for WebSocket security function names
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isWebSocketSecurityFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "websocket-security-function",
				Title:       "WebSocket Security Function Issue",
				Description: "Function '" + fn.Name.Name + "' may have WebSocket security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review WebSocket security function implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeWebSocketSecurityStruct analyzes struct declarations for WebSocket security issues
func analyzeWebSocketSecurityStruct(structType *ast.StructType, ctx *analyzer.AnalyzerContext) {
	// Check for WebSocket security struct fields
	if structType.Fields != nil {
		for _, field := range structType.Fields.List {
			if field.Names != nil {
				for _, name := range field.Names {
					fieldName := strings.ToLower(name.Name)
					if isWebSocketSecurityField(fieldName) {
						pos := ctx.GetFset().Position(name.Pos())
						ctx.Report(result.Issue{
							ID:          "websocket-security-field",
							Title:       "WebSocket Security Field Issue",
							Description: "Field '" + name.Name + "' may have WebSocket security vulnerabilities",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Review WebSocket security field implementation for vulnerabilities",
							References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
						})
					}
				}
			}
		}
	}
}

// isWebSocketSecurityIssue checks if function call indicates WebSocket security issues
func isWebSocketSecurityIssue(funcName string) bool {
	websocketPatterns := []string{
		"websocket", "ws", "wss", "upgrade", "connection",
		"handshake", "upgrade", "protocol", "origin",
		"subprotocol", "extensions", "compression",
		"ping", "pong", "close", "message", "text",
		"binary", "data", "send", "receive", "read",
		"write", "flush", "buffer", "frame", "mask",
		"unmask", "fragmentation", "continuation",
		"control", "data_frame", "ping_frame", "pong_frame",
		"close_frame", "opcode", "fin", "rsv1", "rsv2",
		"rsv3", "payload_length", "masking_key",
		"payload_data", "close_code", "close_reason",
		"status_code", "error_code", "error_message",
		"connection_id", "session_id", "client_id",
		"server_id", "endpoint", "url", "path",
		"query", "headers", "cookies", "authentication",
		"authorization", "token", "bearer", "api_key",
		"rate_limit", "throttle", "quota", "limit",
		"timeout", "deadline", "cancel", "abort",
		"heartbeat", "keepalive", "alive", "dead",
		"reconnect", "retry", "backoff", "exponential",
		"linear", "jitter", "random", "secure", "tls",
		"ssl", "certificate", "key", "pem", "crt",
		"ca", "ca_bundle", "verify", "validation",
		"sanitize", "escape", "encode", "decode",
		"serialize", "deserialize", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle",
		"route", "router", "dispatcher", "handler",
		"middleware", "interceptor", "filter", "gateway",
		"proxy", "load_balancer", "reverse_proxy",
		"cdn", "cache", "compression", "gzip", "deflate",
		"brotli", "lz4", "snappy", "zstd", "lzma",
		"create_websocket", "new_websocket", "open_websocket",
		"connect_websocket", "dial_websocket", "upgrade_websocket",
		"handshake_websocket", "close_websocket", "shutdown_websocket",
		"send_websocket", "receive_websocket", "read_websocket",
		"write_websocket", "flush_websocket", "buffer_websocket",
		"frame_websocket", "mask_websocket", "unmask_websocket",
		"fragment_websocket", "continuation_websocket",
		"control_websocket", "data_frame_websocket", "ping_frame_websocket",
		"pong_frame_websocket", "close_frame_websocket",
		"opcode_websocket", "fin_websocket", "rsv1_websocket",
		"rsv2_websocket", "rsv3_websocket", "payload_length_websocket",
		"masking_key_websocket", "payload_data_websocket",
		"close_code_websocket", "close_reason_websocket",
		"status_code_websocket", "error_code_websocket",
		"error_message_websocket", "connection_id_websocket",
		"session_id_websocket", "client_id_websocket",
		"server_id_websocket", "endpoint_websocket", "url_websocket",
		"path_websocket", "query_websocket", "headers_websocket",
		"cookies_websocket", "authentication_websocket",
		"authorization_websocket", "token_websocket", "bearer_websocket",
		"api_key_websocket", "rate_limit_websocket", "throttle_websocket",
		"quota_websocket", "limit_websocket", "timeout_websocket",
		"deadline_websocket", "cancel_websocket", "abort_websocket",
		"heartbeat_websocket", "keepalive_websocket", "alive_websocket",
		"dead_websocket", "reconnect_websocket", "retry_websocket",
		"backoff_websocket", "exponential_websocket", "linear_websocket",
		"jitter_websocket", "random_websocket", "secure_websocket",
		"tls_websocket", "ssl_websocket", "certificate_websocket",
		"key_websocket", "pem_websocket", "crt_websocket",
		"ca_websocket", "ca_bundle_websocket", "verify_websocket",
		"validation_websocket", "sanitize_websocket", "escape_websocket",
		"encode_websocket", "decode_websocket", "serialize_websocket",
		"deserialize_websocket", "marshal_websocket", "unmarshal_websocket",
		"json_websocket", "xml_websocket", "protobuf_websocket",
		"msgpack_websocket", "avro_websocket", "thrift_websocket",
		"grpc_websocket", "rpc_websocket", "remote_websocket",
		"call_websocket", "invoke_websocket", "execute_websocket",
		"process_websocket", "handle_websocket", "route_websocket",
		"router_websocket", "dispatcher_websocket", "handler_websocket",
		"middleware_websocket", "interceptor_websocket", "filter_websocket",
		"gateway_websocket", "proxy_websocket", "load_balancer_websocket",
		"reverse_proxy_websocket", "cdn_websocket", "cache_websocket",
		"compression_websocket", "gzip_websocket", "deflate_websocket",
		"brotli_websocket", "lz4_websocket", "snappy_websocket",
		"zstd_websocket", "lzma_websocket",
	}

	for _, pattern := range websocketPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isWebSocketSecurityArgument checks if function argument indicates WebSocket security issues
func isWebSocketSecurityArgument(arg ast.Expr) bool {
	// Check for WebSocket security identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isWebSocketSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for WebSocket security literals
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		websocketValues := []string{
			"websocket", "ws", "wss", "upgrade", "connection",
			"handshake", "upgrade", "protocol", "origin",
			"subprotocol", "extensions", "compression",
			"ping", "pong", "close", "message", "text",
			"binary", "data", "send", "receive", "read",
			"write", "flush", "buffer", "frame", "mask",
			"unmask", "fragmentation", "continuation",
			"control", "data_frame", "ping_frame", "pong_frame",
			"close_frame", "opcode", "fin", "rsv1", "rsv2",
			"rsv3", "payload_length", "masking_key",
			"payload_data", "close_code", "close_reason",
			"status_code", "error_code", "error_message",
			"connection_id", "session_id", "client_id",
			"server_id", "endpoint", "url", "path",
			"query", "headers", "cookies", "authentication",
			"authorization", "token", "bearer", "api_key",
			"rate_limit", "throttle", "quota", "limit",
			"timeout", "deadline", "cancel", "abort",
			"heartbeat", "keepalive", "alive", "dead",
			"reconnect", "retry", "backoff", "exponential",
			"linear", "jitter", "random", "secure", "tls",
			"ssl", "certificate", "key", "pem", "crt",
			"ca", "ca_bundle", "verify", "validation",
			"sanitize", "escape", "encode", "decode",
			"serialize", "deserialize", "marshal", "unmarshal",
			"json", "xml", "protobuf", "msgpack", "avro",
			"thrift", "grpc", "rpc", "remote", "call",
			"invoke", "execute", "process", "handle",
			"route", "router", "dispatcher", "handler",
			"middleware", "interceptor", "filter", "gateway",
			"proxy", "load_balancer", "reverse_proxy",
			"cdn", "cache", "compression", "gzip", "deflate",
			"brotli", "lz4", "snappy", "zstd", "lzma",
		}
		for _, websocketValue := range websocketValues {
			if strings.Contains(value, websocketValue) {
				return true
			}
		}
	}

	return false
}

// isWebSocketSecurityAssignment checks if assignment indicates WebSocket security issues
func isWebSocketSecurityAssignment(expr ast.Expr) bool {
	// Check for WebSocket security identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isWebSocketSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for WebSocket security literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		websocketValues := []string{
			"websocket", "ws", "wss", "upgrade", "connection",
			"handshake", "upgrade", "protocol", "origin",
			"subprotocol", "extensions", "compression",
			"ping", "pong", "close", "message", "text",
			"binary", "data", "send", "receive", "read",
			"write", "flush", "buffer", "frame", "mask",
			"unmask", "fragmentation", "continuation",
			"control", "data_frame", "ping_frame", "pong_frame",
			"close_frame", "opcode", "fin", "rsv1", "rsv2",
			"rsv3", "payload_length", "masking_key",
			"payload_data", "close_code", "close_reason",
			"status_code", "error_code", "error_message",
			"connection_id", "session_id", "client_id",
			"server_id", "endpoint", "url", "path",
			"query", "headers", "cookies", "authentication",
			"authorization", "token", "bearer", "api_key",
			"rate_limit", "throttle", "quota", "limit",
			"timeout", "deadline", "cancel", "abort",
			"heartbeat", "keepalive", "alive", "dead",
			"reconnect", "retry", "backoff", "exponential",
			"linear", "jitter", "random", "secure", "tls",
			"ssl", "certificate", "key", "pem", "crt",
			"ca", "ca_bundle", "verify", "validation",
			"sanitize", "escape", "encode", "decode",
			"serialize", "deserialize", "marshal", "unmarshal",
			"json", "xml", "protobuf", "msgpack", "avro",
			"thrift", "grpc", "rpc", "remote", "call",
			"invoke", "execute", "process", "handle",
			"route", "router", "dispatcher", "handler",
			"middleware", "interceptor", "filter", "gateway",
			"proxy", "load_balancer", "reverse_proxy",
			"cdn", "cache", "compression", "gzip", "deflate",
			"brotli", "lz4", "snappy", "zstd", "lzma",
		}
		for _, websocketValue := range websocketValues {
			if strings.Contains(value, websocketValue) {
				return true
			}
		}
	}

	return false
}

// isWebSocketSecurityCondition checks if condition indicates WebSocket security issues
func isWebSocketSecurityCondition(condition string) bool {
	websocketPatterns := []string{
		"websocket", "ws", "wss", "upgrade", "connection",
		"handshake", "upgrade", "protocol", "origin",
		"subprotocol", "extensions", "compression",
		"ping", "pong", "close", "message", "text",
		"binary", "data", "send", "receive", "read",
		"write", "flush", "buffer", "frame", "mask",
		"unmask", "fragmentation", "continuation",
		"control", "data_frame", "ping_frame", "pong_frame",
		"close_frame", "opcode", "fin", "rsv1", "rsv2",
		"rsv3", "payload_length", "masking_key",
		"payload_data", "close_code", "close_reason",
		"status_code", "error_code", "error_message",
		"connection_id", "session_id", "client_id",
		"server_id", "endpoint", "url", "path",
		"query", "headers", "cookies", "authentication",
		"authorization", "token", "bearer", "api_key",
		"rate_limit", "throttle", "quota", "limit",
		"timeout", "deadline", "cancel", "abort",
		"heartbeat", "keepalive", "alive", "dead",
		"reconnect", "retry", "backoff", "exponential",
		"linear", "jitter", "random", "secure", "tls",
		"ssl", "certificate", "key", "pem", "crt",
		"ca", "ca_bundle", "verify", "validation",
		"sanitize", "escape", "encode", "decode",
		"serialize", "deserialize", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle",
		"route", "router", "dispatcher", "handler",
		"middleware", "interceptor", "filter", "gateway",
		"proxy", "load_balancer", "reverse_proxy",
		"cdn", "cache", "compression", "gzip", "deflate",
		"brotli", "lz4", "snappy", "zstd", "lzma",
		"websocket == nil", "websocket == \"\"", "websocket == null",
		"ws == nil", "ws == \"\"", "ws == null",
		"wss == nil", "wss == \"\"", "wss == null",
		"upgrade == nil", "upgrade == \"\"", "upgrade == null",
		"connection == nil", "connection == \"\"", "connection == null",
		"handshake == nil", "handshake == \"\"", "handshake == null",
		"protocol == nil", "protocol == \"\"", "protocol == null",
		"origin == nil", "origin == \"\"", "origin == null",
		"!websocket", "!ws", "!wss", "!upgrade", "!connection",
		"!handshake", "!protocol", "!origin",
		"websocket == false", "ws == false", "wss == false",
		"upgrade == false", "connection == false", "handshake == false",
		"protocol == false", "origin == false",
		"websocket == 0", "ws == 0", "wss == 0",
		"upgrade == 0", "connection == 0", "handshake == 0",
		"protocol == 0", "origin == 0",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range websocketPatterns {
		if strings.Contains(condLower, pattern) {
			return true
		}
	}
	return false
}

// isWebSocketSecurityFunction checks if function name indicates WebSocket security issues
func isWebSocketSecurityFunction(funcName string) bool {
	websocketFunctions := []string{
		"websocket", "ws", "wss", "upgrade", "connection",
		"handshake", "upgrade", "protocol", "origin",
		"subprotocol", "extensions", "compression",
		"ping", "pong", "close", "message", "text",
		"binary", "data", "send", "receive", "read",
		"write", "flush", "buffer", "frame", "mask",
		"unmask", "fragmentation", "continuation",
		"control", "data_frame", "ping_frame", "pong_frame",
		"close_frame", "opcode", "fin", "rsv1", "rsv2",
		"rsv3", "payload_length", "masking_key",
		"payload_data", "close_code", "close_reason",
		"status_code", "error_code", "error_message",
		"connection_id", "session_id", "client_id",
		"server_id", "endpoint", "url", "path",
		"query", "headers", "cookies", "authentication",
		"authorization", "token", "bearer", "api_key",
		"rate_limit", "throttle", "quota", "limit",
		"timeout", "deadline", "cancel", "abort",
		"heartbeat", "keepalive", "alive", "dead",
		"reconnect", "retry", "backoff", "exponential",
		"linear", "jitter", "random", "secure", "tls",
		"ssl", "certificate", "key", "pem", "crt",
		"ca", "ca_bundle", "verify", "validation",
		"sanitize", "escape", "encode", "decode",
		"serialize", "deserialize", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle",
		"route", "router", "dispatcher", "handler",
		"middleware", "interceptor", "filter", "gateway",
		"proxy", "load_balancer", "reverse_proxy",
		"cdn", "cache", "compression", "gzip", "deflate",
		"brotli", "lz4", "snappy", "zstd", "lzma",
		"create_websocket", "new_websocket", "open_websocket",
		"connect_websocket", "dial_websocket", "upgrade_websocket",
		"handshake_websocket", "close_websocket", "shutdown_websocket",
		"send_websocket", "receive_websocket", "read_websocket",
		"write_websocket", "flush_websocket", "buffer_websocket",
		"frame_websocket", "mask_websocket", "unmask_websocket",
		"fragment_websocket", "continuation_websocket",
		"control_websocket", "data_frame_websocket", "ping_frame_websocket",
		"pong_frame_websocket", "close_frame_websocket",
		"opcode_websocket", "fin_websocket", "rsv1_websocket",
		"rsv2_websocket", "rsv3_websocket", "payload_length_websocket",
		"masking_key_websocket", "payload_data_websocket",
		"close_code_websocket", "close_reason_websocket",
		"status_code_websocket", "error_code_websocket",
		"error_message_websocket", "connection_id_websocket",
		"session_id_websocket", "client_id_websocket",
		"server_id_websocket", "endpoint_websocket", "url_websocket",
		"path_websocket", "query_websocket", "headers_websocket",
		"cookies_websocket", "authentication_websocket",
		"authorization_websocket", "token_websocket", "bearer_websocket",
		"api_key_websocket", "rate_limit_websocket", "throttle_websocket",
		"quota_websocket", "limit_websocket", "timeout_websocket",
		"deadline_websocket", "cancel_websocket", "abort_websocket",
		"heartbeat_websocket", "keepalive_websocket", "alive_websocket",
		"dead_websocket", "reconnect_websocket", "retry_websocket",
		"backoff_websocket", "exponential_websocket", "linear_websocket",
		"jitter_websocket", "random_websocket", "secure_websocket",
		"tls_websocket", "ssl_websocket", "certificate_websocket",
		"key_websocket", "pem_websocket", "crt_websocket",
		"ca_websocket", "ca_bundle_websocket", "verify_websocket",
		"validation_websocket", "sanitize_websocket", "escape_websocket",
		"encode_websocket", "decode_websocket", "serialize_websocket",
		"deserialize_websocket", "marshal_websocket", "unmarshal_websocket",
		"json_websocket", "xml_websocket", "protobuf_websocket",
		"msgpack_websocket", "avro_websocket", "thrift_websocket",
		"grpc_websocket", "rpc_websocket", "remote_websocket",
		"call_websocket", "invoke_websocket", "execute_websocket",
		"process_websocket", "handle_websocket", "route_websocket",
		"router_websocket", "dispatcher_websocket", "handler_websocket",
		"middleware_websocket", "interceptor_websocket", "filter_websocket",
		"gateway_websocket", "proxy_websocket", "load_balancer_websocket",
		"reverse_proxy_websocket", "cdn_websocket", "cache_websocket",
		"compression_websocket", "gzip_websocket", "deflate_websocket",
		"brotli_websocket", "lz4_websocket", "snappy_websocket",
		"zstd_websocket", "lzma_websocket",
	}

	for _, websocketFunc := range websocketFunctions {
		if strings.Contains(funcName, websocketFunc) {
			return true
		}
	}
	return false
}

// isWebSocketSecurityField checks if struct field indicates WebSocket security issues
func isWebSocketSecurityField(fieldName string) bool {
	websocketFields := []string{
		"websocket", "ws", "wss", "upgrade", "connection",
		"handshake", "upgrade", "protocol", "origin",
		"subprotocol", "extensions", "compression",
		"ping", "pong", "close", "message", "text",
		"binary", "data", "send", "receive", "read",
		"write", "flush", "buffer", "frame", "mask",
		"unmask", "fragmentation", "continuation",
		"control", "data_frame", "ping_frame", "pong_frame",
		"close_frame", "opcode", "fin", "rsv1", "rsv2",
		"rsv3", "payload_length", "masking_key",
		"payload_data", "close_code", "close_reason",
		"status_code", "error_code", "error_message",
		"connection_id", "session_id", "client_id",
		"server_id", "endpoint", "url", "path",
		"query", "headers", "cookies", "authentication",
		"authorization", "token", "bearer", "api_key",
		"rate_limit", "throttle", "quota", "limit",
		"timeout", "deadline", "cancel", "abort",
		"heartbeat", "keepalive", "alive", "dead",
		"reconnect", "retry", "backoff", "exponential",
		"linear", "jitter", "random", "secure", "tls",
		"ssl", "certificate", "key", "pem", "crt",
		"ca", "ca_bundle", "verify", "validation",
		"sanitize", "escape", "encode", "decode",
		"serialize", "deserialize", "marshal", "unmarshal",
		"json", "xml", "protobuf", "msgpack", "avro",
		"thrift", "grpc", "rpc", "remote", "call",
		"invoke", "execute", "process", "handle",
		"route", "router", "dispatcher", "handler",
		"middleware", "interceptor", "filter", "gateway",
		"proxy", "load_balancer", "reverse_proxy",
		"cdn", "cache", "compression", "gzip", "deflate",
		"brotli", "lz4", "snappy", "zstd", "lzma",
	}

	for _, websocketField := range websocketFields {
		if strings.Contains(fieldName, websocketField) {
			return true
		}
	}
	return false
}

// getWebSocketNodeString returns a string representation of an AST node
func getWebSocketNodeString(node ast.Node) string {
	// This is a simplified implementation
	// In a real implementation, you would use go/printer to get the exact string
	switch x := node.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.BinaryExpr:
		return getWebSocketNodeString(x.X) + " " + x.Op.String() + " " + getWebSocketNodeString(x.Y)
	default:
		return "unknown"
	}
} 