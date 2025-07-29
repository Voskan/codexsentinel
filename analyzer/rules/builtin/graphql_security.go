package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterGraphQLSecurityRule registers the GraphQL Security Issues detection rule.
func RegisterGraphQLSecurityRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "graphql-security",
		Title:    "GraphQL Security Issues",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "GraphQL security vulnerabilities can lead to unauthorized access and data exposure.",
		Matcher:  matchGraphQLSecurity,
	})
}

// matchGraphQLSecurity detects GraphQL security vulnerabilities
func matchGraphQLSecurity(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				analyzeGraphQLSecurityCall(x, ctx)
			case *ast.AssignStmt:
				analyzeGraphQLSecurityAssignment(x, ctx)
			case *ast.IfStmt:
				analyzeGraphQLSecurityCondition(x, ctx)
			case *ast.FuncDecl:
				analyzeGraphQLSecurityFunction(x, ctx)
			case *ast.StructType:
				analyzeGraphQLSecurityStruct(x, ctx)
			}
			return true
		})
	}
}

// analyzeGraphQLSecurityCall analyzes function calls for GraphQL security issues
func analyzeGraphQLSecurityCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for GraphQL security function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isGraphQLSecurityIssue(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "graphql-security-call",
				Title:       "GraphQL Security Issue",
				Description: "Function call '" + fun.Name + "' may have GraphQL security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review GraphQL security implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}

	// Check for GraphQL security issues in function arguments
	for _, arg := range call.Args {
		if isGraphQLSecurityArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "graphql-security-argument",
				Title:       "GraphQL Security Argument Issue",
				Description: "GraphQL security argument may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review GraphQL security arguments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeGraphQLSecurityAssignment analyzes assignments for GraphQL security issues
func analyzeGraphQLSecurityAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for GraphQL security assignments
	for _, expr := range assign.Rhs {
		if isGraphQLSecurityAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "graphql-security-assignment",
				Title:       "GraphQL Security Assignment Issue",
				Description: "GraphQL security assignment may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review GraphQL security assignments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeGraphQLSecurityCondition analyzes if statements for GraphQL security issues
func analyzeGraphQLSecurityCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for GraphQL security conditions
	if ifStmt.Cond != nil {
		condStr := getGraphQLNodeString(ifStmt.Cond)
		if isGraphQLSecurityCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "graphql-security-condition",
				Title:       "GraphQL Security Condition Issue",
				Description: "GraphQL security condition may have security vulnerabilities: " + condStr,
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review GraphQL security conditions for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeGraphQLSecurityFunction analyzes function declarations for GraphQL security issues
func analyzeGraphQLSecurityFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for GraphQL security function names
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isGraphQLSecurityFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "graphql-security-function",
				Title:       "GraphQL Security Function Issue",
				Description: "Function '" + fn.Name.Name + "' may have GraphQL security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review GraphQL security function implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeGraphQLSecurityStruct analyzes struct declarations for GraphQL security issues
func analyzeGraphQLSecurityStruct(structType *ast.StructType, ctx *analyzer.AnalyzerContext) {
	// Check for GraphQL security struct fields
	if structType.Fields != nil {
		for _, field := range structType.Fields.List {
			if field.Names != nil {
				for _, name := range field.Names {
					fieldName := strings.ToLower(name.Name)
					if isGraphQLSecurityField(fieldName) {
						pos := ctx.GetFset().Position(name.Pos())
						ctx.Report(result.Issue{
							ID:          "graphql-security-field",
							Title:       "GraphQL Security Field Issue",
							Description: "Field '" + name.Name + "' may have GraphQL security vulnerabilities",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Review GraphQL security field implementation for vulnerabilities",
							References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
						})
					}
				}
			}
		}
	}
}

// isGraphQLSecurityIssue checks if function call indicates GraphQL security issues
func isGraphQLSecurityIssue(funcName string) bool {
	graphqlPatterns := []string{
		"graphql", "gql", "query", "mutation", "subscription",
		"resolver", "schema", "type", "field", "argument",
		"introspection", "introspect", "__schema", "__type",
		"directive", "fragment", "variable", "alias",
		"union", "interface", "enum", "scalar",
		"input", "input_type", "output", "output_type",
		"deprecated", "deprecation", "deprecation_reason",
		"auth", "authorization", "permission", "role",
		"rate_limit", "throttle", "depth_limit", "complexity_limit",
		"query_cost", "query_complexity", "query_depth",
		"max_depth", "max_complexity", "max_cost",
		"timeout", "deadline", "cancel", "abort",
		"cache", "cache_control", "cache_key", "cache_ttl",
		"validation", "validate", "sanitize", "escape",
		"injection", "sql_injection", "nosql_injection",
		"xss", "cross_site_scripting", "script_injection",
		"csrf", "cross_site_request_forgery", "forgery",
		"dos", "denial_of_service", "resource_exhaustion",
		"batching", "batch", "batch_size", "batch_limit",
		"persisted", "persist", "persisted_query",
		"query_id", "query_hash", "query_signature",
		"query_whitelist", "query_blacklist", "query_allowlist",
		"query_denylist", "query_validation", "query_sanitization",
		"query_escaping", "query_injection", "query_xss",
		"query_csrf", "query_dos", "query_batching",
		"mutation_auth", "mutation_authorization", "mutation_permission",
		"mutation_role", "mutation_rate_limit", "mutation_throttle",
		"mutation_validation", "mutation_sanitize", "mutation_escape",
		"mutation_injection", "mutation_xss", "mutation_csrf",
		"subscription_auth", "subscription_authorization", "subscription_permission",
		"subscription_role", "subscription_rate_limit", "subscription_throttle",
		"subscription_validation", "subscription_sanitize", "subscription_escape",
		"subscription_injection", "subscription_xss", "subscription_csrf",
		"resolver_auth", "resolver_authorization", "resolver_permission",
		"resolver_role", "resolver_rate_limit", "resolver_throttle",
		"resolver_validation", "resolver_sanitize", "resolver_escape",
		"resolver_injection", "resolver_xss", "resolver_csrf",
		"schema_auth", "schema_authorization", "schema_permission",
		"schema_role", "schema_validation", "schema_sanitize",
		"schema_escape", "schema_injection", "schema_xss",
		"type_auth", "type_authorization", "type_permission",
		"type_role", "type_validation", "type_sanitize",
		"type_escape", "type_injection", "type_xss",
		"field_auth", "field_authorization", "field_permission",
		"field_role", "field_validation", "field_sanitize",
		"field_escape", "field_injection", "field_xss",
		"argument_auth", "argument_authorization", "argument_permission",
		"argument_role", "argument_validation", "argument_sanitize",
		"argument_escape", "argument_injection", "argument_xss",
		"directive_auth", "directive_authorization", "directive_permission",
		"directive_role", "directive_validation", "directive_sanitize",
		"directive_escape", "directive_injection", "directive_xss",
		"fragment_auth", "fragment_authorization", "fragment_permission",
		"fragment_role", "fragment_validation", "fragment_sanitize",
		"fragment_escape", "fragment_injection", "fragment_xss",
		"variable_auth", "variable_authorization", "variable_permission",
		"variable_role", "variable_validation", "variable_sanitize",
		"variable_escape", "variable_injection", "variable_xss",
		"alias_auth", "alias_authorization", "alias_permission",
		"alias_role", "alias_validation", "alias_sanitize",
		"alias_escape", "alias_injection", "alias_xss",
		"union_auth", "union_authorization", "union_permission",
		"union_role", "union_validation", "union_sanitize",
		"union_escape", "union_injection", "union_xss",
		"interface_auth", "interface_authorization", "interface_permission",
		"interface_role", "interface_validation", "interface_sanitize",
		"interface_escape", "interface_injection", "interface_xss",
		"enum_auth", "enum_authorization", "enum_permission",
		"enum_role", "enum_validation", "enum_sanitize",
		"enum_escape", "enum_injection", "enum_xss",
		"scalar_auth", "scalar_authorization", "scalar_permission",
		"scalar_role", "scalar_validation", "scalar_sanitize",
		"scalar_escape", "scalar_injection", "scalar_xss",
		"input_auth", "input_authorization", "input_permission",
		"input_role", "input_validation", "input_sanitize",
		"input_escape", "input_injection", "input_xss",
		"output_auth", "output_authorization", "output_permission",
		"output_role", "output_validation", "output_sanitize",
		"output_escape", "output_injection", "output_xss",
	}

	for _, pattern := range graphqlPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isGraphQLSecurityArgument checks if function argument indicates GraphQL security issues
func isGraphQLSecurityArgument(arg ast.Expr) bool {
	// Check for GraphQL security identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isGraphQLSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for GraphQL security literals
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		graphqlValues := []string{
			"graphql", "gql", "query", "mutation", "subscription",
			"resolver", "schema", "type", "field", "argument",
			"introspection", "introspect", "__schema", "__type",
			"directive", "fragment", "variable", "alias",
			"union", "interface", "enum", "scalar",
			"input", "input_type", "output", "output_type",
			"deprecated", "deprecation", "deprecation_reason",
			"auth", "authorization", "permission", "role",
			"rate_limit", "throttle", "depth_limit", "complexity_limit",
			"query_cost", "query_complexity", "query_depth",
			"max_depth", "max_complexity", "max_cost",
			"timeout", "deadline", "cancel", "abort",
			"cache", "cache_control", "cache_key", "cache_ttl",
			"validation", "validate", "sanitize", "escape",
			"injection", "sql_injection", "nosql_injection",
			"xss", "cross_site_scripting", "script_injection",
			"csrf", "cross_site_request_forgery", "forgery",
			"dos", "denial_of_service", "resource_exhaustion",
			"batching", "batch", "batch_size", "batch_limit",
			"persisted", "persist", "persisted_query",
			"query_id", "query_hash", "query_signature",
			"query_whitelist", "query_blacklist", "query_allowlist",
			"query_denylist", "query_validation", "query_sanitization",
			"query_escaping", "query_injection", "query_xss",
			"query_csrf", "query_dos", "query_batching",
		}
		for _, graphqlValue := range graphqlValues {
			if strings.Contains(value, graphqlValue) {
				return true
			}
		}
	}

	return false
}

// isGraphQLSecurityAssignment checks if assignment indicates GraphQL security issues
func isGraphQLSecurityAssignment(expr ast.Expr) bool {
	// Check for GraphQL security identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isGraphQLSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for GraphQL security literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		graphqlValues := []string{
			"graphql", "gql", "query", "mutation", "subscription",
			"resolver", "schema", "type", "field", "argument",
			"introspection", "introspect", "__schema", "__type",
			"directive", "fragment", "variable", "alias",
			"union", "interface", "enum", "scalar",
			"input", "input_type", "output", "output_type",
			"deprecated", "deprecation", "deprecation_reason",
			"auth", "authorization", "permission", "role",
			"rate_limit", "throttle", "depth_limit", "complexity_limit",
			"query_cost", "query_complexity", "query_depth",
			"max_depth", "max_complexity", "max_cost",
			"timeout", "deadline", "cancel", "abort",
			"cache", "cache_control", "cache_key", "cache_ttl",
			"validation", "validate", "sanitize", "escape",
			"injection", "sql_injection", "nosql_injection",
			"xss", "cross_site_scripting", "script_injection",
			"csrf", "cross_site_request_forgery", "forgery",
			"dos", "denial_of_service", "resource_exhaustion",
			"batching", "batch", "batch_size", "batch_limit",
			"persisted", "persist", "persisted_query",
			"query_id", "query_hash", "query_signature",
			"query_whitelist", "query_blacklist", "query_allowlist",
			"query_denylist", "query_validation", "query_sanitization",
			"query_escaping", "query_injection", "query_xss",
			"query_csrf", "query_dos", "query_batching",
		}
		for _, graphqlValue := range graphqlValues {
			if strings.Contains(value, graphqlValue) {
				return true
			}
		}
	}

	return false
}

// isGraphQLSecurityCondition checks if condition indicates GraphQL security issues
func isGraphQLSecurityCondition(condition string) bool {
	graphqlPatterns := []string{
		"graphql", "gql", "query", "mutation", "subscription",
		"resolver", "schema", "type", "field", "argument",
		"introspection", "introspect", "__schema", "__type",
		"directive", "fragment", "variable", "alias",
		"union", "interface", "enum", "scalar",
		"input", "input_type", "output", "output_type",
		"deprecated", "deprecation", "deprecation_reason",
		"auth", "authorization", "permission", "role",
		"rate_limit", "throttle", "depth_limit", "complexity_limit",
		"query_cost", "query_complexity", "query_depth",
		"max_depth", "max_complexity", "max_cost",
		"timeout", "deadline", "cancel", "abort",
		"cache", "cache_control", "cache_key", "cache_ttl",
		"validation", "validate", "sanitize", "escape",
		"injection", "sql_injection", "nosql_injection",
		"xss", "cross_site_scripting", "script_injection",
		"csrf", "cross_site_request_forgery", "forgery",
		"dos", "denial_of_service", "resource_exhaustion",
		"batching", "batch", "batch_size", "batch_limit",
		"persisted", "persist", "persisted_query",
		"query_id", "query_hash", "query_signature",
		"query_whitelist", "query_blacklist", "query_allowlist",
		"query_denylist", "query_validation", "query_sanitization",
		"query_escaping", "query_injection", "query_xss",
		"query_csrf", "query_dos", "query_batching",
		"graphql == nil", "graphql == \"\"", "graphql == null",
		"gql == nil", "gql == \"\"", "gql == null",
		"query == nil", "query == \"\"", "query == null",
		"mutation == nil", "mutation == \"\"", "mutation == null",
		"subscription == nil", "subscription == \"\"", "subscription == null",
		"resolver == nil", "resolver == \"\"", "resolver == null",
		"schema == nil", "schema == \"\"", "schema == null",
		"type == nil", "type == \"\"", "type == null",
		"field == nil", "field == \"\"", "field == null",
		"argument == nil", "argument == \"\"", "argument == null",
		"introspection == nil", "introspection == \"\"", "introspection == null",
		"introspect == nil", "introspect == \"\"", "introspect == null",
		"__schema == nil", "__schema == \"\"", "__schema == null",
		"__type == nil", "__type == \"\"", "__type == null",
		"!graphql", "!gql", "!query", "!mutation", "!subscription",
		"!resolver", "!schema", "!type", "!field", "!argument",
		"!introspection", "!introspect", "!__schema", "!__type",
		"graphql == false", "gql == false", "query == false",
		"mutation == false", "subscription == false", "resolver == false",
		"schema == false", "type == false", "field == false", "argument == false",
		"introspection == false", "introspect == false", "__schema == false", "__type == false",
		"graphql == 0", "gql == 0", "query == 0", "mutation == 0",
		"subscription == 0", "resolver == 0", "schema == 0", "type == 0",
		"field == 0", "argument == 0", "introspection == 0", "introspect == 0",
		"__schema == 0", "__type == 0",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range graphqlPatterns {
		if strings.Contains(condLower, pattern) {
			return true
		}
	}
	return false
}

// isGraphQLSecurityFunction checks if function name indicates GraphQL security issues
func isGraphQLSecurityFunction(funcName string) bool {
	graphqlFunctions := []string{
		"graphql", "gql", "query", "mutation", "subscription",
		"resolver", "schema", "type", "field", "argument",
		"introspection", "introspect", "__schema", "__type",
		"directive", "fragment", "variable", "alias",
		"union", "interface", "enum", "scalar",
		"input", "input_type", "output", "output_type",
		"deprecated", "deprecation", "deprecation_reason",
		"auth", "authorization", "permission", "role",
		"rate_limit", "throttle", "depth_limit", "complexity_limit",
		"query_cost", "query_complexity", "query_depth",
		"max_depth", "max_complexity", "max_cost",
		"timeout", "deadline", "cancel", "abort",
		"cache", "cache_control", "cache_key", "cache_ttl",
		"validation", "validate", "sanitize", "escape",
		"injection", "sql_injection", "nosql_injection",
		"xss", "cross_site_scripting", "script_injection",
		"csrf", "cross_site_request_forgery", "forgery",
		"dos", "denial_of_service", "resource_exhaustion",
		"batching", "batch", "batch_size", "batch_limit",
		"persisted", "persist", "persisted_query",
		"query_id", "query_hash", "query_signature",
		"query_whitelist", "query_blacklist", "query_allowlist",
		"query_denylist", "query_validation", "query_sanitization",
		"query_escaping", "query_injection", "query_xss",
		"query_csrf", "query_dos", "query_batching",
		"create_graphql", "get_graphql", "update_graphql", "delete_graphql",
		"create_gql", "get_gql", "update_gql", "delete_gql",
		"create_query", "get_query", "update_query", "delete_query",
		"create_mutation", "get_mutation", "update_mutation", "delete_mutation",
		"create_subscription", "get_subscription", "update_subscription", "delete_subscription",
		"create_resolver", "get_resolver", "update_resolver", "delete_resolver",
		"create_schema", "get_schema", "update_schema", "delete_schema",
		"create_type", "get_type", "update_type", "delete_type",
		"create_field", "get_field", "update_field", "delete_field",
		"create_argument", "get_argument", "update_argument", "delete_argument",
		"create_introspection", "get_introspection", "update_introspection", "delete_introspection",
		"create_introspect", "get_introspect", "update_introspect", "delete_introspect",
		"create___schema", "get___schema", "update___schema", "delete___schema",
		"create___type", "get___type", "update___type", "delete___type",
		"graphql_auth", "graphql_authorization", "graphql_permission", "graphql_role",
		"graphql_rate_limit", "graphql_throttle", "graphql_depth_limit", "graphql_complexity_limit",
		"graphql_query_cost", "graphql_query_complexity", "graphql_query_depth",
		"graphql_max_depth", "graphql_max_complexity", "graphql_max_cost",
		"graphql_timeout", "graphql_deadline", "graphql_cancel", "graphql_abort",
		"graphql_cache", "graphql_cache_control", "graphql_cache_key", "graphql_cache_ttl",
		"graphql_validation", "graphql_validate", "graphql_sanitize", "graphql_escape",
		"graphql_injection", "graphql_sql_injection", "graphql_nosql_injection",
		"graphql_xss", "graphql_cross_site_scripting", "graphql_script_injection",
		"graphql_csrf", "graphql_cross_site_request_forgery", "graphql_forgery",
		"graphql_dos", "graphql_denial_of_service", "graphql_resource_exhaustion",
		"graphql_batching", "graphql_batch", "graphql_batch_size", "graphql_batch_limit",
		"graphql_persisted", "graphql_persist", "graphql_persisted_query",
		"graphql_query_id", "graphql_query_hash", "graphql_query_signature",
		"graphql_query_whitelist", "graphql_query_blacklist", "graphql_query_allowlist",
		"graphql_query_denylist", "graphql_query_validation", "graphql_query_sanitization",
		"graphql_query_escaping", "graphql_query_injection", "graphql_query_xss",
		"graphql_query_csrf", "graphql_query_dos", "graphql_query_batching",
	}

	for _, graphqlFunc := range graphqlFunctions {
		if strings.Contains(funcName, graphqlFunc) {
			return true
		}
	}
	return false
}

// isGraphQLSecurityField checks if struct field indicates GraphQL security issues
func isGraphQLSecurityField(fieldName string) bool {
	graphqlFields := []string{
		"graphql", "gql", "query", "mutation", "subscription",
		"resolver", "schema", "type", "field", "argument",
		"introspection", "introspect", "__schema", "__type",
		"directive", "fragment", "variable", "alias",
		"union", "interface", "enum", "scalar",
		"input", "input_type", "output", "output_type",
		"deprecated", "deprecation", "deprecation_reason",
		"auth", "authorization", "permission", "role",
		"rate_limit", "throttle", "depth_limit", "complexity_limit",
		"query_cost", "query_complexity", "query_depth",
		"max_depth", "max_complexity", "max_cost",
		"timeout", "deadline", "cancel", "abort",
		"cache", "cache_control", "cache_key", "cache_ttl",
		"validation", "validate", "sanitize", "escape",
		"injection", "sql_injection", "nosql_injection",
		"xss", "cross_site_scripting", "script_injection",
		"csrf", "cross_site_request_forgery", "forgery",
		"dos", "denial_of_service", "resource_exhaustion",
		"batching", "batch", "batch_size", "batch_limit",
		"persisted", "persist", "persisted_query",
		"query_id", "query_hash", "query_signature",
		"query_whitelist", "query_blacklist", "query_allowlist",
		"query_denylist", "query_validation", "query_sanitization",
		"query_escaping", "query_injection", "query_xss",
		"query_csrf", "query_dos", "query_batching",
	}

	for _, graphqlField := range graphqlFields {
		if strings.Contains(fieldName, graphqlField) {
			return true
		}
	}
	return false
}

// getGraphQLNodeString returns a string representation of an AST node
func getGraphQLNodeString(node ast.Node) string {
	// This is a simplified implementation
	// In a real implementation, you would use go/printer to get the exact string
	switch x := node.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.BinaryExpr:
		return getGraphQLNodeString(x.X) + " " + x.Op.String() + " " + getGraphQLNodeString(x.Y)
	default:
		return "unknown"
	}
} 