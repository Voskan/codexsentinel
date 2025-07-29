package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterJWTSecurityRule registers the JWT Token Security Issues detection rule.
func RegisterJWTSecurityRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "jwt-security",
		Title:    "JWT Token Security Issues",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "JWT token security vulnerabilities can lead to unauthorized access and token forgery.",
		Matcher:  matchJWTSecurity,
	})
}

// matchJWTSecurity detects JWT security vulnerabilities
func matchJWTSecurity(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				analyzeJWTSecurityCall(x, ctx)
			case *ast.AssignStmt:
				analyzeJWTSecurityAssignment(x, ctx)
			case *ast.IfStmt:
				analyzeJWTSecurityCondition(x, ctx)
			case *ast.FuncDecl:
				analyzeJWTSecurityFunction(x, ctx)
			case *ast.StructType:
				analyzeJWTSecurityStruct(x, ctx)
			}
			return true
		})
	}
}

// analyzeJWTSecurityCall analyzes function calls for JWT security issues
func analyzeJWTSecurityCall(call *ast.CallExpr, ctx *analyzer.AnalyzerContext) {
	// Check for JWT security function calls
	if fun, ok := call.Fun.(*ast.Ident); ok {
		funcName := strings.ToLower(fun.Name)
		if isJWTSecurityIssue(funcName) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "jwt-security-call",
				Title:       "JWT Security Issue",
				Description: "Function call '" + fun.Name + "' may have JWT security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review JWT security implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}

	// Check for JWT security issues in function arguments
	for _, arg := range call.Args {
		if isJWTSecurityArgument(arg) {
			pos := ctx.GetFset().Position(call.Pos())
			ctx.Report(result.Issue{
				ID:          "jwt-security-argument",
				Title:       "JWT Security Argument Issue",
				Description: "JWT security argument may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review JWT security arguments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeJWTSecurityAssignment analyzes assignments for JWT security issues
func analyzeJWTSecurityAssignment(assign *ast.AssignStmt, ctx *analyzer.AnalyzerContext) {
	// Check for JWT security assignments
	for _, expr := range assign.Rhs {
		if isJWTSecurityAssignment(expr) {
			pos := ctx.GetFset().Position(assign.Pos())
			ctx.Report(result.Issue{
				ID:          "jwt-security-assignment",
				Title:       "JWT Security Assignment Issue",
				Description: "JWT security assignment may have security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review JWT security assignments for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeJWTSecurityCondition analyzes if statements for JWT security issues
func analyzeJWTSecurityCondition(ifStmt *ast.IfStmt, ctx *analyzer.AnalyzerContext) {
	// Check for JWT security conditions
	if ifStmt.Cond != nil {
		condStr := getJWTNodeString(ifStmt.Cond)
		if isJWTSecurityCondition(condStr) {
			pos := ctx.GetFset().Position(ifStmt.Pos())
			ctx.Report(result.Issue{
				ID:          "jwt-security-condition",
				Title:       "JWT Security Condition Issue",
				Description: "JWT security condition may have security vulnerabilities: " + condStr,
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review JWT security conditions for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeJWTSecurityFunction analyzes function declarations for JWT security issues
func analyzeJWTSecurityFunction(fn *ast.FuncDecl, ctx *analyzer.AnalyzerContext) {
	// Check for JWT security function names
	if fn.Name != nil {
		funcName := strings.ToLower(fn.Name.Name)
		if isJWTSecurityFunction(funcName) {
			pos := ctx.GetFset().Position(fn.Pos())
			ctx.Report(result.Issue{
				ID:          "jwt-security-function",
				Title:       "JWT Security Function Issue",
				Description: "Function '" + fn.Name.Name + "' may have JWT security vulnerabilities",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "security",
				Suggestion:  "Review JWT security function implementation for vulnerabilities",
				References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
			})
		}
	}
}

// analyzeJWTSecurityStruct analyzes struct declarations for JWT security issues
func analyzeJWTSecurityStruct(structType *ast.StructType, ctx *analyzer.AnalyzerContext) {
	// Check for JWT security struct fields
	if structType.Fields != nil {
		for _, field := range structType.Fields.List {
			if field.Names != nil {
				for _, name := range field.Names {
					fieldName := strings.ToLower(name.Name)
					if isJWTSecurityField(fieldName) {
						pos := ctx.GetFset().Position(name.Pos())
						ctx.Report(result.Issue{
							ID:          "jwt-security-field",
							Title:       "JWT Security Field Issue",
							Description: "Field '" + name.Name + "' may have JWT security vulnerabilities",
							Severity:    result.SeverityHigh,
							Location:    result.NewLocationFromPos(pos, "", ""),
							Category:    "security",
							Suggestion:  "Review JWT security field implementation for vulnerabilities",
							References:  []string{"https://owasp.org/www-project-api-security-top-10/"},
						})
					}
				}
			}
		}
	}
}

// isJWTSecurityIssue checks if function call indicates JWT security issues
func isJWTSecurityIssue(funcName string) bool {
	jwtPatterns := []string{
		"jwt", "token", "bearer", "authorization", "auth",
		"sign", "verify", "validate", "decode", "encode",
		"header", "payload", "signature", "claims",
		"issuer", "subject", "audience", "expiration",
		"issued_at", "not_before", "jwt_id", "type",
		"algorithm", "alg", "typ", "kid", "x5u", "x5c",
		"x5t", "x5t#s256", "crit", "cty", "zip",
		"hs256", "hs384", "hs512", "rs256", "rs384",
		"rs512", "es256", "es384", "es512", "ps256",
		"ps384", "ps512", "none", "nbf", "exp", "iat",
		"iss", "sub", "aud", "jti", "azp", "auth_time",
		"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
		"events", "toe", "txn", "rur", "pnu", "ace_profile",
		"c_hash", "at_hash", "s_hash",
	}

	for _, pattern := range jwtPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// isJWTSecurityArgument checks if function argument indicates JWT security issues
func isJWTSecurityArgument(arg ast.Expr) bool {
	// Check for JWT security identifiers
	if ident, ok := arg.(*ast.Ident); ok {
		return isJWTSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for JWT security literals
	if lit, ok := arg.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		jwtValues := []string{
			"jwt", "token", "bearer", "authorization", "auth",
			"sign", "verify", "validate", "decode", "encode",
			"header", "payload", "signature", "claims",
			"issuer", "subject", "audience", "expiration",
			"issued_at", "not_before", "jwt_id", "type",
			"algorithm", "alg", "typ", "kid", "x5u", "x5c",
			"x5t", "x5t#s256", "crit", "cty", "zip",
			"hs256", "hs384", "hs512", "rs256", "rs384",
			"rs512", "es256", "es384", "es512", "ps256",
			"ps384", "ps512", "none", "nbf", "exp", "iat",
			"iss", "sub", "aud", "jti", "azp", "auth_time",
			"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
			"events", "toe", "txn", "rur", "pnu", "ace_profile",
			"c_hash", "at_hash", "s_hash",
		}
		for _, jwtValue := range jwtValues {
			if strings.Contains(value, jwtValue) {
				return true
			}
		}
	}

	return false
}

// isJWTSecurityAssignment checks if assignment indicates JWT security issues
func isJWTSecurityAssignment(expr ast.Expr) bool {
	// Check for JWT security identifiers
	if ident, ok := expr.(*ast.Ident); ok {
		return isJWTSecurityIssue(strings.ToLower(ident.Name))
	}

	// Check for JWT security literals
	if lit, ok := expr.(*ast.BasicLit); ok {
		value := strings.ToLower(lit.Value)
		jwtValues := []string{
			"jwt", "token", "bearer", "authorization", "auth",
			"sign", "verify", "validate", "decode", "encode",
			"header", "payload", "signature", "claims",
			"issuer", "subject", "audience", "expiration",
			"issued_at", "not_before", "jwt_id", "type",
			"algorithm", "alg", "typ", "kid", "x5u", "x5c",
			"x5t", "x5t#s256", "crit", "cty", "zip",
			"hs256", "hs384", "hs512", "rs256", "rs384",
			"rs512", "es256", "es384", "es512", "ps256",
			"ps384", "ps512", "none", "nbf", "exp", "iat",
			"iss", "sub", "aud", "jti", "azp", "auth_time",
			"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
			"events", "toe", "txn", "rur", "pnu", "ace_profile",
			"c_hash", "at_hash", "s_hash",
		}
		for _, jwtValue := range jwtValues {
			if strings.Contains(value, jwtValue) {
				return true
			}
		}
	}

	return false
}

// isJWTSecurityCondition checks if condition indicates JWT security issues
func isJWTSecurityCondition(condition string) bool {
	jwtPatterns := []string{
		"jwt", "token", "bearer", "authorization", "auth",
		"sign", "verify", "validate", "decode", "encode",
		"header", "payload", "signature", "claims",
		"issuer", "subject", "audience", "expiration",
		"issued_at", "not_before", "jwt_id", "type",
		"algorithm", "alg", "typ", "kid", "x5u", "x5c",
		"x5t", "x5t#s256", "crit", "cty", "zip",
		"hs256", "hs384", "hs512", "rs256", "rs384",
		"rs512", "es256", "es384", "es512", "ps256",
		"ps384", "ps512", "none", "nbf", "exp", "iat",
		"iss", "sub", "aud", "jti", "azp", "auth_time",
		"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
		"events", "toe", "txn", "rur", "pnu", "ace_profile",
		"c_hash", "at_hash", "s_hash",
		"jwt == nil", "jwt == \"\"", "jwt == null",
		"token == nil", "token == \"\"", "token == null",
		"bearer == nil", "bearer == \"\"", "bearer == null",
		"authorization == nil", "authorization == \"\"", "authorization == null",
		"auth == nil", "auth == \"\"", "auth == null",
		"!jwt", "!token", "!bearer", "!authorization", "!auth",
		"jwt == false", "token == false", "bearer == false",
		"authorization == false", "auth == false",
		"jwt == 0", "token == 0", "bearer == 0",
		"authorization == 0", "auth == 0",
	}

	condLower := strings.ToLower(condition)
	for _, pattern := range jwtPatterns {
		if strings.Contains(condLower, pattern) {
			return true
		}
	}
	return false
}

// isJWTSecurityFunction checks if function name indicates JWT security issues
func isJWTSecurityFunction(funcName string) bool {
	jwtFunctions := []string{
		"jwt", "token", "bearer", "authorization", "auth",
		"sign", "verify", "validate", "decode", "encode",
		"header", "payload", "signature", "claims",
		"issuer", "subject", "audience", "expiration",
		"issued_at", "not_before", "jwt_id", "type",
		"algorithm", "alg", "typ", "kid", "x5u", "x5c",
		"x5t", "x5t#s256", "crit", "cty", "zip",
		"hs256", "hs384", "hs512", "rs256", "rs384",
		"rs512", "es256", "es384", "es512", "ps256",
		"ps384", "ps512", "none", "nbf", "exp", "iat",
		"iss", "sub", "aud", "jti", "azp", "auth_time",
		"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
		"events", "toe", "txn", "rur", "pnu", "ace_profile",
		"c_hash", "at_hash", "s_hash",
		"create_jwt", "generate_jwt", "sign_jwt", "verify_jwt",
		"validate_jwt", "decode_jwt", "encode_jwt", "parse_jwt",
		"extract_jwt", "get_jwt", "set_jwt", "update_jwt",
		"delete_jwt", "revoke_jwt", "blacklist_jwt", "whitelist_jwt",
		"jwt_token", "jwt_bearer", "jwt_authorization", "jwt_auth",
		"jwt_sign", "jwt_verify", "jwt_validate", "jwt_decode",
		"jwt_encode", "jwt_header", "jwt_payload", "jwt_signature",
		"jwt_claims", "jwt_issuer", "jwt_subject", "jwt_audience",
		"jwt_expiration", "jwt_issued_at", "jwt_not_before",
		"jwt_jwt_id", "jwt_type", "jwt_algorithm", "jwt_alg",
		"jwt_typ", "jwt_kid", "jwt_x5u", "jwt_x5c", "jwt_x5t",
		"jwt_x5t#s256", "jwt_crit", "jwt_cty", "jwt_zip",
		"jwt_hs256", "jwt_hs384", "jwt_hs512", "jwt_rs256",
		"jwt_rs384", "jwt_rs512", "jwt_es256", "jwt_es384",
		"jwt_es512", "jwt_ps256", "jwt_ps384", "jwt_ps512",
		"jwt_none", "jwt_nbf", "jwt_exp", "jwt_iat", "jwt_iss",
		"jwt_sub", "jwt_aud", "jwt_jti", "jwt_azp", "jwt_auth_time",
		"jwt_nonce", "jwt_acr", "jwt_amr", "jwt_cnf", "jwt_sid",
		"jwt_sub_jwk", "jwt_events", "jwt_toe", "jwt_txn",
		"jwt_rur", "jwt_pnu", "jwt_ace_profile", "jwt_c_hash",
		"jwt_at_hash", "jwt_s_hash",
	}

	for _, jwtFunc := range jwtFunctions {
		if strings.Contains(funcName, jwtFunc) {
			return true
		}
	}
	return false
}

// isJWTSecurityField checks if struct field indicates JWT security issues
func isJWTSecurityField(fieldName string) bool {
	jwtFields := []string{
		"jwt", "token", "bearer", "authorization", "auth",
		"sign", "verify", "validate", "decode", "encode",
		"header", "payload", "signature", "claims",
		"issuer", "subject", "audience", "expiration",
		"issued_at", "not_before", "jwt_id", "type",
		"algorithm", "alg", "typ", "kid", "x5u", "x5c",
		"x5t", "x5t#s256", "crit", "cty", "zip",
		"hs256", "hs384", "hs512", "rs256", "rs384",
		"rs512", "es256", "es384", "es512", "ps256",
		"ps384", "ps512", "none", "nbf", "exp", "iat",
		"iss", "sub", "aud", "jti", "azp", "auth_time",
		"nonce", "acr", "amr", "cnf", "sid", "sub_jwk",
		"events", "toe", "txn", "rur", "pnu", "ace_profile",
		"c_hash", "at_hash", "s_hash",
	}

	for _, jwtField := range jwtFields {
		if strings.Contains(fieldName, jwtField) {
			return true
		}
	}
	return false
}

// getJWTNodeString returns a string representation of an AST node
func getJWTNodeString(node ast.Node) string {
	// This is a simplified implementation
	// In a real implementation, you would use go/printer to get the exact string
	switch x := node.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.BinaryExpr:
		return getJWTNodeString(x.X) + " " + x.Op.String() + " " + getJWTNodeString(x.Y)
	default:
		return "unknown"
	}
} 