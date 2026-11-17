package builtin

import "github.com/Voskan/codexsentinel/v2/analyzer"

// RegisterAll registers every built-in rule on ctx.
func RegisterAll(ctx *analyzer.AnalyzerContext) {
	for _, register := range []func(*analyzer.AnalyzerContext){
		RegisterCommandExecRule,
		RegisterSQLInjectionRule,
		RegisterXSSRule,
		RegisterAccessControlRule,
		RegisterInsecureDesignRule,
		RegisterDataIntegrityRule,
		RegisterLoggingMonitoringRule,
		RegisterSSRFRule,
		RegisterNoSQLInjectionRule,
		RegisterCSRFRule,
		RegisterPathTraversalRule,
		RegisterCryptoWeakRule,
		RegisterSecurityMisconfigRule,
		RegisterAuthBypassRule,
		RegisterSessionManagementRule,
		RegisterAPISecurityRule,
		RegisterGraphQLSecurityRule,
		RegisterJWTSecurityRule,
		RegisterWebSocketSecurityRule,
		RegisterHardcodedSecretRule,
		RegisterGRPCSecurityRules,
		RegisterResourceLeakRules,
		RegisterUnsafeErrcheckRules,
		RegisterBOPLARules,
	} {
		register(ctx)
	}
}
