package builtin

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var (
	timingCompareMeta = ruleMeta{ID: "auth-non-constant-time-compare", Title: "Secret Compared in Non-Constant Time", Severity: result.SeverityHigh, CWE: "CWE-208", OWASP: "A07:2025", Confidence: 0.8,
		Suggestion: "Compare secrets, MACs and tokens with crypto/subtle.ConstantTimeCompare or hmac.Equal.",
		References: []string{"https://cwe.mitre.org/data/definitions/208.html"}}
	hardcodedCredentialMeta = ruleMeta{ID: "auth-hardcoded-credential", Title: "Hardcoded Credential Check", Severity: result.SeverityCritical, CWE: "CWE-798", OWASP: "A07:2025", Confidence: 0.9,
		Suggestion: "Verify credentials against a salted hash (bcrypt/argon2) stored outside the source code.",
		References: []string{"https://cwe.mitre.org/data/definitions/798.html"}}
)

var macWords = map[string]bool{"hmac": true, "mac": true, "signature": true, "sig": true, "secret": true, "token": true, "apikey": true, "digest": true, "otp": true, "totp": true, "csrf": true, "xsrf": true, "nonce": true, "passwordhash": true}

var credentialWords = map[string]bool{"password": true, "passwd": true, "pwd": true, "secret": true, "token": true, "apikey": true, "passphrase": true, "credential": true, "credentials": true, "pin": true}

// secretName reports whether the last word of an identifier denotes a secret
// (e.g. expectedSig, apiKey, authToken but not tokenType or passwordPolicy).
func secretName(name string, words map[string]bool) bool {
	parts := splitWords(name)
	if len(parts) == 0 {
		return false
	}
	last := parts[len(parts)-1]
	if words[last] {
		return true
	}
	if last == "key" && len(parts) > 1 && (parts[len(parts)-2] == "api" || parts[len(parts)-2] == "secret" || parts[len(parts)-2] == "access") {
		return true
	}
	return last == "hash" && len(parts) > 1 && (parts[len(parts)-2] == "password" || parts[len(parts)-2] == "token")
}

// RegisterAuthBypassRule reports timing-unsafe secret comparisons and
// credentials compared against string literals.
func RegisterAuthBypassRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{timingCompareMeta, hardcodedCredentialMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BinaryExpr:
					if x.Op != token.EQL && x.Op != token.NEQ {
						return true
					}
					checkComparison(r, info, x, x.X, x.Y)
				case *ast.CallExpr:
					if isFunc(calleeFunc(info, x), "bytes", "Equal") && len(x.Args) == 2 {
						if secretOperand(info, x.Args[0]) || secretOperand(info, x.Args[1]) {
							r.report(timingCompareMeta, x, "bytes.Equal leaks timing information when comparing secrets.")
						}
					}
				}
				return true
			})
		}
	})
}

// secretOperand reports whether e names a secret. Argument-less method calls
// (accessors such as s.signature()) are only treated as secrets when the
// method belongs to a cryptographic or token package.
func secretOperand(info *types.Info, e ast.Expr) bool {
	if call, ok := ast.Unparen(e).(*ast.CallExpr); ok && len(call.Args) == 0 {
		fn := calleeFunc(info, call)
		if fn == nil || fn.Pkg() == nil || !(strings.HasPrefix(fn.Pkg().Path(), "crypto/") || strings.Contains(fn.Pkg().Path(), "jwt") || strings.Contains(fn.Pkg().Path(), "jose")) {
			return false
		}
	}
	return secretName(exprName(e), macWords)
}

func checkComparison(r *reporter, info *types.Info, node ast.Node, a, b ast.Expr) {
	if !isStringLike(typeOf(info, a)) || !isStringLike(typeOf(info, b)) {
		return
	}
	ca, cb := isConst(info, a), isConst(info, b)
	switch {
	case !ca && !cb:
		if isNil(info, a) || isNil(info, b) {
			return
		}
		if secretOperand(info, a) || secretOperand(info, b) {
			r.report(timingCompareMeta, node, "Secret value is compared with ==/!=, which leaks timing information.")
		}
	case ca != cb:
		lit, other := a, b
		if cb {
			lit, other = b, a
		}
		s, ok := constString(info, lit)
		if !ok || len(s) < 3 || !secretName(exprName(other), credentialWords) || placeholderValue(s) {
			return
		}
		r.report(hardcodedCredentialMeta, node, "Credential "+`"`+exprName(other)+`"`+" is compared against a hardcoded literal.")
	}
}

func placeholderValue(s string) bool {
	switch s {
	case "Bearer", "bearer", "Basic", "basic", "null", "undefined", "none", "true", "false":
		return true
	}
	return false
}

func isStringLike(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}
