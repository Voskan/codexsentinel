package builtin

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"unicode"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var (
	weakHashMeta = ruleMeta{ID: "crypto-weak-hash", Title: "Weak Hash Algorithm", Severity: result.SeverityMedium, CWE: "CWE-328", OWASP: "A04:2025",
		Suggestion: "Use SHA-256 or stronger (crypto/sha256, crypto/sha512, crypto/sha3); for passwords use bcrypt, scrypt or argon2.",
		References: []string{"https://cwe.mitre.org/data/definitions/328.html"}}
	weakCipherMeta = ruleMeta{ID: "crypto-weak-cipher", Title: "Weak Cipher or Static Nonce", Severity: result.SeverityHigh, CWE: "CWE-327", OWASP: "A04:2025",
		Suggestion: "Use AES-GCM or ChaCha20-Poly1305 with a unique random nonce read from crypto/rand for every message.",
		References: []string{"https://cwe.mitre.org/data/definitions/327.html"}}
	weakRSAMeta = ruleMeta{ID: "crypto-weak-rsa", Title: "Weak RSA Key Size", Severity: result.SeverityHigh, CWE: "CWE-326", OWASP: "A04:2025",
		Suggestion: "Generate RSA keys of at least 2048 bits (3072 or more recommended), or use Ed25519/ECDSA P-256.",
		References: []string{"https://cwe.mitre.org/data/definitions/326.html"}}
	weakRandMeta = ruleMeta{ID: "crypto-weak-rand", Title: "Insecure Randomness for Security Value", Severity: result.SeverityHigh, CWE: "CWE-338", OWASP: "A04:2025", Confidence: 0.8,
		Suggestion: "Use crypto/rand (rand.Read or rand.Text in Go 1.24+) to generate keys, tokens, nonces, salts and identifiers.",
		References: []string{"https://cwe.mitre.org/data/definitions/338.html"}}
	tlsInsecureMeta = ruleMeta{ID: "tls-insecure-config", Title: "Insecure TLS Configuration", Severity: result.SeverityHigh, CWE: "CWE-295", OWASP: "A04:2025",
		Suggestion: "Keep certificate verification enabled and set MinVersion to tls.VersionTLS12 or newer.",
		References: []string{"https://cwe.mitre.org/data/definitions/295.html"}}
)

var securityWords = map[string]bool{
	"token": true, "tokens": true, "secret": true, "secrets": true, "password": true, "passwd": true, "pwd": true,
	"nonce": true, "salt": true, "otp": true, "totp": true, "session": true, "sessionid": true, "sid": true,
	"apikey": true, "csrf": true, "xsrf": true, "iv": true, "credential": true, "credentials": true, "privkey": true, "passphrase": true,
}

var keyQualifiers = map[string]bool{"api": true, "secret": true, "private": true, "signing": true, "encryption": true, "aes": true, "hmac": true, "crypto": true, "master": true, "access": true}

// securityName reports whether an identifier names a security-sensitive value,
// splitting camelCase and snake_case words.
func securityName(name string) bool {
	words := splitWords(name)
	for i, w := range words {
		if securityWords[w] {
			return true
		}
		if (w == "key" || w == "keys") && i > 0 && keyQualifiers[words[i-1]] {
			return true
		}
		if w == "key" && len(words) == 2 && (words[0] == "gen" || words[0] == "generate" || words[0] == "new") {
			return true
		}
	}
	return false
}

func splitWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, c := range runes {
		switch {
		case c == '_' || c == '-' || c == '.' || c == ' ':
			flush()
		case unicode.IsUpper(c) && len(cur) > 0 && (unicode.IsLower(cur[len(cur)-1]) || i+1 < len(runes) && unicode.IsLower(runes[i+1])):
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return words
}

// RegisterCryptoWeakRule reports weak primitives, short RSA keys, insecure
// randomness for security values and insecure TLS settings.
func RegisterCryptoWeakRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{weakHashMeta, weakCipherMeta, weakRSAMeta, weakRandMeta, tlsInsecureMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					checkCryptoCall(r, info, x)
				case *ast.CompositeLit:
					if typeIs(typeOf(info, x), "crypto/tls", "Config") {
						checkTLSLiteral(r, info, x)
					}
				case *ast.AssignStmt:
					checkTLSAssign(r, info, x)
				}
				return true
			})
			for _, unit := range funcUnits(file) {
				checkNonces(r, info, unit)
				checkWeakRand(r, info, unit)
			}
		}
	})
}

func checkCryptoCall(r *reporter, info *types.Info, call *ast.CallExpr) {
	fn := calleeFunc(info, call)
	switch {
	case isFunc(fn, "crypto/md5", "New", "Sum"), isFunc(fn, "crypto/sha1", "New", "Sum"), isFunc(fn, "golang.org/x/crypto/md4", "New"), isFunc(fn, "golang.org/x/crypto/ripemd160", "New"):
		r.report(weakHashMeta, call, fmt.Sprintf("%s.%s uses a collision-prone hash algorithm.", fn.Pkg().Name(), fn.Name()))
	case isFunc(fn, "crypto/des", "NewCipher", "NewTripleDESCipher"), isFunc(fn, "crypto/rc4", "NewCipher"), isFunc(fn, "golang.org/x/crypto/blowfish", "NewCipher", "NewSaltedCipher"), isFunc(fn, "golang.org/x/crypto/cast5", "NewCipher"), isFunc(fn, "golang.org/x/crypto/tea", "NewCipher"):
		r.report(weakCipherMeta, call, fmt.Sprintf("%s.%s uses a broken or legacy cipher.", fn.Pkg().Name(), fn.Name()))
	case isFunc(fn, "crypto/rsa", "GenerateKey") && len(call.Args) == 2:
		checkRSABits(r, info, call.Args[1])
	case isFunc(fn, "crypto/rsa", "GenerateMultiPrimeKey") && len(call.Args) == 3:
		checkRSABits(r, info, call.Args[2])
	}
}

func checkRSABits(r *reporter, info *types.Info, bits ast.Expr) {
	if v, ok := constInt(info, bits); ok && v < 2048 {
		r.report(weakRSAMeta, bits, fmt.Sprintf("RSA key size %d is below the 2048-bit minimum.", v))
	}
}

const tlsVersion12 = 0x0303

func checkTLSLiteral(r *reporter, info *types.Info, lit *ast.CompositeLit) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		checkTLSField(r, info, exprName(kv.Key), kv.Value)
	}
}

func checkTLSAssign(r *reporter, info *types.Info, as *ast.AssignStmt) {
	for i, lhs := range as.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok || i >= len(as.Rhs) || !typeIs(typeOf(info, sel.X), "crypto/tls", "Config") {
			continue
		}
		checkTLSField(r, info, sel.Sel.Name, as.Rhs[i])
	}
}

func checkTLSField(r *reporter, info *types.Info, field string, value ast.Expr) {
	switch field {
	case "InsecureSkipVerify":
		if v, ok := constBool(info, value); ok && v {
			r.reportWith(tlsInsecureMeta, value, "InsecureSkipVerify disables TLS certificate verification and enables man-in-the-middle attacks.", "", r.replaceFix("Enable certificate verification", value, "false"))
		}
	case "MinVersion", "MaxVersion":
		if v, ok := constInt(info, value); ok && v > 0 && v < tlsVersion12 {
			r.reportWith(tlsInsecureMeta, value, fmt.Sprintf("TLS %s allows deprecated protocol versions older than TLS 1.2.", field), "", r.replaceFix("Require TLS 1.2", value, "tls.VersionTLS12"))
		}
	}
}

// checkNonces reports AEAD and block-mode calls whose nonce or IV is a constant
// or a zero buffer that is never filled from crypto/rand.
func checkNonces(r *reporter, info *types.Info, unit funcUnit) {
	assigns := assignments(info, unit.Body)
	filled := map[types.Object]bool{}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		var targets []ast.Expr
		switch {
		case isFunc(fn, "crypto/rand", "Read") && len(call.Args) == 1:
			targets = call.Args
		case isFunc(fn, "io", "ReadFull", "ReadAtLeast") && len(call.Args) >= 2:
			targets = call.Args[1:2]
		}
		for _, t := range targets {
			if obj := objOf(info, rootExpr(t)); obj != nil {
				filled[obj] = true
			}
		}
		return true
	})
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		idx := -1
		switch {
		case isMethod(fn, "crypto/cipher", "AEAD", "Seal"):
			idx = 1
		case isFunc(fn, "crypto/cipher", "NewCBCEncrypter", "NewCTR", "NewCFBEncrypter", "NewOFB"):
			idx = 1
		}
		if idx < 0 || idx >= len(call.Args) {
			return true
		}
		arg := call.Args[idx]
		if staticBuffer(info, arg, assigns, filled) {
			r.report(weakCipherMeta, arg, "Nonce/IV is constant or all zeros; reusing it breaks confidentiality and integrity.")
		}
		return true
	})
}

func rootExpr(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.SliceExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return e
		}
	}
}

func staticBuffer(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, filled map[types.Object]bool) bool {
	e = rootExpr(e)
	switch x := e.(type) {
	case *ast.CallExpr:
		if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
			return isConst(info, x.Args[0])
		}
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" {
			_, builtin := info.Uses[id].(*types.Builtin)
			return builtin
		}
	case *ast.CompositeLit:
		return true
	case *ast.Ident:
		obj := objOf(info, x)
		if obj == nil || filled[obj] {
			return false
		}
		rhs := assigns[obj]
		if len(rhs) == 0 {
			return false
		}
		for _, v := range rhs {
			if !staticBuffer(info, v, assigns, filled) {
				return false
			}
		}
		return true
	}
	return false
}

// checkWeakRand reports math/rand usage that produces security-sensitive values.
func checkWeakRand(r *reporter, info *types.Info, unit funcUnit) {
	sensitiveFunc := securityName(unit.Name) && unit.Name != "func literal"
	reported := map[token.Pos]bool{}
	report := func(call *ast.CallExpr, why string) {
		if !reported[call.Pos()] {
			reported[call.Pos()] = true
			r.report(weakRandMeta, call, why)
		}
	}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				name := exprName(lhs)
				if !securityName(name) {
					continue
				}
				rhs := x.Rhs[0]
				if len(x.Rhs) == len(x.Lhs) {
					rhs = x.Rhs[i]
				}
				if call := mathRandCall(info, rhs); call != nil {
					report(call, fmt.Sprintf("%q is generated with math/rand, which is predictable.", name))
				}
			}
		case *ast.CallExpr:
			if !isMathRand(calleeFunc(info, x)) {
				return true
			}
			if sensitiveFunc {
				report(x, fmt.Sprintf("math/rand is predictable and must not be used in %s.", unit.Name))
			} else if fn := calleeFunc(info, x); fn.Name() == "Read" && len(x.Args) == 1 && securityName(exprName(x.Args[0])) {
				report(x, fmt.Sprintf("%q is filled from math/rand, which is predictable.", exprName(x.Args[0])))
			}
		}
		return true
	})
}

func isMathRand(fn *types.Func) bool {
	return fn != nil && fn.Pkg() != nil && (fn.Pkg().Path() == "math/rand" || fn.Pkg().Path() == "math/rand/v2")
}

func mathRandCall(info *types.Info, e ast.Expr) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && found == nil && isMathRand(calleeFunc(info, call)) {
			found = call
		}
		return found == nil
	})
	return found
}
