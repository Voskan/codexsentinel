package builtin

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var jwtPackages = []string{"github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go", "github.com/form3tech-oss/jwt-go"}

var (
	jwtAlgNoneMeta = ruleMeta{ID: "jwt-alg-none", Title: "JWT 'none' Algorithm Allowed", Severity: result.SeverityCritical, CWE: "CWE-347", OWASP: "A04:2025",
		Suggestion: "Never sign or accept tokens with the 'none' algorithm; use HS256/RS256/EdDSA with a verified key.",
		References: []string{"https://cwe.mitre.org/data/definitions/347.html"}}
	jwtUnverifiedMeta = ruleMeta{ID: "jwt-unverified-parse", Title: "JWT Parsed Without Signature Verification", Severity: result.SeverityHigh, CWE: "CWE-347", OWASP: "A07:2025",
		Suggestion: "Use jwt.Parse or jwt.ParseWithClaims with a key function so the signature is verified before trusting claims.",
		References: []string{"https://cwe.mitre.org/data/definitions/347.html"}}
	jwtMissingAlgMeta = ruleMeta{ID: "jwt-missing-alg-check", Title: "JWT Signing Algorithm Not Enforced", Severity: result.SeverityHigh, CWE: "CWE-347", OWASP: "A07:2025", Confidence: 0.8,
		Suggestion: "Pass jwt.WithValidMethods([]string{\"RS256\"}) or check token.Method in the key function to prevent algorithm confusion attacks.",
		References: []string{"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"}}
	jwtWeakSecretMeta = ruleMeta{ID: "jwt-weak-secret", Title: "Hardcoded or Weak JWT Signing Secret", Severity: result.SeverityHigh, CWE: "CWE-326", OWASP: "A04:2025",
		Suggestion: "Load a random signing key of at least 32 bytes from a secret store or environment instead of embedding it in code.",
		References: []string{"https://cwe.mitre.org/data/definitions/798.html"}}
)

func isJWTObject(obj types.Object, names ...string) bool {
	return obj != nil && obj.Pkg() != nil && pkgMatches(obj.Pkg().Path(), jwtPackages...) && nameIn(obj.Name(), names)
}

func isJWTFunc(fn *types.Func, names ...string) bool {
	return fn != nil && isJWTObject(fn, names...)
}

// RegisterJWTSecurityRule reports insecure use of JWT libraries.
func RegisterJWTSecurityRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{jwtAlgNoneMeta, jwtUnverifiedMeta, jwtMissingAlgMeta, jwtWeakSecretMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		decls := funcDecls(r.pass.Files, info)
		inits := packageVarInits(r.pass.Files, info)
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && isJWTObject(info.Uses[sel.Sel], "SigningMethodNone", "UnsafeAllowNoneSignatureType") {
					r.report(jwtAlgNoneMeta, sel, "The JWT 'none' algorithm disables signature verification.")
				}
				return true
			})
			for _, unit := range funcUnits(file) {
				assigns := assignments(info, unit.Body)
				var unverified []*ast.CallExpr
				verified := false
				inspectShallow(unit.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					fn := calleeFunc(info, call)
					if !isJWTFunc(fn) {
						return true
					}
					switch fn.Name() {
					case "ParseUnverified":
						unverified = append(unverified, call)
					case "Parse", "ParseWithClaims":
						verified = true
						checkAlgorithm(r, info, call, fn, assigns, decls)
					case "SignedString":
						if len(call.Args) == 1 {
							if secret, ok := hardcodedBytes(info, call.Args[0], assigns, inits); ok {
								desc := "JWT is signed with a secret embedded in source code."
								if len(secret) < 32 {
									desc = "JWT is signed with a short hardcoded secret (fewer than 32 bytes)."
								}
								r.report(jwtWeakSecretMeta, call.Args[0], desc)
							}
						}
					}
					return true
				})
				if !verified {
					for _, call := range unverified {
						r.report(jwtUnverifiedMeta, call, "ParseUnverified returns claims without verifying the token signature.")
					}
				}
			}
		}
	})
}

// checkAlgorithm reports jwt.Parse calls that neither restrict valid methods nor
// verify token.Method inside the key function.
func checkAlgorithm(r *reporter, info *types.Info, call *ast.CallExpr, fn *types.Func, assigns map[types.Object][]ast.Expr, decls map[types.Object]*ast.FuncDecl) {
	keyIdx := 1
	if fn.Name() == "ParseWithClaims" {
		keyIdx = 2
	}
	if keyIdx >= len(call.Args) {
		return
	}
	for _, opt := range call.Args[keyIdx+1:] {
		if hasValidMethods(info, opt) {
			return
		}
	}
	if recvOf(fn) != nil {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && parserRestricted(info, sel.X, assigns) {
			return
		}
	}
	var body ast.Node
	switch kf := call.Args[keyIdx].(type) {
	case *ast.FuncLit:
		body = kf.Body
	default:
		if decl := decls[objOf(info, kf)]; decl != nil {
			body = decl.Body
		}
	}
	if body == nil || checksAlgorithm(info, body) {
		return
	}
	r.report(jwtMissingAlgMeta, call, "Token signature algorithm is not restricted; an attacker may switch RS256 to HS256 or other methods.")
}

func hasValidMethods(info *types.Info, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && isJWTFunc(calleeFunc(info, call), "WithValidMethods")
}

func parserRestricted(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr) bool {
	exprs := []ast.Expr{e}
	if obj := objOf(info, e); obj != nil {
		exprs = append(exprs, assigns[obj]...)
	}
	for _, x := range exprs {
		if call, ok := x.(*ast.CallExpr); ok && isJWTFunc(calleeFunc(info, call), "NewParser") {
			for _, arg := range call.Args {
				if hasValidMethods(info, arg) {
					return true
				}
			}
		}
		if cl, ok := x.(*ast.UnaryExpr); ok {
			if lit, ok := cl.X.(*ast.CompositeLit); ok {
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok && exprName(kv.Key) == "ValidMethods" {
						return true
					}
				}
			}
		}
	}
	return false
}

// checksAlgorithm reports whether a key function inspects token.Method or the alg header.
func checksAlgorithm(info *types.Info, body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "Method" && isJWTObject(info.Uses[x.Sel]) {
				found = true
			}
		case *ast.IndexExpr:
			if s, ok := constString(info, x.Index); ok && s == "alg" {
				found = true
			}
		}
		return !found
	})
	return found
}

// hardcodedBytes reports whether e is a []byte conversion of a constant string,
// directly or through a local or package-level variable.
func hardcodedBytes(info *types.Info, e ast.Expr, assigns, inits map[types.Object][]ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.CallExpr:
		if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
			if s, ok := constString(info, x.Args[0]); ok {
				return s, true
			}
		}
	case *ast.Ident:
		obj := objOf(info, x)
		for _, rhs := range append(assigns[obj], inits[obj]...) {
			if s, ok := hardcodedBytes(info, rhs, nil, nil); ok {
				return s, true
			}
		}
	}
	return "", false
}

// packageVarInits indexes the initializers of package-level variables.
func packageVarInits(files []*ast.File, info *types.Info) map[types.Object][]ast.Expr {
	out := map[types.Object][]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if obj := info.Defs[name]; obj != nil {
							out[obj] = append(out[obj], vs.Values[i])
						}
					}
				}
			}
		}
	}
	return out
}

// funcDecls indexes the function declarations of the package by object.
func funcDecls(files []*ast.File, info *types.Info) map[types.Object]*ast.FuncDecl {
	out := map[types.Object]*ast.FuncDecl{}
	for _, file := range files {
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				if obj := info.Defs[fd.Name]; obj != nil {
					out[obj] = fd
				}
			}
		}
	}
	return out
}
