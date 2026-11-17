package builtin

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var ssrfMeta = ruleMeta{
	ID: "ssrf", Title: "Server-Side Request Forgery", Severity: result.SeverityMedium, CWE: "CWE-918", OWASP: "A01:2025",
	Confidence: 0.6,
	Suggestion: "Parse the URL with net/url and validate its scheme and Hostname() against an allowlist before issuing the request.",
	References: []string{"https://cwe.mitre.org/data/definitions/918.html"},
}

var fixedHost = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#@]+[/?#]`)

// RegisterSSRFRule reports outbound HTTP requests to non-constant URLs whose
// host is not validated in the same function.
func RegisterSSRFRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{ssrfMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				validated := validatesHost(info, unit.Body)
				lt := newLocalTaint(info, unit.Body)
				assigns := lt.assigns
				r.expandConstantLookups(assigns)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					idx := ssrfURLArg(calleeFunc(info, call))
					if idx < 0 || idx >= len(call.Args) {
						return true
					}
					arg := call.Args[idx]
					if isConst(info, arg) || hasFixedHost(info, arg, assigns, 0) {
						return true
					}
					if lt.tainted(arg, "ssrf") {
						r.reportWith(ssrfMeta, arg, "Outbound request URL is derived from HTTP request input.", result.SeverityHigh, nil)
						return true
					}
					if !validated {
						// Without evidence that the URL is attacker-controlled this is a
						// hardening hint; flows from request input are reported above.
						r.reportWith(ssrfMeta, arg, "Outbound request uses a non-constant URL without host validation.", result.SeverityLow, nil)
					}
					return true
				})
			}
		}
	})
}

func ssrfURLArg(fn *types.Func) int {
	switch {
	case isFunc(fn, "net/http", "Get", "Head", "Post", "PostForm"):
		return 0
	case isFunc(fn, "net/http", "NewRequest"):
		return 1
	case isFunc(fn, "net/http", "NewRequestWithContext"):
		return 2
	case isMethod(fn, "net/http", "Client", "Get", "Head", "Post", "PostForm"):
		return 0
	}
	return -1
}

// validatesHost reports whether the function inspects a parsed URL's host,
// e.g. u.Hostname() or u.Host compared against an allowlist.
func validatesHost(info *types.Info, body ast.Node) bool {
	found := false
	inspectShallow(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || found {
			return !found
		}
		if typeIs(typeOf(info, sel.X), "net/url", "URL") && (sel.Sel.Name == "Hostname" || sel.Sel.Name == "Host") {
			found = true
		}
		return true
	})
	return found
}

// fixedURLHost reports whether e is a url.URL value, or a pointer to one,
// built from a composite literal with a constant non-empty Host.
func fixedURLHost(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, depth int) bool {
	if depth > 6 {
		return false
	}
	switch x := ast.Unparen(e).(type) {
	case *ast.UnaryExpr:
		return x.Op == token.AND && fixedURLHost(info, x.X, assigns, depth+1)
	case *ast.CompositeLit:
		if !typeIs(typeOf(info, x), "net/url", "URL") {
			return false
		}
		for _, elt := range x.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Host" {
					host, ok := constString(info, kv.Value)
					return ok && host != ""
				}
			}
		}
	case *ast.Ident:
		obj, ok := info.Uses[x].(*types.Var)
		if !ok || len(assigns[obj]) == 0 {
			return false
		}
		for _, rhs := range assigns[obj] {
			if !fixedURLHost(info, rhs, assigns, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// hasFixedHost reports whether the URL starts with a constant scheme and host.
func hasFixedHost(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr, depth int) bool {
	if depth > 6 {
		return false
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		return hasFixedHost(info, x.X, assigns, depth+1)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return false
		}
		if s, ok := constString(info, x); ok {
			return fixedHost.MatchString(s)
		}
		return hasFixedHost(info, x.X, assigns, depth+1)
	case *ast.CallExpr:
		fn := calleeFunc(info, x)
		if isFunc(fn, "fmt", "Sprintf") && len(x.Args) > 0 {
			if format, ok := constString(info, x.Args[0]); ok {
				return fixedHost.MatchString(format)
			}
		}
		if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && isMethod(fn, "net/url", "URL", "String") {
			return fixedURLHost(info, sel.X, assigns, depth+1)
		}
	case *ast.Ident:
		if obj, ok := info.Uses[x].(*types.Var); ok && len(assigns[obj]) > 0 {
			for _, rhs := range assigns[obj] {
				if !isConst(info, rhs) && !hasFixedHost(info, rhs, assigns, depth+1) {
					return false
				}
				if s, ok := constString(info, rhs); ok && !fixedHost.MatchString(s) {
					return false
				}
			}
			return true
		}
	}
	if s, ok := constString(info, e); ok {
		return fixedHost.MatchString(s)
	}
	return false
}
