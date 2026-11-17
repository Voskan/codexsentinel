package builtin

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var (
	contextMeta = ruleMeta{ID: "context-propagation-missing", Title: "Request Context Not Propagated", Severity: result.SeverityMedium, CWE: "CWE-400", OWASP: "A06:2025", Confidence: 0.9,
		Suggestion: "Pass the incoming ctx (or r.Context()) to context-aware APIs such as QueryContext, NewRequestWithContext and CommandContext.",
		References: []string{"https://go.dev/blog/context"}}
	httpClientMeta = ruleMeta{ID: "http-client-unsafe", Title: "Unsafe HTTP Client Configuration", Severity: result.SeverityMedium, CWE: "CWE-400", OWASP: "A06:2025",
		Suggestion: "Set http.Client.Timeout (or transport-level timeouts) and never copy credentials onto redirected requests.",
		References: []string{"https://cwe.mitre.org/data/definitions/400.html"}}
)

// RegisterInsecureDesignRule reports lost request contexts and HTTP clients
// without timeouts or with credential-forwarding redirect policies.
func RegisterInsecureDesignRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{contextMeta, httpClientMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				if hasContextParam(info, unit.Type) {
					checkContextUse(r, info, unit)
				}
				checkCredentialForwarding(r, info, unit)
				later := literalFieldAssignments(info, unit.Body)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					lit, ok := n.(*ast.CompositeLit)
					if !ok || !typeIs(typeOf(info, lit), "net/http", "Client") {
						return true
					}
					fields := literalFields(lit)
					for k, v := range later[lit] {
						fields[k] = v
					}
					if fields["Timeout"] == nil && fields["Transport"] == nil {
						r.report(httpClientMeta, lit, "http.Client has no Timeout; a slow server can hang this goroutine forever.")
					}
					if cr, ok := fields["CheckRedirect"].(*ast.FuncLit); ok && forwardsCredentials(info, cr) {
						r.reportWith(httpClientMeta, cr, "CheckRedirect copies headers onto redirected requests, leaking credentials to other hosts.", result.SeverityHigh, nil)
					}
					return true
				})
			}
		}
	})
}

func hasContextParam(info *types.Info, ft *ast.FuncType) bool {
	for _, p := range params(info, ft) {
		if typeIs(p.Type(), "context", "Context") || typeIs(p.Type(), "net/http", "Request") {
			return true
		}
	}
	return false
}

func checkContextUse(r *reporter, info *types.Info, unit funcUnit) {
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		replacement := ""
		switch {
		case isMethod(fn, "database/sql", "DB", "Query", "QueryRow", "Exec", "Prepare", "Begin"),
			isMethod(fn, "database/sql", "Tx", "Query", "QueryRow", "Exec", "Prepare"),
			isMethod(fn, "database/sql", "Conn", "Query", "QueryRow", "Exec", "Prepare"):
			replacement = fn.Name() + "Context"
			if fn.Name() == "Begin" {
				replacement = "BeginTx"
			}
		case isFunc(fn, "net/http", "Get", "Post", "Head", "PostForm", "NewRequest"), isMethod(fn, "net/http", "Client", "Get", "Post", "Head", "PostForm"):
			replacement = "http.NewRequestWithContext"
		case isFunc(fn, "os/exec", "Command"):
			replacement = "exec.CommandContext"
		case isFunc(fn, "net", "Dial", "DialTimeout"):
			replacement = "(*net.Dialer).DialContext"
		}
		for _, arg := range call.Args {
			if inner, ok := arg.(*ast.CallExpr); ok {
				if bg := calleeFunc(info, inner); isFunc(bg, "context", "Background", "TODO") {
					r.report(contextMeta, inner, fmt.Sprintf("context.%s() is passed to %s, discarding the caller's cancellation and deadline; pass the incoming context.", bg.Name(), callName(call)))
				}
			}
		}
		if replacement != "" {
			r.report(contextMeta, call, fmt.Sprintf("%s ignores the incoming context; use %s.", fn.Name(), replacement))
		}
		return true
	})
}

// forwardsCredentials reports whether a CheckRedirect function copies headers
// (or an Authorization header) from previous requests onto the redirect.
func forwardsCredentials(info *types.Info, fn *ast.FuncLit) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Header" && typeIs(typeOf(info, sel.X), "net/http", "Request") {
					found = true
				}
			}
		case *ast.CallExpr:
			if isMethod(calleeFunc(info, x), "net/http", "Header", "Set", "Add") && len(x.Args) == 2 {
				if key, ok := constString(info, x.Args[0]); ok && (strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie")) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// checkCredentialForwarding reports Authorization or Cookie headers attached to
// outgoing requests whose URL is controlled by the incoming HTTP request.
func checkCredentialForwarding(r *reporter, info *types.Info, unit funcUnit) {
	lt := newLocalTaint(info, unit.Body)
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || !isMethod(calleeFunc(info, call), "net/http", "Header", "Set", "Add") {
			return true
		}
		key, ok := constString(info, call.Args[0])
		if !ok || !(strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie")) {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		hdr, ok := sel.X.(*ast.SelectorExpr)
		if !ok || hdr.Sel.Name != "Header" {
			return true
		}
		obj, ok := objOf(info, hdr.X).(*types.Var)
		if !ok {
			return true
		}
		for _, rhs := range lt.assigns[obj] {
			req, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			fn := calleeFunc(info, req)
			idx := -1
			switch {
			case isFunc(fn, "net/http", "NewRequest"):
				idx = 1
			case isFunc(fn, "net/http", "NewRequestWithContext"):
				idx = 2
			}
			if idx >= 0 && idx < len(req.Args) && lt.tainted(req.Args[idx], "ssrf") {
				r.reportWith(httpClientMeta, call, fmt.Sprintf("%s header is sent to a URL taken from the incoming request; the credential can be delivered to an attacker-chosen host.", key), result.SeverityHigh, nil)
				return true
			}
		}
		return true
	})
}
