package builtin

import (
	"go/ast"
	"go/types"
	"regexp"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var (
	cookieHTTPOnlyMeta = ruleMeta{ID: "cookie-missing-httponly", Title: "Session Cookie Without HttpOnly", Severity: result.SeverityMedium, CWE: "CWE-1004", OWASP: "A07:2025",
		Suggestion: "Set HttpOnly: true on session and authentication cookies so scripts cannot read them.",
		References: []string{"https://cwe.mitre.org/data/definitions/1004.html"}}
	cookieSecureMeta = ruleMeta{ID: "cookie-missing-secure", Title: "Session Cookie Without Secure", Severity: result.SeverityMedium, CWE: "CWE-614", OWASP: "A07:2025",
		Suggestion: "Set Secure: true so session cookies are only sent over HTTPS.",
		References: []string{"https://cwe.mitre.org/data/definitions/614.html"}}
	cookieSameSiteMeta = ruleMeta{ID: "cookie-insecure-samesite", Title: "Insecure Cookie SameSite Policy", Severity: result.SeverityMedium, CWE: "CWE-1275", OWASP: "A07:2025",
		Suggestion: "Use SameSite=Lax or Strict for session cookies; SameSite=None requires Secure.",
		References: []string{"https://cwe.mitre.org/data/definitions/1275.html"}}
)

var sensitiveCookie = regexp.MustCompile(`(?i)(sess|sid|auth|token|jwt|login|remember|identity|access|refresh|credential)`)

// RegisterSessionManagementRule checks the attributes of session cookies.
func RegisterSessionManagementRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{cookieHTTPOnlyMeta, cookieSecureMeta, cookieSameSiteMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				later := literalFieldAssignments(info, unit.Body)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CompositeLit:
						if typeIs(typeOf(info, x), "net/http", "Cookie") {
							checkCookie(r, info, x, later)
						}
					case *ast.CallExpr:
						checkGinCookie(r, info, x)
					}
					return true
				})
			}
		}
	})
}

type cookieAttrs struct {
	name             string
	nameKnown        bool
	httpOnly, secure bool
	sameSite         string
}

// literalFieldAssignments records struct fields set after construction,
// keyed by the composite literal assigned to the variable.
func literalFieldAssignments(info *types.Info, body ast.Node) map[*ast.CompositeLit]map[string]ast.Expr {
	vars := map[types.Object]*ast.CompositeLit{}
	out := map[*ast.CompositeLit]map[string]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			rhs := as.Rhs[i]
			if u, ok := rhs.(*ast.UnaryExpr); ok {
				rhs = u.X
			}
			if lit, ok := rhs.(*ast.CompositeLit); ok {
				if obj := objOf(info, lhs); obj != nil {
					vars[obj] = lit
				}
				continue
			}
			if sel, ok := lhs.(*ast.SelectorExpr); ok {
				if lit := vars[objOf(info, sel.X)]; lit != nil {
					if out[lit] == nil {
						out[lit] = map[string]ast.Expr{}
					}
					out[lit][sel.Sel.Name] = as.Rhs[i]
				}
			}
		}
		return true
	})
	return out
}

func checkCookie(r *reporter, info *types.Info, lit *ast.CompositeLit, later map[*ast.CompositeLit]map[string]ast.Expr) {
	fields := map[string]ast.Expr{}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			fields[exprName(kv.Key)] = kv.Value
		}
	}
	for k, v := range later[lit] {
		fields[k] = v
	}
	var attrs cookieAttrs
	if v, ok := fields["Name"]; ok {
		attrs.name, attrs.nameKnown = constString(info, v)
	}
	attrs.httpOnly = boolField(info, fields["HttpOnly"])
	attrs.secure = boolField(info, fields["Secure"])
	if v, ok := fields["SameSite"]; ok {
		if obj := objOf(info, v); obj != nil {
			attrs.sameSite = obj.Name()
		} else {
			attrs.sameSite = "dynamic"
		}
	}
	reportCookie(r, lit, attrs)
}

// boolField treats a missing field as false and a non-constant one as true.
func boolField(info *types.Info, e ast.Expr) bool {
	if e == nil {
		return false
	}
	if v, ok := constBool(info, e); ok {
		return v
	}
	return true
}

func reportCookie(r *reporter, node ast.Node, attrs cookieAttrs) {
	sensitive := attrs.nameKnown && sensitiveCookie.MatchString(attrs.name)
	label := "cookie"
	if attrs.nameKnown {
		label = "cookie " + `"` + attrs.name + `"`
	}
	if sensitive && !attrs.httpOnly {
		r.report(cookieHTTPOnlyMeta, node, "Session "+label+" is readable by JavaScript because HttpOnly is not set.")
	}
	if sensitive && !attrs.secure {
		r.report(cookieSecureMeta, node, "Session "+label+" can be sent over plain HTTP because Secure is not set.")
	}
	switch {
	case attrs.sameSite == "SameSiteNoneMode" && !attrs.secure:
		r.report(cookieSameSiteMeta, node, "SameSite=None "+label+" must also be Secure.")
	case attrs.sameSite == "SameSiteDefaultMode" && sensitive:
		r.report(cookieSameSiteMeta, node, "Session "+label+" uses SameSiteDefaultMode; set SameSite to Lax or Strict.")
	}
}

// checkGinCookie inspects (*gin.Context).SetCookie(name, value, maxAge, path, domain, secure, httpOnly).
func checkGinCookie(r *reporter, info *types.Info, call *ast.CallExpr) {
	if !isMethod(calleeFunc(info, call), "github.com/gin-gonic/gin", "Context", "SetCookie") || len(call.Args) != 7 {
		return
	}
	var attrs cookieAttrs
	attrs.name, attrs.nameKnown = constString(info, call.Args[0])
	attrs.secure = boolField(info, call.Args[5])
	attrs.httpOnly = boolField(info, call.Args[6])
	reportCookie(r, call, attrs)
}
