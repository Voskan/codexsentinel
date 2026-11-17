package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var csrfMeta = ruleMeta{ID: "csrf-missing-protection", Title: "Missing CSRF Protection", Severity: result.SeverityMedium, CWE: "CWE-352", OWASP: "A01:2025", Confidence: 0.7,
	Suggestion: "Wrap the router with http.NewCrossOriginProtection().Handler(mux) (Go 1.25+) or a CSRF middleware such as gorilla/csrf.",
	References: []string{"https://cwe.mitre.org/data/definitions/352.html", "https://pkg.go.dev/net/http#CrossOriginProtection"}}

var csrfMiddlewarePackages = []string{"github.com/gorilla/csrf", "github.com/justinas/nosurf", "github.com/utrack/gin-csrf", "github.com/gofiber/fiber/v2/middleware/csrf", "github.com/gofiber/fiber/v3/middleware/csrf"}

var mutatingMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// RegisterCSRFRule reports packages that register state-changing routes on an
// http.ServeMux, rely on cookies for authentication and apply no cross-origin
// or CSRF protection.
func RegisterCSRFRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{csrfMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		var mutating []*ast.CallExpr
		usesCookies, protected := false, false
		for _, file := range r.pass.Files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				for _, p := range csrfMiddlewarePackages {
					if path == p {
						protected = true
					}
				}
				if strings.HasSuffix(path, "/middleware") && strings.Contains(path, "labstack/echo") {
					protected = protected || fileUsesIdent(file, "CSRF", "CSRFWithConfig")
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := calleeFunc(info, call)
				switch {
				case isMethod(fn, "net/http", "ServeMux", "HandleFunc", "Handle") || isFunc(fn, "net/http", "HandleFunc", "Handle"):
					if len(call.Args) > 0 {
						if pattern, ok := constString(info, call.Args[0]); ok && mutatingPattern(pattern) {
							mutating = append(mutating, call)
						}
					}
				case isMethod(fn, "net/http", "Request", "Cookie", "Cookies", "CookiesNamed") || isFunc(fn, "net/http", "SetCookie"):
					usesCookies = true
				case isFunc(fn, "net/http", "NewCrossOriginProtection"):
					protected = true
				}
				return true
			})
		}
		if protected || !usesCookies {
			return
		}
		for _, call := range mutating {
			pattern, _ := constString(info, call.Args[0])
			r.report(csrfMeta, call, "State-changing route "+`"`+pattern+`"`+" uses cookie-based sessions without cross-origin request protection.")
		}
	})
}

func mutatingPattern(pattern string) bool {
	method, _, ok := strings.Cut(strings.TrimSpace(pattern), " ")
	if !ok {
		return false
	}
	for _, m := range mutatingMethods {
		if method == m {
			return true
		}
	}
	return false
}

func fileUsesIdent(file *ast.File, names ...string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && nameIn(sel.Sel.Name, names) {
			found = true
		}
		return !found
	})
	return found
}
