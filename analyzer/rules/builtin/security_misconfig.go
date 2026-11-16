package builtin

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var (
	serverTimeoutMeta = ruleMeta{ID: "http-server-missing-timeout", Title: "HTTP Server Without Read Timeouts", Severity: result.SeverityHigh, CWE: "CWE-400", OWASP: "A02:2025",
		Suggestion: "Use an http.Server with ReadHeaderTimeout (e.g. 5 * time.Second) and ReadTimeout instead of http.ListenAndServe.",
		References: []string{"https://cwe.mitre.org/data/definitions/400.html"}}
	debugEndpointMeta = ruleMeta{ID: "debug-endpoint-exposed", Title: "Debug Endpoint Exposed", Severity: result.SeverityMedium, CWE: "CWE-489", OWASP: "A02:2025",
		Suggestion: "Serve net/http/pprof only on a separate internal listener, never on the public mux.",
		References: []string{"https://cwe.mitre.org/data/definitions/489.html"}}
	corsMeta = ruleMeta{ID: "cors-wildcard-credentials", Title: "CORS Allows Credentials From Any Origin", Severity: result.SeverityHigh, CWE: "CWE-942", OWASP: "A02:2025",
		Suggestion: "Reflect only origins from an explicit allowlist when Access-Control-Allow-Credentials is true.",
		References: []string{"https://cwe.mitre.org/data/definitions/942.html"}}
	filePermMeta = ruleMeta{ID: "insecure-file-permissions", Title: "Insecure File Permissions", Severity: result.SeverityMedium, CWE: "CWE-732", OWASP: "A02:2025",
		Suggestion: "Use 0600/0644 for files and 0700/0755 for directories; avoid group- or world-writable modes.",
		References: []string{"https://cwe.mitre.org/data/definitions/732.html"}}
)

// RegisterSecurityMisconfigRule reports HTTP servers without timeouts, exposed
// profiling endpoints, permissive CORS with credentials and writable file modes.
func RegisterSecurityMisconfigRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{serverTimeoutMeta, debugEndpointMeta, corsMeta, filePermMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		defaultMux := false
		var pprofImports []*ast.ImportSpec
		for _, file := range r.pass.Files {
			for _, imp := range file.Imports {
				if strings.Trim(imp.Path.Value, `"`) == "net/http/pprof" && imp.Name != nil && imp.Name.Name == "_" {
					pprofImports = append(pprofImports, imp)
				}
			}
			for _, unit := range funcUnits(file) {
				later := literalFieldAssignments(info, unit.Body)
				checkCORS(r, info, unit)
				inspectShallow(unit.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						fn := calleeFunc(info, x)
						switch {
						case isFunc(fn, "net/http", "ListenAndServe", "ListenAndServeTLS"):
							r.report(serverTimeoutMeta, x, fmt.Sprintf("http.%s starts a server without read timeouts (Slowloris).", fn.Name()))
							if h := len(x.Args) - 1; h >= 0 && isNil(info, x.Args[h]) {
								defaultMux = true
							}
						case isMethod(fn, "net/http", "ServeMux", "Handle", "HandleFunc") || isFunc(fn, "net/http", "Handle", "HandleFunc"):
							if len(x.Args) == 2 && pprofHandler(info, x.Args[1]) {
								r.report(debugEndpointMeta, x, "Profiling handler from net/http/pprof is registered on an application router.")
							}
						default:
							checkFileMode(r, info, x, fn)
						}
					case *ast.CompositeLit:
						if typeIs(typeOf(info, x), "net/http", "Server") {
							fields := literalFields(x)
							for k, v := range later[x] {
								fields[k] = v
							}
							if fields["ReadHeaderTimeout"] == nil && fields["ReadTimeout"] == nil {
								r.report(serverTimeoutMeta, x, "http.Server has neither ReadHeaderTimeout nor ReadTimeout (Slowloris).")
							}
							if h, ok := fields["Handler"]; !ok || isNil(info, h) {
								defaultMux = true
							}
						}
					}
					return true
				})
			}
		}
		if r.pass.Pkg.Name() == "main" && defaultMux {
			for _, imp := range pprofImports {
				r.report(debugEndpointMeta, imp, "net/http/pprof registers /debug/pprof on http.DefaultServeMux, which this program serves publicly.")
			}
		}
	})
}

func literalFields(lit *ast.CompositeLit) map[string]ast.Expr {
	fields := map[string]ast.Expr{}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			fields[exprName(kv.Key)] = kv.Value
		}
	}
	return fields
}

func isNil(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	return ok && tv.IsNil()
}

func pprofHandler(info *types.Info, e ast.Expr) bool {
	if call, ok := e.(*ast.CallExpr); ok {
		e = call.Fun
	}
	obj := objOf(info, e)
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net/http/pprof"
}

// checkFileMode reports permission arguments that grant group or world write access.
func checkFileMode(r *reporter, info *types.Info, call *ast.CallExpr, fn *types.Func) {
	idx := -1
	switch {
	case isFunc(fn, "os", "Chmod", "Mkdir", "MkdirAll"):
		idx = 1
	case isFunc(fn, "os", "WriteFile", "OpenFile"), isFunc(fn, "io/ioutil", "WriteFile"):
		idx = 2
	case isMethod(fn, "os", "File", "Chmod"):
		idx = 0
	}
	if idx < 0 || idx >= len(call.Args) {
		return
	}
	mode, ok := constInt(info, call.Args[idx])
	if !ok || mode&0o022 == 0 {
		return
	}
	r.reportWith(filePermMeta, call.Args[idx], fmt.Sprintf("Permission %#o makes the path writable by group or other users.", mode&0o7777), "", nil)
}

// checkCORS reports handlers that allow credentials together with a wildcard
// or reflected, unvalidated Origin.
func checkCORS(r *reporter, info *types.Info, unit funcUnit) {
	var credentials ast.Node
	var origin ast.Expr
	var originNode ast.Node
	inspectShallow(unit.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if !isMethod(calleeFunc(info, x), "net/http", "Header", "Set", "Add") || len(x.Args) != 2 {
				return true
			}
			key, _ := constString(info, x.Args[0])
			switch strings.ToLower(key) {
			case "access-control-allow-credentials":
				if v, _ := constString(info, x.Args[1]); strings.EqualFold(v, "true") {
					credentials = x
				}
			case "access-control-allow-origin":
				origin, originNode = x.Args[1], x
			}
		case *ast.CompositeLit:
			t := typeOf(info, x)
			if typeIs(t, "github.com/rs/cors", "Options") || typeIs(t, "github.com/gin-contrib/cors", "Config") {
				f := literalFields(x)
				creds, _ := constBool(info, f["AllowCredentials"])
				all, _ := constBool(info, f["AllowAllOrigins"])
				if creds && (all || wildcardList(info, f["AllowedOrigins"]) || wildcardList(info, f["AllowOrigins"])) {
					r.report(corsMeta, x, "CORS configuration allows credentials for any origin.")
				}
			}
		}
		return true
	})
	if credentials == nil || origin == nil {
		return
	}
	if v, ok := constString(info, origin); ok && v == "*" {
		r.report(corsMeta, originNode, "Access-Control-Allow-Origin '*' is combined with Access-Control-Allow-Credentials: true.")
		return
	}
	if reflectsOrigin(info, origin, unit.Body) {
		r.report(corsMeta, originNode, "The request Origin is reflected without validation while credentials are allowed.")
	}
}

func wildcardList(info *types.Info, e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		if s, ok := constString(info, elt); ok && s == "*" {
			return true
		}
	}
	return false
}

func isOriginHeader(info *types.Info, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || !isMethod(calleeFunc(info, call), "net/http", "Header", "Get") || len(call.Args) != 1 {
		return false
	}
	s, _ := constString(info, call.Args[0])
	return strings.EqualFold(s, "origin")
}

// reflectsOrigin reports whether e is the request Origin header, directly or
// through a variable that is never compared or looked up before use.
func reflectsOrigin(info *types.Info, e ast.Expr, body ast.Node) bool {
	if isOriginHeader(info, e) {
		return true
	}
	obj := objOf(info, e)
	if obj == nil {
		return false
	}
	fromHeader, checked := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if objOf(info, lhs) == obj && i < len(x.Rhs) && isOriginHeader(info, x.Rhs[i]) {
					fromHeader = true
				}
			}
		case *ast.BinaryExpr:
			if objOf(info, x.X) == obj || objOf(info, x.Y) == obj {
				checked = true
			}
		case *ast.IndexExpr:
			if objOf(info, x.Index) == obj {
				checked = true
			}
		case *ast.CallExpr:
			if !isMethod(calleeFunc(info, x), "net/http", "Header", "Set", "Add") {
				for _, arg := range x.Args {
					if objOf(info, arg) == obj {
						checked = true
					}
				}
			}
		}
		return true
	})
	return fromHeader && !checked
}
