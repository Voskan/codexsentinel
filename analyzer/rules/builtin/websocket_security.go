package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var wsOriginMeta = ruleMeta{ID: "websocket-origin-bypass", Title: "WebSocket Origin Check Disabled", Severity: result.SeverityHigh, CWE: "CWE-346", OWASP: "A01:2025",
	Suggestion: "Validate the Origin header against an allowlist in CheckOrigin/OriginPatterns to prevent cross-site WebSocket hijacking.",
	References: []string{"https://cwe.mitre.org/data/definitions/1385.html"}}

var upgraderPackages = []string{"github.com/gorilla/websocket", "github.com/fasthttp/websocket"}
var acceptPackages = []string{"nhooyr.io/websocket", "github.com/coder/websocket"}

// RegisterWebSocketSecurityRule reports WebSocket servers that accept any origin.
func RegisterWebSocketSecurityRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{wsOriginMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					t := typeOf(info, x)
					for _, elt := range x.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						field := exprName(kv.Key)
						switch {
						case field == "CheckOrigin" && isWSType(t, upgraderPackages, "Upgrader"):
							if alwaysTrue(info, kv.Value) {
								r.report(wsOriginMeta, kv, "Upgrader.CheckOrigin accepts every origin.")
							}
						case field == "InsecureSkipVerify" && isWSType(t, acceptPackages, "AcceptOptions"):
							if v, ok := constBool(info, kv.Value); ok && v {
								r.report(wsOriginMeta, kv, "AcceptOptions.InsecureSkipVerify disables the Origin check.")
							}
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || i >= len(x.Rhs) || sel.Sel.Name != "CheckOrigin" || !isWSType(typeOf(info, sel.X), upgraderPackages, "Upgrader") {
							continue
						}
						if alwaysTrue(info, x.Rhs[i]) {
							r.report(wsOriginMeta, x, "Upgrader.CheckOrigin accepts every origin.")
						}
					}
				case *ast.SelectorExpr:
					if obj := info.Uses[x.Sel]; obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "golang.org/x/net/websocket" && obj.Name() == "Handler" {
						if _, isType := obj.(*types.TypeName); isType {
							r.report(wsOriginMeta, x, "golang.org/x/net/websocket.Handler does not verify the Origin header; use websocket.Server with a Handshake check.")
						}
					}
				}
				return true
			})
		}
	})
}

func isWSType(t types.Type, pkgs []string, name string) bool {
	for _, p := range pkgs {
		if typeIs(t, p, name) {
			return true
		}
	}
	return false
}

// alwaysTrue reports whether e is a function literal whose every return is the constant true.
func alwaysTrue(info *types.Info, e ast.Expr) bool {
	lit, ok := e.(*ast.FuncLit)
	if !ok {
		return false
	}
	returns, allTrue := 0, true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok {
			returns++
			if len(ret.Results) != 1 {
				allTrue = false
			} else if v, ok := constBool(info, ret.Results[0]); !ok || !v {
				allTrue = false
			}
		}
		return true
	})
	return returns > 0 && allTrue
}
