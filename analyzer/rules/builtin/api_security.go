package builtin

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var (
	unboundedBodyMeta = ruleMeta{ID: "http-unbounded-body-read", Title: "Unbounded HTTP Request Body Read", Severity: result.SeverityHigh, CWE: "CWE-400", OWASP: "A06:2025",
		Suggestion: "Limit the body with r.Body = http.MaxBytesReader(w, r.Body, maxBytes) before reading it.",
		References: []string{"https://pkg.go.dev/net/http#MaxBytesReader"}}
	sliceAllocMeta = ruleMeta{ID: "untrusted-slice-allocation", Title: "Allocation Sized by Untrusted Input", Severity: result.SeverityHigh, CWE: "CWE-789", OWASP: "A06:2025", Confidence: 0.8,
		Suggestion: "Validate the requested size against an upper bound (and reject negatives) before calling make.",
		References: []string{"https://cwe.mitre.org/data/definitions/789.html"}}
)

// RegisterAPISecurityRule reports request bodies read without a size limit and
// allocations sized directly from request input.
func RegisterAPISecurityRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{unboundedBodyMeta, sliceAllocMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				checkBodyReads(r, info, unit)
				checkAllocations(r, info, unit)
			}
		}
	})
}

// requestBody reports whether e is r.Body of an *http.Request.
func requestBody(info *types.Info, e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Body" && typeIs(typeOf(info, sel.X), "net/http", "Request")
}

func checkBodyReads(r *reporter, info *types.Info, unit funcUnit) {
	limited := false
	inspectShallow(unit.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			fn := calleeFunc(info, call)
			if isFunc(fn, "net/http", "MaxBytesReader") || isFunc(fn, "io", "LimitReader") {
				for _, arg := range call.Args {
					if requestBody(info, arg) {
						limited = true
					}
				}
			}
		}
		return true
	})
	if limited {
		return
	}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		if (isFunc(fn, "io", "ReadAll") || isFunc(fn, "io/ioutil", "ReadAll")) && len(call.Args) == 1 && requestBody(info, call.Args[0]) {
			r.report(unboundedBodyMeta, call, "Request body is read entirely without http.MaxBytesReader; a large request can exhaust memory.")
		}
		return true
	})
}

// checkAllocations reports make() calls sized by request-derived or parsed
// integers that are not bounds-checked in the same function.
func checkAllocations(r *reporter, info *types.Info, unit funcUnit) {
	lt := newLocalTaint(info, unit.Body)
	untrusted := map[types.Object]bool{}
	ast.Inspect(unit.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isFunc(calleeFunc(info, call), "strconv", "Atoi", "ParseInt", "ParseUint") || len(call.Args) == 0 {
			return true
		}
		if !lt.tainted(call.Args[0], "allocation") {
			return true
		}
		if obj := objOf(info, as.Lhs[0]); obj != nil {
			untrusted[obj] = true
		}
		return true
	})
	if len(untrusted) == 0 {
		return
	}
	bounded := map[types.Object]bool{}
	ast.Inspect(unit.Body, func(n ast.Node) bool {
		if be, ok := n.(*ast.BinaryExpr); ok {
			switch be.Op {
			case token.GTR, token.GEQ, token.LSS, token.LEQ:
				for _, side := range []ast.Expr{be.X, be.Y} {
					if obj := objOf(info, side); obj != nil && untrusted[obj] {
						bounded[obj] = true
					}
				}
			}
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "min" {
				for _, arg := range call.Args {
					if obj := objOf(info, arg); obj != nil {
						bounded[obj] = true
					}
				}
			}
		}
		return true
	})
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "make" || len(call.Args) < 2 {
			return true
		}
		if _, builtin := info.Uses[id].(*types.Builtin); !builtin {
			return true
		}
		for _, size := range call.Args[1:] {
			ast.Inspect(size, func(m ast.Node) bool {
				if obj := objOf(info, asExpr(m)); obj != nil && untrusted[obj] && !bounded[obj] {
					r.report(sliceAllocMeta, call, "Allocation size comes from request input without an upper bound check.")
					return false
				}
				return true
			})
		}
		return true
	})
}

func asExpr(n ast.Node) ast.Expr {
	if e, ok := n.(ast.Expr); ok {
		return e
	}
	return nil
}
