package builtin

import (
	"go/ast"
	"go/types"
	"regexp"
	"strings"
	"unicode"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var idorMeta = ruleMeta{ID: "idor-unscoped-mutation", Title: "Unscoped Resource Mutation (IDOR)", Severity: result.SeverityMedium, CWE: "CWE-639", OWASP: "A01:2025", Confidence: 0.7,
	Suggestion: "Scope the statement to the caller (e.g. AND owner_id = $2 or tenant_id) or check authorization for the resource before mutating it.",
	References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"}}

var (
	mutationSQL  = regexp.MustCompile(`(?is)^\s*(delete\s+from|update)\s+\S+.*?\swhere\s+(.*)$`)
	ownerColumn  = regexp.MustCompile(`(?i)\b(user|tenant|org|organization|owner|account|customer|team|workspace|created_by|author)(_?id)?\b`)
	placeholders = regexp.MustCompile(`\?|\$\d+|@\w+|:\w+`)
)

// RegisterAccessControlRule reports handlers that delete or update a record
// selected only by an identifier taken from the URL.
func RegisterAccessControlRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{idorMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				if isHandlerFunc(info, unit.Type) {
					checkUnscopedMutation(r, info, unit)
				}
			}
		}
	})
}

// isPathParam reports whether call extracts a route parameter.
func isPathParam(fn *types.Func) bool {
	return isMethod(fn, "net/http", "Request", "PathValue") ||
		isFunc(fn, "github.com/go-chi/chi", "URLParam") ||
		isFunc(fn, "github.com/gorilla/mux", "Vars") ||
		isMethod(fn, "github.com/gin-gonic/gin", "Context", "Param") ||
		isMethod(fn, "github.com/labstack/echo", "Context", "Param") ||
		isMethod(fn, "github.com/gofiber/fiber", "Ctx", "Params", "ParamsInt")
}

// isAuthzCall reports whether a call looks like an authorization check.
func isAuthzCall(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	name := fn.Name()
	for _, prefix := range []string{"authorize", "authorise", "can", "check", "require", "ensure", "enforce", "allow", "verify", "has"} {
		if len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
			if len(name) == len(prefix) || unicode.IsUpper(rune(name[len(prefix)])) {
				return true
			}
		}
	}
	return false
}

func checkUnscopedMutation(r *reporter, info *types.Info, unit funcUnit) {
	hasParam, hasAuthz := false, false
	inspectShallow(unit.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			fn := calleeFunc(info, call)
			hasParam = hasParam || isPathParam(fn)
			hasAuthz = hasAuthz || isAuthzCall(fn)
		}
		return true
	})
	if !hasParam || hasAuthz {
		return
	}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		idx := sqlQueryArg(calleeFunc(info, call))
		if idx < 0 || idx >= len(call.Args) {
			return true
		}
		query, ok := constString(info, call.Args[idx])
		if !ok {
			return true
		}
		m := mutationSQL.FindStringSubmatch(query)
		if m == nil {
			return true
		}
		where := m[2]
		if ownerColumn.MatchString(where) || len(placeholders.FindAllString(where, -1)) != 1 {
			return true
		}
		r.report(idorMeta, call, "Record is "+strings.ToLower(strings.Fields(m[1])[0])+"d by a URL identifier alone, without an ownership condition or authorization check.")
		return true
	})
}
