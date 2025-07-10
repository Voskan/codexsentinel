package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer/context"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/matcher"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// RegisterCommandExecRule registers the command injection detection rule.
func RegisterCommandExecRule(ctx *context.AnalyzerContext) {
	ctx.RegisterRule(&context.Rule{
		ID:       "command-exec-taint",
		Title:    "Potential Command Injection via exec.Command",
		Category: "security",
		Severity: result.High,
		Summary:  "Using user input in exec.Command without validation may lead to command injection.",
		Matcher:  matchExecCommandInjection,
	})
}

// matchExecCommandInjection detects untrusted input used in exec.Command or exec.CommandContext.
func matchExecCommandInjection(ctx *context.AnalyzerContext, inspectResult *inspect.Analyzer) {
	inspector := inspectResult.Result.(*inspector.Inspector)

	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}
	inspector.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return
		}

		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}

		pkgIdent, ok := selector.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "exec" {
			return
		}

		if selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
			return
		}

		// Check if any argument comes from untrusted input
		for _, arg := range call.Args {
			if isTainted(ctx, arg) {
				pos := ctx.Fset().Position(arg.Pos())
				ctx.Report(result.Issue{
					RuleID:    "command-exec-taint",
					Severity:  result.High,
					Location:  result.NewLocation(pos),
					Message:   "Untrusted input used in exec.Command may lead to command injection",
					Suggestion: "Validate or sanitize the input before using it in exec.Command",
				})
				break
			}
		}
	})
}

// isTainted checks whether an expression is tainted by user input.
func isTainted(ctx *context.AnalyzerContext, expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		if funIdent, ok := e.Fun.(*ast.SelectorExpr); ok {
			pkgIdent, ok := funIdent.X.(*ast.Ident)
			if !ok {
				return false
			}
			fullCall := pkgIdent.Name + "." + funIdent.Sel.Name
			// Common user input sources
			switch fullCall {
			case "os.Getenv", "req.FormValue", "req.URL.Query", "req.PostFormValue":
				return true
			}
		}
	case *ast.Ident:
		obj := ctx.Info().Uses[e]
		if obj == nil {
			return false
		}
		if v, ok := obj.(*types.Var); ok && v.Pkg() != nil {
			// Heuristic: check if variable name contains suspicious input identifiers
			return matcher.MatchesAny(e.Name, []string{"input", "param", "cmd", "arg", "data"})
		}
	}
	return false
}
