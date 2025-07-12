package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/matcher"
	"golang.org/x/tools/go/analysis"
)

// RegisterCommandExecRule registers the command injection detection rule.
func RegisterCommandExecRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "command-exec-taint",
		Title:    "Potential Command Injection via exec.Command",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Using user input in exec.Command without validation may lead to command injection.",
		Matcher:  matchExecCommandInjection,
	})
}

// matchExecCommandInjection detects untrusted input used in exec.Command or exec.CommandContext.
func matchExecCommandInjection(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}

			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			pkgIdent, ok := selector.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "exec" {
				return true
			}

			if selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext" {
				return true
			}

			// Check if any argument comes from untrusted input
			for _, arg := range call.Args {
				if isTainted(ctx, arg) {
					pos := ctx.GetFset().Position(arg.Pos())
					ctx.Report(result.Issue{
						ID:          "command-exec-taint",
						Title:       "Potential Command Injection",
						Description: "Untrusted input used in exec.Command may lead to command injection",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate or sanitize the input before using it in exec.Command",
					})
					break
				}
			}
			return true
		})
	}
}

// isTainted checks whether an expression is tainted by user input.
func isTainted(ctx *analyzer.AnalyzerContext, expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		if funIdent, ok := e.Fun.(*ast.SelectorExpr); ok {
			pkgIdent, ok := funIdent.X.(*ast.Ident)
			if !ok {
				return false
			}
			// Common user input sources
			switch pkgIdent.Name {
			case "os":
				if funIdent.Sel.Name == "Getenv" {
					return true
				}
			case "r":
				if funIdent.Sel.Name == "URL" || funIdent.Sel.Name == "FormValue" || funIdent.Sel.Name == "PostFormValue" {
					return true
				}
			}
		}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.SelectorExpr); ok {
			if pkg, ok := x.X.(*ast.Ident); ok {
				if pkg.Name == "r" && x.Sel.Name == "URL" && e.Sel.Name == "Query" {
					return true
				}
			}
		}
	case *ast.Ident:
		// Check if variable name suggests user input
		if matcher.New([]string{"userInput", "input", "param", "cmd", "arg", "data", "filename"}).Match(e.Name) {
			return true
		}
		// Also check types info if available
		if ctx.Info() != nil {
			obj := ctx.Info().Uses[e]
			if obj != nil {
				if v, ok := obj.(*types.Var); ok && v.Pkg() != nil {
					// Heuristic: check if variable name contains suspicious input identifiers
					return matcher.New([]string{"input", "param", "cmd", "arg", "data"}).Match(e.Name)
				}
			}
		}
	}
	return false
}
