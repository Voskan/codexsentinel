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
		return isCallExprTainted(ctx, e)
	case *ast.SelectorExpr:
		return isSelectorExprTainted(ctx, e)
	case *ast.Ident:
		return isIdentTainted(ctx, e)
	}
	return false
}

// isCallExprTainted checks if a call expression is tainted
func isCallExprTainted(ctx *analyzer.AnalyzerContext, call *ast.CallExpr) bool {
	if funIdent, ok := call.Fun.(*ast.SelectorExpr); ok {
		return isPackageCallTainted(ctx, funIdent)
	}
	return false
}

// isPackageCallTainted checks if a package call is tainted
func isPackageCallTainted(ctx *analyzer.AnalyzerContext, funIdent *ast.SelectorExpr) bool {
	pkgIdent, ok := funIdent.X.(*ast.Ident)
	if !ok {
		return false
	}

	switch pkgIdent.Name {
	case "os":
		return funIdent.Sel.Name == "Getenv"
	case "r":
		return isHTTPRequestTainted(funIdent.Sel.Name)
	}
	return false
}

// isHTTPRequestTainted checks if HTTP request methods are tainted
func isHTTPRequestTainted(methodName string) bool {
	return methodName == "URL" || methodName == "FormValue" || methodName == "PostFormValue"
}

// isSelectorExprTainted checks if a selector expression is tainted
func isSelectorExprTainted(ctx *analyzer.AnalyzerContext, selector *ast.SelectorExpr) bool {
	if x, ok := selector.X.(*ast.SelectorExpr); ok {
		return isHTTPQueryTainted(ctx, x, selector)
	}
	return false
}

// isHTTPQueryTainted checks if HTTP query parameters are tainted
func isHTTPQueryTainted(ctx *analyzer.AnalyzerContext, x *ast.SelectorExpr, selector *ast.SelectorExpr) bool {
	if pkg, ok := x.X.(*ast.Ident); ok {
		return pkg.Name == "r" && x.Sel.Name == "URL" && selector.Sel.Name == "Query"
	}
	return false
}

// isIdentTainted checks if an identifier is tainted
func isIdentTainted(ctx *analyzer.AnalyzerContext, ident *ast.Ident) bool {
	// Check if variable name suggests user input
	if isVariableNameTainted(ident.Name) {
		return true
	}
	
	// Also check types info if available
	return isTypeInfoTainted(ctx, ident)
}

// isVariableNameTainted checks if a variable name suggests tainted input
func isVariableNameTainted(name string) bool {
	return matcher.New([]string{"userInput", "input", "param", "cmd", "arg", "data", "filename"}).Match(name)
}

// isTypeInfoTainted checks if type information suggests tainted input
func isTypeInfoTainted(ctx *analyzer.AnalyzerContext, ident *ast.Ident) bool {
	if ctx.Info() == nil {
		return false
	}
	
	obj := ctx.Info().Uses[ident]
	if obj == nil {
		return false
	}
	
	if v, ok := obj.(*types.Var); ok && v.Pkg() != nil {
		// Heuristic: check if variable name contains suspicious input identifiers
		return matcher.New([]string{"input", "param", "cmd", "arg", "data"}).Match(ident.Name)
	}
	
	return false
}
