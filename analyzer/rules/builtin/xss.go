package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var xssMeta = ruleMeta{
	ID: "xss", Title: "Cross-Site Scripting", Severity: result.SeverityHigh, CWE: "CWE-79", OWASP: "A05:2025",
	Confidence: 0.7,
	Suggestion: "Render HTML with html/template or escape dynamic values with html.EscapeString before writing them to the response.",
	References: []string{"https://cwe.mitre.org/data/definitions/79.html"},
}

var trustedTemplateTypes = map[string]bool{"HTML": true, "HTMLAttr": true, "JS": true, "JSStr": true, "CSS": true, "URL": true, "Srcset": true}

// RegisterXSSRule reports unescaped dynamic text written to an HTTP response,
// text/template rendering into a response, and conversions of dynamic text to
// trusted html/template types.
func RegisterXSSRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{xssMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
					if pkg, name := namedOf(tv.Type); pkg == "html/template" && trustedTemplateTypes[name] && len(call.Args) == 1 && !isConst(info, call.Args[0]) {
						r.report(xssMeta, call, "Dynamic value converted to trusted template."+name+" bypasses contextual escaping.")
					}
					return true
				}
				fn := calleeFunc(info, call)
				switch {
				case isMethod(fn, "net/http", "ResponseWriter", "Write") && len(call.Args) == 1:
					if unescapedText(info, call.Args[0]) {
						r.report(xssMeta, call.Args[0], "Unescaped dynamic text is written to the HTTP response.")
					}
				case isFunc(fn, "io", "WriteString") && len(call.Args) == 2 && responseWriter(info, call.Args[0]):
					if unescapedText(info, call.Args[1]) {
						r.report(xssMeta, call.Args[1], "Unescaped dynamic text is written to the HTTP response.")
					}
				case isFunc(fn, "fmt", "Fprint", "Fprintf", "Fprintln") && len(call.Args) > 1 && responseWriter(info, call.Args[0]):
					start := 1
					if fn.Name() == "Fprintf" {
						start = 2
					}
					for _, arg := range call.Args[start:] {
						if unescapedText(info, arg) {
							r.report(xssMeta, arg, "Unescaped dynamic text is formatted into the HTTP response.")
							break
						}
					}
				case isMethod(fn, "text/template", "Template", "Execute", "ExecuteTemplate") && len(call.Args) > 1 && responseWriter(info, call.Args[0]):
					r.report(xssMeta, call, "text/template does not escape HTML; rendering it into an HTTP response enables XSS. Use html/template.")
				}
				return true
			})
		}
	})
}

// responseWriter reports whether e is an http.ResponseWriter (or implements it).
func responseWriter(info *types.Info, e ast.Expr) bool {
	t := typeOf(info, e)
	if t == nil {
		return false
	}
	if typeIs(t, "net/http", "ResponseWriter") {
		return true
	}
	for _, m := range []string{"Header", "WriteHeader", "Write"} {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, m)
		if _, ok := obj.(*types.Func); !ok {
			return false
		}
	}
	return true
}

// unescapedText reports whether e is dynamic string or byte data that was not
// produced by an escaping or encoding function.
func unescapedText(info *types.Info, e ast.Expr) bool {
	if isConst(info, e) {
		return false
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		return unescapedText(info, x.X)
	case *ast.CallExpr:
		if tv, ok := info.Types[x.Fun]; ok && tv.IsType() {
			return len(x.Args) == 1 && unescapedText(info, x.Args[0])
		}
		fn := calleeFunc(info, x)
		if fn != nil && sanitizes(fn, "xss") {
			return false
		}
		if isFunc(fn, "fmt", "Sprintf", "Sprint", "Sprintln") {
			for _, arg := range x.Args {
				if unescapedText(info, arg) && !isConst(info, arg) {
					if _, isCall := arg.(*ast.CallExpr); !isCall || unescapedText(info, arg) {
						return true
					}
				}
			}
			return false
		}
		if isFunc(fn, "strings", "Join", "Repeat", "ToUpper", "ToLower", "TrimSpace", "Trim") {
			for _, arg := range x.Args {
				if unescapedText(info, arg) {
					return true
				}
			}
			return false
		}
		return false
	case *ast.BinaryExpr:
		return unescapedText(info, x.X) || unescapedText(info, x.Y)
	case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr:
		t := typeOf(info, e)
		if b, ok := t.Underlying().(*types.Basic); ok {
			return b.Info()&types.IsString != 0
		}
	}
	return false
}
