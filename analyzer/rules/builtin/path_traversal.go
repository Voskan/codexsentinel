package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterPathTraversalRule registers the Path Traversal detection rule.
func RegisterPathTraversalRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "path-traversal-vulnerability",
		Title:    "Path Traversal Vulnerability",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Unvalidated file paths may lead to path traversal attacks allowing access to sensitive files.",
		Matcher:  matchPathTraversalVulnerability,
	})
}

// matchPathTraversalVulnerability detects Path Traversal vulnerabilities
func matchPathTraversalVulnerability(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// Check for file operations with user input
				if isPathTraversalFileOperation(x) && hasPathTraversalUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "path-traversal-vulnerability",
						Title:       "Potential Path Traversal",
						Description: "File operation with user input may lead to path traversal attacks",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate and sanitize file paths before file operations",
						References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
					})
				}

				// Check for file system operations with user input
				if isFileSystemOperation(x) && hasPathTraversalUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "path-traversal-vulnerability",
						Title:       "File System Operation with User Input",
						Description: "File system operation with untrusted input may lead to path traversal",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use filepath.Clean() and validate paths before file operations",
						References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
					})
				}

				// Check for directory operations with user input
				if isDirectoryOperation(x) && hasPathTraversalUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "path-traversal-vulnerability",
						Title:       "Directory Operation with User Input",
						Description: "Directory operation with untrusted input may lead to path traversal",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate directory paths and use safe directory operations",
						References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
					})
				}

				// Check for template operations with user input
				if isTemplateOperation(x) && hasPathTraversalUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "path-traversal-vulnerability",
						Title:       "Template Operation with User Input",
						Description: "Template operation with untrusted input may lead to path traversal",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate template paths and use safe template operations",
						References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
					})
				}

				// Check for include operations with user input
				if isIncludeOperation(x) && hasPathTraversalUserInput(ctx, x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "path-traversal-vulnerability",
						Title:       "Include Operation with User Input",
						Description: "Include operation with untrusted input may lead to path traversal",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate include paths and use safe include operations",
						References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
					})
				}
			}
			return true
		})
	}
}

// isPathTraversalFileOperation checks if call is a file operation
func isPathTraversalFileOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		filePatterns := []string{
			"open", "read", "write", "create", "delete", "remove",
			"readfile", "writefile", "readdir", "mkdir", "rmdir",
			"stat", "lstat", "chmod", "chown", "truncate",
			"copy", "move", "rename", "link", "symlink",
		}

		for _, pattern := range filePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}

		// Check for os package file operations
		if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "os" {
			osFilePatterns := []string{
				"Open", "Create", "Remove", "RemoveAll", "Mkdir", "MkdirAll",
				"Rename", "Symlink", "Link", "Chmod", "Chown", "Truncate",
			}
			for _, pattern := range osFilePatterns {
				if fun.Sel.Name == pattern {
					return true
				}
			}
		}

		// Check for ioutil package file operations
		if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "ioutil" {
			ioutilFilePatterns := []string{
				"ReadFile", "WriteFile", "ReadDir", "TempDir", "TempFile",
			}
			for _, pattern := range ioutilFilePatterns {
				if fun.Sel.Name == pattern {
					return true
				}
			}
		}
	}
	return false
}

// isFileSystemOperation checks if call is a file system operation
func isFileSystemOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		fsPatterns := []string{
			"readdir", "readfile", "writefile", "exists", "isdir", "isfile",
			"walk", "walkdir", "glob", "match", "join", "split", "clean",
		}

		for _, pattern := range fsPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}

		// Check for filepath package operations
		if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "filepath" {
			filepathPatterns := []string{
				"Join", "Split", "Dir", "Base", "Ext", "Clean", "Abs",
				"Rel", "Walk", "WalkDir", "Glob", "Match",
			}
			for _, pattern := range filepathPatterns {
				if fun.Sel.Name == pattern {
					return true
				}
			}
		}
	}
	return false
}

// isDirectoryOperation checks if call is a directory operation
func isDirectoryOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		dirPatterns := []string{
			"mkdir", "rmdir", "readdir", "walkdir", "isdir",
			"chdir", "getwd", "tempdir", "homedir",
		}

		for _, pattern := range dirPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}

		// Check for os package directory operations
		if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "os" {
			osDirPatterns := []string{
				"Mkdir", "MkdirAll", "Remove", "RemoveAll", "Getwd", "Chdir",
			}
			for _, pattern := range osDirPatterns {
				if fun.Sel.Name == pattern {
					return true
				}
			}
		}
	}
	return false
}

// isTemplateOperation checks if call is a template operation
func isTemplateOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		templatePatterns := []string{
			"parse", "parsefiles", "parseglob", "executetemplate",
			"loadtemplates", "loadtemplate", "template", "render",
		}

		for _, pattern := range templatePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}

		// Check for template package operations
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "template" {
				templatePkgPatterns := []string{
					"Parse", "ParseFiles", "ParseGlob", "ExecuteTemplate",
					"LoadTemplates", "LoadTemplate",
				}
				for _, pattern := range templatePkgPatterns {
					if fun.Sel.Name == pattern {
						return true
					}
				}
			}
		}
	}
	return false
}

// isIncludeOperation checks if call is an include operation
func isIncludeOperation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		includePatterns := []string{
			"include", "require", "import", "load", "importfile",
			"readtemplate", "loadtemplate", "parsefile",
		}

		for _, pattern := range includePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// hasPathTraversalUserInput checks if the call has user input as arguments
func hasPathTraversalUserInput(ctx *analyzer.AnalyzerContext, call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isPathTraversalUserInputExpr(ctx, arg) {
			return true
		}
	}
	return false
}

// isPathTraversalUserInputExpr checks if the expression is likely user input
func isPathTraversalUserInputExpr(ctx *analyzer.AnalyzerContext, expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		// Check for common user input variable names
		varName := strings.ToLower(e.Name)
		userInputPatterns := []string{
			"user", "input", "param", "arg", "file", "path", "filename",
			"url", "uri", "query", "form", "post", "get", "request",
			"upload", "download", "template", "include", "config",
		}
		for _, pattern := range userInputPatterns {
			if strings.Contains(varName, pattern) {
				return true
			}
		}
	case *ast.SelectorExpr:
		// Check for HTTP request form values
		if sel, ok := e.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "r" {
				if sel.Sel.Name == "FormValue" || sel.Sel.Name == "PostFormValue" {
					return true
				}
			}
		}
	case *ast.CallExpr:
		// Check for function calls that return user input
		if fun, ok := e.Fun.(*ast.SelectorExpr); ok {
			funcName := strings.ToLower(fun.Sel.Name)
			userInputFuncs := []string{
				"formvalue", "postformvalue", "query", "param", "get",
				"read", "scan", "input", "userinput", "request",
			}
			for _, pattern := range userInputFuncs {
				if strings.Contains(funcName, pattern) {
					return true
				}
			}
		}
	}
	return false
} 