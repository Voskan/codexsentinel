package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterInsecureDesignRule registers the insecure design detection rule.
func RegisterInsecureDesignRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "insecure-design",
		Title:    "Insecure Design",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Architectural and design flaws that lead to security vulnerabilities.",
		Matcher:  matchInsecureDesign,
	})
}

// matchInsecureDesign detects insecure design patterns
func matchInsecureDesign(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.StructType:
				// Check for structs with sensitive fields exposed
				if hasExposedSensitiveFields(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "insecure-design",
						Title:       "Exposed Sensitive Fields",
						Description: "Struct contains sensitive fields that are publicly accessible",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use private fields and provide secure access methods",
					})
				}
			case *ast.InterfaceType:
				// Check for interfaces that expose too much
				if hasOverlyPermissiveInterface(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "insecure-design",
						Title:       "Overly Permissive Interface",
						Description: "Interface exposes too many methods, violating principle of least privilege",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Split interface into smaller, more focused interfaces",
					})
				}
			case *ast.FuncDecl:
				// Check for functions with too many responsibilities
				if hasTooManyResponsibilities(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "insecure-design",
						Title:       "Function with Too Many Responsibilities",
						Description: "Function violates single responsibility principle",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Split function into smaller, focused functions",
					})
				}
			case *ast.CallExpr:
				// Check for hardcoded secrets in code
				if hasHardcodedSecrets(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "insecure-design",
						Title:       "Hardcoded Secrets",
						Description: "Secrets should not be hardcoded in source code",
						Severity:    result.SeverityCritical,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use environment variables or secure secret management",
					})
				}
			}
			return true
		})
	}
}

// hasExposedSensitiveFields checks if struct has exposed sensitive fields
func hasExposedSensitiveFields(structType *ast.StructType) bool {
	if structType.Fields == nil {
		return false
	}
	
	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			continue
		}
		
		fieldName := field.Names[0].Name
		// Check if field name suggests sensitive data
		sensitivePatterns := []string{
			"password", "secret", "key", "token", "credential",
			"private", "sensitive", "confidential", "auth",
		}
		
		fieldNameLower := strings.ToLower(fieldName)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(fieldNameLower, pattern) {
				// Check if field is exported (starts with uppercase)
				if len(fieldName) > 0 && fieldName[0] >= 'A' && fieldName[0] <= 'Z' {
					return true
				}
			}
		}
	}
	return false
}

// hasOverlyPermissiveInterface checks if interface has too many methods
func hasOverlyPermissiveInterface(interfaceType *ast.InterfaceType) bool {
	if interfaceType.Methods == nil {
		return false
	}
	
	// Consider interface overly permissive if it has more than 10 methods
	return len(interfaceType.Methods.List) > 10
}

// hasTooManyResponsibilities checks if function has too many responsibilities
func hasTooManyResponsibilities(funcDecl *ast.FuncDecl) bool {
	if funcDecl.Body == nil {
		return false
	}
	
	// Count different types of operations
	var dbOps, fileOps, netOps, cryptoOps int
	
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				// Count different operation types
				if strings.Contains(strings.ToLower(funcName), "query") || 
				   strings.Contains(strings.ToLower(funcName), "exec") {
					dbOps++
				}
				if strings.Contains(strings.ToLower(funcName), "read") || 
				   strings.Contains(strings.ToLower(funcName), "write") {
					fileOps++
				}
				if strings.Contains(strings.ToLower(funcName), "http") || 
				   strings.Contains(strings.ToLower(funcName), "get") {
					netOps++
				}
				if strings.Contains(strings.ToLower(funcName), "encrypt") || 
				   strings.Contains(strings.ToLower(funcName), "hash") {
					cryptoOps++
				}
			}
		}
		return true
	})
	
	// Function has too many responsibilities if it performs multiple different types of operations
	operationTypes := 0
	if dbOps > 0 { operationTypes++ }
	if fileOps > 0 { operationTypes++ }
	if netOps > 0 { operationTypes++ }
	if cryptoOps > 0 { operationTypes++ }
	
	return operationTypes > 2
}

// hasHardcodedSecrets checks if call contains hardcoded secrets
func hasHardcodedSecrets(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.BasicLit); ok {
			value := lit.Value
			// Check for common secret patterns
			secretPatterns := []string{
				"password", "secret", "key", "token", "credential",
				"private", "sensitive", "auth", "api_key",
			}
			
			for _, pattern := range secretPatterns {
				if strings.Contains(strings.ToLower(value), pattern) {
					// Check if it looks like a hardcoded value (not a variable)
					if len(value) > 8 && !strings.Contains(value, "${") {
						return true
					}
				}
			}
		}
	}
	return false
} 