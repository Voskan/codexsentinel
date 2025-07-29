package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterDataIntegrityRule registers the data integrity failure detection rule.
func RegisterDataIntegrityRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "data-integrity-failure",
		Title:    "Software and Data Integrity Failures (A08:2025)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Missing integrity checks for software updates, critical data, and CI/CD pipelines.",
		Matcher:  matchDataIntegrityFailures,
	})
}

// matchDataIntegrityFailures detects data integrity failures
func matchDataIntegrityFailures(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// Check for file operations without integrity checks
				if isFileOperationWithoutIntegrity(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "data-integrity-failure",
						Title:       "File Operation Without Integrity Check",
						Description: "File operation performed without integrity verification",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Add checksums, signatures, or other integrity verification",
					})
				}

				// Check for network downloads without integrity checks
				if isNetworkDownloadWithoutIntegrity(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "data-integrity-failure",
						Title:       "Network Download Without Integrity Check",
						Description: "Downloading files from network without integrity verification",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Verify checksums or signatures of downloaded files",
					})
				}

				// Check for untrusted data processing
				if isUntrustedDataProcessing(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "data-integrity-failure",
						Title:       "Untrusted Data Processing",
						Description: "Processing data from untrusted sources without validation",
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Validate and sanitize all untrusted data before processing",
					})
				}
			case *ast.FuncDecl:
				// Check for functions that handle critical data without integrity checks
				if isCriticalDataHandler(x) && !hasIntegrityChecks(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "data-integrity-failure",
						Title:       "Critical Data Handler Without Integrity Checks",
						Description: "Function handles critical data without integrity verification",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Add integrity checks for critical data operations",
					})
				}
			}
			return true
		})
	}
}

// isFileOperationWithoutIntegrity checks if file operation lacks integrity checks
func isFileOperationWithoutIntegrity(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		// Check for file operations that should have integrity checks
		fileOps := []string{"ReadFile", "WriteFile", "Copy", "Move", "Create"}

		for _, op := range fileOps {
			if funcName == op {
				// Check if there are any integrity-related calls in the same scope
				return !hasIntegrityChecks(call)
			}
		}
	}
	return false
}

// isNetworkDownloadWithoutIntegrity checks if network download lacks integrity checks
func isNetworkDownloadWithoutIntegrity(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		// Check for network operations that should have integrity checks
		netOps := []string{"Get", "Download", "Fetch", "Retrieve"}

		for _, op := range netOps {
			if strings.Contains(funcName, op) {
				return !hasIntegrityChecks(call)
			}
		}
	}
	return false
}

// isUntrustedDataProcessing checks if data processing lacks validation
func isUntrustedDataProcessing(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := fun.Sel.Name
		// Check for data processing operations
		processingOps := []string{"Parse", "Unmarshal", "Decode", "Deserialize"}

		for _, op := range processingOps {
			if strings.Contains(funcName, op) {
				// Check if there are validation calls
				return !hasValidationChecks(call)
			}
		}
	}
	return false
}

// isCriticalDataHandler checks if function handles critical data
func isCriticalDataHandler(funcDecl *ast.FuncDecl) bool {
	funcName := strings.ToLower(funcDecl.Name.Name)
	criticalPatterns := []string{
		"config", "setting", "credential", "token", "key",
		"user", "admin", "system", "critical", "sensitive",
	}

	for _, pattern := range criticalPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}
	return false
}

// hasIntegrityChecks checks if operation has integrity verification
func hasIntegrityChecks(node ast.Node) bool {
	var hasChecks bool
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				// Check for integrity-related functions
				integrityPatterns := []string{
					"Verify", "Validate", "Check", "Hash", "Checksum",
					"Signature", "Integrity", "Authenticate",
				}
				for _, pattern := range integrityPatterns {
					if strings.Contains(funcName, pattern) {
						hasChecks = true
						return false
					}
				}
			}
		}
		return true
	})
	return hasChecks
}

// hasValidationChecks checks if operation has validation
func hasValidationChecks(node ast.Node) bool {
	var hasValidation bool
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
				funcName := fun.Sel.Name
				// Check for validation-related functions
				validationPatterns := []string{
					"Validate", "Check", "Verify", "Sanitize", "Clean",
					"Filter", "Validate", "IsValid",
				}
				for _, pattern := range validationPatterns {
					if strings.Contains(funcName, pattern) {
						hasValidation = true
						return false
					}
				}
			}
		}
		return true
	})
	return hasValidation
}
