package analyzer

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ContextAnalyzer provides context-aware analysis to reduce false positives
type ContextAnalyzer struct {
	// Track validation functions
	validationFunctions map[string]bool
	// Track safe patterns
	safePatterns map[string]bool
	// Track context information
	contextInfo map[string]interface{}
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		validationFunctions: make(map[string]bool),
		safePatterns:        make(map[string]bool),
		contextInfo:         make(map[string]interface{}),
	}
}

// AnalyzeContext analyzes the context around a potential vulnerability
func (ca *ContextAnalyzer) AnalyzeContext(node ast.Node, pass *analysis.Pass) *ContextInfo {
	info := &ContextInfo{
		HasValidation:    false,
		HasSanitization:  false,
		IsSafePattern:    false,
		Confidence:       1.0,
		ContextType:      "unknown",
		Recommendation:   "",
	}

	// Analyze the context around the node
	ca.analyzeValidationContext(node, pass, info)
	ca.analyzeSanitizationContext(node, pass, info)
	ca.analyzeSafePatternContext(node, pass, info)
	ca.calculateConfidence(info)

	return info
}

// analyzeValidationContext checks if there are validation functions nearby
func (ca *ContextAnalyzer) analyzeValidationContext(node ast.Node, pass *analysis.Pass, info *ContextInfo) {
	// Look for validation functions in the same function
	if funcDecl := ca.findContainingFunction(node, pass); funcDecl != nil {
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if ca.isValidationFunction(call) {
					info.HasValidation = true
					info.Confidence *= 0.3 // Reduce confidence if validation exists
					return false
				}
			}
			return true
		})
	}
}

// analyzeSanitizationContext checks if there are sanitization functions nearby
func (ca *ContextAnalyzer) analyzeSanitizationContext(node ast.Node, pass *analysis.Pass, info *ContextInfo) {
	// Look for sanitization functions in the same function
	if funcDecl := ca.findContainingFunction(node, pass); funcDecl != nil {
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if ca.isSanitizationFunction(call) {
					info.HasSanitization = true
					info.Confidence *= 0.2 // Reduce confidence if sanitization exists
					return false
				}
			}
			return true
		})
	}
}

// analyzeSafePatternContext checks if the code follows safe patterns
func (ca *ContextAnalyzer) analyzeSafePatternContext(node ast.Node, pass *analysis.Pass, info *ContextInfo) {
	// Check for safe patterns
	if ca.isSafePattern(node) {
		info.IsSafePattern = true
		info.Confidence *= 0.1 // Significantly reduce confidence for safe patterns
	}
}

// calculateConfidence calculates the overall confidence score
func (ca *ContextAnalyzer) calculateConfidence(info *ContextInfo) {
	// Base confidence adjustments
	if info.HasValidation {
		info.Recommendation += "Validation detected - consider if this is a false positive. "
	}
	if info.HasSanitization {
		info.Recommendation += "Sanitization detected - consider if this is a false positive. "
	}
	if info.IsSafePattern {
		info.Recommendation += "Safe pattern detected - this may be a false positive. "
	}

	// Ensure confidence doesn't go below 0.1
	if info.Confidence < 0.1 {
		info.Confidence = 0.1
	}
}

// findContainingFunction finds the function that contains the given node
func (ca *ContextAnalyzer) findContainingFunction(node ast.Node, pass *analysis.Pass) *ast.FuncDecl {
	var funcDecl *ast.FuncDecl
	ast.Inspect(pass.Files[0], func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok {
			if fd.Pos() <= node.Pos() && node.Pos() <= fd.End() {
				funcDecl = fd
				return false
			}
		}
		return true
	})
	return funcDecl
}

// isValidationFunction checks if a function call is a validation function
func (ca *ContextAnalyzer) isValidationFunction(call *ast.CallExpr) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(selector.Sel.Name)
		validationPatterns := []string{
			"validate", "check", "verify", "test", "assert",
			"isvalid", "isvalid", "isvalid", "isvalid",
			"validateinput", "validateparam", "validateuser",
		}
		for _, pattern := range validationPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isSanitizationFunction checks if a function call is a sanitization function
func (ca *ContextAnalyzer) isSanitizationFunction(call *ast.CallExpr) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(selector.Sel.Name)
		sanitizationPatterns := []string{
			"escape", "sanitize", "clean", "filter", "strip",
			"html.escape", "template.escape", "url.escape",
			"escapehtml", "escapeurl", "escapestring",
		}
		for _, pattern := range sanitizationPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isSafePattern checks if the code follows a safe pattern
func (ca *ContextAnalyzer) isSafePattern(node ast.Node) bool {
	// Check for safe patterns like:
	// - String literals only
	// - Hardcoded values
	// - Safe function calls
	switch n := node.(type) {
	case *ast.BasicLit:
		return true // String literals are generally safe
	case *ast.CallExpr:
		return ca.isSafeFunctionCall(n)
	case *ast.BinaryExpr:
		// Check if both sides are safe
		return ca.isSafePattern(n.X) && ca.isSafePattern(n.Y)
	}
	return false
}

// isSafeFunctionCall checks if a function call is considered safe
func (ca *ContextAnalyzer) isSafeFunctionCall(call *ast.CallExpr) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(selector.Sel.Name)
		safePatterns := []string{
			"escape", "sanitize", "validate", "check",
			"template", "html", "url", "path",
		}
		for _, pattern := range safePatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// ContextInfo holds information about the context of a potential vulnerability
type ContextInfo struct {
	HasValidation    bool    // Whether validation functions are present
	HasSanitization  bool    // Whether sanitization functions are present
	IsSafePattern    bool    // Whether the code follows safe patterns
	Confidence       float64 // Confidence score (0.0 to 1.0)
	ContextType      string  // Type of context (e.g., "validation", "sanitization")
	Recommendation   string  // Recommendation for the finding
}

// ShouldSuppress determines if a finding should be suppressed based on context
func (ci *ContextInfo) ShouldSuppress(threshold float64) bool {
	return ci.Confidence < threshold
}

// GetSeverityAdjustment returns how much to adjust the severity based on context
func (ci *ContextInfo) GetSeverityAdjustment() string {
	if ci.Confidence < 0.3 {
		return "low"
	} else if ci.Confidence < 0.7 {
		return "medium"
	}
	return "high"
}
