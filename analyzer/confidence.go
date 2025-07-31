package analyzer

import (
	"go/ast"
	"strings"
)

// ConfidenceScorer provides confidence scoring for security findings
type ConfidenceScorer struct {
	// Configuration for confidence scoring
	config ConfidenceConfig
}

// ConfidenceConfig holds configuration for confidence scoring
type ConfidenceConfig struct {
	EnableContextAnalysis   bool    `yaml:"enable_context_analysis"`
	EnableValidationChecks  bool    `yaml:"enable_validation_checks"`
	EnableSafePatterns      bool    `yaml:"enable_safe_patterns"`
	MinConfidence          float64 `yaml:"min_confidence"`
	MaxFalsePositiveRate   float64 `yaml:"max_false_positive_rate"`
}

// NewConfidenceScorer creates a new confidence scorer
func NewConfidenceScorer(config ConfidenceConfig) *ConfidenceScorer {
	return &ConfidenceScorer{
		config: config,
	}
}

// ScoreConfidence calculates a confidence score for a potential vulnerability
func (cs *ConfidenceScorer) ScoreConfidence(node ast.Node, context *ContextInfo) float64 {
	confidence := 1.0

	// Apply context-based adjustments
	if cs.config.EnableContextAnalysis {
		confidence *= cs.calculateContextScore(context)
	}

	// Apply validation-based adjustments
	if cs.config.EnableValidationChecks {
		confidence *= cs.calculateValidationScore(node, context)
	}

	// Apply safe pattern adjustments
	if cs.config.EnableSafePatterns {
		confidence *= cs.calculateSafePatternScore(node, context)
	}

	// Ensure confidence is within bounds
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateContextScore calculates confidence based on context
func (cs *ConfidenceScorer) calculateContextScore(context *ContextInfo) float64 {
	score := 1.0

	// Reduce confidence if validation is present
	if context.HasValidation {
		score *= 0.3
	}

	// Reduce confidence if sanitization is present
	if context.HasSanitization {
		score *= 0.2
	}

	// Reduce confidence if safe patterns are detected
	if context.IsSafePattern {
		score *= 0.1
	}

	return score
}

// calculateValidationScore calculates confidence based on validation functions
func (cs *ConfidenceScorer) calculateValidationScore(node ast.Node, context *ContextInfo) float64 {
	score := 1.0

	// Check for validation functions in the same scope
	if context.HasValidation {
		score *= 0.4
	}

	// Check for input validation patterns
	if cs.hasInputValidation(node) {
		score *= 0.5
	}

	return score
}

// calculateSafePatternScore calculates confidence based on safe patterns
func (cs *ConfidenceScorer) calculateSafePatternScore(node ast.Node, context *ContextInfo) float64 {
	score := 1.0

	// Check for safe patterns
	if context.IsSafePattern {
		score *= 0.2
	}

	// Check for hardcoded values
	if cs.isHardcodedValue(node) {
		score *= 0.3
	}

	// Check for safe function calls
	if cs.isSafeFunctionCall(node) {
		score *= 0.4
	}

	return score
}

// hasInputValidation checks if there are input validation patterns
func (cs *ConfidenceScorer) hasInputValidation(node ast.Node) bool {
	var hasValidation bool
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if cs.isValidationFunction(call) {
				hasValidation = true
				return false
			}
		}
		return true
	})
	return hasValidation
}

// isValidationFunction checks if a function call is a validation function
func (cs *ConfidenceScorer) isValidationFunction(call *ast.CallExpr) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(selector.Sel.Name)
		validationPatterns := []string{
			"validate", "check", "verify", "test", "assert",
			"isvalid", "validateinput", "validateparam", "validateuser",
			"sanitize", "escape", "clean", "filter",
		}
		for _, pattern := range validationPatterns {
			if strings.Contains(funcName, pattern) {
				return true
			}
		}
	}
	return false
}

// isHardcodedValue checks if a node represents a hardcoded value
func (cs *ConfidenceScorer) isHardcodedValue(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		// Check if it's a constant or hardcoded value
		name := strings.ToLower(n.Name)
		hardcodedPatterns := []string{
			"const", "default", "static", "fixed", "hardcoded",
			"literal", "template", "config", "setting",
		}
		for _, pattern := range hardcodedPatterns {
			if strings.Contains(name, pattern) {
				return true
			}
		}
	}
	return false
}

// isSafeFunctionCall checks if a node represents a safe function call
func (cs *ConfidenceScorer) isSafeFunctionCall(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.CallExpr:
		if selector, ok := n.Fun.(*ast.SelectorExpr); ok {
			funcName := strings.ToLower(selector.Sel.Name)
			safePatterns := []string{
				"escape", "sanitize", "validate", "check",
				"template", "html", "url", "path", "safe",
			}
			for _, pattern := range safePatterns {
				if strings.Contains(funcName, pattern) {
					return true
				}
			}
		}
	}
	return false
}

// ShouldReport determines if a finding should be reported based on confidence
func (cs *ConfidenceScorer) ShouldReport(confidence float64) bool {
	return confidence >= cs.config.MinConfidence
}

// GetSeverityAdjustment returns severity adjustment based on confidence
func (cs *ConfidenceScorer) GetSeverityAdjustment(confidence float64) string {
	if confidence < 0.3 {
		return "low"
	} else if confidence < 0.7 {
		return "medium"
	}
	return "high"
}

// GetRecommendation returns a recommendation based on confidence and context
func (cs *ConfidenceScorer) GetRecommendation(confidence float64, context *ContextInfo) string {
	var recommendations []string

	if confidence < 0.3 {
		recommendations = append(recommendations, "Low confidence finding - consider manual review")
	}

	if context.HasValidation {
		recommendations = append(recommendations, "Validation detected - may be a false positive")
	}

	if context.HasSanitization {
		recommendations = append(recommendations, "Sanitization detected - may be a false positive")
	}

	if context.IsSafePattern {
		recommendations = append(recommendations, "Safe pattern detected - may be a false positive")
	}

	if len(recommendations) == 0 {
		return "High confidence finding - immediate attention recommended"
	}

	return strings.Join(recommendations, "; ")
} 