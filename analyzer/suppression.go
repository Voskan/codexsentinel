package analyzer

import (
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// SuppressionManager manages automatic suppression of false positives
type SuppressionManager struct {
	// Configuration for suppression
	config SuppressionConfig
	// Track suppressed findings
	suppressedFindings map[string]bool
}

// SuppressionConfig holds configuration for suppression
type SuppressionConfig struct {
	EnableAutoSuppression bool    `yaml:"enable_auto_suppression"`
	MaxSuppressionRate    float64 `yaml:"max_suppression_rate"`
	ConfidenceThreshold   float64 `yaml:"confidence_threshold"`
}

// NewSuppressionManager creates a new suppression manager
func NewSuppressionManager(config SuppressionConfig) *SuppressionManager {
	return &SuppressionManager{
		config:             config,
		suppressedFindings: make(map[string]bool),
	}
}

// ShouldSuppress determines if a finding should be suppressed based on context
func (sm *SuppressionManager) ShouldSuppress(issue *result.Issue, context *ContextInfo) bool {
	if !sm.config.EnableAutoSuppression {
		return false
	}

	// Check confidence threshold
	if context.Confidence >= sm.config.ConfidenceThreshold {
		return false
	}

	// Check for safe patterns
	if sm.isSafePattern(issue, context) {
		return true
	}

	// Check for test files
	if sm.isTestFile(issue.Location.File) {
		return true
	}

	// Check for common false positive patterns
	if sm.isCommonFalsePositive(issue, context) {
		return true
	}

	return false
}

// isSafePattern checks if the finding is in a safe pattern
func (sm *SuppressionManager) isSafePattern(issue *result.Issue, context *ContextInfo) bool {
	// Check for validation context
	if context.HasValidation {
		return true
	}

	// Check for sanitization context
	if context.HasSanitization {
		return true
	}

	// Check for safe patterns
	if context.IsSafePattern {
		return true
	}

	// Check issue-specific safe patterns
	switch issue.ID {
	case "sql-injection":
		return sm.isSafeSQLPattern(issue)
	case "xss-vulnerability-builtin":
		return sm.isSafeXSSPattern(issue)
	case "command-exec-taint":
		return sm.isSafeCommandPattern(issue)
	case "path-traversal-vulnerability":
		return sm.isSafePathPattern(issue)
	}

	return false
}

// isSafeSQLPattern checks if SQL injection finding is in a safe pattern
func (sm *SuppressionManager) isSafeSQLPattern(issue *result.Issue) bool {
	// Check for safe SQL patterns
	safePatterns := []string{
		"SELECT COUNT(*)", "SELECT 1", "SELECT id",
		"INSERT INTO logs", "INSERT INTO audit",
		"UPDATE config", "UPDATE settings",
	}
	
	description := strings.ToLower(issue.Description)
	for _, pattern := range safePatterns {
		if strings.Contains(description, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// isSafeXSSPattern checks if XSS finding is in a safe pattern
func (sm *SuppressionManager) isSafeXSSPattern(issue *result.Issue) bool {
	// Check for safe XSS patterns
	safePatterns := []string{
		"html.EscapeString", "template.HTMLEscapeString",
		"json.Marshal", "xml.Marshal",
		"text/template", "html/template",
	}
	
	description := strings.ToLower(issue.Description)
	for _, pattern := range safePatterns {
		if strings.Contains(description, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// isSafeCommandPattern checks if command injection finding is in a safe pattern
func (sm *SuppressionManager) isSafeCommandPattern(issue *result.Issue) bool {
	// Check for safe command patterns
	safePatterns := []string{
		"echo", "ls", "cat", "head", "tail", "grep",
		"wc", "sort", "uniq", "cut", "awk", "sed",
		"ps", "top", "df", "du", "free", "uptime",
	}
	
	description := strings.ToLower(issue.Description)
	for _, pattern := range safePatterns {
		if strings.Contains(description, pattern) {
			return true
		}
	}
	
	return false
}

// isSafePathPattern checks if path traversal finding is in a safe pattern
func (sm *SuppressionManager) isSafePathPattern(issue *result.Issue) bool {
	// Check for safe path patterns
	safePatterns := []string{
		"filepath.Clean", "filepath.Join", "os.Stat",
		"config/", "static/", "assets/", "templates/",
	}
	
	description := strings.ToLower(issue.Description)
	for _, pattern := range safePatterns {
		if strings.Contains(description, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// isTestFile checks if the file is a test file
func (sm *SuppressionManager) isTestFile(filename string) bool {
	testPatterns := []string{
		"_test.go", "test_", "_test", "mock_", "_mock",
		"testdata/", "tests/", "testing/",
	}
	
	filenameLower := strings.ToLower(filename)
	for _, pattern := range testPatterns {
		if strings.Contains(filenameLower, pattern) {
			return true
		}
	}
	
	return false
}

// isCommonFalsePositive checks if the finding is a common false positive
func (sm *SuppressionManager) isCommonFalsePositive(issue *result.Issue, context *ContextInfo) bool {
	// Check for common false positive patterns
	commonFalsePositives := []string{
		"example", "sample", "demo", "test", "mock",
		"placeholder", "template", "default", "config",
		"localhost", "127.0.0.1", "0.0.0.0",
	}
	
	description := strings.ToLower(issue.Description)
	for _, pattern := range commonFalsePositives {
		if strings.Contains(description, pattern) {
			return true
		}
	}
	
	// Check for low confidence findings
	if context.Confidence < 0.3 {
		return true
	}
	
	return false
}

// GetSuppressionReason returns the reason for suppression
func (sm *SuppressionManager) GetSuppressionReason(issue *result.Issue, context *ContextInfo) string {
	var reasons []string
	
	if context.HasValidation {
		reasons = append(reasons, "validation detected")
	}
	
	if context.HasSanitization {
		reasons = append(reasons, "sanitization detected")
	}
	
	if context.IsSafePattern {
		reasons = append(reasons, "safe pattern detected")
	}
	
	if sm.isTestFile(issue.Location.File) {
		reasons = append(reasons, "test file")
	}
	
	if context.Confidence < 0.3 {
		reasons = append(reasons, "low confidence")
	}
	
	if len(reasons) == 0 {
		return "unknown reason"
	}
	
	return strings.Join(reasons, ", ")
} 