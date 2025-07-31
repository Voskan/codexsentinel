// Package config defines the configuration schema for CodexSentinel.
package config

// Config represents the full configuration for CodexSentinel.
type Config struct {
	Scan                    ScanConfig                    `yaml:"scan"`
	Rules                   RuleConfig                   `yaml:"rules"`
	Report                  ReportConfig                 `yaml:"report"`
	Dependencies            DependencyConfig             `yaml:"dependencies"`
	Metrics                 MetricsConfig                `yaml:"metrics"`
	Architecture            ArchConfig                   `yaml:"architecture"`
	WebChecks               WebCheckConfig               `yaml:"web_checks"`
	FalsePositiveManagement FalsePositiveManagementConfig `yaml:"false_positive_management"`
}

// ScanConfig defines parameters for scanning source code.
type ScanConfig struct {
	IncludeTests        bool     `yaml:"include_tests"`        // Include *_test.go files
	IncludeVendor       bool     `yaml:"include_vendor"`       // Include vendor directory
	IncludeGenerated    bool     `yaml:"include_generated"`    // Include generated files
	ExcludedPaths       []string `yaml:"excluded_paths"`       // Paths to exclude from scanning
	MaxFileSizeBytes    int      `yaml:"max_file_size_bytes"`  // Max size of files to scan
	SupportedExtensions []string `yaml:"supported_extensions"` // File extensions to scan
}

// RuleConfig defines rule loading and filtering behavior.
type RuleConfig struct {
	Enabled             []string              `yaml:"enabled"`    // List of enabled rule IDs or "*" for all
	Disabled            []string              `yaml:"disabled"`   // List of disabled rule IDs
	Severity            map[string]string     `yaml:"severity"`   // Override severity for specific rules
	RulePaths           []string              `yaml:"rule_paths"` // Directories where YAML rules are stored
	RuleFiles           []string              `yaml:"rule_files"` // Specific YAML rule files to load
	FalsePositiveConfig FalsePositiveConfig   `yaml:"false_positive_config"` // False positive management settings
}

// FalsePositiveConfig defines false positive management settings
type FalsePositiveConfig struct {
	EnableContextAnalysis   bool    `yaml:"enable_context_analysis"`   // Enable context-aware analysis
	EnableValidationChecks  bool    `yaml:"enable_validation_checks"`  // Check for validation functions
	EnableSafePatterns      bool    `yaml:"enable_safe_patterns"`      // Enable safe pattern detection
	MinConfidence          float64 `yaml:"min_confidence"`             // Minimum confidence threshold
	MaxFalsePositiveRate   float64 `yaml:"max_false_positive_rate"`   // Maximum acceptable false positive rate
}

// FalsePositiveManagementConfig defines advanced false positive management
type FalsePositiveManagementConfig struct {
	EnableAutoSuppression        bool    `yaml:"enable_auto_suppression"`        // Automatically suppress low-confidence findings
	EnableConfidenceScoring      bool    `yaml:"enable_confidence_scoring"`      // Enable confidence scoring for findings
	EnableContextAwareAnalysis   bool    `yaml:"enable_context_aware_analysis"`   // Enable context-aware analysis
	EnableSafePatternDetection   bool    `yaml:"enable_safe_pattern_detection"`   // Detect safe patterns to reduce false positives
	EnableValidationTracking     bool    `yaml:"enable_validation_tracking"`     // Track validation functions
	ConfidenceThreshold         float64 `yaml:"confidence_threshold"`            // Confidence threshold for reporting
	MaxSuppressionRate          float64 `yaml:"max_suppression_rate"`            // Maximum rate of suppressed findings
}

// ReportConfig defines output formats and report generation settings.
type ReportConfig struct {
	Formats       []string `yaml:"formats"`        // List of output formats: json, sarif, html, markdown
	OutputPath    string   `yaml:"output_path"`    // Directory to write report files
	IncludeIssues bool     `yaml:"include_issues"` // Include individual issues in report
}

// DependencyConfig defines settings for dependency audit.
type DependencyConfig struct {
	CheckVulnerabilities bool     `yaml:"check_vulnerabilities"` // Enable CVE audit
	CheckLicenses        bool     `yaml:"check_licenses"`        // Enable license scan
	AllowLicenses        []string `yaml:"allow_licenses"`        // Allowlisted licenses
	DenyLicenses         []string `yaml:"deny_licenses"`         // Denylisted licenses
}

// MetricsConfig defines static code metric thresholds.
type MetricsConfig struct {
	Enable            bool `yaml:"enable"`             // Enable code metrics
	MaxFunctionLOC    int  `yaml:"max_function_loc"`   // Max lines of code per function
	MaxFileLOC        int  `yaml:"max_file_loc"`       // Max lines of code per file
	MaxCyclomatic     int  `yaml:"max_cyclomatic"`     // Max cyclomatic complexity
	EnableDuplication bool `yaml:"enable_duplication"` // Enable detection of duplicated code
}

// ArchConfig defines architecture and structural enforcement.
type ArchConfig struct {
	Enable            bool `yaml:"enable"`              // Enable architecture analysis
	CheckImportCycles bool `yaml:"check_import_cycles"` // Detect circular dependencies
	CheckLayering     bool `yaml:"check_layering"`      // Detect direct cross-layer calls
	CheckGodStructs   bool `yaml:"check_god_structs"`   // Detect structs with too many responsibilities
}

// WebCheckConfig defines security-related web analysis settings.
type WebCheckConfig struct {
	EnableCORSCheck     bool `yaml:"enable_cors_check"`     // Check for open CORS
	EnableCSRFCheck     bool `yaml:"enable_csrf_check"`     // Check for CSRF protection
	EnableHeaderChecks  bool `yaml:"enable_header_checks"`  // Check for missing security headers
	EnableAuthChecks    bool `yaml:"enable_auth_checks"`    // Check for auth validations in handlers
	EnableInputValidate bool `yaml:"enable_input_validate"` // Check for unvalidated inputs
}
