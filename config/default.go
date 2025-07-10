// Package config provides loading and management of CodexSentinel configuration.
package config

// DefaultConfig holds the default configuration used when no .codex.yml is provided.
var DefaultConfig = Config{
	Scan: ScanConfig{
		IncludeTests:        false,
		IncludeVendor:       false,
		ExcludedPaths:       []string{"testdata/", "vendor/", "scripts/"},
		IncludeGenerated:    false,
		MaxFileSizeBytes:    512 * 1024, // 512KB
		SupportedExtensions: []string{".go"},
	},
	Rules: RuleConfig{
		Enabled:   []string{"*"},
		Disabled:  []string{},
		Severity:  map[string]string{},
		RulePaths: []string{"rules/"},
	},
	Report: ReportConfig{
		Formats:       []string{"json"},
		OutputPath:    "report/",
		IncludeIssues: true,
	},
	Dependencies: DependencyConfig{
		CheckVulnerabilities: true,
		CheckLicenses:        true,
		AllowLicenses:        []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		DenyLicenses:         []string{"AGPL-3.0", "GPL-3.0", "BSL-1.1"},
	},
	Metrics: MetricsConfig{
		Enable:            true,
		MaxFunctionLOC:    80,
		MaxFileLOC:        500,
		MaxCyclomatic:     10,
		EnableDuplication: true,
	},
	Architecture: ArchConfig{
		Enable:            true,
		CheckImportCycles: true,
		CheckLayering:     true,
		CheckGodStructs:   true,
	},
	WebChecks: WebCheckConfig{
		EnableCORSCheck:     true,
		EnableCSRFCheck:     true,
		EnableHeaderChecks:  true,
		EnableAuthChecks:    true,
		EnableInputValidate: true,
	},
}
