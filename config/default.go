package config

import (
	"maps"
	"slices"
)

// DefaultConfig supplies conservative scan settings and optional analysis defaults.
var DefaultConfig = Config{
	Version: 1,
	Scan: ScanConfig{
		ExcludedPaths:       []string{"vendor", "testdata", "node_modules", ".git"},
		MaxFileSizeBytes:    10 * 1024 * 1024,
		SupportedExtensions: []string{".go"},
	},
	Rules: RuleConfig{Enabled: []string{"*"}, SeverityOverrides: map[string]string{}},
	Taint: TaintConfig{Enable: true, Interprocedural: true},
	Architecture: ArchConfig{
		Enable: true, CheckCycles: true, CheckGodStructs: true, CheckBoundaries: true,
		GodStructMaxMethods: 15, GodStructMaxFields: 20,
		Layers: map[string][]string{}, AllowedDeps: map[string][]string{},
	},
	Metrics: MetricsConfig{
		Enable: true, MaxCyclomatic: 15, MaxFunctionLOC: 80, MaxFileLOC: 600, MinDuplicateLOC: 10,
		EnableDuplication: true, EnableDeadCode: true, EnableGlobals: true,
	},
	Dependencies: DependencyConfig{
		Enable: false, CheckVulnerabilities: true, CheckReachability: true, CheckCapabilities: true, CheckLicenses: true,
		CapabilityLockfile: ".codexsentinel.caps.json",
		AllowLicenses:      []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"},
		DenyLicenses:       []string{"AGPL-3.0", "GPL-3.0", "GPL-2.0", "SSPL-1.0", "BSL-1.1"},
	},
	Suppression: SuppressionConfig{
		IgnoreFile: ".codexsentinel.ignore", EnableInlineIgnore: true, MinConfidence: 0.5,
	},
	Report: ReportConfig{Formats: []string{"sarif"}, OutputDir: "scan_reports"},
}

// NewDefaultConfig returns an independent configuration that callers may modify.
func NewDefaultConfig() Config {
	cfg := DefaultConfig
	cfg.Scan.ExcludedPaths = slices.Clone(cfg.Scan.ExcludedPaths)
	cfg.Scan.SupportedExtensions = slices.Clone(cfg.Scan.SupportedExtensions)
	cfg.Rules.Enabled = slices.Clone(cfg.Rules.Enabled)
	cfg.Rules.Disabled = slices.Clone(cfg.Rules.Disabled)
	cfg.Rules.RulePaths = slices.Clone(cfg.Rules.RulePaths)
	cfg.Rules.RuleFiles = slices.Clone(cfg.Rules.RuleFiles)
	cfg.Rules.SeverityOverrides = maps.Clone(cfg.Rules.SeverityOverrides)
	cfg.Taint.CustomSources = slices.Clone(cfg.Taint.CustomSources)
	for i := range cfg.Taint.CustomSources {
		cfg.Taint.CustomSources[i].Tags = slices.Clone(cfg.Taint.CustomSources[i].Tags)
	}
	cfg.Taint.CustomSinks = slices.Clone(cfg.Taint.CustomSinks)
	for i := range cfg.Taint.CustomSinks {
		cfg.Taint.CustomSinks[i].CheckArgs = slices.Clone(cfg.Taint.CustomSinks[i].CheckArgs)
	}
	cfg.Taint.CustomSanitizers = slices.Clone(cfg.Taint.CustomSanitizers)
	for i := range cfg.Taint.CustomSanitizers {
		cfg.Taint.CustomSanitizers[i].Categories = slices.Clone(cfg.Taint.CustomSanitizers[i].Categories)
	}
	cfg.Architecture.Layers = cloneLists(cfg.Architecture.Layers)
	cfg.Architecture.AllowedDeps = cloneLists(cfg.Architecture.AllowedDeps)
	cfg.Dependencies.AllowLicenses = slices.Clone(cfg.Dependencies.AllowLicenses)
	cfg.Dependencies.DenyLicenses = slices.Clone(cfg.Dependencies.DenyLicenses)
	cfg.Report.Formats = slices.Clone(cfg.Report.Formats)
	return cfg
}

func cloneLists(src map[string][]string) map[string][]string {
	dst := maps.Clone(src)
	for key, values := range dst {
		dst[key] = slices.Clone(values)
	}
	return dst
}
