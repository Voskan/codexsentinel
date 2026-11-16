package config

type Config struct {
	Version      int               `yaml:"version"`
	Scan         ScanConfig        `yaml:"scan"`
	Rules        RuleConfig        `yaml:"rules"`
	Taint        TaintConfig       `yaml:"taint"`
	Architecture ArchConfig        `yaml:"architecture"`
	Metrics      MetricsConfig     `yaml:"metrics"`
	Dependencies DependencyConfig  `yaml:"dependencies"`
	Suppression  SuppressionConfig `yaml:"suppression"`
	Report       ReportConfig      `yaml:"report"`
}

type ScanConfig struct {
	IncludeTests        bool     `yaml:"include_tests"`
	IncludeVendor       bool     `yaml:"include_vendor"`
	IncludeGenerated    bool     `yaml:"include_generated"`
	ExcludedPaths       []string `yaml:"excluded_paths"`
	MaxFileSizeBytes    int64    `yaml:"max_file_size_bytes"`
	SupportedExtensions []string `yaml:"supported_extensions"`
	Concurrency         int      `yaml:"concurrency"`
	// EnableCache stores per-package results on disk and reuses them while the
	// package, its dependencies, the configuration and the analyzer are unchanged.
	EnableCache bool `yaml:"enable_cache"`
	// CacheDir is the cache location; empty uses $CODEXSENTINEL_CACHE_DIR or
	// codexsentinel/cache-v1 in the user cache directory.
	CacheDir string `yaml:"cache_dir"`
}

type RuleConfig struct {
	Enabled           []string          `yaml:"enabled"`
	Disabled          []string          `yaml:"disabled"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	RulePaths         []string          `yaml:"rule_paths"`
	RuleFiles         []string          `yaml:"rule_files"`
}

type TaintConfig struct {
	Enable           bool               `yaml:"enable"`
	Interprocedural  bool               `yaml:"interprocedural"`
	CustomSources    []CustomSourceSpec `yaml:"custom_sources"`
	CustomSinks      []CustomSinkSpec   `yaml:"custom_sinks"`
	CustomSanitizers []CustomSanSpec    `yaml:"custom_sanitizers"`
}

type CustomSourceSpec struct {
	Package  string   `yaml:"package"`
	Receiver string   `yaml:"receiver,omitempty"`
	Function string   `yaml:"function"`
	Tags     []string `yaml:"tags,omitempty"`
}

type CustomSinkSpec struct {
	Package   string `yaml:"package"`
	Receiver  string `yaml:"receiver,omitempty"`
	Function  string `yaml:"function"`
	CheckArgs []int  `yaml:"check_args"`
	Category  string `yaml:"category"`
}

type CustomSanSpec struct {
	Package    string   `yaml:"package"`
	Receiver   string   `yaml:"receiver,omitempty"`
	Function   string   `yaml:"function"`
	Categories []string `yaml:"categories"`
}

type ArchConfig struct {
	Enable              bool                `yaml:"enable"`
	Layers              map[string][]string `yaml:"layers"`
	AllowedDeps         map[string][]string `yaml:"allowed_deps"`
	CheckCycles         bool                `yaml:"check_cycles"`
	CheckGodStructs     bool                `yaml:"check_god_structs"`
	CheckBoundaries     bool                `yaml:"check_boundaries"`
	GodStructMaxMethods int                 `yaml:"god_struct_max_methods"`
	GodStructMaxFields  int                 `yaml:"god_struct_max_fields"`
}

type MetricsConfig struct {
	Enable            bool `yaml:"enable"`
	MaxCyclomatic     int  `yaml:"max_cyclomatic"`
	MaxFunctionLOC    int  `yaml:"max_function_loc"`
	MaxFileLOC        int  `yaml:"max_file_loc"`
	MinDuplicateLOC   int  `yaml:"min_duplicate_loc"`
	EnableDuplication bool `yaml:"enable_duplication"`
	EnableDeadCode    bool `yaml:"enable_dead_code"`
	EnableGlobals     bool `yaml:"enable_globals"`
}

type DependencyConfig struct {
	Enable               bool     `yaml:"enable"`
	CheckVulnerabilities bool     `yaml:"check_vulnerabilities"`
	CheckReachability    bool     `yaml:"check_reachability"`
	CheckCapabilities    bool     `yaml:"check_capabilities"`
	CapabilityLockfile   string   `yaml:"capability_lockfile"`
	CheckLicenses        bool     `yaml:"check_licenses"`
	AllowLicenses        []string `yaml:"allow_licenses"`
	DenyLicenses         []string `yaml:"deny_licenses"`
}

type SuppressionConfig struct {
	IgnoreFile          string  `yaml:"ignore_file"`
	EnableInlineIgnore  bool    `yaml:"enable_inline_ignore"`
	RequireIgnoreReason bool    `yaml:"require_ignore_reason"`
	MinConfidence       float64 `yaml:"min_confidence"`
}

type ReportConfig struct {
	Formats        []string `yaml:"formats"`
	OutputDir      string   `yaml:"output_dir"`
	FailOnSeverity string   `yaml:"fail_on_severity"`
}
