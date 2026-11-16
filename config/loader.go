package config

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultConfigFilename = ".codexsentinel.yaml"

// FindDefaultConfigFile returns the first configured file in precedence order.
func FindDefaultConfigFile(dir string) string {
	for _, name := range []string{DefaultConfigFilename, ".codexsentinel.yml", "codex.yaml", ".codex.yml"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// Load merges an explicit configuration file over independent default values.
func Load(path string) (Config, error) {
	cfg := NewDefaultConfig()
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("read configuration %q: %w", path, err)
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
		return cfg, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return cfg, fmt.Errorf("parse configuration %q: %w", path, err)
		}
		return cfg, fmt.Errorf("configuration %q must contain one YAML document", path)
	}
	if err := Validate(&cfg); err != nil {
		return cfg, fmt.Errorf("configuration %q: %w", path, err)
	}
	return cfg, nil
}

func LoadDefaultPath() (Config, error) {
	path := FindDefaultConfigFile(".")
	if path == "" {
		return NewDefaultConfig(), nil
	}
	return Load(path)
}

func LoadFromPath(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func LoadDefaultPathPtr() (*Config, error) {
	cfg, err := LoadDefaultPath()
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks policy settings before analysis starts.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration must not be nil")
	}
	if cfg.Version < 0 || cfg.Version > 1 {
		return fmt.Errorf("unsupported configuration version %d", cfg.Version)
	}
	switch strings.ToLower(cfg.Report.FailOnSeverity) {
	case "", "critical", "high", "medium", "low":
	default:
		return fmt.Errorf("report.fail_on_severity must be critical, high, medium, low, or empty")
	}
	if math.IsNaN(cfg.Suppression.MinConfidence) || cfg.Suppression.MinConfidence < 0 || cfg.Suppression.MinConfidence > 1 {
		return fmt.Errorf("suppression.min_confidence must be between 0 and 1")
	}
	thresholds := []struct {
		name  string
		value int64
	}{
		{"scan.max_file_size_bytes", cfg.Scan.MaxFileSizeBytes},
		{"metrics.max_cyclomatic", int64(cfg.Metrics.MaxCyclomatic)},
		{"metrics.max_function_loc", int64(cfg.Metrics.MaxFunctionLOC)},
		{"metrics.max_file_loc", int64(cfg.Metrics.MaxFileLOC)},
		{"metrics.min_duplicate_loc", int64(cfg.Metrics.MinDuplicateLOC)},
		{"architecture.god_struct_max_methods", int64(cfg.Architecture.GodStructMaxMethods)},
		{"architecture.god_struct_max_fields", int64(cfg.Architecture.GodStructMaxFields)},
	}
	for _, threshold := range thresholds {
		if threshold.value < 0 {
			return fmt.Errorf("%s must not be negative", threshold.name)
		}
	}
	for rule, severity := range cfg.Rules.SeverityOverrides {
		switch strings.ToLower(severity) {
		case "critical", "high", "medium", "low", "info":
		default:
			return fmt.Errorf("rules.severity_overrides[%q] has invalid severity %q", rule, severity)
		}
	}
	for _, format := range cfg.Report.Formats {
		switch format {
		case "json", "sarif", "markdown", "html":
		default:
			return fmt.Errorf("unsupported report format %q", format)
		}
	}
	for i, sink := range cfg.Taint.CustomSinks {
		for _, arg := range sink.CheckArgs {
			if arg < 0 {
				return fmt.Errorf("taint.custom_sinks[%d].check_args must not contain negative indexes", i)
			}
		}
	}
	return nil
}
