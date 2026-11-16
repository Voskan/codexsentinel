package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRepositoryConfig(t *testing.T) {
	cfg, err := LoadFromPath(filepath.Join("..", "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.Metrics.MaxCyclomatic != 30 || !cfg.Suppression.RequireIgnoreReason || cfg.Suppression.MinConfidence != 0.5 {
		t.Fatalf("unexpected root config: %+v", cfg)
	}
}

func TestDefaultSearchOrder(t *testing.T) {
	dir := t.TempDir()
	names := []string{".codexsentinel.yaml", ".codexsentinel.yml", "codex.yaml", ".codex.yml"}
	for i := len(names) - 1; i >= 0; i-- {
		path := writeConfig(t, dir, names[i], "version: 1\n")
		if got := FindDefaultConfigFile(dir); got != path {
			t.Fatalf("got %q, want %q", got, path)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	tests := map[string]string{
		"unknown":        "typo: true\n",
		"nested-unknown": "scan:\n  include_test: true\n",
		"confidence":     "suppression:\n  min_confidence: 1.5\n",
		"nan":            "suppression:\n  min_confidence: .nan\n",
		"negative":       "metrics:\n  max_cyclomatic: -1\n",
		"severity":       "report:\n  fail_on_severity: severe\n",
		"override":       "rules:\n  severity_overrides:\n    sql-injection: severe\n",
		"documents":      "version: 1\n---\nversion: 1\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFromPath(writeConfig(t, t.TempDir(), "config.yaml", data)); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestMissingConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := LoadFromPath("missing.yaml"); err == nil {
		t.Fatal("explicit missing path accepted")
	}
	cfg, err := LoadDefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, DefaultConfig) {
		t.Fatal("default discovery did not return defaults")
	}
}

func TestDefaultsRemainIndependent(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "config.yaml", "rules:\n  severity_overrides:\n    sql-injection: HIGH\n")
	first, err := LoadFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Rules.SeverityOverrides["sql-injection"] = "LOW"
	first.Scan.ExcludedPaths[0] = "changed"
	first.Architecture.Layers["domain"] = []string{"changed"}
	first.Report.Formats[0] = "html"
	if len(DefaultConfig.Rules.SeverityOverrides) != 0 || DefaultConfig.Scan.ExcludedPaths[0] != "vendor" || len(DefaultConfig.Architecture.Layers) != 0 || DefaultConfig.Report.Formats[0] != "sarif" {
		t.Fatal("load modified global defaults")
	}
	second, err := LoadFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rules.SeverityOverrides["sql-injection"] != "HIGH" || second.Scan.ExcludedPaths[0] != "vendor" {
		t.Fatal("loads share mutable defaults")
	}
}

func TestExplicitFalseAndZero(t *testing.T) {
	cfg, err := LoadFromPath(writeConfig(t, t.TempDir(), "config.yaml", "taint:\n  enable: false\nsuppression:\n  min_confidence: 0\nscan:\n  concurrency: -1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Taint.Enable || cfg.Suppression.MinConfidence != 0 || cfg.Scan.Concurrency != -1 {
		t.Fatal("explicit zero values were lost")
	}
}

func TestUnknownFieldNamesInError(t *testing.T) {
	_, err := LoadFromPath(writeConfig(t, t.TempDir(), "config.yaml", "scan:\n  incude_tests: true\n"))
	if err == nil || !strings.Contains(err.Error(), "incude_tests") {
		t.Fatalf("error does not identify field: %v", err)
	}
}
