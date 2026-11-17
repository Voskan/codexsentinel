package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/config"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func layeredModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"go.mod":                        "module example.test/shop\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.10.0\n",
		"main.go":                       "package main\n\nimport \"log/slog\"\n\nfunc main() { slog.Info(\"start\") }\n",
		"internal/domain/order.go":      "package domain\n\ntype Order struct{ ID int }\n",
		"internal/repo/orders.go":       "package repo\n\nimport \"example.test/shop/internal/domain\"\n\nfunc Find() domain.Order { return domain.Order{} }\n",
		"internal/service/orders.go":    "package service\n\nimport \"example.test/shop/internal/repo\"\n\nfunc Get() int { return repo.Find().ID }\n",
		"internal/handler/orders.go":    "package handler\n\nimport \"example.test/shop/internal/repo\"\n\nfunc Show() int { return repo.Find().ID }\n",
		"internal/mocks/orders_mock.go": "package mocks\n",
	})
	return dir
}

func TestInitWritesLoadableConfig(t *testing.T) {
	dir := layeredModule(t)
	out, err := runCLIOutput(t, "init", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Go 1.24", "example.test/shop", "gin", "slog", "delivery -> service, domain"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	cfg, err := config.LoadFromPath(filepath.Join(dir, config.DefaultConfigFilename))
	if err != nil {
		t.Fatalf("generated config does not load: %v", err)
	}
	layers := cfg.Architecture.Layers
	if got := layers["repository"]; len(got) != 1 || got[0] != "internal/repo" {
		t.Errorf("repository layer = %v", got)
	}
	if got := layers["delivery"]; len(got) != 1 || got[0] != "internal/handler" {
		t.Errorf("delivery layer = %v", got)
	}
	if !strings.Contains(strings.Join(cfg.Scan.ExcludedPaths, ","), "**/mocks/**") {
		t.Errorf("mocks not excluded: %v", cfg.Scan.ExcludedPaths)
	}
	if _, err := os.Stat(filepath.Join(dir, ".codexsentinel.ignore")); err != nil {
		t.Errorf("ignore file not created: %v", err)
	}

	// The handler imports the repository directly, which the layers forbid.
	report := filepath.Join(t.TempDir(), "r.json")
	if err := runCLI(t, "scan", dir, "--config", filepath.Join(dir, config.DefaultConfigFilename),
		"--format", "json", "--out", report, "--no-cache"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Issues []struct {
			RuleID string `json:"rule_id"`
			File   string `json:"file"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	var violations []string
	for _, is := range parsed.Issues {
		if is.RuleID == "arch-layer-violation" {
			violations = append(violations, is.File)
		}
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "handler") {
		t.Errorf("layer violations = %v, want one in the handler", violations)
	}
}

func TestInitKeepsExistingConfigWithoutForce(t *testing.T) {
	dir := layeredModule(t)
	if _, err := runCLIOutput(t, "init", dir); err != nil {
		t.Fatal(err)
	}
	ignore := filepath.Join(dir, ".codexsentinel.ignore")
	if err := os.WriteFile(ignore, []byte("custom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLIOutput(t, "init", dir); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second init without --force: err = %v", err)
	}
	if _, err := runCLIOutput(t, "init", dir, "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	if data, _ := os.ReadFile(ignore); string(data) != "custom\n" {
		t.Errorf("existing ignore file was overwritten: %q", data)
	}
}

func TestInitWithoutLayersKeepsStructuralChecks(t *testing.T) {
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	if _, err := runCLIOutput(t, "init", dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromPath(filepath.Join(dir, config.DefaultConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Architecture.Layers) != 0 || !cfg.Architecture.CheckCycles {
		t.Errorf("layers = %v, check_cycles = %v", cfg.Architecture.Layers, cfg.Architecture.CheckCycles)
	}
}

func TestInitRequiresGoModule(t *testing.T) {
	if _, err := runCLIOutput(t, "init", t.TempDir()); err == nil {
		t.Fatal("init succeeded without go.mod")
	}
}
