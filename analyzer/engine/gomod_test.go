package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/config"
)

func TestScanReportsGoModProblemsAtTheirLines(t *testing.T) {
	dir := t.TempDir()
	goMod := `module example.test/app

go 1.24

require (
	example.test/shared v0.0.0
	github.com/spf13/corba v1.8.0
)

replace example.test/shared => ./shared
`
	files := map[string]string{
		"go.mod":           goMod,
		"main.go":          "package main\n\nfunc main() {}\n",
		"shared/go.mod":    "module example.test/shared\n\ngo 1.24\n",
		"shared/shared.go": "package shared\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	issues, err := Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"dependency-typosquatting": 7, "gomod-local-replace": 10, "gomod-missing-checksum": 7}
	got := map[string]int{}
	for _, is := range issues {
		if _, ok := want[is.ID]; ok {
			if is.Location.File != "go.mod" || is.Category != "supply-chain" {
				t.Errorf("%s at %s, category %s", is.ID, is.Location.File, is.Category)
			}
			got[is.ID] = is.Location.Line
		}
	}
	for id, line := range want {
		if got[id] != line {
			t.Errorf("%s at line %d, want %d (all: %v)", id, got[id], line, got)
		}
	}

	cfg.Dependencies.CheckHygiene, cfg.Dependencies.CheckProvenance = false, false
	issues, err = Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range issues {
		if _, ok := want[is.ID]; ok {
			t.Errorf("%s reported with the checks disabled", is.ID)
		}
	}
}
