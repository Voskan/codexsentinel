package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMinimalFileHasNoSyntheticFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(path, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issues, err := Run(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("unexpected findings for empty program: %+v", issues)
	}
}
