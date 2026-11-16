package engine

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Voskan/codexsentinel/config"
)

func TestConcurrentWorkspaceAnalysis(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"go.mod": "module example.test/concurrent\n\ngo 1.24.2\n", "main.go": "package main\nfunc main() {}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := config.NewDefaultConfig()
			cfg.Metrics.Enable = false
			if issues, err := Run(context.Background(), dir, &cfg); err != nil || len(issues) != 0 {
				t.Errorf("Run: %v, %v", issues, err)
			}
		}()
	}
	wg.Wait()
}

func TestCanceledWorkspaceAnalysis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, t.TempDir(), nil); err == nil {
		t.Fatal("expected cancellation error")
	}
}
