package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/v2/config"
)

func TestRunReportsInterproceduralTaint(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/taint\n\ngo 1.24\n",
		"main.go": `package main

import (
	"net/http"
	"os/exec"
)

func run(name string) { exec.Command(name).Run() }

func handler(w http.ResponseWriter, r *http.Request) { run(r.FormValue("bin")) }

func main() { http.HandleFunc("/", handler) }
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.NewDefaultConfig()
	cfg.Metrics.Enable = false
	cfg.Rules.Enabled = []string{"command-injection"}
	issues, err := Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	var traced bool
	for _, issue := range issues {
		if issue.ID == "command-injection" && len(issue.Trace) >= 3 {
			traced = true
			if issue.Location.File != "main.go" || issue.Trace[0].Location.File != "main.go" || issue.Location.Line != 8 {
				t.Fatalf("unexpected location: %+v", issue.Location)
			}
		}
	}
	if !traced {
		t.Fatalf("expected traced command-injection, got %+v", issues)
	}
	cfg.Taint.Interprocedural = false
	cfg.Rules.Enabled = []string{"command-injection"}
	issues, err = Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range issues {
		if len(issue.Trace) > 0 {
			t.Fatalf("intraprocedural mode should not report cross-function flow: %+v", issue)
		}
	}
}
