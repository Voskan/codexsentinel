package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/v2/config"
)

// writeGoWorkspace writes a go.work workspace whose service passes request
// input to a query built in a sibling library module.
func writeGoWorkspace(t *testing.T) string {
	t.Helper()
	t.Setenv("GOWORK", "")
	dir := t.TempDir()
	files := map[string]string{
		"go.work":        "go 1.24\n\nuse (\n\t./svc/api\n\t./lib\n)\n",
		"lib/go.mod":     "module example.test/lib\n\ngo 1.24\n",
		"lib/lib.go":     "package lib\n\nimport \"database/sql\"\n\nfunc Find(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id = \" + id)\n}\n",
		"svc/api/go.mod": "module example.test/api\n\ngo 1.24\n\nrequire example.test/lib v0.0.0\n",
		"svc/api/main.go": `package main

import (
	"net/http"

	"example.test/lib"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lib.Find(nil, r.FormValue("id"))
	})
}
`,
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
	return dir
}

func TestGoWorkspaceRootScansEveryModule(t *testing.T) {
	dir := writeGoWorkspace(t)
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	issues, err := Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range issues {
		if is.ID == "gomod-missing-checksum" {
			t.Errorf("workspace module reported without checksum: %s", is.Description)
		}
		if is.ID == "sql-injection" && is.Location.File == "lib/lib.go" && is.Location.Line == 6 {
			found = true
			if len(is.Trace) == 0 || is.Trace[0].Location.File != "svc/api/main.go" {
				t.Errorf("trace does not start in the service: %+v", is.Trace)
			}
		}
	}
	if !found {
		t.Fatalf("cross-module SQL injection not reported: %+v", issues)
	}
}

func TestGoWorkspaceModuleHasNoChecksumFinding(t *testing.T) {
	dir := writeGoWorkspace(t)
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	issues, err := Run(context.Background(), filepath.Join(dir, "svc", "api"), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range issues {
		if is.Category == "supply-chain" {
			t.Errorf("unexpected supply-chain finding for a workspace module: %s %s", is.ID, is.Description)
		}
	}
}
