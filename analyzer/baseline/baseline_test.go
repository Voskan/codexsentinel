package baseline_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Voskan/codexsentinel/v2/analyzer/baseline"
	"github.com/Voskan/codexsentinel/v2/analyzer/engine"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/config"
)

const handler = `package app

import (
	"database/sql"
	"net/http"
)

// Search looks items up by name.
//
// The query is assembled from request input.
func Search(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		_ = name
		db.Query("SELECT * FROM items WHERE name = '" + name + "'")
	}
}
`

const second = `
func Remove(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		db.Exec("DELETE FROM items WHERE id = " + r.FormValue("id"))
	}
}
`

func scan(t *testing.T, dir string) []result.Issue {
	t.Helper()
	cfg := config.NewDefaultConfig()
	cfg.Metrics.Enable = false
	cfg.Architecture.Enable = false
	cfg.Rules.Enabled = []string{"sql-injection"}
	issues, err := engine.Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return issues
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineSurvivesShiftedLines(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/app\n\ngo 1.24\n")
	file := filepath.Join(dir, "app", "app.go")
	write(t, file, handler)

	initial := scan(t, dir)
	if len(initial) != 1 || initial[0].Location.Line != 15 || initial[0].Fingerprint == "" {
		t.Fatalf("want one fingerprinted finding on line 15, got %+v", initial)
	}
	path := filepath.Join(t.TempDir(), baseline.DefaultFile)
	if err := baseline.New(initial, time.Now()).Write(path); err != nil {
		t.Fatal(err)
	}
	known, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	var header strings.Builder
	for i := 0; i < 10; i++ {
		header.WriteString("// license header line\n")
	}
	helper := "\nfunc helper() int {\n\tx := 1\n\tx++\n\tx++\n\tx++\n\tx++\n\tx++\n\treturn x\n}\n"
	shifted := header.String() + strings.Replace(handler, ")\n\n// Search", ")\n"+helper+"\n// Search", 1)
	write(t, file, shifted)
	moved := scan(t, dir)
	if len(moved) != 1 || moved[0].Location.Line != 35 {
		t.Fatalf("want the finding moved to line 35, got %+v", moved)
	}
	if fresh, removed := known.Filter(moved); len(fresh) != 0 || removed != 1 {
		t.Fatalf("baseline did not match the moved finding: %+v", fresh)
	}

	write(t, file, shifted+second)
	fresh, _ := known.Filter(scan(t, dir))
	if len(fresh) != 1 || fresh[0].Location.Line <= 35 {
		t.Fatalf("want exactly the new finding, got %+v", fresh)
	}
}

func TestFingerprintDistinguishesOccurrences(t *testing.T) {
	issues := []result.Issue{
		{ID: "r", Location: result.Location{File: "a.go", Line: 9, Function: "f"}},
		{ID: "r", Location: result.Location{File: "a.go", Line: 4, Function: "f"}},
	}
	baseline.Assign("", nil, nil, issues)
	if issues[0].Fingerprint == issues[1].Fingerprint {
		t.Fatal("identical lines in one function share a fingerprint")
	}
	if issues[1].Fingerprint != baseline.Fingerprint("r", "a.go", "f", "", 0) {
		t.Fatal("first occurrence should have index 0")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	write(t, path, `{"version": 99, "entries": []}`)
	if _, err := baseline.Load(path); err == nil {
		t.Fatal("unknown version accepted")
	}
}
