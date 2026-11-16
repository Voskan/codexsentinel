package metrics

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/dc\n\ngo 1.24\n"
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAnalyzeDeadCodeFromGraph(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": `package main

import "example.com/dc/lib"

type runner interface{ run() }

type job struct{}

func (job) run() {}

func (job) orphan() {}

func used() {}

func unused() {}

func callback() {}

func apply(f func()) { f() }

func main() {
	used()
	var r runner = job{}
	r.run()
	apply(callback)
	lib.Public()
}
`,
		"lib/lib.go": `package lib

func Public() { helper() }

func Exported() {}

func helper() {}

func stale() {}
`,
	})
	dead, err := AnalyzeDeadCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, fn := range dead {
		names = append(names, fn.Name)
	}
	sort.Strings(names)
	want := []string{"orphan", "stale", "unused"}
	if len(names) != len(want) {
		t.Fatalf("dead functions = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("dead functions = %v, want %v", names, want)
		}
	}
}
