package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

func writeFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replace(file, src, old, text string) result.Issue {
	start := strings.Index(src, old)
	return result.Issue{Fix: &result.SuggestedFix{Edits: []result.TextEdit{{File: file, StartOffset: start, EndOffset: start + len(old), NewText: text}}}}
}

func TestApplyFixesResolvesRelativePaths(t *testing.T) {
	root := t.TempDir()
	src := "package a\n\nvar insecure = true\n"
	writeFile(t, filepath.Join(root, "pkg", "a.go"), src)
	changed, err := ApplyFixes(root, []result.Issue{replace("pkg/a.go", src, "true", "false")})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "pkg", "a.go")
	if len(changed) != 1 || changed[0] != want {
		t.Fatalf("changed = %v, want [%s]", changed, want)
	}
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "var insecure = false") {
		t.Fatalf("fix not applied:\n%s", data)
	}
}

func TestApplyFixesSkipsOverlappingFixes(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a.go")
	src := "package a\n\nvar x = 1 + 2\n"
	writeFile(t, file, src)
	first := replace(file, src, "1 + 2", "3")
	second := replace(file, src, "2", "4")
	if _, err := ApplyFixes("", []result.Issue{first, second, {ID: "no-fix"}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	if !strings.Contains(string(data), "var x = 3") {
		t.Fatalf("first fix should win:\n%s", data)
	}
}

func TestApplyFixesRejectsBrokenOutput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.go")
	src := "package a\n\nvar x = 1\n"
	writeFile(t, file, src)
	if _, err := ApplyFixes("", []result.Issue{replace(file, src, "1", "(")}); err == nil {
		t.Fatal("broken fix applied")
	}
	if data, _ := os.ReadFile(file); string(data) != src {
		t.Fatal("file modified despite error")
	}
}

func TestApplyFixesRejectsStaleOffsets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.go")
	writeFile(t, file, "package a\n")
	issue := result.Issue{Fix: &result.SuggestedFix{Edits: []result.TextEdit{{File: file, StartOffset: 5, EndOffset: 500, NewText: "x"}}}}
	if _, err := ApplyFixes("", []result.Issue{issue}); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("err = %v, want out of range", err)
	}
}
