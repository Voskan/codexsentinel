package codex

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/cache"
)

func runCLIOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCmd(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestScanNoCacheAndCacheClean(t *testing.T) {
	t.Chdir(t.TempDir())
	cacheDir := t.TempDir()
	t.Setenv(cache.EnvDir, cacheDir)
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	report := filepath.Join(t.TempDir(), "r.json")

	if err := runCLI(t, "scan", dir, "--format", "json", "--out", report, "--no-cache"); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := cache.Usage(cacheDir); n != 0 {
		t.Fatalf("--no-cache wrote %d entries", n)
	}

	if err := runCLI(t, "scan", dir, "--format", "json", "--out", report); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := cache.Usage(cacheDir); n != 1 {
		t.Fatalf("want one cache entry, got %d", n)
	}

	out, err := runCLIOutput(t, "cache", "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{cacheDir, "Entries:   1", "Enabled:   true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output lacks %q:\n%s", want, out)
		}
	}

	out, err = runCLIOutput(t, "cache", "clean")
	if err != nil || !strings.Contains(out, "Removed 1 cache entries") {
		t.Fatalf("clean = %q, %v", out, err)
	}
	if n, _, _ := cache.Usage(cacheDir); n != 0 {
		t.Fatalf("%d entries left after clean", n)
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
