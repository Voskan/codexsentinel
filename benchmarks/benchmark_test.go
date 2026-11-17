package benchmarks

import (
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/cache"
	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
)

type expectation struct {
	Class  string `json:"class"`
	Rule   string `json:"rule"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

func (e expectation) key() string { return fmt.Sprintf("%s %s:%d", e.Rule, e.File, e.Line) }

type manifest struct {
	Defects    []expectation `json:"defects"`
	Additional []expectation `json:"additional"`
}

func scan(tb testing.TB, dir string, c *cache.Cache) []result.Issue {
	tb.Helper()
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = c != nil
	issues, err := engine.RunWithOptions(context.Background(), dir, &cfg, engine.Options{Cache: c})
	if err != nil {
		tb.Fatal(err)
	}
	return issues
}

func issueKey(is result.Issue) string {
	return fmt.Sprintf("%s %s:%d", is.ID, filepath.ToSlash(is.Location.File), is.Location.Line)
}

// supports reports whether the toolchain can load a module that requires
// the given Go release, without downloading another toolchain.
func supports(release string) bool { return slices.Contains(build.Default.ReleaseTags, release) }

func TestBenchmarkPrecisionAndRecall(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("corpus", "vulnerable-app", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, is := range scan(t, filepath.Join("corpus", "vulnerable-app"), nil) {
		found[issueKey(is)] = true
	}

	expected := map[string]bool{}
	tp := 0
	for _, d := range m.Defects {
		expected[d.key()] = true
		if found[d.key()] {
			tp++
		} else {
			t.Errorf("missed defect %q: %s", d.Class, d.key())
		}
	}
	for _, a := range m.Additional {
		expected[a.key()] = true
		if !found[a.key()] {
			t.Errorf("missed additional finding %s", a.key())
		}
	}
	var unexpected []string
	for k := range found {
		if !expected[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(unexpected)
	recall := float64(tp) / float64(len(m.Defects))
	t.Logf("vulnerable-app: %d/%d defects found (recall %.1f%%), %d additional, %d unexpected",
		tp, len(m.Defects), 100*recall, len(m.Additional), len(unexpected))
	if recall < 0.95 {
		t.Errorf("recall %.1f%% is below 95%%", 100*recall)
	}
	if len(unexpected) > 0 {
		t.Errorf("findings not in the manifest: %v", unexpected)
	}

	if !supports("go1.25") {
		t.Skip("safe-app requires Go 1.25")
	}
	safe := scan(t, filepath.Join("corpus", "safe-app"), nil)
	for _, is := range safe {
		t.Errorf("false positive on safe-app: %s: %s", issueKey(is), is.Description)
	}
	precision := float64(tp) / float64(tp+len(unexpected)+len(safe))
	t.Logf("safe-app: %d findings; precision %.1f%%", len(safe), 100*precision)
}

func BenchmarkFullEngineScan(b *testing.B) {
	dir := filepath.Join("corpus", "vulnerable-app")
	b.Run("cold", func(b *testing.B) {
		for b.Loop() {
			scan(b, dir, nil)
		}
	})
	b.Run("warm-cache", func(b *testing.B) {
		c, err := cache.Open(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		scan(b, dir, c)
		for b.Loop() {
			scan(b, dir, c)
		}
	})
}
