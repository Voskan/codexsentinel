package docgen

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/catalog"
)

// TestCommittedReferenceIsCurrent fails when docs/rules differs from the
// generator's output; run `make docs-generate` after changing rules.
func TestCommittedReferenceIsCurrent(t *testing.T) {
	committed := filepath.Join("..", "..", "docs", "rules")
	want := Files()
	entries, err := os.ReadDir(committed)
	if err != nil {
		t.Fatalf("%v; run make docs-generate", err)
	}
	var extra []string
	for _, e := range entries {
		if _, ok := want[e.Name()]; !ok {
			extra = append(extra, e.Name())
		}
	}
	if len(extra) > 0 {
		t.Errorf("docs/rules has files the catalog does not generate: %v; run make docs-generate", extra)
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got, err := os.ReadFile(filepath.Join(committed, name))
		if err != nil || !bytes.Equal(got, want[name]) {
			t.Errorf("docs/rules/%s is out of date; run make docs-generate", name)
		}
	}
}

func TestWriteIsDeterministicAndPrunes(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "removed-rule.md")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("not generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("page of a removed rule was kept")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("non-Markdown file was removed")
	}
	first, _ := os.ReadFile(filepath.Join(dir, "README.md"))
	if err := Write(dir); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, "README.md"))
	if !bytes.Equal(first, second) {
		t.Error("output differs between runs")
	}
}

func TestPagesCoverEveryRule(t *testing.T) {
	files := Files()
	index := string(files["README.md"])
	for _, d := range catalog.All() {
		p := string(files[d.ID+".md"])
		for _, want := range []string{"# [" + d.Code + "] " + d.Title + " (" + d.ID + ")", "## Why It Matters in Go", "## Vulnerable / Problematic Example",
			"## Safe / Idiomatic Go Pattern", "## Configuration & Suppression", "//codex:ignore " + d.ID + " -- <reason>"} {
			if !strings.Contains(p, want) {
				t.Errorf("%s page lacks %q", d.ID, want)
			}
		}
		if !strings.Contains(index, "[`"+d.ID+"`]("+d.ID+".md)") {
			t.Errorf("index lacks %s", d.ID)
		}
	}
	if got := anchor("Reliability & Concurrency"); got != "reliability--concurrency" {
		t.Errorf("anchor = %q", got)
	}
}
