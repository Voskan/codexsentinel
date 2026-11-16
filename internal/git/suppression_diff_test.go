package git

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const baseMain = "package main\n\nimport \"fmt\"\n\nconst doc = `\nexample\n`\n\nfunc main() {\n\tfmt.Println(\"a\") //nolint:errcheck // reviewed\n}\n"

// changedMain adds two directives (lines 12 and 13), rewrites the line that
// already had one (line 10) and adds directive-like text inside a raw string
// (line 6), which is not a comment.
const changedMain = "package main\n\nimport \"fmt\"\n\nconst doc = `\nx := 1 //codex:ignore sql-injection -- only text\n`\n\nfunc main() {\n\tfmt.Println(\"A\") //nolint:errcheck // reviewed again\n\tfmt.Println(\"b\")\n\tfmt.Println(\"c\") //codex:ignore sql-injection -- temp\n\t_ = 1 //nolint:gosec\n}\n"

const baseConfig = "version: 1\nrules:\n  enabled: [\"*\"]\n  disabled: []\nscan:\n  excluded_paths: [\"vendor\"]\nsuppression:\n  min_confidence: 0.5\n"

// changedConfig disables a rule (line 4, reported) and tightens or keeps the
// other settings: testdata is excluded by default and a lower confidence
// threshold reports more.
const changedConfig = "version: 1\nrules:\n  enabled: [\"*\"]\n  disabled: [sql-injection]\nscan:\n  excluded_paths: [\"vendor\", \"testdata\"]\nsuppression:\n  min_confidence: 0.3\n"

func suppressionRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), baseMain)
	writeFile(t, filepath.Join(dir, ".codexsentinel.ignore"), "# reviewed findings\nlegacy/** sql-injection\n")
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), baseConfig)
	gitCmd(t, dir, "init", "-q")
	gitCmd(t, dir, "add", ".")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	return dir
}

func TestScanAddedSuppressions(t *testing.T) {
	dir := suppressionRepo(t)
	writeFile(t, filepath.Join(dir, "main.go"), changedMain)
	// A comment and a moved entry are not new; cmd/** is.
	writeFile(t, filepath.Join(dir, ".codexsentinel.ignore"), "# reviewed findings\n# comment only\ncmd/** path-traversal\nlegacy/** sql-injection\n")
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), changedConfig)
	writeFile(t, filepath.Join(dir, "extra.go"), "package main\n\nfunc extra() {\n\t_ = 2 // #nosec G104\n}\n")
	writeFile(t, filepath.Join(dir, ".golangci.yml"), "linters:\n  disable:\n    - gosec\n  enable:\n    - errcheck\n")

	found, err := ScanAddedSuppressions(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range found {
		got = append(got, f.File+":"+itoa(f.Line))
	}
	want := []string{".codexsentinel.ignore:3", ".codexsentinel.yaml:4", ".golangci.yml:3", "extra.go:4", "main.go:12", "main.go:13"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("found %v, want %v", got, want)
	}
	is := found[0].Issue()
	if is.ID != SuppressionRuleID || is.Severity.String() != "CRITICAL" || is.CWE != "CWE-693" {
		t.Fatalf("unexpected issue %+v", is)
	}
}

func TestScanAddedSuppressionsSubdirectoryAndRef(t *testing.T) {
	dir := suppressionRepo(t)
	writeFile(t, filepath.Join(dir, "sub", "x.go"), "package sub\n\nvar X = 1 //codex:ignore global-variable -- config\n")
	writeFile(t, filepath.Join(dir, "other", "y.go"), "package other\n\nvar Y = 1 //nolint\n")
	found, err := ScanAddedSuppressions(context.Background(), filepath.Join(dir, "sub"), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].File != "x.go" || found[0].Line != 3 {
		t.Fatalf("found %+v, want only sub/x.go:3 relative to the directory", found)
	}
	if _, err := ScanAddedSuppressions(context.Background(), dir, "no-such-ref"); err == nil {
		t.Fatal("unknown reference accepted")
	}
	if _, err := ScanAddedSuppressions(context.Background(), dir, "--output=x"); err == nil {
		t.Fatal("option-like reference accepted")
	}
}

func TestDirectiveOf(t *testing.T) {
	cases := map[string]string{
		"//codex:ignore sql-injection -- reason": "codex:ignore sql-injection",
		"// codex:ignore *":                      "codex:ignore *",
		"/* codex:ignore ssrf */":                "codex:ignore ssrf",
		"//nolint":                               "nolint",
		"//nolint:gosec // reviewed":             "nolint:gosec",
		"// #nosec G101":                         "#nosec G101",
		"//nolintish":                            "",
		"// see codex:ignore docs":               "",
		"// regular comment":                     "",
	}
	for in, want := range cases {
		if got := directiveOf(in); got != want {
			t.Errorf("directiveOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWeakerValue(t *testing.T) {
	cases := []struct {
		key, value, old string
		hadOld, want    bool
	}{
		{"enable_inline_ignore", "true", "false", true, true},
		{"enable_inline_ignore", "true", "", false, false},
		{"enable_inline_ignore", "false", "true", true, false},
		{"forbid_new_suppressions", "false", "true", true, true},
		{"min_confidence", "0.9", "", false, true},
		{"min_confidence", "0.4", "0.6", true, false},
		{"fail_on_severity", "critical", "high", true, true},
		{"fail_on_severity", "low", "high", true, false},
		{"fail_on_severity", "high", "", false, false},
		{"disabled", "[]", "", false, false},
		{"disabled", "[a, b]", "[a, b, c]", true, false},
		{"disabled", "[a, d]", "[a, b]", true, true},
		{"excluded_paths", `["vendor", "**/testdata/**"]`, "", false, false},
		{"excluded_paths", `["internal/auth"]`, "", false, true},
		{"disable-all", "true", "", false, true},
	}
	for _, c := range cases {
		if got := weakerValue(c.key, c.value, c.old, c.hadOld); got != c.want {
			t.Errorf("weakerValue(%s: %s, old %q) = %v, want %v", c.key, c.value, c.old, got, c.want)
		}
	}
}

func TestParseAddedLinesHeaderLikeContent(t *testing.T) {
	diff := "diff --git a/x.txt b/x.txt\n--- a/x.txt\n+++ b/x.txt\n@@ -1,0 +2,2 @@\n+++ not a header\n+second\n"
	changes, err := parseAddedLines(strings.NewReader(diff))
	if err != nil {
		t.Fatal(err)
	}
	c := changes["x.txt"]
	if c == nil || len(c.added) != 2 || c.added[0] != 2 || c.added[1] != 3 {
		t.Fatalf("changes = %+v", c)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
