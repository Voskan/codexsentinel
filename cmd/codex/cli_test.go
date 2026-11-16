package codex

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/ignore"
	"github.com/Voskan/codexsentinel/report"
)

func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewRootCmd(context.Background())
	cmd.SetArgs(args)
	return cmd.Execute()
}

func fixture(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/fixture\n\ngo 1.24.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanOutputAndRecursiveTarget(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package main\nfunc main() {}\n")
	output := filepath.Join(t.TempDir(), "nested", "custom.json")
	if err := runCLI(t, "scan", dir+"/...", "--format", "json", "--out", output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("invalid JSON: %s", data)
	}
	if _, err := os.Stat("scan_reports"); !os.IsNotExist(err) {
		t.Fatalf("unexpected report directory: %v", err)
	}
}

func TestStrictScan(t *testing.T) {
	t.Chdir(t.TempDir())
	clean := fixture(t, "package main\nfunc main() {}\n")
	output := filepath.Join(t.TempDir(), "clean.json")
	if err := runCLI(t, "scan", clean, "--format", "json", "--out", output, "--strict"); err != nil {
		t.Fatal(err)
	}
	unsafe := fixture(t, "package main\nimport \"database/sql\"\nfunc query(db *sql.DB, input string) { db.Query(\"SELECT * FROM users WHERE id = \" + input) }\nfunc main() {}\n")
	err := runCLI(t, "scan", unsafe, "--format", "json", "--out", output, "--strict")
	var found *IssuesFoundError
	if !errors.As(err, &found) || found.Count == 0 {
		t.Fatalf("want IssuesFoundError, got %v", err)
	}
}

func TestMarkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ignore")
	args := []string{"mark", "handler.go:42", "--rule", "sql-injection", "--reason", "validated upstream", "--ignore-file", path}
	for i := 0; i < 2; i++ {
		if err := runCLI(t, args...); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "handler.go:42") != 1 {
		t.Fatalf("duplicate entry: %s", data)
	}
	manager := ignore.NewManager()
	if err := manager.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if !manager.IsIgnored("handler.go", 42, "sql-injection") {
		t.Fatal("suppression was not recognized")
	}
	if err := runCLI(t, "mark", "handler.go", "--ignore-file", path); err == nil {
		t.Fatal("missing rule accepted")
	}
}

func TestReportMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	issue := result.Issue{ID: "sql-injection", Category: "security", References: []string{"https://example.org/one", "https://example.org/two"}, Location: result.Location{File: "handler.go", Line: 12, Column: 9, PackagePath: "example.org/app"}}
	if err := writeReport([]result.Issue{issue}, "json", path, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got report.ReportData
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	i := got.Issues[0]
	if i.Column != 9 || i.Package != "example.org/app" || i.Category != "security" || len(i.References) != 2 || i.Reference != issue.References[0] {
		t.Fatalf("metadata lost: %+v", i)
	}
}

func TestStdoutReport(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package main\nfunc main() {}\n")
	for _, format := range []string{"json", "sarif", "markdown"} {
		t.Run(format, func(t *testing.T) {
			f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdout
			os.Stdout = f
			defer func() { os.Stdout = old; f.Close() }()
			err = runCLI(t, "scan", dir, "--format", format, "--out", "-")
			os.Stdout = old
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if format != "markdown" && !json.Valid(data) {
				t.Fatalf("stdout is not JSON: %s", data)
			}
			if format == "markdown" && !strings.HasPrefix(string(data), "# ") {
				t.Fatalf("unexpected markdown: %s", data)
			}
			if _, err := os.Stat("-"); !os.IsNotExist(err) {
				t.Fatalf("created dash file: %v", err)
			}
		})
	}
}

func TestNormalizeTargetPath(t *testing.T) {
	for input, want := range map[string]string{"./...": ".", "./pkg/...": "./pkg", "/tmp/...": "/tmp", "/...": "/", "main.go": "main.go"} {
		if got := normalizeTargetPath(input); got != want {
			t.Errorf("%s: got %s, want %s", input, got, want)
		}
	}
}

func TestFailOnSeverity(t *testing.T) {
	issues := []result.Issue{{Severity: result.SeverityLow}, {Severity: result.SeverityHigh}}
	for _, tc := range []struct {
		strict    bool
		threshold string
		want      int
	}{
		{false, "", 0}, {false, "critical", 0}, {false, "high", 1}, {false, "low", 2}, {true, "critical", 2},
	} {
		if got := failingIssues(issues, tc.strict, tc.threshold); got != tc.want {
			t.Errorf("%+v: got %d", tc, got)
		}
	}
}

func TestConfiguredFailureThreshold(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package sample\nimport \"database/sql\"\nfunc query(db *sql.DB, input string) { db.Query(\"SELECT * FROM users WHERE id = \" + input) }\n")
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	out := filepath.Join(t.TempDir(), "report.json")
	for _, threshold := range []string{"critical", "high"} {
		content := "rules:\n  enabled: [sql-injection]\nmetrics:\n  enable: false\ndependencies:\n  enable: false\nreport:\n  fail_on_severity: " + threshold + "\n"
		if err := os.WriteFile(cfg, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		err := runCLI(t, "scan", filepath.Join(dir, "main.go"), "--config", cfg, "--format", "json", "--out", out)
		var found *IssuesFoundError
		if threshold == "high" && !errors.As(err, &found) {
			t.Fatalf("expected threshold failure: %v", err)
		}
		if threshold == "critical" && err != nil {
			t.Fatal(err)
		}
	}
}

// TestScanAppliesEmbeddedRulesOutsideRepository runs the scan from a directory
// without assets/rules, the way an installed binary runs in another project,
// and runs it twice in one process as long-lived servers do.
func TestScanAppliesEmbeddedRulesOutsideRepository(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package main\n\nimport \"net/http\"\n\nfunc main() {\n\tresp, err := http.Get(\"http://example.com/data\")\n\tif err == nil {\n\t\tresp.Body.Close()\n\t}\n}\n")
	for run := 0; run < 2; run++ {
		output := filepath.Join(t.TempDir(), "report.json")
		if err := runCLI(t, "scan", dir, "--format", "json", "--out", output); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var rep report.ReportData
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, issue := range rep.Issues {
			if issue.RuleID == "go.security.plaintext-http-request" {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("run %d: want one embedded YAML finding, got %d: %+v", run, found, rep.Issues)
		}
	}
}

func TestScanFixResolvesPathsAgainstProjectRoot(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package main\n\nimport \"crypto/tls\"\n\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n\nfunc main() { _ = cfg }\n")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", filepath.Join(t.TempDir(), "r.json"), "--fix"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "InsecureSkipVerify: false") {
		t.Fatalf("fix not applied from another working directory:\n%s", data)
	}
}
