package codex

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/report"
)

const sqlFixture = "package sample\n\nimport \"database/sql\"\n\nfunc query(db *sql.DB, input string) {\n\tdb.Query(\"SELECT * FROM users WHERE id = \" + input)\n}\n"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readReport(t *testing.T, path string) report.ReportData {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep report.ReportData
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func ruleIDs(rep report.ReportData) map[string]int {
	out := map[string]int{}
	for _, is := range rep.Issues {
		out[is.RuleID]++
	}
	return out
}

// Scanning a module from another directory uses the module's configuration,
// resolves its rule paths against the configuration file, and reads git
// metadata from the module's repository.
func TestScanUsesConfigurationOfTarget(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, sqlFixture)
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), "version: 1\nrules:\n  disabled: [sql-injection]\n  rule_paths: [rules]\n")
	writeFile(t, filepath.Join(dir, "rules", "query.yaml"), "id: acme.raw-query\ntitle: Raw Query\ncategory: style\nseverity: LOW\ndescription: A query call.\nmatch:\n  pattern: \"$DB.Query($...)\"\nsuggestion: Use the repository.\n")
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "-m", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out); err != nil {
		t.Fatal(err)
	}
	rep := readReport(t, out)
	ids := ruleIDs(rep)
	if ids["sql-injection"] != 0 || ids["acme.raw-query"] != 1 {
		t.Fatalf("configuration of the target not applied: %v", ids)
	}
	if rep.Git.CommitHash == "" || rep.Git.Message != "fixture" {
		t.Fatalf("git metadata of the target missing: %+v", rep.Git)
	}
}

// A configuration at the repository root applies to a module below it.
func TestScanFindsConfigurationAboveModule(t *testing.T) {
	t.Chdir(t.TempDir())
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(repo, ".codexsentinel.yaml"), "version: 1\nrules:\n  disabled: [sql-injection]\n")
	mod := filepath.Join(repo, "services", "api")
	writeFile(t, filepath.Join(mod, "go.mod"), "module example.test/api\n\ngo 1.24.2\n")
	writeFile(t, filepath.Join(mod, "main.go"), sqlFixture)
	out := filepath.Join(t.TempDir(), "report.json")
	if err := runCLI(t, "scan", mod, "--format", "json", "--out", out); err != nil {
		t.Fatal(err)
	}
	if ids := ruleIDs(readReport(t, out)); ids["sql-injection"] != 0 {
		t.Fatalf("repository configuration not applied: %v", ids)
	}
}

// Without --format, every format of report.formats is written to
// report.output_dir.
func TestScanWritesConfiguredFormats(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, sqlFixture)
	reports := t.TempDir()
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), "version: 1\nreport:\n  formats: [json, gitlab, json]\n  output_dir: "+reports+"\n")
	if err := runCLI(t, "scan", dir); err != nil {
		t.Fatal(err)
	}
	if ids := ruleIDs(readReport(t, filepath.Join(reports, "codex-report.json"))); ids["sql-injection"] != 1 {
		t.Fatalf("json report: %v", ids)
	}
	data, err := os.ReadFile(filepath.Join(reports, "gl-code-quality-report.json"))
	if err != nil || !strings.Contains(string(data), `"check_name": "sql-injection"`) {
		t.Fatalf("gitlab report: %v\n%s", err, data)
	}
	if _, err := os.Stat(filepath.Join(reports, "codex-report.sarif")); !os.IsNotExist(err) {
		t.Fatalf("the sarif default must not be written when formats are configured: %v", err)
	}

	err = runCLI(t, "scan", dir, "--out", filepath.Join(t.TempDir(), "r"))
	if err == nil || !strings.Contains(err.Error(), "--out needs a single report format") {
		t.Fatalf("--out with several formats: %v", err)
	}
	// --format overrides the configured list.
	single := filepath.Join(t.TempDir(), "only.json")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", single); err != nil {
		t.Fatal(err)
	}
}

// --severity applies to the dependency audit as well.
func TestDependencyScanHonorsSeverity(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.test/deps\n\ngo 1.24.2\n\nrequire example.test/lib v1.0.0\n\nreplace example.test/lib => ../lib\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), "version: 1\ndependencies:\n  check_vulnerabilities: false\n  check_licenses: false\n  check_provenance: false\n")
	run := func(extra ...string) map[string]int {
		out := filepath.Join(t.TempDir(), "deps.json")
		if err := runCLI(t, append([]string{"scan", dir, "--deps", "--format", "json", "--out", out}, extra...)...); err != nil {
			t.Fatal(err)
		}
		return ruleIDs(readReport(t, out))
	}
	if ids := run(); ids["gomod-local-replace"] != 1 {
		t.Fatalf("local replace not reported: %v", ids)
	}
	if ids := run("--severity", "high"); len(ids) != 0 {
		t.Fatalf("--severity high kept %v", ids)
	}
}

// At the root of a go.work workspace, --deps audits every module and sbom
// asks for one of them.
func TestGoWorkspaceRootDependencies(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("GOWORK", "")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.work"), "go 1.24.2\n\nuse (\n\t./svc/api\n\t./lib\n)\n")
	writeFile(t, filepath.Join(dir, "lib", "go.mod"), "module example.test/lib\n\ngo 1.24.2\n\nrequire example.test/tool v1.0.0\n\nreplace example.test/tool => ../tool\n")
	writeFile(t, filepath.Join(dir, "lib", "lib.go"), "package lib\n")
	writeFile(t, filepath.Join(dir, "svc", "api", "go.mod"), "module example.test/api\n\ngo 1.24.2\n\nrequire example.test/lib v0.0.0\n")
	writeFile(t, filepath.Join(dir, "svc", "api", "main.go"), "package main\n\nimport _ \"example.test/lib\"\n\nfunc main() {}\n")
	writeFile(t, filepath.Join(dir, ".codexsentinel.yaml"), "version: 1\ndependencies:\n  check_vulnerabilities: false\n  check_licenses: false\n")

	out := filepath.Join(t.TempDir(), "deps.json")
	if err := runCLI(t, "scan", dir, "--deps", "--format", "json", "--out", out); err != nil {
		t.Fatal(err)
	}
	rep := readReport(t, out)
	var got []string
	for _, is := range rep.Issues {
		got = append(got, is.RuleID+" "+is.File)
	}
	if len(got) != 1 || got[0] != "gomod-local-replace lib/go.mod" {
		t.Fatalf("workspace dependency findings = %v, want only the local replace in lib/go.mod", got)
	}

	err := runCLI(t, "sbom", dir, "--offline", "--no-caps")
	if err == nil || !strings.Contains(err.Error(), "lib, svc/api") {
		t.Fatalf("sbom at the workspace root: %v", err)
	}
	if _, err := runCLIOutput(t, "sbom", filepath.Join(dir, "svc", "api"), "--offline", "--no-caps"); err != nil {
		t.Fatalf("sbom of a workspace module: %v", err)
	}
}
