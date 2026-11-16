package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLIStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(context.Background())
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestSBOMWritesCleanJSONToStdout(t *testing.T) {
	dir := fixture(t, "package main\n\nimport \"net/http\"\n\nfunc main() { _ = http.ListenAndServe(\":8080\", nil) }\n")
	stdout, _, err := runCLIStreams(t, "sbom", dir, "--out", "-")
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components []struct{ Name, PURL string } `json:"components"`
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	if err := dec.Decode(&bom); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout has content after the document:\n%s", stdout)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.Metadata.Component.Name != "example.test/fixture" {
		t.Errorf("bom: %+v", bom)
	}
	if len(bom.Components) != 1 || bom.Components[0].PURL != "pkg:golang/stdlib@v1.24.2" {
		t.Errorf("components: %+v", bom.Components)
	}
}

func TestSBOMWritesSPDXFile(t *testing.T) {
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	out := filepath.Join(t.TempDir(), "sbom.spdx.json")
	stdout, _, err := runCLIStreams(t, "sbom", dir, "--format", "spdx", "--out", out, "--no-caps")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Errorf("unexpected stdout: %q", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil || doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("SPDX document: %v %v", err, doc["spdxVersion"])
	}
}

func TestSBOMRejectsBadFlags(t *testing.T) {
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	if _, _, err := runCLIStreams(t, "sbom", dir, "--format", "xml"); err == nil {
		t.Error("unknown format accepted")
	}
	if _, _, err := runCLIStreams(t, "sbom", dir, "--vex", "--offline"); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Errorf("--vex with --offline: %v", err)
	}
}
