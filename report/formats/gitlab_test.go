package formats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/v2/report"
)

func TestGitLabEmptyReportIsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gl.json")
	if err := WriteGitLabReport(nil, path, nil); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "[]\n" {
		t.Fatalf("empty report = %q", data)
	}
}

func TestGitLabCodeQuality(t *testing.T) {
	issues := append(ciIssues(),
		report.Issue{RuleID: "dependency-vulnerability", Title: "Vulnerable Dependency", Severity: report.SeverityHigh, Category: "supply-chain", Fingerprint: "fp-1"},
		report.Issue{RuleID: "code-duplication", Title: "Duplicate Code", Severity: report.SeverityInfo, Category: "metrics", File: `pkg\x.go`, Line: 0},
	)
	path := filepath.Join(t.TempDir(), "gl.json")
	if err := WriteGitLabReport(issues, path, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(issues) {
		t.Fatalf("entries = %d", len(got))
	}
	severities := map[string]string{}
	fingerprints := map[string]bool{}
	for _, e := range got {
		for _, field := range []string{"description", "check_name", "fingerprint", "severity", "location"} {
			if e[field] == nil || e[field] == "" {
				t.Errorf("entry %v lacks %s", e, field)
			}
		}
		loc := e["location"].(map[string]any)
		begin := loc["lines"].(map[string]any)["begin"].(float64)
		if loc["path"] == "" || begin < 1 {
			t.Errorf("bad location %v", loc)
		}
		severities[e["check_name"].(string)] = e["severity"].(string)
		fp := e["fingerprint"].(string)
		if fingerprints[fp] {
			t.Errorf("duplicate fingerprint %s", fp)
		}
		fingerprints[fp] = true
	}
	want := map[string]string{"sql-injection": "blocker", "dependency-vulnerability": "critical", "http-client-unsafe": "major", "weak-hash": "minor", "code-duplication": "info"}
	for rule, sev := range want {
		if severities[rule] != sev {
			t.Errorf("%s severity = %q, want %q", rule, severities[rule], sev)
		}
	}
	entries := GitLabCodeQuality(issues)
	byRule := map[string]GitLabCodeQualityIssue{}
	for _, e := range entries {
		byRule[e.CheckName] = e
	}
	if p := byRule["sql-injection"].Location.Path; p != "repo/user.go" {
		t.Errorf("path = %q", p)
	}
	if e := byRule["dependency-vulnerability"]; e.Location.Path != "go.mod" || e.Fingerprint != "fp-1" {
		t.Errorf("dependency entry = %+v", e)
	}
	if e := byRule["code-duplication"]; e.Location.Path != "pkg/x.go" || e.Location.Lines.Begin != 1 || e.Categories[0] != "Duplication" {
		t.Errorf("duplication entry = %+v", e)
	}
	if again := GitLabCodeQuality(issues); again[0].Fingerprint != entries[0].Fingerprint {
		t.Error("fingerprints are not deterministic")
	}
}
