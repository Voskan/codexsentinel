package formats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/version"
	"github.com/Voskan/codexsentinel/report"
)

func tracedIssue() report.Issue {
	step := func(file string, line, col int, kind, msg string) result.TraceStep {
		return result.TraceStep{Location: result.Location{File: file, Line: line, Column: col}, Kind: kind, Message: msg}
	}
	return report.Issue{
		RuleID: "sql-injection", Title: "SQL Injection", Description: "Untrusted data flows into a SQL query",
		Severity: report.SeverityHigh, File: "repo/repo.go", Line: 52, Column: 20, Category: "security", CWE: "CWE-89",
		Trace: []result.TraceStep{
			step("handler/handler.go", 18, 7, "source", "untrusted input"),
			step("service/service.go", 34, 9, "call", "passed to FindUnsafe"),
			step("repo/repo.go", 52, 20, "sink", "reaches (*database/sql.DB).Query"),
		},
		Fix: &result.SuggestedFix{Message: "use placeholder", Edits: []result.TextEdit{{File: "repo/repo.go", StartLine: 52, StartColumn: 21, EndLine: 52, EndColumn: 30, NewText: "$1"}}},
	}
}

func TestSARIFCodeFlows(t *testing.T) {
	data, err := BuildSARIF([]report.Issue{tracedIssue()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Version string `json:"version"`
					Rules   []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				CodeFlows []struct {
					ThreadFlows []struct {
						Locations []struct {
							Location struct {
								PhysicalLocation struct {
									ArtifactLocation struct {
										URI string `json:"uri"`
									} `json:"artifactLocation"`
									Region struct {
										StartLine   int `json:"startLine"`
										StartColumn int `json:"startColumn"`
									} `json:"region"`
								} `json:"physicalLocation"`
								Message struct {
									Text string `json:"text"`
								} `json:"message"`
							} `json:"location"`
						} `json:"locations"`
					} `json:"threadFlows"`
				} `json:"codeFlows"`
				Fixes []json.RawMessage `json:"fixes"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF envelope: %s", data)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Version != version.Version {
		t.Fatalf("driver version = %q", run.Tool.Driver.Version)
	}
	res := run.Results[0]
	if res.Locations[0].PhysicalLocation.Region.StartLine != 52 || res.Locations[0].PhysicalLocation.Region.StartColumn != 20 {
		t.Fatalf("unexpected primary region: %+v", res.Locations[0])
	}
	locs := res.CodeFlows[0].ThreadFlows[0].Locations
	if len(locs) != 3 {
		t.Fatalf("expected 3 thread flow locations, got %d", len(locs))
	}
	first := locs[0].Location.PhysicalLocation
	if first.ArtifactLocation.URI != "handler/handler.go" || first.Region.StartLine != 18 || first.Region.StartColumn != 7 {
		t.Fatalf("unexpected first step: %+v", first)
	}
	if locs[2].Location.Message.Text == "" || len(res.Fixes) != 1 {
		t.Fatal("expected step messages and fixes")
	}
	if tags, _ := run.Tool.Driver.Rules[0].Properties["tags"].([]any); len(tags) == 0 {
		t.Fatal("expected rule tags")
	}
}

func TestMarkdownAndHTMLRenderTrace(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "r.md")
	if err := WriteMarkdownReport([]report.Issue{tracedIssue()}, md, nil); err != nil {
		t.Fatal(err)
	}
	html := filepath.Join(dir, "r.html")
	if err := WriteHTMLReport([]report.Issue{tracedIssue()}, html, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{md, html} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "handler/handler.go:18") || !strings.Contains(string(data), "repo/repo.go:52") {
			t.Fatalf("%s does not render the trace", filepath.Base(path))
		}
	}
}
