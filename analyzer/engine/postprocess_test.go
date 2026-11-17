package engine

import (
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

func TestDedupPrefersTraceThenConfidence(t *testing.T) {
	loc := result.Location{File: "a.go", Line: 3}
	local := result.Issue{ID: "sql-injection", Location: loc, Confidence: 0.9}
	taint := result.Issue{ID: "sql-injection", Location: loc, Confidence: 0.8, Trace: []result.TraceStep{{Kind: "source"}, {Kind: "sink"}}}
	other := result.Issue{ID: "xss", Location: loc}
	got := dedupIssues([]result.Issue{local, other, taint})
	if len(got) != 2 || len(got[0].Trace) != 2 || got[1].ID != "xss" {
		t.Fatalf("dedup = %+v", got)
	}
	low := result.Issue{ID: "r", Location: loc, Confidence: 0.5}
	high := result.Issue{ID: "r", Location: loc, Confidence: 0.9}
	if got := dedupIssues([]result.Issue{low, high}); len(got) != 1 || got[0].Confidence != 0.9 {
		t.Fatalf("confidence tie-break = %+v", got)
	}
}

func TestSortIssuesBySeverityThenLocation(t *testing.T) {
	issues := []result.Issue{
		{ID: "b", Severity: result.SeverityLow, Location: result.Location{File: "a.go", Line: 1}},
		{ID: "a", Severity: result.SeverityHigh, Location: result.Location{File: "z.go", Line: 9}},
		{ID: "c", Severity: result.SeverityHigh, Location: result.Location{File: "b.go", Line: 2}},
		{ID: "a", Severity: result.SeverityHigh, Location: result.Location{File: "b.go", Line: 2}},
	}
	sortIssues(issues)
	want := []string{"a@b.go", "c@b.go", "a@z.go", "b@a.go"}
	for i, issue := range issues {
		if got := issue.ID + "@" + issue.Location.File; got != want[i] {
			t.Fatalf("order[%d] = %s, want %s", i, got, want[i])
		}
	}
}
