package analyzer

import (
	"github.com/Voskan/codexsentinel/analyzer/result"
	"sync"
	"testing"
)

func TestConcurrentReports(t *testing.T) {
	ctx := &AnalyzerContext{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx.Report(result.Issue{ID: "test"})
			ctx.SetCustom("key", true)
			ctx.GetCustom("key")
			ctx.GetIssues()
		}()
	}
	wg.Wait()
	issues := ctx.GetIssues()
	if len(issues) != 20 {
		t.Fatalf("lost reports: %d", len(issues))
	}
	issues[0].ID = "changed"
	if ctx.GetIssues()[0].ID == "changed" {
		t.Fatal("GetIssues exposes mutable slice")
	}
	ctx.ClearIssues()
	if len(ctx.GetIssues()) != 0 {
		t.Fatal("clear failed")
	}
}
